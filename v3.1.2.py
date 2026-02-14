#!/usr/bin/env python3
"""
RS-RQH-CRL-Heliotron :: HELIOTRON v3.1.2-HARDENED-AI
Single-file, copy/paste bootstrap optimized for AI sessions.

GOALS
- Deterministic Canonical Wire Format (CWF-1) serialization.
- Domain-locked SHA-256 sealing to prevent cross-protocol replay.
- Append-only hash chain with strict continuity.
- Zero-trust full-chain verifier with tiered gates and uniform error codes.
- Single-writer design, forensic-reader design.

NON-GOALS (explicit)
- This file does NOT provide authorship/signature attestation by itself (use GPG/TPM/etc externally).
- This file does NOT provide multi-writer concurrency (single writer by design).
- This file does NOT prevent whole-file replacement (anchor tips externally if needed).

USAGE
  # verify
  python heliotron_v3_1_2_hardened_ai.py verify --log logs/audit.jsonl

  # append event
  python heliotron_v3_1_2_hardened_ai.py log --log logs/audit.jsonl --status SYSTEM_STARTUP --evidence '{"subsystem":"CORE"}'

  # initialize + seal marker (requires --run-all gate)
  python heliotron_v3_1_2_hardened_ai.py seal --log logs/audit.jsonl --run-all

  # run checklist (verify + env checks)
  python heliotron_v3_1_2_hardened_ai.py checklist --log logs/audit.jsonl --run-all

  # create minimal environment
  mkdir -p logs && touch logs/audit.jsonl && chmod 600 logs/audit.jsonl
"""

from __future__ import annotations

import os
import sys
import json
import math
import struct
import hashlib
import argparse
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import is_dataclass, asdict
from typing import Any, Dict, List, Tuple, Optional, Union


# =============================================================================
# DO NOT EDIT (PROTOCOL LOCK) — Editing breaks compatibility with RS-RQH-CRL-v1.1
# =============================================================================

PROTOCOL_ID: str = "RS-RQH-CRL-v1.1"
CWF_ID: str = "CWF-1"
GENESIS_PREV: str = "GENESIS_BLOCK_INIT"
DOMAIN_PREFIX: str = "RS-RQH-CRL-v1.1|AUDIT_ENTRY|"

# Canonical JSON settings: stable key order, no whitespace, UTF-8.
CANON_JSON = dict(sort_keys=True, separators=(",", ":"), ensure_ascii=False)

# Protocol invariant: Domain pinning must match.
# INV-DOMAIN-01: entry["domain_prefix"] == DOMAIN_PREFIX


# =============================================================================
# SAFE TO TUNE (IMPLEMENTATION CONSTANTS) — Does not change protocol semantics
# =============================================================================

MAX_STATUS_LEN: int = 128
MAX_TS_LEN: int = 64
TAIL_SCAN_BYTES: int = 65536  # 64KB
MAX_LINE_BYTES: int = 4 * 1024 * 1024  # 4MB sanity limit per jsonl line


# =============================================================================
# ERROR CODES (UNIFORM)
# =============================================================================

# Syntactic
E_JSON_DECODE_FAIL = "E_JSON_DECODE_FAIL"
E_LINE_TOO_LARGE = "E_LINE_TOO_LARGE"

# Schema / Types / Bounds
E_MISSING_KEYS = "E_MISSING_KEYS"
E_BAD_FIELD_TYPES = "E_BAD_FIELD_TYPES"
E_STATUS_TOO_LONG = "E_STATUS_TOO_LONG"
E_BAD_TS_TYPE = "E_BAD_TS_TYPE"
E_BAD_TIMESTAMP_FORMAT = "E_BAD_TIMESTAMP_FORMAT"
E_INVALID_ISO_TIMESTAMP = "E_INVALID_ISO_TIMESTAMP"
E_NAIVE_TIMESTAMP = "E_NAIVE_TIMESTAMP"
E_NON_UTC_TIMESTAMP = "E_NON_UTC_TIMESTAMP"

# Identity & Hash format
E_DOMAIN_PREFIX_MISMATCH = "E_DOMAIN_PREFIX_MISMATCH"
E_BAD_ENTRY_HASH_FORMAT = "E_BAD_ENTRY_HASH_FORMAT"
E_BAD_PREV_HASH_FORMAT = "E_BAD_PREV_HASH_FORMAT"

# Continuity
E_GENESIS_PREV_MISMATCH = "E_GENESIS_PREV_MISMATCH"
E_GENESIS_REAPPEARED = "E_GENESIS_REAPPEARED"
E_CHAIN_LINK_BROKEN = "E_CHAIN_LINK_BROKEN"

# Cryptographic / Sanitization
E_UNSANITIZED_ON_DISK = "E_UNSANITIZED_ON_DISK"
E_HASH_MISMATCH = "E_HASH_MISMATCH"

# Writer hardening
E_STATUS_MUST_BE_STR = "E_STATUS_MUST_BE_STR"
E_AUDIT_TIP_UNRECOVERABLE = "E_AUDIT_TIP_UNRECOVERABLE"


# =============================================================================
# CANONICAL ENTRY SCHEMA — SINGLE SOURCE OF TRUTH
# =============================================================================

def canonical_entry_keys() -> Tuple[str, ...]:
    """
    Canonical schema keys (writer and verifier must match).
    Note: 'entry_sha256' is excluded when computing seal.
    """
    return (
        "protocol",
        "cwf",
        "domain_prefix",
        "ts_iso",
        "status",
        "prev_entry_sha256",
        "evidence",
        "extra",
        "entry_sha256",
    )


def required_keys() -> Tuple[str, ...]:
    """Keys that MUST exist on disk."""
    return canonical_entry_keys()


def seal_keys() -> Tuple[str, ...]:
    """Keys that are sealed (all except entry_sha256)."""
    return tuple(k for k in canonical_entry_keys() if k != "entry_sha256")


# =============================================================================
# DETERMINISTIC SERIALIZATION (CWF-1)
# =============================================================================

def _float64_hex(v: float) -> str:
    """Deterministic IEEE 754 little-endian hex encoding for floats."""
    if not math.isfinite(v):
        raise ValueError(f"NON_FINITE_FLOAT:{repr(v)}")
    # Normalize -0.0 to +0.0 for determinism.
    return struct.pack("<d", float(0.0 if v == 0.0 else v)).hex()


def _json_sanitize(x: Any) -> Any:
    """Recursively reduces complex types to Canonical Wire Format (CWF-1)."""
    if x is None or isinstance(x, (bool, str, int)):
        return x
    if isinstance(x, float):
        return {"__f64le__": _float64_hex(x)}
    if is_dataclass(x):
        return _json_sanitize(asdict(x))
    if isinstance(x, (bytes, bytearray)):
        return {"__bytes_hex__": bytes(x).hex()}
    if isinstance(x, Path):
        return str(x)
    if isinstance(x, (list, tuple)):
        return [_json_sanitize(v) for v in x]
    if isinstance(x, dict):
        return {str(k): _json_sanitize(v) for k, v in x.items()}
    raise TypeError(f"UNSERIALIZABLE_TYPE:{type(x).__name__}")


def _assert_sanitized(x: Any) -> None:
    """
    Recursive schema-aware validator ensuring no raw floats / exotic types reach hashing.
    Accepts:
      - None, bool, int, str
      - list
      - dict with str keys
      - special tag dicts: {"__f64le__": <16 hex>} or {"__bytes_hex__": <even hex>}
    """
    if isinstance(x, float):
        raise TypeError("UNSANITIZED_FLOAT_DETECTED")

    if isinstance(x, (list, tuple)):
        for v in x:
            _assert_sanitized(v)
        return

    if isinstance(x, dict):
        for k in x.keys():
            if not isinstance(k, str):
                raise TypeError("UNSANITIZED_KEY_TYPE_DETECTED")

        if "__f64le__" in x:
            if set(x.keys()) != {"__f64le__"}:
                raise TypeError("BAD_F64LE_TAG_SHAPE")
            v = x["__f64le__"]
            if not (isinstance(v, str) and len(v) == 16 and all(c in "0123456789abcdef" for c in v)):
                raise TypeError("BAD_F64LE_VALUE")
            return

        if "__bytes_hex__" in x:
            if set(x.keys()) != {"__bytes_hex__"}:
                raise TypeError("BAD_BYTES_TAG_SHAPE")
            v = x["__bytes_hex__"]
            if not (isinstance(v, str) and len(v) % 2 == 0 and all(c in "0123456789abcdef" for c in v)):
                raise TypeError("BAD_BYTES_HEX_VALUE")
            return

        for v in x.values():
            _assert_sanitized(v)
        return

    if x is None or isinstance(x, (bool, int, str)):
        return

    raise TypeError(f"UNSANITIZED_TYPE_DETECTED:{type(x).__name__}")


def is_valid_hex_sha256(h: Any) -> bool:
    """Strict 64-char lowercase hex validator."""
    return isinstance(h, str) and len(h) == 64 and all(c in "0123456789abcdef" for c in h)


def compute_seal_sanitized(sanitized: Dict[str, Any]) -> str:
    """
    Canonical Seal:
      seal = SHA256( Bytes(DOMAIN_PREFIX) || Bytes(CanonicalJSON(sanitized)) )
    """
    _assert_sanitized(sanitized)
    payload = json.dumps(sanitized, **CANON_JSON).encode("utf-8")
    h = hashlib.sha256()
    h.update(DOMAIN_PREFIX.encode("utf-8"))
    h.update(payload)
    return h.hexdigest()


# =============================================================================
# UTILS
# =============================================================================

def _preview(x: Any, n: int = 80) -> str:
    try:
        s = str(x) if x is not None else "None"
    except Exception:
        return "<unstringifiable>"
    return s if len(s) <= n else s[:n] + "...(trunc)"


def _err(line: int, code: str, **fields: Any) -> Dict[str, Any]:
    out = {"line": line, "error_code": code}
    out.update(fields)
    return out


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso_utc(ts: str) -> datetime:
    # Accepts "...Z" or "...+00:00"
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError(E_NAIVE_TIMESTAMP)
    off = dt.utcoffset()
    if off is None or off.total_seconds() != 0:
        raise ValueError(E_NON_UTC_TIMESTAMP)
    return dt


# =============================================================================
# WRITER (LOGGER)
# =============================================================================

class CRLAuditLogger:
    """
    Single-writer append-only logger.
    Hardening:
      - If an existing non-empty log has no recoverable tip, REFUSE to write.
      - Every write is fsync()'d for hardware persistence.
    """

    def __init__(self, log_path: Union[str, Path]):
        self.path = Path(log_path)
        self.tip_hash = self._load_tip_hash_if_any()

        if self.path.exists() and self.path.stat().st_size > 0 and self.tip_hash is None:
            raise RuntimeError(f"{E_AUDIT_TIP_UNRECOVERABLE}:RUN_CHAIN_REPAIR")

    def _load_tip_hash_if_any(self) -> Optional[str]:
        """
        Self-healing initialization:
        - Read tail window and scan backward for the first valid entry_sha256.
        - This is intentionally conservative: we only recover the tip format, not integrity.
          Integrity MUST be certified by verifier/checklist before sealing.
        """
        if not self.path.exists() or self.path.stat().st_size == 0:
            return None
        try:
            with open(self.path, "rb") as f:
                f.seek(0, 2)
                f.seek(max(0, f.tell() - TAIL_SCAN_BYTES))
                lines = f.read().splitlines()

            for raw in reversed(lines):
                try:
                    obj = json.loads(raw.decode("utf-8"))
                    tip = obj.get("entry_sha256")
                    if is_valid_hex_sha256(tip):
                        return tip
                except Exception:
                    continue
            return None
        except Exception:
            return None

    def _build_entry_core(self, status: str, evidence: Any, extra: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        # Status gate
        if not isinstance(status, str):
            raise TypeError(f"{E_STATUS_MUST_BE_STR}:found={type(status).__name__}")
        if len(status) > MAX_STATUS_LEN:
            raise ValueError(E_STATUS_TOO_LONG)

        prev = self.tip_hash if self.tip_hash else GENESIS_PREV

        return {
            "protocol": PROTOCOL_ID,
            "cwf": CWF_ID,
            "domain_prefix": DOMAIN_PREFIX,
            "ts_iso": _utc_now_z(),
            "status": status,
            "prev_entry_sha256": prev,
            "evidence": evidence,
            "extra": extra or {},
        }

    def log_event(self, status: str, evidence: Any, extra: Optional[Dict[str, Any]] = None) -> str:
        """
        Append a single event:
          1) build core entry
          2) sanitize to CWF-1
          3) seal domain-prefixed
          4) append jsonl + fsync
        """
        core = self._build_entry_core(status=status, evidence=evidence, extra=extra)
        sanitized = _json_sanitize(core)

        # INV-DOMAIN-01: pin domain field
        if sanitized.get("domain_prefix") != DOMAIN_PREFIX:
            raise RuntimeError(E_DOMAIN_PREFIX_MISMATCH)

        entry_sha = compute_seal_sanitized(sanitized)
        sanitized["entry_sha256"] = entry_sha

        # Enforce file mode hardening if file exists
        if self.path.exists():
            try:
                os.chmod(self.path, 0o600)
            except Exception:
                # Non-fatal; environment-dependent.
                pass
        else:
            # Ensure parent exists
            self.path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(sanitized, **CANON_JSON) + "\n")
            f.flush()
            os.fsync(f.fileno())

        self.tip_hash = entry_sha
        return entry_sha


# =============================================================================
# READER (VERIFIER)
# =============================================================================

class CRLIntegrityVerifier:
    """Zero-trust full-chain verifier."""

    def __init__(self, log_path: Union[str, Path]):
        self.path = Path(log_path)

    def verify_full_chain(self) -> Tuple[bool, Dict[str, Any]]:
        report: Dict[str, Any] = {
            "verified_at": _utc_now_z(),
            "entries_processed": 0,
            "first_corrupt_line": None,
            "first_chain_break_line": None,
            "last_verified_tip": None,
            "last_verified_line": 0,
            "file_tip_hash": None,
            "corrupt_entries": [],
            "chain_breaks": [],
        }

        if not self.path.exists():
            return False, report

        expected_prev = GENESIS_PREV
        req = required_keys()

        with open(self.path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                # Tier -2: Line size sanity (prevents memory/CPU abuse)
                if len(line) > MAX_LINE_BYTES:
                    if report["first_corrupt_line"] is None:
                        report["first_corrupt_line"] = line_no
                    report["corrupt_entries"].append(_err(line_no, E_LINE_TOO_LARGE, bytes=len(line)))
                    continue

                raw = line.strip()
                if not raw:
                    continue

                # Tier -1: JSON decode
                try:
                    entry = json.loads(raw)
                except Exception as e:
                    if report["first_corrupt_line"] is None:
                        report["first_corrupt_line"] = line_no
                    report["corrupt_entries"].append(_err(line_no, E_JSON_DECODE_FAIL, details=str(e)))
                    continue

                # Track raw file tip progress safely (stringified)
                report["file_tip_hash"] = _preview(entry.get("entry_sha256"))

                # Tier 0: Schema presence
                missing = [k for k in req if k not in entry]
                if missing:
                    if report["first_corrupt_line"] is None:
                        report["first_corrupt_line"] = line_no
                    report["corrupt_entries"].append(_err(line_no, E_MISSING_KEYS, keys=missing))
                    continue

                # Extract fields
                ts = entry.get("ts_iso")
                status_val = entry.get("status")
                actual_entry_hash = entry.get("entry_sha256")
                actual_prev_hash = entry.get("prev_entry_sha256")
                domain_field = entry.get("domain_prefix")

                # -----------------------------------------------------------------
                # Tier 0.5: Explicit Type & Geometry Gates (expanded, AI-proof)
                # -----------------------------------------------------------------
                try:
                    # Fundamental type validation
                    if not isinstance(ts, str):
                        raise ValueError(E_BAD_TS_TYPE)
                    if not isinstance(status_val, str):
                        raise ValueError(E_BAD_FIELD_TYPES)
                    if not isinstance(actual_entry_hash, str):
                        raise ValueError(E_BAD_FIELD_TYPES)
                    if not isinstance(actual_prev_hash, str):
                        raise ValueError(E_BAD_FIELD_TYPES)
                    if not isinstance(domain_field, str):
                        raise ValueError(E_BAD_FIELD_TYPES)

                    # Boundary validations
                    if len(ts) > MAX_TS_LEN:
                        raise ValueError(E_BAD_TIMESTAMP_FORMAT)
                    if len(status_val) > MAX_STATUS_LEN:
                        raise ValueError(E_STATUS_TOO_LONG)

                    # Domain pinning invariant
                    if domain_field != DOMAIN_PREFIX:
                        raise ValueError(E_DOMAIN_PREFIX_MISMATCH)

                    # Hex/Genesis parity gate
                    if not is_valid_hex_sha256(actual_entry_hash):
                        raise ValueError(E_BAD_ENTRY_HASH_FORMAT)
                    if not (actual_prev_hash == GENESIS_PREV or is_valid_hex_sha256(actual_prev_hash)):
                        raise ValueError(E_BAD_PREV_HASH_FORMAT)

                except ValueError as e:
                    code = str(e)
                    if report["first_corrupt_line"] is None:
                        report["first_corrupt_line"] = line_no
                    report["corrupt_entries"].append(
                        _err(
                            line_no,
                            code,
                            status_preview=_preview(status_val),
                            entry_hash_preview=_preview(actual_entry_hash),
                            prev_hash_preview=_preview(actual_prev_hash),
                            ts_preview=_preview(ts),
                            domain_preview=_preview(domain_field),
                            types={
                                "ts_iso": type(ts).__name__,
                                "status": type(status_val).__name__,
                                "entry_sha256": type(actual_entry_hash).__name__,
                                "prev_entry_sha256": type(actual_prev_hash).__name__,
                                "domain_prefix": type(domain_field).__name__,
                            },
                        )
                    )
                    continue

                # -----------------------------------------------------------------
                # Tier 0.7: Semantic Timestamp & Anchor Gate
                # -----------------------------------------------------------------
                try:
                    _parse_iso_utc(ts)
                except Exception as e:
                    if report["first_corrupt_line"] is None:
                        report["first_corrupt_line"] = line_no
                    # Prefer stable code if possible
                    code = str(e)
                    if code not in (E_NAIVE_TIMESTAMP, E_NON_UTC_TIMESTAMP):
                        code = E_INVALID_ISO_TIMESTAMP
                    report["corrupt_entries"].append(
                        _err(line_no, code, found=_preview(ts), details=_preview(e))
                    )
                    continue

#-----------------------------------------------------------------
                # Tier 0.7: Semantic Timestamp & Anchor Gate
                # -----------------------------------------------------------------
                try:
                    _parse_iso_utc(ts)
                except Exception as e:
                    if report["first_corrupt_line"] is None:
                        report["first_corrupt_line"] = line_no
                    # Prefer stable code if possible
                    code = str(e)
                    if code not in (E_NAIVE_TIMESTAMP, E_NON_UTC_TIMESTAMP):
                        code = E_INVALID_ISO_TIMESTAMP
                    report["corrupt_entries"].append(
                        _err(line_no, code, found=_preview(ts), details=_preview(e))
                    )
                    continue

                # -----------------------------------------------------------------
                # Tier 2: Continuity Gates
                # -----------------------------------------------------------------
                if report["entries_processed"] == 0:
                    if actual_prev_hash != GENESIS_PREV:
                        if report["first_chain_break_line"] is None:
                            report["first_chain_break_line"] = line_no
                        report["chain_breaks"].append(
                            _err(
                                line_no,
                                E_GENESIS_PREV_MISMATCH,
                                found=_preview(actual_prev_hash),
                                expected=_preview(GENESIS_PREV),
                            )
                        )
                        continue
                else:
                    if actual_prev_hash == GENESIS_PREV:
                        if report["first_chain_break_line"] is None:
                            report["first_chain_break_line"] = line_no
                        report["chain_breaks"].append(_err(line_no, E_GENESIS_REAPPEARED))
                        continue
                    if actual_prev_hash != expected_prev:
                        if report["first_chain_break_line"] is None:
                            report["first_chain_break_line"] = line_no
                        report["chain_breaks"].append(
                            _err(
                                line_no,
                                E_CHAIN_LINK_BROKEN,
                                found=_preview(actual_prev_hash),
                                expected=_preview(expected_prev),
                            )
                        )
                        continue

                # -----------------------------------------------------------------
                # Tier 3: Cryptographic Seal & Sanitization Assertion
                # -----------------------------------------------------------------
                core = dict(entry)
                core.pop("entry_sha256", None)
                try:
                    computed = compute_seal_sanitized(core)
                except TypeError as e:
                    if report["first_corrupt_line"] is None:
                        report["first_corrupt_line"] = line_no
                    report["corrupt_entries"].append(
                        _err(line_no, E_UNSANITIZED_ON_DISK, details=str(e))
                    )
                    continue

                if computed != actual_entry_hash:
                    if report["first_corrupt_line"] is None:
                        report["first_corrupt_line"] = line_no
                    report["corrupt_entries"].append(
                        _err(
                            line_no,
                            E_HASH_MISMATCH,
                            expected=_preview(computed),
                            found=_preview(actual_entry_hash),
                        )
                    )
                    continue

                # Tier 4: State advancement
                report["entries_processed"] += 1
                report["last_verified_tip"] = actual_entry_hash
                report["last_verified_line"] = line_no
                expected_prev = actual_entry_hash

        ok = (len(report["corrupt_entries"]) == 0 and len(report["chain_breaks"]) == 0)
        return ok, report


# =============================================================================
# CHECKLIST + SEALING
# =============================================================================

class Checklist:
    """
    Minimal 'AI-proof' checklist:
      - permission hardening
      - file existence
      - full-chain verify
    """

    def __init__(self, log_path: str):
        self.log_path = log_path
        self.report: Dict[str, Any] = {
            "checklist_at": _utc_now_z(),
            "log_path": log_path,
            "checks": [],
            "ok": False,
        }

    def _add(self, name: str, ok: bool, **details: Any) -> None:
        self.report["checks"].append({"name": name, "ok": ok, **details})

    def run(self, run_all: bool = False) -> bool:
        path = Path(self.log_path)

        # Check 1: Path exists
        self._add("LOG_EXISTS", path.exists(), found=str(path))

        # Check 2: Permissions (best-effort cross-platform)
        perm_ok = True
        perm_detail = {}
        if path.exists():
            try:
                mode = path.stat().st_mode & 0o777
                perm_detail["mode_octal"] = oct(mode)
                # Require <= 0600 on POSIX; on Windows this may be meaningless.
                perm_ok = (mode & 0o077) == 0
            except Exception as e:
                perm_ok = False
                perm_detail["error"] = str(e)
        self._add("LOG_PERMISSIONS_RESTRICTED", perm_ok, **perm_detail)

        # Check 3: Full-chain verify
        if run_all and path.exists():
            verifier = CRLIntegrityVerifier(self.log_path)
            ok, vrep = verifier.verify_full_chain()
            self._add("FULL_CHAIN_VERIFY", ok, summary={
                "entries_processed": vrep.get("entries_processed"),
                "last_verified_line": vrep.get("last_verified_line"),
                "last_verified_tip": _preview(vrep.get("last_verified_tip")),
                "first_corrupt_line": vrep.get("first_corrupt_line"),
                "first_chain_break_line": vrep.get("first_chain_break_line"),
            })
            self.report["verifier_report"] = vrep

        # Final
        # If run_all, require FULL_CHAIN_VERIFY ok; else minimal env checks only.
        if run_all:
            self.report["ok"] = all(c["ok"] for c in self.report["checks"] if c["name"] in ("LOG_EXISTS", "FULL_CHAIN_VERIFY"))
        else:
            self.report["ok"] = all(c["ok"] for c in self.report["checks"] if c["name"] == "LOG_EXISTS")

        return bool(self.report["ok"])

    def print_report(self) -> None:
        print(json.dumps(self.report, indent=2, sort_keys=True))


def maybe_seal_production(log_path: str) -> str:
    """
    Append the production seal marker event.
    This is a normal log_event() entry: it is sealed and chained like all others.
    """
    logger = CRLAuditLogger(log_path)
    return logger.log_event(
        status="V3_1_2_PRODUCTION_SEALED",
        evidence={
            "manifest_version": "3.1.2",
            "deployment_anchor": "SECURE_BOOT",
        },
        extra={},
    )


# =============================================================================
# CLI
# =============================================================================

def _load_json_arg(s: str) -> Any:
    try:
        return json.loads(s)
    except Exception:
        # Accept raw strings as a convenience.
        return s


def cmd_verify(args: argparse.Namespace) -> int:
    v = CRLIntegrityVerifier(args.log)
    ok, rep = v.verify_full_chain()
    print("=== VERIFY_REPORT ===")
    print(f"ok: {ok}")
    print(f"entries_processed: {rep['entries_processed']}")
    print(f"last_verified_line: {rep['last_verified_line']}")
    print(f"last_verified_tip: {_preview(rep['last_verified_tip'])}")
    if not ok:
        print("--- corrupt_entries[0:3] ---")
        print(json.dumps(rep["corrupt_entries"][:3], indent=2, sort_keys=True))
        print("--- chain_breaks[0:3] ---")
        print(json.dumps(rep["chain_breaks"][:3], indent=2, sort_keys=True))
    return 0 if ok else 2


def cmd_log(args: argparse.Namespace) -> int:
    logger = CRLAuditLogger(args.log)
    evidence = _load_json_arg(args.evidence) if args.evidence is not None else {}
    extra = _load_json_arg(args.extra) if args.extra is not None else {}
    tip = logger.log_event(status=args.status, evidence=evidence, extra=extra)
    print("=== LOG_EVENT ===")
    print(f"new_tip: {tip}")
    return 0


def cmd_checklist(args: argparse.Namespace) -> int:
    checklist = Checklist(args.log)
    ok = checklist.run(run_all=args.run_all)
    checklist.print_report()
    return 0 if ok else 2


def cmd_seal(args: argparse.Namespace) -> int:
    # Guardrail: --seal requires --run-all
    if not args.run_all:
        print("CRITICAL_ERROR: SEAL_REFUSED")
        print("REASON: seal requires --run-all to ensure chain integrity.")
        return 3

    checklist = Checklist(args.log)
    ok = checklist.run(run_all=True)
    checklist.print_report()

    if not ok:
        print("\nOVERALL: FAIL - SEALING_ABORTED")
        return 2

    print("\nOVERALL: PASS")
    print("INITIATING_PRODUCTION_SEAL...")
    new_tip = maybe_seal_production(args.log)
    print(f"PRODUCTION_SEAL_TIP: {new_tip}")

    # Final verification pass
    v = CRLIntegrityVerifier(args.log)
    ok2, rep2 = v.verify_full_chain()
    print(f"POST_SEAL_VERIFY_OK: {ok2}")
    print(f"POST_SEAL_ENTRIES:   {rep2['entries_processed']}")
    return 0 if ok2 else 2


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="RS-RQH-CRL-Heliotron v3.1.2-HARDENED-AI")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_verify = sub.add_parser("verify", help="Verify full chain integrity")
    ap_verify.add_argument("--log", required=True, help="Path to CRL audit jsonl file")
    ap_verify.set_defaults(func=cmd_verify)

    ap_log = sub.add_parser("log", help="Append one event")
    ap_log.add_argument("--log", required=True, help="Path to CRL audit jsonl file")
    ap_log.add_argument("--status", required=True, help="Status string (<=128 chars)")
    ap_log.add_argument("--evidence", default=None, help='JSON evidence payload (or raw string)')
    ap_log.add_argument("--extra", default=None, help='JSON extra payload (or raw string)')
    ap_log.set_defaults(func=cmd_log)

    ap_check = sub.add_parser("checklist", help="Run minimal checklist (use --run-all for full chain verify)")
    ap_check.add_argument("--log", required=True, help="Path to CRL audit jsonl file")
    ap_check.add_argument("--run-all", action="store_true", help="Run full checklist including full-chain verify")
    ap_check.set_defaults(func=cmd_checklist)

    ap_seal = sub.add_parser("seal", help="Seal v3.1.2 production marker (requires --run-all)")
    ap_seal.add_argument("--log", required=True, help="Path to CRL audit jsonl file")
    ap_seal.add_argument("--run-all", action="store_true", help="Required guardrail: run full verification first")
    ap_seal.set_defaults(func=cmd_seal)

    return ap


def main() -> int:
    ap = build_arg_parser()
    args = ap.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())