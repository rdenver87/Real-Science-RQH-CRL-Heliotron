"""
svs_flameflow_v1_0.py
SVS-FLAMEFLOW-v1.0 — Self-Verifying Science Protocol for Fluid & Combustion Systems
(standalone, code-only reference implementation)

Debugged notes (v1.0 implementation choices):
- Calibration lock: epsilon per channel is alpha*sigma, alpha fixed prior to fitting.
- Residual test uses RMS-normalized residual: rmse(diff)/sigma < alpha
  (RMS is used instead of L2 to avoid the threshold scaling with sqrt(N) samples.)
- Physics/constraint compliance is enforced via explicit checks + optional physics residual thresholds.
- Append-only JSONL logging for CRL-style audit trails.

This file is designed to be copied into another session and remain coherent.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union
import json
import hashlib
import math
import time


# =========================
# 1) Version + Constants
# =========================

SVS_PROTOCOL_NAME = "SVS-FLAMEFLOW"
SVS_PROTOCOL_VERSION = "v1.0"
SVS_PROTOCOL_ID = f"{SVS_PROTOCOL_NAME}-{SVS_PROTOCOL_VERSION}"

# Recommended default: alpha=3 (3-sigma rule)
DEFAULT_ALPHA = 3.0


# =========================
# 2) Failure / Reason Codes
# =========================

class ReasonCode(str, Enum):
    FAIL_OBSERVABILITY = "FAIL_OBSERVABILITY"
    FAIL_CALIBRATION = "FAIL_CALIBRATION"
    FAIL_CLOSURE_MODEL = "FAIL_CLOSURE_MODEL"
    FAIL_CONSTRAINT = "FAIL_CONSTRAINT"
    FAIL_NUMERICS = "FAIL_NUMERICS"
    FAIL_OVERFIT = "FAIL_OVERFIT"
    FAIL_RESIDUAL_THRESHOLD = "FAIL_RESIDUAL_THRESHOLD"
    FAIL_REPRODUCIBILITY = "FAIL_REPRODUCIBILITY"
    PASS = "PASS"


# =========================
# 3) Data Models
# =========================

@dataclass(frozen=True)
class SensorCalibration:
    """
    Calibration record for one sensor channel.

    IMPORTANT:
    - sigma MUST come from calibration (instrument noise), not from fit residuals.
    """
    sensor_id: str
    channel: str  # e.g., "pressure", "temperature", "flow_rate", "o2", "co2"
    units: str
    gain: float
    offset: float
    sampling_hz: float
    sigma: float  # noise standard deviation in measurement units AFTER gain/offset mapping
    method: str
    timestamp_unix: int

    def validate(self) -> Tuple[bool, List[str]]:
        issues: List[str] = []
        if not self.sensor_id:
            issues.append("sensor_id missing")
        if not self.channel:
            issues.append("channel missing")
        if self.sampling_hz <= 0:
            issues.append("sampling_hz must be > 0")
        if not math.isfinite(self.gain):
            issues.append("gain must be finite")
        if not math.isfinite(self.offset):
            issues.append("offset must be finite")
        if self.sigma <= 0 or (not math.isfinite(self.sigma)):
            issues.append("sigma must be finite and > 0")
        if not self.units:
            issues.append("units missing")
        if not self.method:
            issues.append("method missing")
        if self.timestamp_unix <= 0:
            issues.append("timestamp_unix must be > 0")
        return (len(issues) == 0), issues


@dataclass(frozen=True)
class CalibrationPacket:
    """
    Packet of calibrations for an experiment. Used to lock epsilons.
    """
    alpha: float = DEFAULT_ALPHA
    sensors: Tuple[SensorCalibration, ...] = field(default_factory=tuple)

    def validate(self) -> Tuple[bool, List[str]]:
        issues: List[str] = []
        if self.alpha <= 0 or (not math.isfinite(self.alpha)):
            issues.append("alpha must be finite and > 0")
        if len(self.sensors) == 0:
            issues.append("no sensors provided")
        seen = set()
        for s in self.sensors:
            ok, s_issues = s.validate()
            if not ok:
                issues.extend([f"{s.sensor_id}:{msg}" for msg in s_issues])
            key = (s.sensor_id, s.channel)
            if key in seen:
                issues.append(f"duplicate sensor_id+channel: {key}")
            seen.add(key)
        return (len(issues) == 0), issues

    def epsilon_by_channel(self) -> Dict[str, float]:
        """
        ε_k = alpha * sigma_k per (sensor_id:channel) key.
        """
        return {f"{s.sensor_id}:{s.channel}": self.alpha * s.sigma for s in self.sensors}

    def sigma_by_channel(self) -> Dict[str, float]:
        return {f"{s.sensor_id}:{s.channel}": s.sigma for s in self.sensors}


@dataclass(frozen=True)
class GeometrySpec:
    """
    Minimal geometry spec for setup hashing.
    Extend as needed (duct size, chamber volume, nozzle diameter, etc.).
    """
    description: str
    parameters: Mapping[str, Union[int, float, str]]

    def canonical_json(self) -> str:
        # Stable, sorted JSON (lightweight canonicalization).
        return json.dumps(
            {"description": self.description, "parameters": dict(self.parameters)},
            sort_keys=True,
            separators=(",", ":"),
        )


@dataclass(frozen=True)
class ConstraintManifest:
    """
    What physics / constraints are enforced for the run.
    """
    conservation_mass: bool = True
    conservation_momentum: bool = True
    conservation_energy: bool = True
    conservation_species: bool = False

    positivity_rho: bool = True
    positivity_T: bool = True
    positivity_Y: bool = True
    sumY_equals_1: bool = True

    turbulence_used: bool = False
    turbulence_nonnegativity: bool = True
    realizability_bounds: bool = True

    entropy_nonnegative: bool = False  # optional inequality constraint

    def canonical_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class ObjectiveSpec:
    """
    Locked objective functional parameters.
    """
    lambda_phys: float = 1.0

    # In v1.0, weights should be sigma-based (1/sigma^2).
    # This field is present for extensibility but must remain empty to stay strict v1.0.
    custom_weights: Mapping[str, float] = field(default_factory=dict)

    def validate(self) -> Tuple[bool, List[str]]:
        issues: List[str] = []
        if self.lambda_phys < 0 or (not math.isfinite(self.lambda_phys)):
            issues.append("lambda_phys must be finite and >= 0")
        if self.custom_weights:
            issues.append("custom_weights is non-empty; v1.0 expects sigma-based weights")
        return (len(issues) == 0), issues

    def canonical_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


@dataclass
class ResidualSummary:
    """
    Summarized residuals for logging.
    """
    # Data residuals (normalized): r_k = RMSE(O - Ohat) / sigma_k
    data_r: Dict[str, float] = field(default_factory=dict)

    # Physics residuals: user-provided (already normalized or not; your choice—document it).
    physics_r: Dict[str, float] = field(default_factory=dict)

    constraint_violations: int = 0
    constraint_violation_messages: List[str] = field(default_factory=list)

    def max_data_r(self) -> float:
        return max(self.data_r.values()) if self.data_r else float("inf")

    def max_physics_r(self) -> float:
        return max(self.physics_r.values()) if self.physics_r else 0.0


@dataclass
class RunRecord:
    """
    Append-only run record suitable for JSONL.
    """
    experiment_id: str
    protocol_id: str = SVS_PROTOCOL_ID

    timestamp_unix: int = field(default_factory=lambda: int(time.time()))
    operator: str = "UNKNOWN"

    setup_hash_sha256: str = ""
    model_class: str = ""
    solver: str = ""
    solver_settings: Dict[str, Any] = field(default_factory=dict)

    parameters_theta_star: Dict[str, Any] = field(default_factory=dict)

    residual_summary: ResidualSummary = field(default_factory=ResidualSummary)
    verdict: ReasonCode = ReasonCode.FAIL_RESIDUAL_THRESHOLD
    reason_codes: List[ReasonCode] = field(default_factory=list)

    raw_data_refs: Dict[str, str] = field(default_factory=dict)

    # Locks (embedded for auditability)
    calibration_packet: Optional[Dict[str, Any]] = None
    constraint_manifest: Optional[Dict[str, Any]] = None
    objective_spec: Optional[Dict[str, Any]] = None

    def to_json(self) -> str:
        payload = asdict(self)
        payload["verdict"] = self.verdict.value
        payload["reason_codes"] = [rc.value for rc in self.reason_codes]
        return json.dumps(payload, sort_keys=True)


# =========================
# 4) Utility: Setup Hashing
# =========================

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def compute_setup_hash(
    geometry: GeometrySpec,
    calibration: CalibrationPacket,
    constraints: ConstraintManifest,
    objective: ObjectiveSpec,
) -> str:
    """
    Hash over geometry + calibration + constraints + objective.
    Pins the run context so you can't quietly change ε, constraints, or weights.
    """
    blob = json.dumps(
        {
            "geometry": json.loads(geometry.canonical_json()),
            "calibration": asdict(calibration),
            "constraints": asdict(constraints),
            "objective": asdict(objective),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256_hex(blob)


# =========================
# 5) Protocol Core: Residuals + Constraints
# =========================

NumericSeries = Sequence[float]
Observations = Dict[str, NumericSeries]  # key: "sensor_id:channel"
Predictions = Dict[str, NumericSeries]   # same keys as Observations


def rmse(diff: NumericSeries) -> float:
    n = len(diff)
    if n == 0:
        return float("inf")
    return math.sqrt(sum((float(x) * float(x)) for x in diff) / n)


def series_diff(a: NumericSeries, b: NumericSeries) -> List[float]:
    if len(a) != len(b):
        raise ValueError(f"Length mismatch: len(a)={len(a)} len(b)={len(b)}")
    return [float(a[i]) - float(b[i]) for i in range(len(a))]


def compute_data_residuals_normalized(
    O: Observations,
    Ohat: Predictions,
    sigma_map: Mapping[str, float],
) -> Dict[str, float]:
    """
    r_k = RMSE(O_k - Ohat_k) / sigma_k
    Keys are "sensor_id:channel".
    """
    r: Dict[str, float] = {}
    for key, obs in O.items():
        if key not in Ohat or key not in sigma_map:
            r[key] = float("inf")
            continue
        diff = series_diff(obs, Ohat[key])
        denom = float(sigma_map[key])
        r[key] = rmse(diff) / denom if denom > 0 else float("inf")
    return r


def check_basic_constraints(
    state: Mapping[str, Any],
    constraints: ConstraintManifest,
) -> Tuple[int, List[str]]:
    """
    Minimal constraint checks (positivity + sum(Y)=1).
    This is a placeholder; in real CFD/combustion you also compute PDE residual norms.
    """
    violations: List[str] = []

    if constraints.positivity_rho and "rho" in state:
        rho = float(state["rho"])
        if rho < 0:
            violations.append("rho < 0")

    if constraints.positivity_T and "T" in state:
        T = float(state["T"])
        if T < 0:
            violations.append("T < 0")

    if constraints.positivity_Y and "Y" in state:
        Y = state["Y"]
        if isinstance(Y, Mapping):
            for k, v in Y.items():
                if float(v) < 0:
                    violations.append(f"Y[{k}] < 0")
        elif isinstance(Y, (list, tuple)):
            for i, v in enumerate(Y):
                if float(v) < 0:
                    violations.append(f"Y[{i}] < 0")

    if constraints.sumY_equals_1 and "Y" in state:
        Y = state["Y"]
        s = 0.0
        if isinstance(Y, Mapping):
            s = sum(float(v) for v in Y.values())
        elif isinstance(Y, (list, tuple)):
            s = sum(float(v) for v in Y)
        if abs(s - 1.0) > 1e-6:
            violations.append(f"sum(Y) != 1 (sum={s})")

    if constraints.turbulence_used and constraints.turbulence_nonnegativity:
        if "k" in state and float(state["k"]) < 0:
            violations.append("k < 0")
        if "nu_t" in state and float(state["nu_t"]) < 0:
            violations.append("nu_t < 0")

    return len(violations), violations


# =========================
# 6) Pass/Fail Evaluation
# =========================

@dataclass(frozen=True)
class PassFailConfig:
    """Controls SVS pass/fail checks."""
    alpha: float = DEFAULT_ALPHA
    require_all_channels_present: bool = True
    physics_thresholds: Mapping[str, float] = field(default_factory=dict)


def evaluate_pass_fail(
    calibration: CalibrationPacket,
    constraints: ConstraintManifest,
    objective: ObjectiveSpec,
    config: PassFailConfig,
    observations: Observations,
    predictions: Predictions,
    inferred_state_for_constraints: Mapping[str, Any],
    physics_residuals: Optional[Mapping[str, float]] = None,
    holdout_verification_ok: bool = True,
    reproducibility_ok: bool = True,
) -> Tuple[ReasonCode, List[ReasonCode], ResidualSummary]:
    """Implements SVS-FLAMEFLOW-v1.0 verdict logic."""
    reasons: List[ReasonCode] = []

    ok_cal, _ = calibration.validate()
    if not ok_cal:
        reasons.append(ReasonCode.FAIL_CALIBRATION)

    ok_obj, _ = objective.validate()
    if not ok_obj:
        reasons.append(ReasonCode.FAIL_NUMERICS)

    sigma_map = calibration.sigma_by_channel()

    if config.require_all_channels_present:
        missing = [k for k in observations.keys() if k not in predictions]
        if missing:
            reasons.append(ReasonCode.FAIL_OBSERVABILITY)

    data_r = compute_data_residuals_normalized(observations, predictions, sigma_map)

    for _, rk in data_r.items():
        if (not math.isfinite(rk)) or rk >= config.alpha:
            reasons.append(ReasonCode.FAIL_RESIDUAL_THRESHOLD)
            break

    nviol, viol_msgs = check_basic_constraints(inferred_state_for_constraints, constraints)
    if nviol > 0:
        reasons.append(ReasonCode.FAIL_CONSTRAINT)

    phys_r: Dict[str, float] = {}
    if physics_residuals:
        for k, v in physics_residuals.items():
            phys_r[k] = float(v)
            thr = config.physics_thresholds.get(k)
            if thr is not None and float(v) > float(thr):
                reasons.append(ReasonCode.FAIL_CONSTRAINT)

    if not holdout_verification_ok:
        reasons.append(ReasonCode.FAIL_OVERFIT)
    if not reproducibility_ok:
        reasons.append(ReasonCode.FAIL_REPRODUCIBILITY)

    # Deduplicate
    dedup: List[ReasonCode] = []
    for r in reasons:
        if r not in dedup:
            dedup.append(r)
    reasons = dedup

    summary = ResidualSummary(
        data_r=data_r,
        physics_r=phys_r,
        constraint_violations=nviol,
        constraint_violation_messages=viol_msgs,
    )

    if not reasons:
        return ReasonCode.PASS, [ReasonCode.PASS], summary

    priority = [
        ReasonCode.FAIL_CALIBRATION,
        ReasonCode.FAIL_OBSERVABILITY,
        ReasonCode.FAIL_CONSTRAINT,
        ReasonCode.FAIL_RESIDUAL_THRESHOLD,
        ReasonCode.FAIL_OVERFIT,
        ReasonCode.FAIL_REPRODUCIBILITY,
        ReasonCode.FAIL_NUMERICS,
        ReasonCode.FAIL_CLOSURE_MODEL,
    ]
    for p in priority:
        if p in reasons:
            return p, reasons, summary
    return reasons[0], reasons, summary


# =========================
# 7) Logging (Append-only JSONL)
# =========================

def append_jsonl(path: str, record: RunRecord) -> None:
    """Append-only JSONL writer."""
    line = record.to_json()
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


# =========================
# 8) Example Predictor (replace with your model+Pi)
# =========================

def example_predictor_identity(observations: Observations) -> Predictions:
    """Placeholder 'model' that predicts exactly what it observed."""
    return {k: list(v) for k, v in observations.items()}


# =========================
# 9) Main Protocol Entrypoint
# =========================

def run_svs_flameflow_v1_0(
    experiment_id: str,
    operator: str,
    geometry: GeometrySpec,
    calibration: CalibrationPacket,
    constraints: ConstraintManifest,
    objective: ObjectiveSpec,
    observations: Observations,
    predictor: Callable[[Observations], Predictions],
    inferred_state_for_constraints: Mapping[str, Any],
    physics_residuals: Optional[Mapping[str, float]] = None,
    holdout_verification_ok: bool = True,
    reproducibility_ok: bool = True,
    solver: str = "UNSPECIFIED",
    solver_settings: Optional[Dict[str, Any]] = None,
    model_class: str = "UNSPECIFIED",
    raw_data_refs: Optional[Dict[str, str]] = None,
    log_jsonl_path: Optional[str] = None,
) -> RunRecord:
    """
    Protocol run:
    - Computes setup hash (pins geometry+calibration+constraints+objective)
    - Runs predictor
    - Evaluates pass/fail
    - Produces a RunRecord (optionally appends to JSONL)
    """
    solver_settings = solver_settings or {}
    raw_data_refs = raw_data_refs or {}

    setup_hash = compute_setup_hash(geometry, calibration, constraints, objective)
    predictions = predictor(observations)

    verdict, reason_codes, residual_summary = evaluate_pass_fail(
        calibration=calibration,
        constraints=constraints,
        objective=objective,
        config=PassFailConfig(alpha=calibration.alpha),
        observations=observations,
        predictions=predictions,
        inferred_state_for_constraints=inferred_state_for_constraints,
        physics_residuals=physics_residuals,
        holdout_verification_ok=holdout_verification_ok,
        reproducibility_ok=reproducibility_ok,
    )

    rec = RunRecord(
        experiment_id=experiment_id,
        operator=operator,
        setup_hash_sha256=setup_hash,
        model_class=model_class,
        solver=solver,
        solver_settings=solver_settings,
        parameters_theta_star={},  # fill with inferred theta* from your solver
        residual_summary=residual_summary,
        verdict=verdict,
        reason_codes=reason_codes if reason_codes else [verdict],
        raw_data_refs=raw_data_refs,
        calibration_packet=asdict(calibration),
        constraint_manifest=asdict(constraints),
        objective_spec=asdict(objective),
    )

    if log_jsonl_path:
        append_jsonl(log_jsonl_path, rec)

    return rec


if __name__ == "__main__":
    now = int(time.time())
    cal = CalibrationPacket(
        alpha=3.0,
        sensors=(
            SensorCalibration("P1", "pressure", "Pa", 1.0, 0.0, 100.0, 5.0, "cal", now),
            SensorCalibration("T1", "temperature", "K", 1.0, 0.0, 10.0, 0.5, "cal", now),
        ),
    )

    geom = GeometrySpec("Demo duct flow rig", {"duct_diameter_m": 0.05, "duct_length_m": 1.0})
    manifest = ConstraintManifest(conservation_species=False)
    obj = ObjectiveSpec(lambda_phys=1.0)

    O: Observations = {
        "P1:pressure": [101325.0, 101330.0, 101327.0, 101326.0],
        "T1:temperature": [300.0, 300.2, 300.1, 300.15],
    }

    inferred_state = {"rho": 1.2, "T": 300.1}

    record = run_svs_flameflow_v1_0(
        experiment_id="SVS-FLAMEFLOW-2026-02-27-001",
        operator="Denver Roberts",
        geometry=geom,
        calibration=cal,
        constraints=manifest,
        objective=obj,
        observations=O,
        predictor=example_predictor_identity,
        inferred_state_for_constraints=inferred_state,
        solver="DEMO",
        model_class="IDENTITY_MODEL",
        log_jsonl_path=None,
    )
    print(record.to_json())
