"""Zero Trust policy engine - risk-based access control."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from config.settings import (
    RISK_THRESHOLD_LOW,
    RISK_THRESHOLD_MEDIUM,
    RISK_THRESHOLD_HIGH,
    ACTION_ALLOW,
    ACTION_ADAPTIVE_AUTH,
    ACTION_RESTRICT,
    ACTION_BLOCK,
)


class PolicyAction(str, Enum):
    ALLOW = ACTION_ALLOW
    ADAPTIVE_AUTH = ACTION_ADAPTIVE_AUTH
    RESTRICT = ACTION_RESTRICT
    BLOCK = ACTION_BLOCK


@dataclass
class RiskAssessment:
    """Result of risk assessment for a session."""
    risk_score: float
    action: PolicyAction
    threat_class: Optional[str] = None
    explanation: Optional[dict] = None
    policy_latency_ms: Optional[float] = None


# Sensitive ports (database, SSH, RDP) add to risk


class ZeroTrustPolicyEngine:
    """Dynamic policy enforcement based on AI risk assessment."""

    def __init__(
        self,
        low_threshold: float = RISK_THRESHOLD_LOW,
        medium_threshold: float = RISK_THRESHOLD_MEDIUM,
        high_threshold: float = RISK_THRESHOLD_HIGH,
    ):
        self.low_threshold = low_threshold
        self.medium_threshold = medium_threshold
        self.high_threshold = high_threshold

    def _compute_asset_sensitivity(self, dst_ip: str, dst_port: int) -> float:
        """Score 0-1 for destination sensitivity (db/admin ports)."""
        sensitive_ports = [3306, 5432, 1433, 27017, 6379, 22, 3389]
        return 0.4 if dst_port in sensitive_ports else 0.0

    def _build_explanation(
        self,
        ai_score: float,
        asset_score: float,
        anomaly_score: float = 0.0,
    ) -> dict:
        """Build explainable breakdown of risk factors."""
        total = ai_score + asset_score + anomaly_score
        if total <= 0:
            total = 1.0
        return {
            "behavioral_deviation": round(ai_score / total, 2),
            "sensitive_asset_access": round(asset_score / total, 2),
            "anomaly_score": round(anomaly_score / total, 2),
        }

    def evaluate(
        self,
        ai_threat_score: float,
        threat_class: Optional[str] = None,
        dst_ip: Optional[str] = None,
        dst_port: Optional[int] = None,
        anomaly_score: float = 0.0,
        explanation: Optional[dict] = None,
    ) -> RiskAssessment:
        """Evaluate risk and return policy action.

        Combines:
        - AI threat score (from classifier/autoencoder)
        - Asset sensitivity
        - Anomaly contribution
        """
        import time
        start = time.perf_counter()

        asset_score = 0.0
        if dst_ip or dst_port:
            asset_score = self._compute_asset_sensitivity(dst_ip or "", dst_port or 0)

        # Combined risk: weighted sum
        risk_score = 0.6 * ai_threat_score + 0.2 * asset_score + 0.2 * anomaly_score
        risk_score = min(max(risk_score, 0.0), 1.0)

        if risk_score < self.low_threshold:
            action = PolicyAction.ALLOW
        elif risk_score < self.medium_threshold:
            action = PolicyAction.ADAPTIVE_AUTH
        elif risk_score < self.high_threshold:
            action = PolicyAction.RESTRICT
        else:
            action = PolicyAction.BLOCK

        elapsed_ms = (time.perf_counter() - start) * 1000

        expl = explanation or self._build_explanation(
            ai_threat_score, asset_score, anomaly_score
        )

        return RiskAssessment(
            risk_score=round(risk_score, 4),
            action=action,
            threat_class=threat_class,
            explanation=expl,
            policy_latency_ms=round(elapsed_ms, 2),
        )
