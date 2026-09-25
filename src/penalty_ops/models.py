"""案件、读数、告警、工单和资源的领域模型。"""
from __future__ import annotations
import hashlib,json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)

@dataclass(frozen=True)
class CaseRecord:
    case_record_id: str; district: str; enforcement_type: str; length_m: float; criticality: int; status: str = "normal"
    def validate(self) -> None:
        if not self.case_record_id.strip() or not self.district.strip(): raise ValueError("case_record id and district are required")
        if self.enforcement_type not in {"water", "drainage", "gas"}: raise ValueError("unsupported enforcement type")
        if self.length_m <= 0 or not 1 <= self.criticality <= 5: raise ValueError("case_record dimensions are invalid")

@dataclass(frozen=True)
class ViolationRecord:
    violation_record_id: str; case_record_id: str; evidence_source_id: str; speed_kmh: float; traffic_flow_vph: float; impact_index: float; observed_at: str
    def validate(self) -> None:
        if not self.violation_record_id.strip() or not self.case_record_id.strip() or not self.evidence_source_id.strip(): raise ValueError("violation_record identifiers are required")
        if min(self.speed_kmh, self.traffic_flow_vph, self.impact_index) < 0: raise ValueError("violation_record values cannot be negative")
        parse_time(self.observed_at)

def as_dict(value: Any) -> dict[str, Any]:
    return {name: getattr(value, name) for name in value.__dataclass_fields__} if hasattr(value, "__dataclass_fields__") else dict(value)

def normalize_quantity(quantity: Any) -> int:
    """把请求数量规范为正整数，保证同一逻辑请求得到同一指纹。"""
    if isinstance(quantity, bool): raise ValueError("quantity must be a positive integer")
    if isinstance(quantity, int): value = quantity
    elif isinstance(quantity, float) and quantity.is_integer(): value = int(quantity)
    else: raise ValueError("quantity must be a positive integer")
    if value <= 0: raise ValueError("quantity must be positive")
    return value

def allocation_fingerprint(response_resource_id: str, case_ticket_id: str, quantity: int) -> str:
    """分配请求关键内容（资源、工单、数量）的稳定 SHA-256 指纹。"""
    body = {"case_ticket_id": case_ticket_id, "quantity": quantity, "response_resource_id": response_resource_id}
    return hashlib.sha256(json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
