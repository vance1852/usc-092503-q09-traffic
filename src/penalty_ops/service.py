"""协调道路执法监测、告警、工单和应急资源分配的应用服务。"""
from __future__ import annotations
import hashlib,json,uuid
from .auth import Auth
from .models import ViolationRecord,CaseRecord,as_dict,utcnow
from .risk import violation_probability,score_violation_record
from .storage import ConflictError,audit,connect,rows,transaction


def _allocation_fingerprint(response_resource_id,case_ticket_id,quantity) -> str:
    body=json.dumps(
        {"response_resource_id":response_resource_id,"case_ticket_id":case_ticket_id,"quantity":quantity},
        ensure_ascii=False,sort_keys=True,separators=(",",":"),
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class PenaltyService:
    def __init__(self,database=":memory:"): self.db=connect(database); self.auth=Auth(self.db)
    def bootstrap(self):
        for uid,pwd,role in (("admin","enforcement-admin","admin"),("operator","enforcement-operator","operator")):
            try:self.auth.create_user(uid,pwd,role)
            except Exception:pass
    def register_case_record(self,token,case_record):
        actor=self.auth.require(token,"admin"); case_record.validate(); now=utcnow()
        with transaction(self.db):
            self.db.execute("INSERT INTO case_records VALUES(?,?,?,?,?,?,?,?)",(case_record.case_record_id,case_record.district,case_record.enforcement_type,case_record.length_m,case_record.criticality,case_record.status,now,now)); audit(self.db,"case_record",case_record.case_record_id,"created",actor.user_id,as_dict(case_record))
        return self.case_record(token,case_record.case_record_id)
    def case_record(self,token,case_record_id):
        self.auth.require(token,"read"); row=self.db.execute("SELECT * FROM case_records WHERE case_record_id=?",(case_record_id,)).fetchone()
        if not row:raise KeyError(case_record_id)
        return dict(row)
    def ingest_violation_record(self,token,violation_record):
        actor=self.auth.require(token,"measure"); violation_record.validate(); seg=self.db.execute("SELECT criticality FROM case_records WHERE case_record_id=?",(violation_record.case_record_id,)).fetchone()
        if not seg:raise KeyError(violation_record.case_record_id)
        risk=score_violation_record(violation_record.speed_kmh,violation_record.traffic_flow_vph,violation_record.impact_index,seg[0]); fingerprint=hashlib.sha256(f"{violation_record.case_record_id}|{violation_record.evidence_source_id}|{violation_record.observed_at}".encode()).hexdigest()
        with transaction(self.db):
            if self.db.execute("SELECT violation_record_id FROM violation_records WHERE violation_record_id=?",(violation_record.violation_record_id,)).fetchone(): return {"violation_record_id":violation_record.violation_record_id,"duplicate":True,"risk":as_dict(risk)}
            self.db.execute("INSERT INTO violation_records VALUES(?,?,?,?,?,?,?)",(violation_record.violation_record_id,violation_record.case_record_id,violation_record.evidence_source_id,violation_record.speed_kmh,violation_record.traffic_flow_vph,violation_record.impact_index,violation_record.observed_at)); alert_id=None
            if risk.severity in {"high","critical"}:
                alert_id="alert-"+fingerprint[:18]; self.db.execute("INSERT OR IGNORE INTO alerts VALUES(?,?,?,?,?,?,?,?)",(alert_id,violation_record.case_record_id,fingerprint,risk.severity,risk.score,"open",utcnow(),None))
            audit(self.db,"violation_record",violation_record.violation_record_id,"ingested",actor.user_id,{"risk":as_dict(risk),"alert_id":alert_id})
        return {"violation_record_id":violation_record.violation_record_id,"duplicate":False,"risk":as_dict(risk),"alert_id":alert_id}
    def risk_report(self,token,case_record_id):
        self.auth.require(token,"analyze"); violation_records=rows(self.db,"SELECT * FROM violation_records WHERE case_record_id=? ORDER BY observed_at",(case_record_id,)); alerts=rows(self.db,"SELECT * FROM alerts WHERE case_record_id=? ORDER BY created_at",(case_record_id,)); return {"case_record_id":case_record_id,"violation_records":len(violation_records),"alerts":alerts,"violation_probability":violation_probability(alerts)}
    def create_case_ticket(self,token,case_record_id,alert_id,assignee,priority=3):
        actor=self.auth.require(token,"case_ticket")
        if not assignee.strip() or not 1<=priority<=5:raise ValueError("assignee and priority are invalid")
        if not self.db.execute("SELECT 1 FROM alerts WHERE alert_id=? AND case_record_id=?",(alert_id,case_record_id)).fetchone():raise KeyError(alert_id)
        wid="wo-"+uuid.uuid4().hex[:16]
        with transaction(self.db): self.db.execute("INSERT INTO case_tickets VALUES(?,?,?,?,?,?,?,?)",(wid,case_record_id,alert_id,assignee,"open",priority,utcnow(),utcnow())); audit(self.db,"case_ticket",wid,"created",actor.user_id,{"case_record_id":case_record_id,"alert_id":alert_id})
        return self.case_ticket(token,wid)
    def case_ticket(self,token,case_ticket_id):
        self.auth.require(token,"read"); row=self.db.execute("SELECT * FROM case_tickets WHERE case_ticket_id=?",(case_ticket_id,)).fetchone()
        if not row:raise KeyError(case_ticket_id)
        return dict(row)
    def transition_case_ticket(self,token,case_ticket_id,target,reason):
        actor=self.auth.require(token,"case_ticket"); allowed={"open":{"assigned","cancelled"},"assigned":{"in_progress","cancelled"},"in_progress":{"completed","blocked"},"blocked":{"in_progress","cancelled"},"completed":set(),"cancelled":set()}
        if not reason.strip():raise ValueError("transition reason is required")
        with transaction(self.db):
            row=self.db.execute("SELECT status FROM case_tickets WHERE case_ticket_id=?",(case_ticket_id,)).fetchone()
            if not row:raise KeyError(case_ticket_id)
            if target not in allowed.get(row[0],set()):raise ValueError("invalid work order transition")
            self.db.execute("UPDATE case_tickets SET status=?,updated_at=? WHERE case_ticket_id=?",(target,utcnow(),case_ticket_id)); audit(self.db,"case_ticket",case_ticket_id,"transition",actor.user_id,{"from":row[0],"to":target,"reason":reason})
        return self.case_ticket(token,case_ticket_id)
    def add_response_resource(self,token,response_resource_id,kind,district,capacity):
        actor=self.auth.require(token,"admin")
        if capacity<=0 or not kind.strip() or not district.strip():raise ValueError("response_resource fields are invalid")
        with transaction(self.db):self.db.execute("INSERT INTO response_resources VALUES(?,?,?,?,?)",(response_resource_id,kind,district,capacity,capacity)); audit(self.db,"response_resource",response_resource_id,"created",actor.user_id,{"kind":kind,"district":district,"capacity":capacity})
        return self.response_resource(token,response_resource_id)
    def response_resource(self,token,response_resource_id):
        self.auth.require(token,"read"); row=self.db.execute("SELECT * FROM response_resources WHERE response_resource_id=?",(response_resource_id,)).fetchone()
        if not row:raise KeyError(response_resource_id)
        return dict(row)
    def allocate(self,token,response_resource_id,case_ticket_id,quantity):
        """首次分配保存请求指纹；同指纹重试重放原结果，指纹冲突时拒绝且不动库存。"""
        actor=self.auth.require(token,"allocate")
        if quantity<=0:raise ValueError("quantity must be positive")
        request_sha=_allocation_fingerprint(response_resource_id,case_ticket_id,quantity)
        # 先在事务外读取已存响应：完全相同的重试直接重放，不触碰库存。
        existing=self.db.execute(
            "SELECT plan_id,quantity,request_sha256 FROM allocations WHERE response_resource_id=? AND case_ticket_id=?",
            (response_resource_id,case_ticket_id),
        ).fetchone()
        if existing is not None:
            if existing["request_sha256"]==request_sha:
                return {"plan_id":existing["plan_id"],"duplicate":True,"replayed":True,
                        "response_resource_id":response_resource_id,"quantity":existing["quantity"]}
            raise ConflictError("该工单对此资源已有分配，请求内容与原分配不一致；如需调整请调用 allocation_adjust",
                                {"plan_id":existing["plan_id"],"existing_quantity":existing["quantity"],
                                 "requested_quantity":quantity})
        aid="alloc-"+uuid.uuid4().hex[:16]
        with transaction(self.db):
            # 行锁内复查：挡住并发首次分配，保证只有一个请求写入并扣减库存。
            existing=self.db.execute(
                "SELECT plan_id,quantity,request_sha256 FROM allocations WHERE response_resource_id=? AND case_ticket_id=?",
                (response_resource_id,case_ticket_id),
            ).fetchone()
            if existing is not None:
                if existing["request_sha256"]==request_sha:
                    return {"plan_id":existing["plan_id"],"duplicate":True,"replayed":True,
                            "response_resource_id":response_resource_id,"quantity":existing["quantity"]}
                raise ConflictError("该工单对此资源已有分配，请求内容与原分配不一致；如需调整请调用 allocation_adjust",
                                    {"plan_id":existing["plan_id"],"existing_quantity":existing["quantity"],
                                     "requested_quantity":quantity})
            response_resource=self.db.execute("SELECT available FROM response_resources WHERE response_resource_id=?",(response_resource_id,)).fetchone()
            if not response_resource:raise KeyError(response_resource_id)
            if not self.db.execute("SELECT 1 FROM case_tickets WHERE case_ticket_id=?",(case_ticket_id,)).fetchone():raise KeyError(case_ticket_id)
            if response_resource[0]<quantity:raise ValueError("response_resource capacity exceeded")
            self.db.execute("INSERT INTO allocations(plan_id,response_resource_id,case_ticket_id,quantity,request_sha256,created_at) VALUES(?,?,?,?,?,?)",(aid,response_resource_id,case_ticket_id,quantity,request_sha,utcnow())); self.db.execute("UPDATE response_resources SET available=available-? WHERE response_resource_id=?",(quantity,response_resource_id)); audit(self.db,"response_resource",response_resource_id,"allocated",actor.user_id,{"plan_id":aid,"case_ticket_id":case_ticket_id,"quantity":quantity,"request_sha256":request_sha})
        return {"plan_id":aid,"duplicate":False,"replayed":False,"response_resource_id":response_resource_id,"quantity":quantity}

    def adjust_allocation(self,token,response_resource_id,case_ticket_id,new_quantity,reason,idempotency_key=None):
        """可审计的分配调整：数量变化通过独立操作完成，记录调整流水，绝不静默覆盖。"""
        actor=self.auth.require(token,"allocate")
        if new_quantity<=0:raise ValueError("new_quantity must be positive")
        if not reason or not reason.strip():raise ValueError("adjustment reason is required")
        key=idempotency_key or "adj-"+uuid.uuid4().hex[:24]
        with transaction(self.db):
            current=self.db.execute(
                "SELECT plan_id,quantity FROM allocations WHERE response_resource_id=? AND case_ticket_id=?",
                (response_resource_id,case_ticket_id),
            ).fetchone()
            if not current:raise KeyError("allocation not found")
            prior=self.db.execute("SELECT adjustment_id,previous_quantity,new_quantity FROM allocation_adjustments WHERE idempotency_key=?",(key,)).fetchone()
            if prior is not None:
                if prior["new_quantity"]!=new_quantity:
                    raise ConflictError("调整幂等键对应不同的调整内容",
                                        {"idempotency_key":key,"existing_new_quantity":prior["new_quantity"],
                                         "requested_new_quantity":new_quantity})
                # 相同调整请求重放：回传首次执行的原始结果，不再次改动库存。
                return {"plan_id":current["plan_id"],"adjustment_id":prior["adjustment_id"],"duplicate":True,
                        "replayed":True,"previous_quantity":prior["previous_quantity"],
                        "quantity":prior["new_quantity"],"delta_units":0}
            previous_quantity=current["quantity"]; delta=new_quantity-previous_quantity
            if delta!=0:
                resource=self.db.execute("SELECT available FROM response_resources WHERE response_resource_id=?",(response_resource_id,)).fetchone()
                if resource[0]<delta:raise ValueError("response_resource capacity exceeded")
                self.db.execute("UPDATE response_resources SET available=available-? WHERE response_resource_id=?",(delta,response_resource_id))
            cursor=self.db.execute(
                "INSERT INTO allocation_adjustments(plan_id,previous_quantity,new_quantity,delta_units,reason,idempotency_key,actor_id,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (current["plan_id"],previous_quantity,new_quantity,delta,reason.strip(),key,actor.user_id,utcnow()),
            )
            self.db.execute("UPDATE allocations SET quantity=?,request_sha256=? WHERE plan_id=?",
                            (new_quantity,_allocation_fingerprint(response_resource_id,case_ticket_id,new_quantity),current["plan_id"]))
            audit(self.db,"allocation",current["plan_id"],"allocation.adjusted",actor.user_id,
                  {"response_resource_id":response_resource_id,"case_ticket_id":case_ticket_id,
                   "previous_quantity":previous_quantity,"new_quantity":new_quantity,"delta_units":delta,
                   "reason":reason.strip(),"idempotency_key":key})
        return {"plan_id":current["plan_id"],"adjustment_id":cursor.lastrowid,"duplicate":False,
                "previous_quantity":previous_quantity,"quantity":new_quantity,"delta_units":delta}

    def allocation(self,token,response_resource_id,case_ticket_id):
        self.auth.require(token,"read")
        row=self.db.execute("SELECT plan_id,response_resource_id,case_ticket_id,quantity,request_sha256,created_at FROM allocations WHERE response_resource_id=? AND case_ticket_id=?",(response_resource_id,case_ticket_id)).fetchone()
        if not row:raise KeyError("allocation not found")
        return dict(row)

    def audit_events(self,token,entity_type,entity_id): self.auth.require(token,"read"); return rows(self.db,"SELECT * FROM audit_events WHERE entity_type=? AND entity_id=? ORDER BY event_id",(entity_type,entity_id))
