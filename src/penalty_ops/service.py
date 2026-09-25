"""协调道路执法监测、告警、工单和应急资源分配的应用服务。"""
from __future__ import annotations
import hashlib,uuid
from .auth import Auth
from .errors import Conflict
from .models import ViolationRecord,CaseRecord,allocation_fingerprint,as_dict,normalize_quantity,utcnow
from .risk import violation_probability,score_violation_record
from .storage import audit,connect,rows,transaction
class PenaltyService:
    def __init__(self,database=":memory:"): self.db=connect(database); self.auth=Auth(self.db)
    def bootstrap(self):
        for uid,pwd,role in (("admin","enforcement-admin","admin"),("operator","enforcement-operator","operator")):
            try:self.auth.create_user(uid,pwd,role)
            except Exception:self.db.rollback()
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
        actor=self.auth.require(token,"allocate")
        quantity=normalize_quantity(quantity); fingerprint=allocation_fingerprint(response_resource_id,case_ticket_id,quantity)
        with transaction(self.db):
            response_resource=self.db.execute("SELECT available FROM response_resources WHERE response_resource_id=?",(response_resource_id,)).fetchone()
            if not response_resource:raise KeyError(response_resource_id)
            if not self.db.execute("SELECT 1 FROM case_tickets WHERE case_ticket_id=?",(case_ticket_id,)).fetchone():raise KeyError(case_ticket_id)
            old=self.db.execute("SELECT * FROM allocations WHERE response_resource_id=? AND case_ticket_id=?",(response_resource_id,case_ticket_id)).fetchone()
            if old:
                if old["request_fingerprint"]==fingerprint:return {"plan_id":old["plan_id"],"duplicate":True,"response_resource_id":response_resource_id,"case_ticket_id":case_ticket_id,"quantity":old["quantity"],"request_fingerprint":fingerprint}
                raise Conflict(f"工单 {case_ticket_id} 已按数量 {old['quantity']} 分配资源 {response_resource_id}，与本次请求数量 {quantity} 冲突；库存未变更，如需调整请调用 adjust_allocation")
            cursor=self.db.execute("UPDATE response_resources SET available=available-? WHERE response_resource_id=? AND available>=?",(quantity,response_resource_id,quantity))
            if cursor.rowcount!=1:raise ValueError(f"资源 {response_resource_id} 可用余额 {response_resource[0]} 不足以分配 {quantity}")
            aid="alloc-"+uuid.uuid4().hex[:16]
            self.db.execute("INSERT INTO allocations(plan_id,response_resource_id,case_ticket_id,quantity,created_at,request_fingerprint) VALUES(?,?,?,?,?,?)",(aid,response_resource_id,case_ticket_id,quantity,utcnow(),fingerprint))
            audit(self.db,"response_resource",response_resource_id,"allocated",actor.user_id,{"case_ticket_id":case_ticket_id,"quantity":quantity,"plan_id":aid,"request_fingerprint":fingerprint})
        return {"plan_id":aid,"duplicate":False,"response_resource_id":response_resource_id,"case_ticket_id":case_ticket_id,"quantity":quantity,"request_fingerprint":fingerprint}
    def adjust_allocation(self,token,plan_id,quantity,reason):
        actor=self.auth.require(token,"allocate")
        quantity=normalize_quantity(quantity)
        if not str(reason).strip():raise ValueError("adjustment reason is required")
        with transaction(self.db):
            allocation=self.db.execute("SELECT * FROM allocations WHERE plan_id=?",(plan_id,)).fetchone()
            if not allocation:raise KeyError(plan_id)
            previous=allocation["quantity"]; delta=quantity-previous
            if delta==0:return {"plan_id":plan_id,"adjusted":False,"response_resource_id":allocation["response_resource_id"],"case_ticket_id":allocation["case_ticket_id"],"quantity":quantity,"request_fingerprint":allocation["request_fingerprint"]}
            if delta>0:
                cursor=self.db.execute("UPDATE response_resources SET available=available-? WHERE response_resource_id=? AND available>=?",(delta,allocation["response_resource_id"],delta))
                if cursor.rowcount!=1:
                    available=self.db.execute("SELECT available FROM response_resources WHERE response_resource_id=?",(allocation["response_resource_id"],)).fetchone()[0]
                    raise ValueError(f"资源 {allocation['response_resource_id']} 可用余额 {available} 不足以追加 {delta}")
            else:self.db.execute("UPDATE response_resources SET available=available+? WHERE response_resource_id=?",(-delta,allocation["response_resource_id"]))
            fingerprint=allocation_fingerprint(allocation["response_resource_id"],allocation["case_ticket_id"],quantity)
            self.db.execute("UPDATE allocations SET quantity=?,request_fingerprint=? WHERE plan_id=?",(quantity,fingerprint,plan_id))
            audit(self.db,"allocation",plan_id,"adjusted",actor.user_id,{"response_resource_id":allocation["response_resource_id"],"case_ticket_id":allocation["case_ticket_id"],"previous_quantity":previous,"quantity":quantity,"reason":reason})
        return {"plan_id":plan_id,"adjusted":True,"response_resource_id":allocation["response_resource_id"],"case_ticket_id":allocation["case_ticket_id"],"quantity":quantity,"previous_quantity":previous,"request_fingerprint":fingerprint}
    def allocation(self,token,plan_id):
        self.auth.require(token,"read"); row=self.db.execute("SELECT * FROM allocations WHERE plan_id=?",(plan_id,)).fetchone()
        if not row:raise KeyError(plan_id)
        return dict(row)
    def audit_events(self,token,entity_type,entity_id): self.auth.require(token,"read"); return rows(self.db,"SELECT * FROM audit_events WHERE entity_type=? AND entity_id=? ORDER BY event_id",(entity_type,entity_id))
