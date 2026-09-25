"""离线命令行验收入口。"""
from __future__ import annotations
import argparse,json
from .models import ViolationRecord,CaseRecord
from .service import PenaltyService
def run():
    s=PenaltyService(); s.bootstrap(); t=s.auth.login("admin","enforcement-admin"); s.register_case_record(t,CaseRecord("CASE-DEMO","north","water",680,5)); r=s.ingest_violation_record(t,ViolationRecord("RD-DEMO","CASE-DEMO","evidence_source-01",160,230,88,"2026-09-24T10:00:00+00:00")); report=s.risk_report(t,"CASE-DEMO"); order=s.create_case_ticket(t,"CASE-DEMO",r["alert_id"],"crew-north",1); s.add_response_resource(t,"PUMP-01","mobile-pump","north",2); allocation=s.allocate(t,"PUMP-01",order["case_ticket_id"],1); replay=s.allocate(t,"PUMP-01",order["case_ticket_id"],1); adjusted=s.adjust_allocation(t,allocation["plan_id"],2,"现场确认两辆受损车辆"); return {"status":"ok","case_record":"CASE-DEMO","severity":r["risk"]["severity"],"probability":report["violation_probability"],"allocation":allocation["plan_id"],"replayed":replay["duplicate"] and replay["plan_id"]==allocation["plan_id"],"adjusted_quantity":adjusted["quantity"],"available":s.response_resource(t,"PUMP-01")["available"]}
def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--workspace",default="."); parser.parse_args(); print(json.dumps(run(),ensure_ascii=False))
if __name__=="__main__":main()
