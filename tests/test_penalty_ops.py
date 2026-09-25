import tempfile
import threading
import unittest
from pathlib import Path

from penalty_ops.errors import Conflict
from penalty_ops.models import ViolationRecord,CaseRecord
from penalty_ops.risk import score_violation_record
from penalty_ops.service import PenaltyService
class UrbanEnforcementTests(unittest.TestCase):
    def setUp(self):
        self.s=PenaltyService(); self.s.bootstrap(); self.t=self.s.auth.login("admin","enforcement-admin"); self.s.register_case_record(self.t,CaseRecord("S1","east","drainage",100,4))
    def test_risk_and_idempotent_violation_record(self):
        r=ViolationRecord("R1","S1","evidence_source",120,250,90,"2026-01-01T00:00:00+00:00"); a=self.s.ingest_violation_record(self.t,r); b=self.s.ingest_violation_record(self.t,r); self.assertFalse(a["duplicate"]); self.assertTrue(b["duplicate"]); self.assertEqual(self.s.risk_report(self.t,"S1")["violation_records"],1)
    def test_case_ticket_and_allocation(self):
        r=self.s.ingest_violation_record(self.t,ViolationRecord("R2","S1","evidence_source",100,250,90,"2026-01-01T00:00:00+00:00")); o=self.s.create_case_ticket(self.t,"S1",r["alert_id"],"crew"); self.s.transition_case_ticket(self.t,o["case_ticket_id"],"assigned","crew accepted"); self.s.add_response_resource(self.t,"R1","pump","east",2); self.assertFalse(self.s.allocate(self.t,"R1",o["case_ticket_id"],1)["duplicate"]); self.assertEqual(self.s.response_resource(self.t,"R1")["available"],1)
    def test_risk_validation(self):
        with self.assertRaises(ValueError):score_violation_record(-1,1,1,2)

class AllocationConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.dir=tempfile.TemporaryDirectory(); self.db_path=str(Path(self.dir.name)/"penalties.sqlite3")
        self.s=self._service(); self.t=self.s.auth.login("admin","enforcement-admin")
        self.s.register_case_record(self.t,CaseRecord("S1","east","drainage",100,4))
        r=self.s.ingest_violation_record(self.t,ViolationRecord("R1","S1","evidence_source",100,250,90,"2026-01-01T00:00:00+00:00"))
        self.ticket=self.s.create_case_ticket(self.t,"S1",r["alert_id"],"crew")["case_ticket_id"]
        self.s.add_response_resource(self.t,"TOW-1","tow-truck","east",3)
    def tearDown(self):
        self.dir.cleanup()
    def _service(self):
        s=PenaltyService(self.db_path); s.bootstrap(); return s
    def _token(self,service):
        return service.auth.login("admin","enforcement-admin")
    def test_same_quantity_retry_replays_original_result(self):
        first=self.s.allocate(self.t,"TOW-1",self.ticket,1)
        replay=self.s.allocate(self.t,"TOW-1",self.ticket,1)
        self.assertFalse(first["duplicate"]); self.assertTrue(replay["duplicate"])
        self.assertEqual(replay["plan_id"],first["plan_id"]); self.assertEqual(replay["quantity"],1)
        self.assertEqual(replay["request_fingerprint"],first["request_fingerprint"])
        self.assertEqual(self.s.response_resource(self.t,"TOW-1")["available"],2)
        replay_float=self.s.allocate(self.t,"TOW-1",self.ticket,1.0)
        self.assertTrue(replay_float["duplicate"]); self.assertEqual(replay_float["plan_id"],first["plan_id"])
    def test_changed_quantity_conflicts_without_touching_inventory(self):
        first=self.s.allocate(self.t,"TOW-1",self.ticket,1)
        with self.assertRaises(Conflict) as ctx: self.s.allocate(self.t,"TOW-1",self.ticket,2)
        message=str(ctx.exception); self.assertIn("1",message); self.assertIn("2",message)
        self.assertEqual(self.s.response_resource(self.t,"TOW-1")["available"],2)
        self.assertEqual(self.s.allocation(self.t,first["plan_id"])["quantity"],1)
    def test_adjust_allocation_is_audited_and_updates_fingerprint(self):
        first=self.s.allocate(self.t,"TOW-1",self.ticket,1)
        adjusted=self.s.adjust_allocation(self.t,first["plan_id"],2,"现场确认两辆受损车辆")
        self.assertTrue(adjusted["adjusted"]); self.assertEqual(adjusted["previous_quantity"],1)
        self.assertEqual(self.s.response_resource(self.t,"TOW-1")["available"],1)
        replay=self.s.allocate(self.t,"TOW-1",self.ticket,2)
        self.assertTrue(replay["duplicate"]); self.assertEqual(replay["plan_id"],first["plan_id"])
        with self.assertRaises(Conflict): self.s.allocate(self.t,"TOW-1",self.ticket,1)
        events=self.s.audit_events(self.t,"allocation",first["plan_id"])
        self.assertEqual(len(events),1); self.assertEqual(events[0]["action"],"adjusted")
        self.assertIn("两辆受损车辆",events[0]["payload"]); self.assertIn('"previous_quantity": 1',events[0]["payload"])
    def test_adjust_down_releases_units(self):
        first=self.s.allocate(self.t,"TOW-1",self.ticket,3)
        adjusted=self.s.adjust_allocation(self.t,first["plan_id"],1,"核减一辆")
        self.assertEqual(adjusted["quantity"],1); self.assertEqual(self.s.response_resource(self.t,"TOW-1")["available"],2)
    def test_adjust_beyond_available_rolls_back(self):
        first=self.s.allocate(self.t,"TOW-1",self.ticket,1)
        with self.assertRaises(ValueError): self.s.adjust_allocation(self.t,first["plan_id"],9,"超出库存")
        self.assertEqual(self.s.response_resource(self.t,"TOW-1")["available"],2)
        self.assertEqual(self.s.allocation(self.t,first["plan_id"])["quantity"],1)
        self.assertEqual(self.s.audit_events(self.t,"allocation",first["plan_id"]),[])
    def test_adjust_requires_reason(self):
        first=self.s.allocate(self.t,"TOW-1",self.ticket,1)
        with self.assertRaises(ValueError): self.s.adjust_allocation(self.t,first["plan_id"],2,"  ")
    def test_concurrent_same_request_allocates_once(self):
        results=[]; errors=[]
        def worker():
            try:
                s=self._service(); results.append(s.allocate(self._token(s),"TOW-1",self.ticket,1))
            except Exception as exc: errors.append(exc)
        threads=[threading.Thread(target=worker) for _ in range(6)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(errors,[])
        self.assertEqual(len({r["plan_id"] for r in results}),1)
        self.assertEqual(sum(1 for r in results if not r["duplicate"]),1)
        self.assertEqual(self.s.response_resource(self.t,"TOW-1")["available"],2)
    def test_concurrent_distinct_tickets_never_oversell(self):
        tickets=[self.ticket]
        for i in range(4):
            r=self.s.ingest_violation_record(self.t,ViolationRecord(f"RX{i}","S1",f"es-{i}",100,250,90,"2026-01-01T00:00:00+00:00"))
            tickets.append(self.s.create_case_ticket(self.t,"S1",r["alert_id"],"crew")["case_ticket_id"])
        outcomes=[]; lock=threading.Lock()
        def worker(ticket):
            s=self._service()
            try: s.allocate(self._token(s),"TOW-1",ticket,2); outcome="ok"
            except ValueError: outcome="rejected"
            with lock: outcomes.append(outcome)
        threads=[threading.Thread(target=worker,args=(ticket,)) for ticket in tickets]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(outcomes.count("ok"),1); self.assertEqual(outcomes.count("rejected"),4)
        self.assertEqual(self.s.response_resource(self.t,"TOW-1")["available"],1)
    def test_restart_replays_and_still_conflicts(self):
        first=self.s.allocate(self.t,"TOW-1",self.ticket,1)
        reopened=self._service(); token=self._token(reopened)
        replay=reopened.allocate(token,"TOW-1",self.ticket,1)
        self.assertTrue(replay["duplicate"]); self.assertEqual(replay["plan_id"],first["plan_id"])
        with self.assertRaises(Conflict): reopened.allocate(token,"TOW-1",self.ticket,2)
        self.assertEqual(reopened.response_resource(token,"TOW-1")["available"],2)
    def test_legacy_rows_without_fingerprint_are_backfilled(self):
        first=self.s.allocate(self.t,"TOW-1",self.ticket,1)
        self.s.db.execute("UPDATE allocations SET request_fingerprint=NULL"); self.s.db.commit()
        reopened=self._service(); token=self._token(reopened)
        row=reopened.allocation(token,first["plan_id"]); self.assertEqual(row["request_fingerprint"],first["request_fingerprint"])
        replay=reopened.allocate(token,"TOW-1",self.ticket,1)
        self.assertTrue(replay["duplicate"]); self.assertEqual(replay["plan_id"],first["plan_id"])
        with self.assertRaises(Conflict): reopened.allocate(token,"TOW-1",self.ticket,3)
