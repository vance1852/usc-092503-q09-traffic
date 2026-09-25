import os, sqlite3, tempfile, threading, unittest
from penalty_ops.models import ViolationRecord,CaseRecord
from penalty_ops.risk import score_violation_record
from penalty_ops.service import PenaltyService
from penalty_ops.storage import ConflictError, connect

def _unlink_with_wal(path):
    for suffix in ("","-wal","-shm"):
        if os.path.exists(path+suffix): os.remove(path+suffix)

class UrbanEnforcementTests(unittest.TestCase):
    def setUp(self):
        self.s=PenaltyService(); self.s.bootstrap(); self.t=self.s.auth.login("admin","enforcement-admin"); self.s.register_case_record(self.t,CaseRecord("S1","east","drainage",100,4))
    def _open_ticket(self, resource="R1", capacity=2):
        r=self.s.ingest_violation_record(self.t,ViolationRecord("R-"+resource,"S1","evidence_source",100,250,90,"2026-01-01T00:00:00+00:00"))
        o=self.s.create_case_ticket(self.t,"S1",r["alert_id"],"crew")
        self.s.transition_case_ticket(self.t,o["case_ticket_id"],"assigned","crew accepted")
        self.s.add_response_resource(self.t,resource,"tow_truck","east",capacity)
        return o["case_ticket_id"]
    def test_risk_and_idempotent_violation_record(self):
        r=ViolationRecord("R1","S1","evidence_source",120,250,90,"2026-01-01T00:00:00+00:00"); a=self.s.ingest_violation_record(self.t,r); b=self.s.ingest_violation_record(self.t,r); self.assertFalse(a["duplicate"]); self.assertTrue(b["duplicate"]); self.assertEqual(self.s.risk_report(self.t,"S1")["violation_records"],1)
    def test_case_ticket_and_allocation(self):
        r=self.s.ingest_violation_record(self.t,ViolationRecord("R2","S1","evidence_source",100,250,90,"2026-01-01T00:00:00+00:00")); o=self.s.create_case_ticket(self.t,"S1",r["alert_id"],"crew"); self.s.transition_case_ticket(self.t,o["case_ticket_id"],"assigned","crew accepted"); self.s.add_response_resource(self.t,"R1","pump","east",2); self.assertFalse(self.s.allocate(self.t,"R1",o["case_ticket_id"],1)["duplicate"]); self.assertEqual(self.s.response_resource(self.t,"R1")["available"],1)
    def test_same_fingerprint_retry_replays_without_double_deduction(self):
        tid=self._open_ticket()
        first=self.s.allocate(self.t,"R1",tid,1)
        again=self.s.allocate(self.t,"R1",tid,1)
        self.assertFalse(first["duplicate"]); self.assertTrue(again["duplicate"]); self.assertTrue(again["replayed"])
        self.assertEqual(first["plan_id"],again["plan_id"]); self.assertEqual(again["quantity"],1)
        self.assertEqual(self.s.response_resource(self.t,"R1")["available"],1)
    def test_changed_quantity_conflicts_and_leaves_inventory_untouched(self):
        tid=self._open_ticket()
        first=self.s.allocate(self.t,"R1",tid,1)
        with self.assertRaises(ConflictError) as ctx: self.s.allocate(self.t,"R1",tid,2)
        self.assertEqual(ctx.exception.details["existing_quantity"],1)
        self.assertEqual(ctx.exception.details["requested_quantity"],2)
        # 库存只按首次的一辆扣减，没有静默覆盖成两辆。
        self.assertEqual(self.s.response_resource(self.t,"R1")["available"],1)
        stored=self.s.allocation(self.t,"R1",tid)
        self.assertEqual(stored["plan_id"],first["plan_id"]); self.assertEqual(stored["quantity"],1)
        self.assertTrue(stored["request_sha256"])
    def test_auditable_adjustment_changes_quantity_and_inventory(self):
        tid=self._open_ticket()
        self.s.allocate(self.t,"R1",tid,1)
        adjusted=self.s.adjust_allocation(self.t,"R1",tid,2,"现场确认有两辆受损车辆","adj-demo")
        self.assertEqual(adjusted["previous_quantity"],1); self.assertEqual(adjusted["quantity"],2); self.assertEqual(adjusted["delta_units"],1)
        self.assertEqual(self.s.response_resource(self.t,"R1")["available"],0)
        # 指纹已随调整更新，新数量的直接重试安全重放。
        replay=self.s.allocate(self.t,"R1",tid,2); self.assertTrue(replay["duplicate"]); self.assertEqual(replay["quantity"],2)
        events=self.s.audit_events(self.t,"allocation",adjusted["plan_id"])
        self.assertTrue(any(e["action"]=="allocation.adjusted" for e in events))
    def test_adjustment_idempotency_key_replays_original_result(self):
        tid=self._open_ticket(capacity=3)
        self.s.allocate(self.t,"R1",tid,1)
        a=self.s.adjust_allocation(self.t,"R1",tid,2,"第二辆拖车","adj-key")
        b=self.s.adjust_allocation(self.t,"R1",tid,2,"第二辆拖车","adj-key")
        self.assertEqual(a["adjustment_id"],b["adjustment_id"]); self.assertTrue(b["duplicate"])
        self.assertEqual(self.s.response_resource(self.t,"R1")["available"],1)
        with self.assertRaises(ConflictError): self.s.adjust_allocation(self.t,"R1",tid,3,"不同内容复用键","adj-key")
    def test_failed_allocation_and_adjustment_roll_back(self):
        tid=self._open_ticket(capacity=1)
        with self.assertRaises(ValueError): self.s.allocate(self.t,"R1",tid,2)
        self.assertEqual(self.s.response_resource(self.t,"R1")["available"],1)
        self.s.allocate(self.t,"R1",tid,1)
        with self.assertRaises(ValueError): self.s.adjust_allocation(self.t,"R1",tid,3,"库存不足的调整","adj-fail")
        self.assertEqual(self.s.response_resource(self.t,"R1")["available"],0)
        self.assertEqual(self.s.allocation(self.t,"R1",tid)["quantity"],1)
    def test_concurrent_first_allocations_deduct_once_and_agree(self):
        path=tempfile.mktemp(suffix=".sqlite3"); self.addCleanup(lambda p=path: _unlink_with_wal(p))
        s=PenaltyService(path); s.bootstrap(); token=s.auth.login("admin","enforcement-admin")
        s.register_case_record(token,CaseRecord("S2","east","drainage",100,4))
        r=s.ingest_violation_record(token,ViolationRecord("R9","S2","src",100,250,90,"2026-01-01T00:00:00+00:00"))
        o=s.create_case_ticket(token,"S2",r["alert_id"],"crew"); s.add_response_resource(token,"RR","tow_truck","east",5)
        results=[]; errors=[]
        def worker():
            peer=PenaltyService(path)
            try: results.append(peer.allocate(token,"RR",o["case_ticket_id"],2))
            except ConflictError as exc: errors.append(exc)
            except Exception as exc: errors.append(exc)
        threads=[threading.Thread(target=worker) for _ in range(8)]
        for th in threads: th.start()
        for th in threads: th.join()
        self.assertFalse(errors, errors)
        self.assertEqual(len(results),8)
        self.assertEqual(len({x["plan_id"] for x in results}),1)
        self.assertEqual(sum(1 for x in results if not x["duplicate"]),1)
        self.assertEqual(PenaltyService(path).response_resource(token,"RR")["available"],3)
    def test_state_survives_restart_and_legacy_schema_migrates(self):
        path=tempfile.mktemp(suffix=".sqlite3"); self.addCleanup(lambda p=path: _unlink_with_wal(p))
        s=PenaltyService(path); s.bootstrap(); token=s.auth.login("admin","enforcement-admin")
        s.register_case_record(token,CaseRecord("S3","east","drainage",100,4))
        r=s.ingest_violation_record(token,ViolationRecord("R3","S3","src",100,250,90,"2026-01-01T00:00:00+00:00"))
        o=s.create_case_ticket(token,"S3",r["alert_id"],"crew"); s.add_response_resource(token,"RP","tow_truck","east",2)
        s.allocate(token,"RP",o["case_ticket_id"],1)
        restarted=PenaltyService(path)
        replay=restarted.allocate(token,"RP",o["case_ticket_id"],1)
        self.assertTrue(replay["duplicate"]); self.assertEqual(restarted.response_resource(token,"RP")["available"],1)
        with self.assertRaises(ConflictError): restarted.allocate(token,"RP",o["case_ticket_id"],2)
        # 旧版数据库（allocations 无指纹列）升级后行为安全：无指纹的历史记录一律视为冲突，不重复扣库存。
        legacy=tempfile.mktemp(suffix=".sqlite3"); self.addCleanup(lambda p=legacy: _unlink_with_wal(p))
        db=sqlite3.connect(legacy)
        db.executescript("CREATE TABLE response_resources(response_resource_id TEXT PRIMARY KEY,kind TEXT,district TEXT,capacity INTEGER,available INTEGER);"
                         "CREATE TABLE allocations(plan_id TEXT PRIMARY KEY,response_resource_id TEXT,case_ticket_id TEXT,quantity INTEGER,created_at TEXT,UNIQUE(response_resource_id,case_ticket_id));"
                         "INSERT INTO response_resources VALUES('OLD','tow_truck','east',2,1);"
                         "INSERT INTO allocations VALUES('alloc-old','OLD','WO-OLD',1,'2026-01-01T00:00:00+00:00');"); db.commit(); db.close()
        migrated=connect(legacy)
        cols={row[1] for row in migrated.execute("PRAGMA table_info(allocations)")}
        self.assertIn("request_sha256",cols)
        row=migrated.execute("SELECT request_sha256 FROM allocations WHERE plan_id='alloc-old'").fetchone()
        self.assertEqual(row[0],"")
        migrated.close()
    def test_risk_validation(self):
        with self.assertRaises(ValueError):score_violation_record(-1,1,1,2)

