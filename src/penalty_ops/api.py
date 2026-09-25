"""依赖标准库的 JSON HTTP API。"""
from __future__ import annotations
import argparse,json,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from .errors import Conflict
from .models import ViolationRecord,CaseRecord
from .service import PenaltyService
class Handler(BaseHTTPRequestHandler):
    service=PenaltyService()
    lock=threading.Lock()
    def _send(self,status,payload):
        data=json.dumps(payload,ensure_ascii=False).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
    def _token(self):return self.headers.get("Authorization","").removeprefix("Bearer ")
    def do_GET(self):
        with Handler.lock: self._handle_get()
    def do_POST(self):
        with Handler.lock: self._handle_post()
    def _handle_get(self):
        try:
            if self.path=="/health":return self._send(200,{"status":"ok","service":"urban-enforcement"})
            if self.path.startswith("/case_records/") and self.path.endswith("/risk"):return self._send(200,self.service.risk_report(self._token(),self.path.split("/")[2]))
            if self.path.startswith("/case_records/"):return self._send(200,self.service.case_record(self._token(),self.path.split("/",2)[2]))
            if self.path.startswith("/allocations/"):return self._send(200,self.service.allocation(self._token(),self.path.split("/")[2]))
            return self._send(404,{"error":"not found"})
        except PermissionError as e:return self._send(403,{"error":str(e)})
        except Conflict as e:return self._send(409,{"error":str(e)})
        except Exception as e:return self._send(400,{"error":str(e)})
    def _handle_post(self):
        try:
            body=json.loads(self.rfile.read(int(self.headers.get("Content-Length","0"))) or b"{}")
            if self.path=="/login":return self._send(200,{"token":self.service.auth.login(body["user_id"],body["password"])})
            token=self._token()
            if self.path=="/case_records":return self._send(201,self.service.register_case_record(token,CaseRecord(body["case_record_id"],body["district"],body["enforcement_type"],body["length_m"],body["criticality"])))
            if self.path.startswith("/case_records/") and self.path.endswith("/violation_records"):
                sid=self.path.split("/")[2]; r=ViolationRecord(body["violation_record_id"],sid,body["evidence_source_id"],body["speed_kmh"],body["traffic_flow_vph"],body["impact_index"],body["observed_at"]); return self._send(201,self.service.ingest_violation_record(token,r))
            if self.path.startswith("/case_records/") and self.path.endswith("/work-orders"):
                return self._send(201,self.service.create_case_ticket(token,self.path.split("/")[2],body["alert_id"],body["assignee"],body.get("priority",3)))
            if self.path=="/allocations":return self._send(201,self.service.allocate(token,body["response_resource_id"],body["case_ticket_id"],body["quantity"]))
            if self.path.startswith("/allocations/") and self.path.endswith("/adjust"):
                return self._send(200,self.service.adjust_allocation(token,self.path.split("/")[2],body["quantity"],body.get("reason","")))
            return self._send(404,{"error":"not found"})
        except PermissionError as e:return self._send(403,{"error":str(e)})
        except Conflict as e:return self._send(409,{"error":str(e)})
        except Exception as e:return self._send(400,{"error":str(e)})
def main():
    p=argparse.ArgumentParser(); p.add_argument("--database",default=":memory:"); p.add_argument("--host",default="127.0.0.1"); p.add_argument("--port",type=int,default=8080); a=p.parse_args(); Handler.service=PenaltyService(a.database); Handler.service.bootstrap(); ThreadingHTTPServer((a.host,a.port),Handler).serve_forever()
if __name__=="__main__":main()
