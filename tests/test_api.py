"""API 与冻结审计集成测试：真实 HTTP 服务 + urllib 客户端。"""

import json
import threading
import unittest
import urllib.error
import urllib.request

from app.server import make_server
from app.store import AuditStore
from app.t1proto import build_block

NAD_TX, NAD_RX = 0x12, 0x21


def blk(nad, pcb, inf=""):
    return build_block(nad, pcb, bytes.fromhex(inf)).hex().upper()


# 合法重传捕获：I(0)链 → R(ACK) → I(1)完成 → RX I(0) → 合法重复 → R(ACK)
# I 块 PCB：N(S)<<6 | M<<5（0x20=N(S)0/M1，0x40=N(S)1/M0）
LEGAL_CAPTURE = [
    {"direction": "TX", "hex": blk(NAD_TX, 0x20, "00A4040007")},
    {"direction": "RX", "hex": blk(NAD_RX, 0x90)},
    {"direction": "TX", "hex": blk(NAD_TX, 0x40, "A0000000031010")},
    {"direction": "RX", "hex": blk(NAD_RX, 0x00, "6F0584039000")},
    {"direction": "RX", "hex": blk(NAD_RX, 0x00, "6F0584039000")},
    {"direction": "TX", "hex": blk(NAD_TX, 0x90)},
]

# 非法等待扩展捕获：WTX 请求后紧跟 I 块
WTX_BAD_CAPTURE = [
    {"direction": "TX", "hex": blk(NAD_TX, 0x00, "00A4040000")},
    {"direction": "RX", "hex": blk(NAD_RX, 0xC3, "05")},
    {"direction": "TX", "hex": blk(NAD_TX, 0x40, "00A4040000")},
]


class ApiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = make_server("127.0.0.1", 0, AuditStore())
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def req(self, method, path, payload=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def post(self, audit_id, blocks):
        return self.req("POST", "/api/audits", {"audit_id": audit_id, "blocks": blocks})


class TestHealth(ApiTestCase):
    def test_health(self):
        status, body = self.req("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_page_served(self):
        url = f"http://127.0.0.1:{self.port}/"
        with urllib.request.urlopen(url, timeout=5) as r:
            html = r.read().decode()
        self.assertEqual(r.status, 200)
        self.assertIn("冻结裁决", html)


class TestFrozenAudit(ApiTestCase):
    def test_submit_freezes_and_replay_returns_original(self):
        status, body = self.post("T-FROZEN-1", LEGAL_CAPTURE)
        self.assertEqual(status, 201)
        self.assertEqual(body["verdict"], "PASS")
        self.assertTrue(body["frozen"])
        self.assertEqual(body["apdus"]["RX"], ["6F0584039000"])  # 未重复拼接
        self.assertEqual(len(body["steps"]), 6)
        # 相同标识 + 相同捕获 → 原冻结结果
        status2, body2 = self.post("T-FROZEN-1", LEGAL_CAPTURE)
        self.assertEqual(status2, 200)
        self.assertTrue(body2.get("replayed"))
        self.assertEqual(body2["created_at"], body["created_at"])
        self.assertEqual(body2["steps"], body["steps"])

    def test_modified_capture_conflicts_and_original_readable(self):
        self.post("T-FROZEN-2", LEGAL_CAPTURE)
        modified = [dict(b) for b in LEGAL_CAPTURE]
        modified[2] = dict(modified[2], hex=blk(NAD_TX, 0x80, "A0000000031011"))  # 改动任一块
        status, body = self.post("T-FROZEN-2", modified)
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "conflict")
        # 原结果仍可读取
        status2, original = self.req("GET", "/api/audits/T-FROZEN-2")
        self.assertEqual(status2, 200)
        self.assertEqual(original["verdict"], "PASS")
        self.assertEqual(original["apdus"]["TX"], ["00A4040007A0000000031010"])

    def test_whitespace_and_case_normalized_for_identity(self):
        self.post("T-FROZEN-3", LEGAL_CAPTURE)
        same = [dict(b, hex=" ".join([b["hex"][i:i + 2] for i in range(0, len(b["hex"]), 2)]).lower())
                for b in LEGAL_CAPTURE]
        status, body = self.post("T-FROZEN-3", same)
        self.assertEqual(status, 200)
        self.assertTrue(body.get("replayed"))

    def test_unknown_audit_404(self):
        status, _ = self.req("GET", "/api/audits/NO-SUCH-ID")
        self.assertEqual(status, 404)

    def test_list_audits(self):
        self.post("T-LIST-1", LEGAL_CAPTURE)
        status, body = self.req("GET", "/api/audits")
        self.assertEqual(status, 200)
        ids = [a["audit_id"] for a in body["audits"]]
        self.assertIn("T-LIST-1", ids)


class TestVerdicts(ApiTestCase):
    def test_illegal_waiting_extension_fail_located(self):
        status, body = self.post("T-WTX-BAD", WTX_BAD_CAPTURE)
        self.assertEqual(status, 201)
        self.assertEqual(body["verdict"], "FAIL")
        self.assertEqual(body["error"]["index"], 2)
        self.assertEqual(body["error"]["code"], "S_WAIT")
        self.assertEqual(len(body["steps"]), 2)  # 首错前的步骤保留

    def test_invalid_hex_located_as_block_fault(self):
        capture = [dict(LEGAL_CAPTURE[0]), {"direction": "RX", "hex": "ZZ"}]
        status, body = self.post("T-BADHEX", capture)
        self.assertEqual(status, 201)
        self.assertEqual(body["verdict"], "FAIL")
        self.assertEqual(body["error"]["index"], 1)
        self.assertEqual(body["error"]["code"], "BAD_HEX")


class TestValidation(ApiTestCase):
    def test_too_many_blocks(self):
        blocks = [{"direction": "TX", "hex": blk(NAD_TX, 0x00, "00")}] * 65
        status, body = self.post("T-TOO-MANY", blocks)
        self.assertEqual(status, 400)
        self.assertIn("64", body["message"])

    def test_bad_direction(self):
        status, _ = self.post("T-BADDIR", [{"direction": "UP", "hex": "00"}])
        self.assertEqual(status, 400)

    def test_empty_blocks(self):
        status, _ = self.post("T-EMPTY", [])
        self.assertEqual(status, 400)

    def test_bad_audit_id(self):
        status, _ = self.post("has space", LEGAL_CAPTURE)
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
