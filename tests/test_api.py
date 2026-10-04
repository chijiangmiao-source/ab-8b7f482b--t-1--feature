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


class TestRoundtripEvidence(ApiTestCase):
    def _capture(self, rows):
        return [{"direction": d, "hex": h} for d, h in rows]

    def test_submit_and_get_include_roundtrip_pairs(self):
        capture = self._capture([
            ("TX", blk(NAD_TX, 0x00, "00A4040000")),
            ("RX", blk(NAD_RX, 0x00, "9000")),
        ])
        status, body = self.post("T-RT-1", capture)
        self.assertEqual(status, 201)
        rt = body["roundtrips"]
        self.assertEqual(rt["command_count"], 1)
        self.assertEqual(rt["answered_count"], 1)
        (p,) = rt["pairs"]
        self.assertEqual(p["status"], "answered")
        self.assertEqual(p["command"]["apdu"], "00A4040000")
        self.assertEqual(p["response"]["apdu"], "9000")
        # GET 同样带往返证据
        status2, got = self.req("GET", "/api/audits/T-RT-1")
        self.assertEqual(status2, 200)
        self.assertEqual(got["roundtrips"], rt)

    def test_wtx_between_apdus_listed_as_control_without_changing_pair(self):
        capture = self._capture([
            ("TX", blk(NAD_TX, 0x00, "00A4040000")),
            ("RX", blk(NAD_RX, 0xC3, "05")),          # WTX 请求
            ("TX", blk(NAD_TX, 0xE3, "05")),          # WTX 应答
            ("RX", blk(NAD_RX, 0x00, "9000")),
        ])
        _, body = self.post("T-RT-WTX", capture)
        (p,) = body["roundtrips"]["pairs"]
        self.assertEqual(p["status"], "answered")
        self.assertEqual([c["index"] for c in p["between_controls"]], [1, 2])
        self.assertIn("WTX", p["between_controls"][0]["detail"])

    def test_unanswered_and_orphan_marked(self):
        # 命令1 → 应答1；R(ACK)；读卡器多余 APDU；命令2（捕获结束前无窗口内应答）
        capture = self._capture([
            ("TX", blk(NAD_TX, 0x00, "00A4040000")),
            ("RX", blk(NAD_RX, 0x00, "6100")),
            ("TX", blk(NAD_TX, 0x90)),
            ("RX", blk(NAD_RX, 0x40, "0090")),
            ("TX", blk(NAD_TX, 0x40, "00B0000000")),
        ])
        _, body = self.post("T-RT-ORPHAN", capture)
        rt = body["roundtrips"]
        self.assertEqual(rt["answered_count"], 1)
        self.assertEqual(rt["unanswered_count"], 1)
        self.assertEqual(rt["pairs"][1]["status"], "unanswered")
        self.assertIsNone(rt["pairs"][1]["response"])
        orphan = rt["orphan_response"]
        self.assertEqual(orphan["apdu"], "0090")
        self.assertEqual((orphan["first_index"], orphan["last_index"]), (3, 3))

    def test_replay_returns_roundtrips(self):
        self.post("T-RT-REPLAY", LEGAL_CAPTURE)
        status, body = self.post("T-RT-REPLAY", LEGAL_CAPTURE)
        self.assertEqual(status, 200)
        self.assertTrue(body.get("replayed"))
        self.assertIn("roundtrips", body)

    def test_legacy_frozen_result_enriched_on_read_without_mutation(self):
        # 先取得一份新结果的 steps/apdus/final_state，模拟功能上线前冻结的旧形态
        _, fresh = self.post("T-RT-LEGACY-SRC", LEGAL_CAPTURE)
        legacy_result = {
            "audit_id": "OLD-1", "frozen": True, "block_count": 6,
            "verdict": "PASS", "error": None,
            "steps": fresh["steps"], "apdus": fresh["apdus"],
            "final_state": fresh["final_state"],
        }
        store2 = AuditStore()
        store2.submit("OLD-1", LEGAL_CAPTURE, legacy_result)  # 无 roundtrips 字段
        httpd2 = make_server("127.0.0.1", 0, store2)
        port2 = httpd2.server_address[1]
        t = threading.Thread(target=httpd2.serve_forever, daemon=True)
        t.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port2}/api/audits/OLD-1", timeout=5) as r:
                self.assertEqual(r.status, 200)
                got = json.loads(r.read())
            rt = got["roundtrips"]
            self.assertEqual(rt["answered_count"], 1)
            self.assertEqual(rt["pairs"][0]["response"]["apdu"], "6F0584039000")
        finally:
            httpd2.shutdown()
            httpd2.server_close()
        # 补算只发生在读取响应上，存储中的冻结结果本体不被写回改写
        self.assertNotIn("roundtrips", store2.get("OLD-1"))
        self.assertEqual(store2.get("OLD-1")["steps"], fresh["steps"])


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
