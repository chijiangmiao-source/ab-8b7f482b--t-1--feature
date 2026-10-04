"""往返证据派生单元测试：命令—应答配对、未应答、无法归属读卡器 APDU 的稳定性。"""

import unittest

from app.roundtrip import build_roundtrips
from app.t1proto import Engine, build_block

NAD_TX = 0x12
NAD_RX = 0x21


def I(ns, more, inf=b"", nad=NAD_TX):
    return build_block(nad, (ns << 6) | (more << 5),
                       bytes.fromhex(inf) if isinstance(inf, str) else inf).hex().upper()


def R(nr, code=0, nad=NAD_RX):
    return build_block(nad, 0x80 | (nr << 4) | code).hex().upper()


def S(stype, resp, inf=b"", nad=NAD_RX):
    return build_block(nad, 0xC0 | stype | (0x20 if resp else 0),
                       bytes.fromhex(inf) if isinstance(inf, str) else inf).hex().upper()


def evidence(blocks):
    result = Engine().run(blocks)
    assert result["verdict"] == "PASS", result["error"]
    return result, build_roundtrips(result)


class TestPairing(unittest.TestCase):
    def test_simple_command_response_pairs(self):
        _, ev = evidence([
            ("TX", I(0, 0, "00A4040000")),          # 命令0 #0
            ("RX", I(0, 0, "9000", nad=NAD_RX)),    # 应答0 #1
            ("TX", I(1, 0, "00B000000A")),          # 命令1 #2
            ("RX", I(1, 0, "6A82", nad=NAD_RX)),    # 应答1 #3
        ])
        self.assertEqual(ev["summary"],
                         {"commands": 2, "answered": 2, "unanswered": 0, "unassignable": 0})
        p0, p1 = ev["pairs"]
        self.assertEqual(p0["status"], "answered")
        self.assertEqual(p0["command"]["apdu"], "00A4040000")
        self.assertEqual((p0["command"]["first_index"], p0["command"]["last_index"]), (0, 0))
        self.assertEqual(p0["response"]["apdu"], "9000")
        self.assertEqual((p0["response"]["first_index"], p0["response"]["last_index"]), (1, 1))
        self.assertEqual(p1["command"]["apdu"], "00B000000A")
        self.assertEqual(p1["response"]["apdu"], "6A82")
        self.assertEqual(ev["unassigned"], [])
        self.assertIsNone(ev["first_unassignable"])

    def test_chained_apdu_uses_first_and_last_i_block_indices(self):
        _, ev = evidence([
            ("TX", I(0, 1, "00A4040007")),          # #0 命令链首
            ("RX", R(1)),                            # #1 链路层 ACK（命令尚未结束）
            ("TX", I(1, 0, "A0000000031010")),      # #2 命令完成
            ("RX", I(0, 1, "6110", nad=NAD_RX)),    # #3 应答链首段
            ("TX", R(1, nad=NAD_TX)),                # #4 链路层 ACK（应答尚未结束）
            ("RX", I(1, 0, "9000", nad=NAD_RX)),    # #5 应答完成
        ])
        p = ev["pairs"][0]
        self.assertEqual(p["command"]["apdu"], "00A4040007A0000000031010")
        self.assertEqual((p["command"]["first_index"], p["command"]["last_index"]), (0, 2))
        self.assertEqual(p["response"]["apdu"], "61109000")
        self.assertEqual((p["response"]["first_index"], p["response"]["last_index"]), (3, 5))
        # R 块均落在各自 APDU 链的组装期内，不落在“命令结束→应答开始”窗口
        self.assertEqual(p["between"], [])

    def test_r_ack_between_command_end_and_response_start(self):
        _, ev = evidence([
            ("TX", I(0, 0, "00A4040000")),          # #0 命令结束
            ("RX", R(1)),                            # #1 命令传输层确认（非应答APDU）
            ("RX", I(0, 0, "9000", nad=NAD_RX)),    # #2 应答开始
        ])
        p = ev["pairs"][0]
        self.assertEqual(p["status"], "answered")
        self.assertEqual(p["response"]["apdu"], "9000")
        between = [(c["index"], c["kind"], c["label"]) for c in p["between"]]
        self.assertEqual(between, [(1, "R", "R(ACK) N(R)=1")])

    def test_wtx_and_ifs_roundtrips_between_command_and_response(self):
        _, ev = evidence([
            ("TX", I(0, 0, "00A4040000")),             # #0 命令
            ("RX", S(0x03, False, "05", nad=NAD_RX)),  # #1 WTX 请求
            ("TX", S(0x03, True, "05", nad=NAD_TX)),   # #2 WTX 应答
            ("RX", S(0x01, False, "20", nad=NAD_RX)),  # #3 IFS 请求
            ("TX", S(0x01, True, "20", nad=NAD_TX)),   # #4 IFS 应答
            ("RX", I(0, 0, "9000", nad=NAD_RX)),       # #5 应答
        ])
        p = ev["pairs"][0]
        self.assertEqual(p["status"], "answered")
        between = [(c["index"], c["kind"]) for c in p["between"]]
        self.assertEqual(between, [(1, "S"), (2, "S"), (3, "S"), (4, "S")])
        labels = " ".join(c["label"] for c in p["between"])
        self.assertIn("WTX", labels)
        self.assertIn("IFS", labels)

    def test_retransmission_contributes_only_one_apdu_and_still_pairs(self):
        dup = I(0, 0, "6F0584039000", nad=NAD_RX)
        _, ev = evidence([
            ("TX", I(0, 0, "00A4040000")),
            ("RX", dup),                             # 应答 APDU
            ("RX", dup),                             # 合法重传，不贡献第二个 APDU
            ("TX", R(1, nad=NAD_TX)),
        ])
        self.assertEqual(ev["summary"]["commands"], 1)
        self.assertEqual(ev["summary"]["answered"], 1)
        self.assertEqual(ev["summary"]["unassignable"], 0)
        resp = ev["pairs"][0]["response"]
        self.assertEqual(resp["apdu"], "6F0584039000")
        self.assertEqual(resp["first_index"], 1)
        self.assertEqual(resp["last_index"], 1)

    def test_command_without_response_before_next_command_is_unanswered(self):
        _, ev = evidence([
            ("TX", I(0, 0, "00A4040000")),          # #0 命令0
            ("RX", R(1)),                            # #1 仅链路层 ACK，无应答 APDU
            ("TX", I(1, 0, "00B000000A")),          # #2 命令1开始 → 关闭命令0窗口
            ("RX", I(0, 0, "9000", nad=NAD_RX)),    # #3 只能应答命令1
        ])
        p0, p1 = ev["pairs"]
        self.assertEqual(p0["status"], "unanswered")
        self.assertEqual(p0["reason"], "NEXT_COMMAND")
        self.assertIn("#2", p0["message"])
        self.assertIsNone(p0["response"])
        self.assertEqual(p0["between"], [])
        self.assertEqual(p1["status"], "answered")
        self.assertEqual(p1["response"]["apdu"], "9000")
        self.assertEqual(ev["summary"]["unanswered"], 1)
        self.assertEqual(ev["unassigned"], [])

    def test_last_command_unanswered_at_capture_end(self):
        _, ev = evidence([
            ("TX", I(0, 0, "00A4040000")),
            ("RX", I(0, 0, "9000", nad=NAD_RX)),
            ("TX", I(1, 0, "00B000000A")),          # 末条命令无应答
        ])
        self.assertEqual(ev["pairs"][0]["status"], "answered")
        p1 = ev["pairs"][1]
        self.assertEqual(p1["status"], "unanswered")
        self.assertEqual(p1["reason"], "CAPTURE_END")

    def test_two_consecutive_reader_apdus_first_orphan_never_lent(self):
        _, ev = evidence([
            ("TX", I(0, 0, "00A4040000")),          # #0 命令0
            ("RX", I(0, 0, "9000", nad=NAD_RX)),    # #1 应答0
            ("TX", R(1, nad=NAD_TX)),                # #2 链路层确认应答0
            ("RX", I(1, 0, "6A82", nad=NAD_RX)),    # #3 连续第二个读卡器 APDU
            ("TX", I(1, 0, "00B000000A")),          # #4 命令1，#3 不得借给它
            ("RX", I(0, 0, "7777", nad=NAD_RX)),    # #5 应答1
        ])
        p0, p1 = ev["pairs"]
        self.assertEqual(p0["response"]["apdu"], "9000")
        self.assertEqual(p1["response"]["apdu"], "7777")
        self.assertEqual(len(ev["unassigned"]), 1)
        orphan = ev["unassigned"][0]
        self.assertEqual(orphan["apdu"], "6A82")
        self.assertEqual((orphan["first_index"], orphan["last_index"]), (3, 3))
        self.assertTrue(orphan["first"])
        self.assertEqual(orphan["reason"], "EXTRA_RESPONSE")
        first = ev["first_unassignable"]
        self.assertEqual(first["first_index"], 3)
        self.assertEqual(first["apdu"], "6A82")
        self.assertEqual(ev["summary"]["unassignable"], 1)

    def test_reader_apdu_before_any_command_is_unassignable(self):
        _, ev = evidence([
            ("RX", I(0, 0, "3B00", nad=NAD_RX)),    # #0 读卡器先发 APDU
            ("TX", I(0, 0, "00A4040000")),          # #1 命令0
            ("RX", I(1, 0, "9000", nad=NAD_RX)),    # #2 应答0
        ])
        p0 = ev["pairs"][0]
        self.assertEqual(p0["status"], "answered")
        self.assertEqual(p0["response"]["apdu"], "9000")
        self.assertEqual(len(ev["unassigned"]), 1)
        orphan = ev["unassigned"][0]
        self.assertEqual(orphan["apdu"], "3B00")
        self.assertEqual(orphan["reason"], "READER_FIRST")
        self.assertTrue(orphan["first"])
        self.assertEqual(ev["first_unassignable"]["first_index"], 0)

    def test_response_completed_after_next_command_start_is_late_not_lent(self):
        _, ev = evidence([
            ("TX", I(0, 1, "00A4040007")),              # #0 命令0链首
            ("RX", R(1)),                                # #1
            ("TX", I(1, 0, "A0000000031010")),          # #2 命令0完成
            ("RX", I(0, 1, "6110", nad=NAD_RX)),        # #3 应答链首段（窗口内）
            ("TX", I(0, 0, "00B000000A")),              # #4 命令1开始
            ("RX", I(1, 0, "9000", nad=NAD_RX)),        # #5 应答链跨边界完成 → 越界
            ("TX", R(0, nad=NAD_TX)),                    # #6 链路层确认
            ("RX", I(0, 0, "7777", nad=NAD_RX)),        # #7 真正应答1
        ])
        p0, p1 = ev["pairs"]
        self.assertEqual(p0["status"], "unanswered")          # 原应答越界不算数
        self.assertEqual(p0["reason"], "NEXT_COMMAND")
        self.assertEqual(p1["response"]["apdu"], "7777")       # 迟到链不借给命令1
        self.assertEqual(len(ev["unassigned"]), 1)
        orphan = ev["unassigned"][0]
        self.assertEqual(orphan["apdu"], "61109000")
        self.assertEqual((orphan["first_index"], orphan["last_index"]), (3, 5))
        self.assertEqual(orphan["reason"], "LATE_RESPONSE")
        self.assertEqual(ev["first_unassignable"]["first_index"], 3)

    def test_orphan_order_is_stable_across_identical_runs(self):
        blocks = [
            ("RX", I(0, 0, "1111", nad=NAD_RX)),    # #0 抢先 APDU
            ("TX", I(0, 0, "00A4040000")),          # #1 命令0
            ("RX", I(1, 0, "9000", nad=NAD_RX)),    # #2 应答0
            ("TX", I(1, 0, "00B000000A")),          # #3 命令1
            ("RX", I(0, 0, "2222", nad=NAD_RX)),    # #4 应答1
            ("TX", R(1, nad=NAD_TX)),                # #5 链路层确认
            ("RX", I(1, 0, "3333", nad=NAD_RX)),    # #6 连续多余 APDU
        ]
        ev1 = build_roundtrips(Engine().run(blocks))
        ev2 = build_roundtrips(Engine().run(blocks))
        self.assertEqual(ev1, ev2)
        self.assertEqual([o["apdu"] for o in ev1["unassigned"]], ["1111", "3333"])
        self.assertEqual(ev1["first_unassignable"]["apdu"], "1111")
        self.assertEqual(ev1["first_unassignable"]["first_index"], 0)

    def test_no_commands_reader_only(self):
        _, ev = evidence([
            ("RX", I(0, 0, "9000", nad=NAD_RX)),
        ])
        self.assertEqual(ev["pairs"], [])
        self.assertEqual(ev["unassigned"][0]["reason"], "READER_FIRST")
        self.assertEqual(ev["summary"]["commands"], 0)
        self.assertEqual(ev["summary"]["unassignable"], 1)


if __name__ == "__main__":
    unittest.main()
