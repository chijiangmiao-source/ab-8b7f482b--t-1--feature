"""T=1 协议引擎单元测试：合法重传、非法等待扩展、序号/长度/LRC 定位等。"""

import unittest

from app.t1proto import Engine, build_block, build_roundtrips

NAD_TX = 0x12  # 站→读卡器
NAD_RX = 0x21  # 读卡器→站（半字节互换）


def I(ns, more, inf=b"", nad=NAD_TX):
    return build_block(nad, (ns << 6) | (more << 5), bytes.fromhex(inf) if isinstance(inf, str) else inf).hex().upper()


def R(nr, code=0, nad=NAD_RX):
    return build_block(nad, 0x80 | (nr << 4) | code).hex().upper()


def S(stype, resp, inf=b"", nad=NAD_RX):
    pcb = 0xC0 | stype | (0x20 if resp else 0)
    return build_block(nad, pcb, bytes.fromhex(inf) if isinstance(inf, str) else inf).hex().upper()


def run(blocks):
    return Engine().run(blocks)


class TestLegalFlow(unittest.TestCase):
    def test_chained_assembly_and_ping_pong(self):
        r = run([
            ("TX", I(0, 1, "00A4040007")),          # 链式段1
            ("RX", R(1)),                            # R(ACK)
            ("TX", I(1, 1, "A000000003")),          # 链式段2
            ("RX", R(0)),                            # R(ACK) N(R)=0
            ("TX", I(0, 0, "1010")),                # 链式段3 → APDU完成
            ("RX", I(0, 0, "9000", nad=NAD_RX)),    # 应答APDU，隐式确认
            ("TX", I(1, 0, "00B0000000")),          # 下一条指令
            ("RX", I(1, 0, "9000", nad=NAD_RX)),
        ])
        self.assertEqual(r["verdict"], "PASS", r["error"])
        self.assertEqual(r["apdus"]["TX"], ["00A4040007A0000000031010", "00B0000000"])
        self.assertEqual(r["apdus"]["RX"], ["9000", "9000"])

    def test_legal_retransmission_then_ack_no_apdu_duplication(self):
        dup = I(0, 0, "6F0584039000", nad=NAD_RX)
        r = run([
            ("TX", I(0, 1, "00A4040007")),
            ("RX", R(1)),
            ("TX", I(1, 0, "A0000000031010")),
            ("RX", dup),                             # RX I(0) → APDU完成
            ("RX", dup),                             # 最近未确认块的合法重复
            ("TX", R(1, nad=NAD_TX)),                # 后续确认
        ])
        self.assertEqual(r["verdict"], "PASS", r["error"])
        # APDU 不得重复拼接
        self.assertEqual(r["apdus"]["RX"], ["6F0584039000"])
        self.assertEqual(r["apdus"]["TX"], ["00A4040007A0000000031010"])
        retx = r["steps"][4]
        self.assertEqual(retx["action"], "retransmission")
        self.assertIn("合法重复", retx["basis"])
        # 重传后序号未推进，R(ACK) 以 N(R)=1 确认
        self.assertEqual(r["steps"][5]["action"], "ack")
        self.assertIsNone(r["final_state"]["unacked"]["RX"])

    def test_nak_then_retransmit(self):
        blk = I(0, 0, "00A4040000")
        r = run([
            ("TX", blk),
            ("RX", R(0, code=1)),                    # R(NAK-EDC) 指向 N(S)=0
            ("TX", blk),                             # 合法重传
            ("RX", R(1)),                            # R(ACK)
        ])
        self.assertEqual(r["verdict"], "PASS", r["error"])
        self.assertEqual(r["steps"][1]["action"], "nak")
        self.assertIn("重传", r["steps"][1]["basis"])
        self.assertEqual(r["steps"][2]["action"], "retransmission")
        self.assertEqual(r["apdus"]["TX"], ["00A4040000"])  # 仅拼接一次

    def test_ifs_negotiation_extends_limit(self):
        big_inf = "AA" * 40  # 超过缺省 IFSC=32
        r = run([
            ("RX", S(0x01, False, "28", nad=NAD_RX)),   # S(IFS) 请求 IFS=40
            ("TX", S(0x01, True, "28", nad=NAD_TX)),    # S(IFS) 应答
            ("TX", I(0, 0, big_inf)),                   # 现可通过
            ("RX", I(0, 0, "9000", nad=NAD_RX)),
        ])
        self.assertEqual(r["verdict"], "PASS", r["error"])
        self.assertEqual(r["final_state"]["ifs_limit"]["TX"], 40)


class TestWaitingExtension(unittest.TestCase):
    def test_wtx_roundtrip_then_continue(self):
        r = run([
            ("TX", I(0, 0, "00A4040000")),
            ("RX", S(0x03, False, "05", nad=NAD_RX)),  # S(WTX) 请求 倍率5
            ("TX", S(0x03, True, "05", nad=NAD_TX)),   # S(WTX) 应答 倍率5
            ("RX", I(0, 0, "9000", nad=NAD_RX)),       # 匹配往返后继续
        ])
        self.assertEqual(r["verdict"], "PASS", r["error"])
        self.assertEqual(r["steps"][2]["action"], "wtx-response")
        self.assertIsNone(r["final_state"]["waiting_extension"])

    def test_wtx_request_then_iblock_rejected(self):
        r = run([
            ("TX", I(0, 0, "00A4040000")),
            ("RX", S(0x03, False, "05", nad=NAD_RX)),
            ("TX", I(1, 0, "00A4040000")),             # 等待期间收到 I 块
        ])
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["error"]["index"], 2)
        self.assertEqual(r["error"]["code"], "S_WAIT")

    def test_wtx_wrong_multiplier_rejected(self):
        r = run([
            ("TX", I(0, 0, "00A4040000")),
            ("RX", S(0x03, False, "05", nad=NAD_RX)),
            ("TX", S(0x03, True, "06", nad=NAD_TX)),   # 倍率不符
        ])
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["error"]["index"], 2)
        self.assertEqual(r["error"]["code"], "S_RESP")
        self.assertIn("倍率", r["error"]["message"])

    def test_wtx_wrong_response_type_rejected(self):
        r = run([
            ("TX", I(0, 0, "00A4040000")),
            ("RX", S(0x03, False, "05", nad=NAD_RX)),
            ("TX", S(0x01, True, "05", nad=NAD_TX)),   # 以 IFS 应答 WTX
        ])
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["error"]["index"], 2)
        self.assertEqual(r["error"]["code"], "S_RESP")
        self.assertIn("类型不符", r["error"]["message"])

    def test_wtx_wrong_direction_rejected(self):
        r = run([
            ("TX", I(0, 0, "00A4040000")),
            ("RX", S(0x03, False, "05", nad=NAD_RX)),
            ("RX", S(0x03, True, "05", nad=NAD_RX)),   # 应答方向不符
        ])
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["error"]["index"], 2)
        self.assertEqual(r["error"]["code"], "S_RESP")
        self.assertIn("方向不符", r["error"]["message"])

    def test_unsolicited_wtx_response_rejected(self):
        r = run([
            ("TX", I(0, 0, "00A4040000")),
            ("TX", S(0x03, True, "05", nad=NAD_TX)),   # 无请求先应答
        ])
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["error"]["index"], 1)
        self.assertEqual(r["error"]["code"], "S_RESP")

    def test_unanswered_wtx_request_fails_at_request(self):
        r = run([
            ("TX", I(0, 0, "00A4040000")),
            ("RX", S(0x03, False, "05", nad=NAD_RX)),
        ])
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["error"]["index"], 1)
        self.assertEqual(r["error"]["code"], "S_UNANSWERED")


class TestFirstFaultLocation(unittest.TestCase):
    def test_lrc_error_locates_first_bad_block(self):
        good = I(0, 0, "00A4040000")
        bad = I(1, 0, "00A4040000")[:-2] + "FF"        # 破坏 LRC
        r = run([("TX", good), ("RX", bad), ("TX", good)])
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["error"]["index"], 1)
        self.assertEqual(r["error"]["code"], "LRC")

    def test_length_mismatch(self):
        blk = I(0, 0, "00A4040000") + "00"             # 多出一字节
        r = run([("TX", blk)])
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["error"]["index"], 0)
        self.assertEqual(r["error"]["code"], "LENGTH")

    def test_inf_out_of_bounds(self):
        r = run([("TX", I(0, 0, "AA" * 33))])          # 超过缺省 IFSC=32
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["error"]["code"], "INF_RANGE")
        self.assertEqual(r["error"]["index"], 0)

    def test_stale_duplicate_rejected(self):
        blk0 = I(0, 0, "00A4040000")
        r = run([
            ("TX", blk0),
            ("RX", I(0, 0, "9000", nad=NAD_RX)),       # 隐式确认 TX I(0)
            ("TX", blk0),                              # 非最近块重复
        ])
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["error"]["index"], 2)
        self.assertEqual(r["error"]["code"], "STALE_DUP")

    def test_r_block_wrong_sequence(self):
        r = run([
            ("TX", I(0, 1, "00A4040007")),
            ("RX", R(0)),                              # 期望 N(R)=1
        ])
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["error"]["index"], 1)
        self.assertEqual(r["error"]["code"], "R_SEQ")

    def test_r_ack_without_unacked(self):
        r = run([("RX", R(1))])
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["error"]["code"], "R_SEQ")

    def test_r_block_with_inf_rejected(self):
        blk = build_block(NAD_RX, 0x90, b"\x00").hex().upper()  # R块不得携带INF
        r = run([("TX", I(0, 1, "00A4040007")), ("RX", blk)])
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["error"]["index"], 1)
        self.assertEqual(r["error"]["code"], "PCB")

    def test_impossible_sequence_advancement(self):
        r = run([
            ("TX", I(0, 1, "00A4040007")),
            ("TX", I(1, 0, "1010")),                   # 未确认即推进
        ])
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["error"]["index"], 1)
        self.assertEqual(r["error"]["code"], "SEQ_JUMP")

    def test_first_block_bad_sequence(self):
        r = run([("TX", I(1, 0, "00A4040000"))])       # 首块 N(S) 必须为 0
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["error"]["code"], "SEQ_JUMP")

    def test_nad_direction_mismatch(self):
        r = run([
            ("TX", I(0, 0, "00A4040000")),
            ("RX", I(0, 0, "9000", nad=0x34)),         # NAD 与方向映射不符
        ])
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["error"]["index"], 1)
        self.assertEqual(r["error"]["code"], "NAD")

    def test_retransmission_with_different_content(self):
        r = run([
            ("TX", I(0, 0, "00A4040000")),
            ("TX", I(0, 0, "00A4040001")),             # 同序号不同内容
        ])
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["error"]["index"], 1)
        self.assertEqual(r["error"]["code"], "SEQ_CONTENT")

    def test_first_fault_is_stable(self):
        # 首错之后的块不再影响定位
        bad_lrc = I(0, 0, "00A4040000")[:-2] + "00"
        r = run([
            ("TX", bad_lrc),                           # 块0 LRC 错
            ("TX", I(1, 0, "00A4040000")),             # 块1 序号亦错
        ])
        self.assertEqual(r["error"]["index"], 0)
        self.assertEqual(r["error"]["code"], "LRC")
        self.assertEqual(len(r["steps"]), 0)


class TestRoundtripPairs(unittest.TestCase):
    """命令—应答往返证据：链边界配对、未应答、无法归属、控制块穿插、重传一次。"""

    def rt(self, blocks):
        r = run(blocks)
        self.assertEqual(r["verdict"], "PASS", r["error"])
        return r["roundtrips"]

    def test_simple_command_response_pair_with_indices(self):
        rt = self.rt([
            ("TX", I(0, 0, "00A4040000")),          # 块0 命令
            ("RX", I(0, 0, "9000", nad=NAD_RX)),    # 块1 应答
        ])
        self.assertEqual(rt["command_count"], 1)
        self.assertEqual(rt["answered_count"], 1)
        self.assertIsNone(rt["orphan_response"])
        (p,) = rt["pairs"]
        self.assertEqual(p["status"], "answered")
        self.assertEqual(p["command"]["apdu"], "00A4040000")
        self.assertEqual((p["command"]["first_index"], p["command"]["last_index"]), (0, 0))
        self.assertEqual(p["response"]["apdu"], "9000")
        self.assertEqual((p["response"]["first_index"], p["response"]["last_index"]), (1, 1))
        self.assertEqual(p["between_controls"], [])

    def test_chained_command_boundaries_and_controls_between(self):
        rt = self.rt([
            ("TX", I(0, 1, "00A4040007")),          # 块0 链式段
            ("RX", R(1)),                            # 块1 R(ACK)：命令未完成
            ("TX", I(1, 0, "A0000000031010")),       # 块2 命令完成
            ("RX", S(0x03, False, "05", nad=NAD_RX)),  # 块3 WTX 请求
            ("TX", S(0x03, True, "05", nad=NAD_TX)),   # 块4 WTX 应答
            ("RX", I(0, 0, "6110", nad=NAD_RX)),     # 块5 读卡器应答
            ("TX", R(1, nad=NAD_TX)),                # 块6 R(ACK)
        ])
        (p,) = rt["pairs"]
        self.assertEqual(p["status"], "answered")
        # 链式命令首块#0、末块#2
        self.assertEqual((p["command"]["first_index"], p["command"]["last_index"]), (0, 2))
        # 应答首末块#5
        self.assertEqual((p["response"]["first_index"], p["response"]["last_index"]), (5, 5))
        # 命令结束(#2)到应答开始(#5)之间穿插：WTX 请求#3、应答#4；
        # 命令链内的 R(ACK)#1 与应答之后的 R(ACK)#6 均不在区间内。
        self.assertEqual([c["index"] for c in p["between_controls"]], [3, 4])
        self.assertTrue(all(c["detail"].startswith("S(WTX)") for c in p["between_controls"]))

    def test_ifs_roundtrip_between_apdus_does_not_change_pairing(self):
        rt = self.rt([
            ("RX", S(0x01, False, "40", nad=NAD_RX)),  # 块0 IFS 请求
            ("TX", S(0x01, True, "40", nad=NAD_TX)),   # 块1 IFS 应答
            ("TX", I(0, 0, "00A4040000")),             # 块2 命令
            ("RX", I(0, 0, "9000", nad=NAD_RX)),       # 块3 应答
        ])
        (p,) = rt["pairs"]
        self.assertEqual(p["status"], "answered")
        # IFS 往返在命令开始之前，不属于命令—应答间隙
        self.assertEqual(p["between_controls"], [])

    def test_unanswered_when_next_command_starts_first(self):
        rt = self.rt([
            ("TX", I(0, 0, "00A4040000")),          # 块0 命令1
            ("RX", R(1)),                            # 块1 R(ACK) 仅确认收讫，无应答APDU
            ("TX", I(1, 0, "00B0000000")),          # 块2 命令2 先开始 → 命令1未应答
            ("RX", I(0, 0, "9000", nad=NAD_RX)),    # 块3 属于命令2窗口
            ("TX", R(1, nad=NAD_TX)),               # 块4
        ])
        self.assertEqual(rt["command_count"], 2)
        self.assertEqual(rt["answered_count"], 1)
        self.assertEqual(rt["unanswered_count"], 1)
        self.assertIsNone(rt["orphan_response"])
        p0, p1 = rt["pairs"]
        self.assertEqual(p0["status"], "unanswered")
        self.assertIsNone(p0["response"])
        # 收讫确认 R(ACK) 穿插在命令1之后，不能当作应答
        self.assertEqual([c["index"] for c in p0["between_controls"]], [1])
        self.assertEqual(p1["status"], "answered")
        self.assertEqual(p1["command"]["apdu"], "00B0000000")
        self.assertEqual(p1["response"]["apdu"], "9000")

    def test_two_consecutive_reader_apdus_first_is_orphan_and_not_borrowed(self):
        rt = self.rt([
            ("TX", I(0, 0, "00A4040000")),          # 块0 命令1
            ("RX", I(0, 0, "6100", nad=NAD_RX)),    # 块1 应答1（隐式确认命令1）
            ("TX", R(1, nad=NAD_TX)),               # 块2 R(ACK) 确认应答1
            ("RX", I(1, 0, "0090", nad=NAD_RX)),    # 块3 又一个读卡器 APDU（无对应命令）
            ("TX", I(1, 0, "00B0000000")),          # 块4 命令2（隐式确认块3）
            ("RX", I(0, 0, "9000", nad=NAD_RX)),    # 块5 本可应答命令2，但#3堵塞
            ("TX", R(1, nad=NAD_TX)),               # 块6
        ])
        # 命令1已应答（#1）；#3 无法归属；命令2窗口的队首是#3（不在窗口）→ 未应答，
        # 且 #5 不得被借给命令2。
        self.assertEqual(rt["answered_count"], 1)
        self.assertEqual(rt["unanswered_count"], 1)
        orphan = rt["orphan_response"]
        self.assertIsNotNone(orphan)
        self.assertEqual(orphan["apdu"], "0090")
        self.assertEqual((orphan["first_index"], orphan["last_index"]), (3, 3))
        self.assertEqual(orphan["extra_count"], 2)
        p1 = rt["pairs"][1]
        self.assertEqual(p1["status"], "unanswered")
        self.assertIsNone(p1["response"])

    def test_reader_sends_apdu_first_is_orphan(self):
        rt = self.rt([
            ("RX", I(0, 0, "6E00", nad=NAD_RX)),    # 块0 读卡器先发
            ("TX", I(0, 0, "00A4040000")),          # 块1 命令
            ("RX", I(1, 0, "9000", nad=NAD_RX)),    # 块2
            ("TX", R(0, nad=NAD_TX)),               # 块3
        ])
        orphan = rt["orphan_response"]
        self.assertIsNotNone(orphan)
        self.assertEqual(orphan["apdu"], "6E00")
        self.assertEqual((orphan["first_index"], orphan["last_index"]), (0, 0))
        self.assertIn("先发出", orphan["reason"])
        # 队首#0 堵塞，命令对其窗口内的#2不可借用 → 命令未应答
        self.assertEqual(rt["unanswered_count"], 1)

    def test_legal_retransmission_contributes_single_apdu_and_pair(self):
        dup = I(0, 0, "9000", nad=NAD_RX)
        rt = self.rt([
            ("TX", I(0, 0, "00A4040000")),          # 块0 命令
            ("RX", dup),                            # 块1 应答
            ("RX", dup),                            # 块2 合法重传：不产生第二个 APDU
            ("TX", R(1, nad=NAD_TX)),               # 块3
        ])
        self.assertEqual(rt["command_count"], 1)
        self.assertEqual(rt["answered_count"], 1)
        self.assertIsNone(rt["orphan_response"])
        (p,) = rt["pairs"]
        self.assertEqual(p["response"]["apdu"], "9000")
        # 重传步骤不是边界；应答首末块仍指向真正完成的块#1
        self.assertEqual((p["response"]["first_index"], p["response"]["last_index"]), (1, 1))

    def test_final_unanswered_command(self):
        rt = self.rt([
            ("TX", I(0, 0, "00A4040000")),          # 命令后捕获结束，无应答
        ])
        self.assertEqual(rt["answered_count"], 0)
        self.assertEqual(rt["unanswered_count"], 1)
        (p,) = rt["pairs"]
        self.assertEqual(p["status"], "unanswered")
        self.assertIsNone(p["response"])
        self.assertIsNone(rt["orphan_response"])

    def test_build_roundtrips_is_read_only_over_frozen_steps(self):
        r = run([
            ("TX", I(0, 0, "00A4040000")),
            ("RX", I(0, 0, "9000", nad=NAD_RX)),
        ])
        # 以相同 steps/apdus 重算必须得到一致证据（冻结可复算）
        again = build_roundtrips(r["steps"], r["apdus"])
        self.assertEqual(again, r["roundtrips"])


if __name__ == "__main__":
    unittest.main()
