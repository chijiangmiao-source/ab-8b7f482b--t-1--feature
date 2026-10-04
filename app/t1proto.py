"""ISO/IEC 7816-3 T=1 块协议复核引擎。

对捕获的带方向原始块（NAD/PCB/LEN/INF/LRC）按顺序重放，校验 NAD、PCB、
长度与 LRC，维护双向发送序号、未确认块与等待扩展状态，处理：
  - I 块链式组装（M 位）与完整 APDU 输出；
  - R 块确认（ACK）或错误重传请求（NAK）；
  - S(IFS/WTX) 请求及对应应答的严格配对。

任一协议违规立即抛出 BlockFailure，由 run() 稳定定位首个违规原始块。
"""

from __future__ import annotations

MAX_BLOCKS = 64

DIRECTIONS = ("TX", "RX")
PEER = {"TX": "RX", "RX": "TX"}
DIR_LABEL = {"TX": "站→读卡器", "RX": "读卡器→站"}

# R 块错误码（PCB 低 4 位）
R_CODES = {0x0: "ACK", 0x1: "NAK-EDC", 0x2: "NAK-OTHER"}
# S 块类型（PCB 低 5 位）
S_TYPES = {0x00: "RESYNCH", 0x01: "IFS", 0x02: "ABORT", 0x03: "WTX"}

# 各传输方向上 INF 的初始上限（接收方 IFS）：
# TX 方向发往读卡器（IFSC 缺省 32），RX 方向发往维护站（IFSD 缺省 254）。
DEFAULT_IFS_LIMIT = {"TX": 32, "RX": 254}


class BlockFailure(Exception):
    """单个原始块引发的协议违规，携带稳定错误码。"""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def nibble_swap(nad: int) -> int:
    """交换 NAD 的源/目的地址半字节，得到对向应使用的 NAD。"""
    return ((nad & 0x0F) << 4) | ((nad >> 4) & 0x0F)


def build_block(nad: int, pcb: int, inf: bytes = b"") -> bytes:
    """构造合法 T=1 块（自动补 LEN 与 LRC），供测试与冒烟复用。"""
    body = bytes([nad, pcb, len(inf)]) + bytes(inf)
    lrc = 0
    for b in body:
        lrc ^= b
    return body + bytes([lrc])


class Engine:
    """T=1 捕获重放状态机。"""

    def __init__(self):
        self.next_seq = {"TX": 0, "RX": 0}        # 各方向下一新 I 块应携带的 N(S)
        self.unacked = {"TX": None, "RX": None}   # 各方向最近未确认 I 块
        self.chaining = {"TX": bytearray(), "RX": bytearray()}  # 链式组装缓冲
        self.apdus = {"TX": [], "RX": []}         # 已完成的完整 APDU
        self.ifs_limit = dict(DEFAULT_IFS_LIMIT)  # 各方向 INF 上限
        self.pending_s = None                     # 等待中的 S(IFS/WTX) 请求
        self.expected_nad = {}                    # 方向 -> 期望 NAD
        self.accepted_i = {"TX": 0, "RX": 0}      # 各方向已接受的新 I 块计数
        self.steps = []

    # ------------------------------------------------------------------ #
    # 顶层入口
    # ------------------------------------------------------------------ #
    def run(self, blocks):
        """按捕获顺序处理 [(direction, hexstr), ...]，返回冻结裁决结果。"""
        for i, (direction, raw_hex) in enumerate(blocks):
            try:
                self.process_block(i, direction, raw_hex)
            except BlockFailure as f:
                return self._result("FAIL", {
                    "index": i,
                    "direction": direction,
                    "raw": raw_hex,
                    "code": f.code,
                    "message": f.message,
                })
        if self.pending_s is not None:
            p = self.pending_s
            return self._result("FAIL", {
                "index": p["index"],
                "direction": p["dir"],
                "raw": p["raw"],
                "code": "S_UNANSWERED",
                "message": f"S({p['stype']})请求直至捕获结束未获应答",
            })
        return self._result("PASS", None)

    def _result(self, verdict, error):
        return {
            "verdict": verdict,
            "error": error,
            "steps": self.steps,
            "apdus": {d: [a.hex().upper() for a in self.apdus[d]] for d in DIRECTIONS},
            "final_state": self.snapshot(),
        }

    def snapshot(self):
        """当前状态快照：双向序号、未确认块、链式缓冲、等待扩展状态。"""
        return {
            "next_seq": dict(self.next_seq),
            "unacked": {
                d: (None if self.unacked[d] is None else {
                    "seq": self.unacked[d]["seq"],
                    "index": self.unacked[d]["index"],
                }) for d in DIRECTIONS
            },
            "chaining_len": {d: len(self.chaining[d]) for d in DIRECTIONS},
            "apdu_count": {d: len(self.apdus[d]) for d in DIRECTIONS},
            "ifs_limit": dict(self.ifs_limit),
            "waiting_extension": (None if self.pending_s is None else {
                "type": self.pending_s["stype"],
                "dir": self.pending_s["dir"],
                "inf": self.pending_s["inf"].hex().upper(),
                "since": self.pending_s["index"],
            }),
        }

    # ------------------------------------------------------------------ #
    # 单块处理
    # ------------------------------------------------------------------ #
    def process_block(self, i, direction, raw_hex):
        if direction not in DIRECTIONS:
            raise BlockFailure("BAD_DIRECTION", f"方向非法：{direction!r}")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError:
            raise BlockFailure("BAD_HEX", "无效十六进制串")
        if len(raw) < 4:
            raise BlockFailure("SHORT", f"块长度过短：{len(raw)}字节（至少4字节）")

        nad, pcb, length = raw[0], raw[1], raw[2]
        if len(raw) != 3 + length + 1:
            raise BlockFailure(
                "LENGTH",
                f"LEN={length}与实际INF长度{len(raw) - 4}不一致",
            )
        inf = raw[3:3 + length]
        lrc = raw[-1]
        calc = 0
        for b in raw[:-1]:
            calc ^= b
        if calc != lrc:
            raise BlockFailure("LRC", f"LRC校验失败：期望{calc:02X}，实际{lrc:02X}")
        if length > self.ifs_limit[direction]:
            raise BlockFailure(
                "INF_RANGE",
                f"INF长度{length}越界：超出该方向接收方IFS={self.ifs_limit[direction]}",
            )
        if nad & 0x88:
            raise BlockFailure("NAD", f"NAD=0x{nad:02X}保留位(b8/b4)非法")
        if direction in self.expected_nad:
            if nad != self.expected_nad[direction]:
                raise BlockFailure(
                    "NAD",
                    f"NAD=0x{nad:02X}与已建立方向映射不一致："
                    f"期望0x{self.expected_nad[direction]:02X}",
                )
        else:
            self.expected_nad[direction] = nad
            self.expected_nad[PEER[direction]] = nibble_swap(nad)

        kind, info = self._decode_pcb(pcb)

        step = {
            "index": i,
            "direction": direction,
            "raw": raw.hex().upper(),
            "nad": f"{nad:02X}",
            "pcb": f"{pcb:02X}",
            "len": length,
            "inf": inf.hex().upper(),
            "lrc": f"{lrc:02X}",
            "kind": kind,
            "action": None,
            "basis": None,
            "notes": [],
        }
        step.update(info)

        if kind == "R" and length != 0:
            raise BlockFailure("PCB", f"R块不允许携带INF（LEN={length}）")
        # 等待扩展状态：S 请求未配对前只允许 S 块进入配对逻辑
        if self.pending_s is not None and kind != "S":
            p = self.pending_s
            raise BlockFailure(
                "S_WAIT",
                f"非法等待扩展：等待S({p['stype']})应答期间收到{kind}块",
            )

        if kind == "I":
            self._handle_i(step, i, direction, info["ns"], info["more"], inf)
        elif kind == "R":
            self._handle_r(step, i, direction, info["nr"], info["rcode"])
        else:
            self._handle_s(step, i, direction, info["stype"], info["sresp"], inf, step["raw"])

        step["state"] = self.snapshot()
        self.steps.append(step)

    # ------------------------------------------------------------------ #
    # PCB 解码
    # ------------------------------------------------------------------ #
    @staticmethod
    def _decode_pcb(pcb):
        if pcb & 0x80 == 0:
            if pcb & 0x1F:
                raise BlockFailure("PCB", f"I块PCB=0x{pcb:02X}保留位非法")
            return "I", {"ns": (pcb >> 6) & 1, "more": (pcb >> 5) & 1}
        if (pcb & 0xE0) == 0x80:
            code = pcb & 0x0F
            if code not in R_CODES:
                raise BlockFailure("PCB", f"R块错误码保留：0x{code:X}")
            return "R", {"nr": (pcb >> 4) & 1, "rcode": code}
        if (pcb & 0xC0) == 0xC0:
            stype = pcb & 0x1F
            if stype not in S_TYPES:
                raise BlockFailure("PCB", f"S块类型保留：0x{stype:02X}")
            return "S", {"stype": S_TYPES[stype], "sresp": bool(pcb & 0x20)}
        raise BlockFailure("PCB", f"PCB=0x{pcb:02X}无法识别")

    # ------------------------------------------------------------------ #
    # I 块
    # ------------------------------------------------------------------ #
    def _handle_i(self, step, i, d, ns, more, inf):
        u = self.unacked[d]
        if u is not None and ns == u["seq"]:
            if inf == u["inf"] and more == u["more"]:
                step["action"] = "retransmission"
                step["basis"] = (
                    f"最近未确认I块(N(S)={ns}, 块#{u['index']})的合法重复；"
                    "不重复拼接APDU、不推进序号"
                )
                return
            raise BlockFailure(
                "SEQ_CONTENT",
                f"重传块内容与最近未确认块(块#{u['index']})不一致",
            )
        if ns != self.next_seq[d]:
            if u is None and self.accepted_i[d] > 0:
                raise BlockFailure(
                    "STALE_DUP",
                    f"非最近块重复：N(S)={ns}的I块此前已被确认",
                )
            raise BlockFailure(
                "SEQ_JUMP",
                f"不可能序号推进：期望N(S)={self.next_seq[d]}，实际N(S)={ns}",
            )
        if u is not None:
            raise BlockFailure(
                "SEQ_JUMP",
                f"不可能序号推进：上一I块(N(S)={u['seq']}, 块#{u['index']})"
                "未确认即推进序号",
            )
        peer = PEER[d]
        if self.unacked[peer] is not None:
            step["notes"].append(
                f"隐式确认对向未确认I块(N(S)={self.unacked[peer]['seq']}, "
                f"块#{self.unacked[peer]['index']})"
            )
            self.unacked[peer] = None
        self.chaining[d] += inf
        self.unacked[d] = {"seq": ns, "more": more, "inf": inf, "index": i}
        self.next_seq[d] ^= 1
        self.accepted_i[d] += 1
        if more:
            step["action"] = "chain-segment"
            step["notes"].append(
                f"链式段已缓存，累计{len(self.chaining[d])}字节，等待后续段"
            )
        else:
            apdu = bytes(self.chaining[d])
            self.apdus[d].append(apdu)
            self.chaining[d] = bytearray()
            step["action"] = "apdu-complete"
            step["notes"].append(f"APDU组装完成，共{len(apdu)}字节")

    # ------------------------------------------------------------------ #
    # R 块
    # ------------------------------------------------------------------ #
    def _handle_r(self, step, i, d, nr, rcode):
        peer = PEER[d]
        u = self.unacked[peer]
        if rcode == 0:  # R(ACK)
            if u is None:
                raise BlockFailure("R_SEQ", "R(ACK)无对应的未确认I块")
            if nr != self.next_seq[peer]:
                raise BlockFailure(
                    "R_SEQ",
                    f"R(ACK)序号错误：期望N(R)={self.next_seq[peer]}，实际N(R)={nr}",
                )
            self.unacked[peer] = None
            step["action"] = "ack"
            step["notes"].append(f"确认对向I块(N(S)={u['seq']}, 块#{u['index']})")
        else:  # R(NAK-*)：请求重传对向最近未确认块
            if u is None:
                raise BlockFailure("R_SEQ", "R(NAK)无对应的未确认I块")
            if nr != u["seq"]:
                raise BlockFailure(
                    "R_SEQ",
                    f"R(NAK)序号错误：应指向最近未确认块N(S)={u['seq']}，实际N(R)={nr}",
                )
            step["action"] = "nak"
            step["basis"] = (
                f"R({R_CODES[rcode]})要求重传对向最近未确认I块"
                f"(N(S)={u['seq']}, 块#{u['index']})"
            )

    # ------------------------------------------------------------------ #
    # S 块
    # ------------------------------------------------------------------ #
    def _handle_s(self, step, i, d, stype, sresp, inf, raw_hex):
        p = self.pending_s
        if p is not None:
            problems = []
            if d == p["dir"]:
                problems.append("方向不符")
            if not sresp:
                problems.append("仍为请求而非应答")
            if stype != p["stype"]:
                problems.append(f"应答类型不符(期望{p['stype']})")
            if inf != p["inf"]:
                problems.append("参数/倍率不符")
            if problems:
                raise BlockFailure(
                    "S_RESP",
                    f"非法等待扩展应答：{'、'.join(problems)}",
                )
            self.pending_s = None
            if p["stype"] == "IFS":
                self.ifs_limit[PEER[p["dir"]]] = p["inf"][0]
                step["notes"].append(
                    f"IFS协商生效：发往{p['dir']}方向的INF上限={p['inf'][0]}"
                )
            else:
                step["notes"].append("WTX等待扩展确认，可继续处理后续块")
            step["action"] = f"{stype.lower()}-response"
            return
        if sresp:
            raise BlockFailure("S_RESP", f"无对应请求的S({stype})应答")
        if stype not in ("IFS", "WTX"):
            raise BlockFailure("S_TYPE", f"暂不支持的S块类型：{stype}")
        if len(inf) != 1:
            raise BlockFailure("INF", f"S({stype})的INF必须为1字节")
        if not 1 <= inf[0] <= 254:
            raise BlockFailure(
                "INF",
                f"S({stype})参数越界：0x{inf[0]:02X}（合法范围0x01-0xFE）",
            )
        self.pending_s = {"stype": stype, "dir": d, "inf": inf, "index": i, "raw": raw_hex}
        step["action"] = f"{stype.lower()}-request"
        step["notes"].append(f"S({stype})请求，等待对向匹配应答")
