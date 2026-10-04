"""往返证据：在冻结裁决结果之上，按已确认的 I 块链边界派生命令—应答对。

纯派生、只读：输入 Engine.run() 的冻结结果（steps/apdus），不重新裁决任何块，
不改变提交、冻结重放与逐块裁决结果。配对规则：

- 命令＝TX 方向由“新接受”I 块（链式段/完成段，重传段不贡献）围成的完整 APDU；
  合法重传只可能贡献一次 APDU，首末块序号取自实际参与组装的 I 块；
- 应答＝RX 方向同理。应答只能归属“命令结束之后、下一条命令首块之前”这一窗口内
  完成且尚未配对的命令；窗口内的 WTX/IFS 往返与 R 块只作穿插证据，不改变配对；
- 命令窗口关闭（下一条命令首块开始）仍无应答，或直至捕获结束无应答 → 未应答；
- 读卡器先发 APDU、一条命令已有应答后又连续出现 APDU、或应答链跨下一条命令
  边界才完成 → 该读卡器 APDU 无法归属，稳定保留在 unassigned 中并标出首个，
  绝不借给后续命令。
"""

from __future__ import annotations

# 促成 APDU 组装的 I 块动作（retransmission 不在其列）
_CHAIN_ACTIONS = ("chain-segment", "apdu-complete")

# 无法归属原因 → 稳定说明
ORPHAN_MESSAGES = {
    "READER_FIRST": "读卡器在任何维护站命令开始前先发出 APDU，无法归属",
    "EXTRA_RESPONSE": "连续出现的多余读卡器 APDU：该命令已有应答，无法归属且不借给后续命令",
    "LATE_RESPONSE": "应答链在下一条维护站命令开始后才完成，不能归属原命令，亦不借给后续命令",
    "OVERLAP": "读卡器 APDU 链与命令链边界重叠，无法归属到任何命令",
}


def _apdu_spans(result):
    """从逐步裁决中提取双向完整 APDU 及其首末原始块序号。

    仅统计 chain-segment/apdu-complete 步骤：retransmission 是最近未确认块的
    合法重复，不重复开启或推进链。完成顺序与 result["apdus"][d] 严格一致，
    按序取回 APDU 十六进制原文。
    """
    spans = {"TX": [], "RX": []}
    chain_start = {"TX": None, "RX": None}
    issued = {"TX": 0, "RX": 0}
    for step in result.get("steps", []):
        if step.get("kind") != "I":
            continue
        action = step.get("action")
        if action not in _CHAIN_ACTIONS:
            continue
        d = step["direction"]
        if chain_start[d] is None:
            chain_start[d] = step["index"]
        if action == "apdu-complete":
            apdu = result["apdus"][d][issued[d]]
            issued[d] += 1
            spans[d].append({
                "apdu": apdu,
                "first_index": chain_start[d],
                "last_index": step["index"],
            })
            chain_start[d] = None
    return spans


def _control_label(step):
    """R/S 控制块的紧凑人类可读标签。"""
    kind = step["kind"]
    if kind == "R":
        names = {0: "ACK", 1: "NAK-EDC", 2: "NAK-OTHER"}
        return f"R({names.get(step.get('rcode'), '?')}) N(R)={step.get('nr')}"
    if kind == "S":
        return f"S({step.get('stype')}){'应答' if step.get('sresp') else '请求'}"
    return kind


def _between_controls(result, command_last, response_first):
    """命令结束块与应答首块之间严格穿插的 R/S 控制块。"""
    out = []
    for step in result.get("steps", []):
        idx = step["index"]
        if not (command_last < idx < response_first):
            continue
        if step.get("kind") not in ("R", "S"):
            continue
        out.append({
            "index": idx,
            "direction": step["direction"],
            "kind": step["kind"],
            "label": _control_label(step),
            "pcb": step.get("pcb"),
            "raw": step.get("raw"),
            "action": step.get("action"),
        })
    return out


def _apdu_view(span):
    return {
        "apdu": span["apdu"],
        "first_index": span["first_index"],
        "last_index": span["last_index"],
    }


def _orphan_view(span, reason, first):
    return {
        **_apdu_view(span),
        "reason": reason,
        "message": ORPHAN_MESSAGES[reason],
        "first": first,
    }


def build_roundtrips(result):
    """对一份 PASS 冻结裁决结果派生往返证据。

    返回 {"pairs": [...], "unassigned": [...], "first_unassignable": ...,
    "summary": {...}}；非 PASS 结果不生成，由调用方先行拦截。
    """
    spans = _apdu_spans(result)
    commands = spans["TX"]
    responses = spans["RX"]
    n = len(commands)
    paired = [None] * n

    # 应答归属：找“应答首块之前最近结束的命令”，再校验应答在下一条命令
    # 首块之前完成且该命令尚未配对。任一不满足即无法归属。
    unassigned = []

    def add_orphan(span, reason):
        unassigned.append(_orphan_view(span, reason, len(unassigned) == 0))

    for resp in responses:
        owner = -1
        for i in range(n - 1, -1, -1):
            if commands[i]["last_index"] < resp["first_index"]:
                owner = i
                break
        if owner < 0:
            if not commands or resp["first_index"] < commands[0]["first_index"]:
                add_orphan(resp, "READER_FIRST")
            else:
                add_orphan(resp, "OVERLAP")
            continue
        if owner + 1 < n and resp["last_index"] >= commands[owner + 1]["first_index"]:
            add_orphan(resp, "LATE_RESPONSE")
            continue
        if paired[owner] is not None:
            add_orphan(resp, "EXTRA_RESPONSE")
            continue
        paired[owner] = resp

    pairs = []
    answered = 0
    for i, cmd in enumerate(commands):
        resp = paired[i]
        if resp is None:
            if i + 1 < n:
                reason = "NEXT_COMMAND"
                message = (
                    "读卡器在下一条维护站命令"
                    f"（首块#{commands[i + 1]['first_index']}）开始前未完成应答"
                )
            else:
                reason = "CAPTURE_END"
                message = "直至捕获结束，读卡器未给出完整应答 APDU"
            pair = {
                "index": i,
                "status": "unanswered",
                "reason": reason,
                "message": message,
                "command": _apdu_view(cmd),
                "response": None,
                "between": [],
            }
        else:
            answered += 1
            pair = {
                "index": i,
                "status": "answered",
                "reason": None,
                "message": None,
                "command": _apdu_view(cmd),
                "response": _apdu_view(resp),
                "between": _between_controls(
                    result, cmd["last_index"], resp["first_index"]
                ),
            }
        pairs.append(pair)

    first_unassignable = None
    if unassigned:
        o = unassigned[0]
        first_unassignable = {
            "apdu": o["apdu"],
            "first_index": o["first_index"],
            "last_index": o["last_index"],
            "reason": o["reason"],
            "message": o["message"],
        }

    return {
        "pairs": pairs,
        "unassigned": unassigned,
        "first_unassignable": first_unassignable,
        "summary": {
            "commands": n,
            "answered": answered,
            "unanswered": n - answered,
            "unassignable": len(unassigned),
        },
    }
