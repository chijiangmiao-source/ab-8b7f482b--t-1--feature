"""API/HTTP 冒烟：对运行中的服务执行健康、页面、冻结、冲突、裁决定位检查。

用法：BASE_URL=http://127.0.0.1:18080 python3 scripts/smoke.py
退出码：0 全部通过；1 存在失败。
"""

import json
import os
import sys
import urllib.error
import urllib.request

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:18080").rstrip("/")
RUN_ID = f"smoke-{os.getpid()}"

FAILURES = []


def check(name, cond, detail=""):
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def req(method, path, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    r = urllib.request.Request(BASE_URL + path, data=data, method=method)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def blk(nad, pcb, inf=""):
    body = bytes([nad, pcb, len(bytes.fromhex(inf))]) + bytes.fromhex(inf)
    lrc = 0
    for b in body:
        lrc ^= b
    return (body + bytes([lrc])).hex().upper()


T, R = 0x12, 0x21
# I 块 PCB：N(S)<<6 | M<<5（0x20=N(S)0/M1，0x40=N(S)1/M0）
LEGAL = [
    {"direction": "TX", "hex": blk(T, 0x20, "00A4040007")},
    {"direction": "RX", "hex": blk(R, 0x90)},
    {"direction": "TX", "hex": blk(T, 0x40, "A0000000031010")},
    {"direction": "RX", "hex": blk(R, 0x00, "6F0584039000")},
    {"direction": "RX", "hex": blk(R, 0x00, "6F0584039000")},
    {"direction": "TX", "hex": blk(T, 0x90)},
]
WTX_BAD = [
    {"direction": "TX", "hex": blk(T, 0x00, "00A4040000")},
    {"direction": "RX", "hex": blk(R, 0xC3, "05")},
    {"direction": "TX", "hex": blk(T, 0x40, "00A4040000")},
]


def main():
    # 1. 健康响应
    st, body = req("GET", "/health")
    check("GET /health → 200 ok", st == 200 and body.get("status") == "ok", f"status={st} body={body}")

    # 2. 页面
    try:
        with urllib.request.urlopen(BASE_URL + "/", timeout=5) as resp:
            html = resp.read().decode()
            page_ok = resp.status == 200 and "冻结裁决" in html
    except Exception as e:
        page_ok, html = False, str(e)
    check("GET / → 复核页面", page_ok, html[:120] if not page_ok else "")

    # 3. 提交合法重传捕获 → PASS 冻结
    st, body = req("POST", "/api/audits", {"audit_id": RUN_ID, "blocks": LEGAL})
    ok = (st == 201 and body.get("verdict") == "PASS" and body.get("frozen") is True
          and body.get("apdus", {}).get("RX") == ["6F0584039000"])
    check("POST 合法重传捕获 → 201 PASS 且 APDU 未重复拼接", ok, f"status={st} body={body}")

    # 4. 相同标识 + 相同捕获 → 原冻结结果
    st2, body2 = req("POST", "/api/audits", {"audit_id": RUN_ID, "blocks": LEGAL})
    check("相同捕获重传 → 200 返回原冻结结果",
          st2 == 200 and body2.get("replayed") is True
          and body2.get("created_at") == body.get("created_at"),
          f"status={st2}")

    # 5. 改动任一块 → 409 冲突
    modified = [dict(b) for b in LEGAL]
    modified[3] = dict(modified[3], hex=blk(R, 0x00, "6F0584039001"))
    st3, body3 = req("POST", "/api/audits", {"audit_id": RUN_ID, "blocks": modified})
    check("改动任一块 → 409 冲突", st3 == 409 and body3.get("error") == "conflict", f"status={st3}")

    # 6. 原结果仍可读取
    st4, body4 = req("GET", f"/api/audits/{RUN_ID}")
    check("冲突后原冻结结果仍可读取",
          st4 == 200 and body4.get("verdict") == "PASS"
          and body4.get("apdus", {}).get("TX") == ["00A4040007A0000000031010"],
          f"status={st4}")

    # 7. 未知标识 → 404
    st5, _ = req("GET", "/api/audits/no-such-audit")
    check("未知审计标识 → 404", st5 == 404, f"status={st5}")

    # 8. 非法等待扩展 → FAIL 且定位首个违规块
    st6, body6 = req("POST", "/api/audits", {"audit_id": RUN_ID + "-wtx", "blocks": WTX_BAD})
    err = body6.get("error") or {}
    check("非法等待扩展 → FAIL 定位块#2 (S_WAIT)",
          st6 == 201 and body6.get("verdict") == "FAIL"
          and err.get("index") == 2 and err.get("code") == "S_WAIT",
          f"status={st6} error={err}")

    # 8b. 往返证据：合法重传捕获恰好 1 对，重传只贡献一次应答
    rt = body.get("roundtrips") or {}
    pairs = rt.get("pairs") or []
    pair_ok = (rt.get("command_count") == 1 and rt.get("answered_count") == 1
               and rt.get("unanswered_count") == 0 and rt.get("orphan_response") is None
               and len(pairs) == 1 and pairs[0].get("status") == "answered"
               and (pairs[0].get("response") or {}).get("apdu") == "6F0584039000"
               and (pairs[0].get("command") or {}).get("first_index") == 0
               and (pairs[0].get("command") or {}).get("last_index") == 2)
    check("往返证据：链式命令配单一应答，首末块序号正确，重传不重复",
          pair_ok, f"roundtrips={rt}")

    # 8c. 往返证据：命令无应答 → 未应答
    no_resp = [{"direction": "TX", "hex": blk(T, 0x00, "00A4040000")}]
    st8, body8 = req("POST", "/api/audits", {"audit_id": RUN_ID + "-noresp", "blocks": no_resp})
    rt8 = (body8 or {}).get("roundtrips") or {}
    check("往返证据：命令未获应答 → unanswered",
          st8 == 201 and rt8.get("unanswered_count") == 1
          and rt8.get("pairs", [{}])[0].get("status") == "unanswered"
          and rt8.get("pairs", [{}])[0].get("response") is None,
          f"status={st8} roundtrips={rt8}")

    # 8d. 往返证据：读卡器先发 APDU → 稳定标出首个无法归属 APDU
    reader_first = [{"direction": "RX", "hex": blk(R, 0x00, "6E00")}]
    st9, body9 = req("POST", "/api/audits", {"audit_id": RUN_ID + "-orphan", "blocks": reader_first})
    rt9 = (body9 or {}).get("roundtrips") or {}
    o = rt9.get("orphan_response") or {}
    check("往返证据：读卡器先发 → 首个无法归属 APDU 被标出",
          st9 == 201 and o.get("apdu") == "6E00"
          and o.get("first_index") == 0 and o.get("last_index") == 0,
          f"status={st9} roundtrips={rt9}")

    # 8e. 往返证据：WTX 往返穿插在两侧 APDU 之间，不改变配对
    wtx_ok = [
        {"direction": "TX", "hex": blk(T, 0x00, "00A4040000")},
        {"direction": "RX", "hex": blk(R, 0xC3, "05")},
        {"direction": "TX", "hex": blk(T, 0xE3, "05")},
        {"direction": "RX", "hex": blk(R, 0x00, "9000")},
    ]
    st10, body10 = req("POST", "/api/audits", {"audit_id": RUN_ID + "-wtxok", "blocks": wtx_ok})
    p10 = ((body10 or {}).get("roundtrips") or {}).get("pairs", [{}])[0]
    ctrls = [c.get("index") for c in (p10.get("between_controls") or [])]
    check("往返证据：WTX 往返列于命令—应答间隙且仍已应答",
          st10 == 201 and p10.get("status") == "answered" and ctrls == [1, 2],
          f"status={st10} pair={p10}")

    # 9. 超过 64 块 → 400
    st7, _ = req("POST", "/api/audits",
                 {"audit_id": RUN_ID + "-65", "blocks": [{"direction": "TX", "hex": blk(T, 0x00, "00")}] * 65})
    check("超过64块 → 400", st7 == 400, f"status={st7}")

    print()
    if FAILURES:
        print(f"SMOKE FAIL：{len(FAILURES)} 项未通过：{', '.join(FAILURES)}")
        return 1
    print("SMOKE OK：全部冒烟检查通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
