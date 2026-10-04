"""HTTP 服务：审计提交/读取 API、健康响应、静态页面。端口经 PORT 环境变量配置。"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

from .store import AuditStore
from .t1proto import DIRECTIONS, MAX_BLOCKS, Engine, build_roundtrips

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
AUDIT_ID_RE = re.compile(r"^[^\s/]{1,128}$")
MAX_BODY = 1 << 20  # 1 MiB


def with_roundtrips(result):
    """返回含往返证据的结果副本。

    新提交的结果已由引擎生成 roundtrips；功能上线前冻结的旧结果缺该字段，
    读取时按其已冻结的 steps/apdus 只读补算，不写回存储（冻结内容不变）。
    """
    if "roundtrips" in result:
        return result
    apdus = result.get("apdus") or {}
    enriched = dict(result)
    enriched["roundtrips"] = build_roundtrips(
        result.get("steps") or [],
        {d: apdus.get(d, []) for d in DIRECTIONS},
    )
    return enriched


def validate_payload(payload):
    """返回 (audit_id, pairs, error_message)。"""
    if not isinstance(payload, dict):
        return None, None, "请求体必须为JSON对象"
    audit_id = payload.get("audit_id")
    if not isinstance(audit_id, str) or not AUDIT_ID_RE.match(audit_id):
        return None, None, "审计标识非法：须为1-128个非空白且不含'/'的字符"
    blocks = payload.get("blocks")
    if not isinstance(blocks, list) or not 1 <= len(blocks) <= MAX_BLOCKS:
        return None, None, f"块数量须为1..{MAX_BLOCKS}"
    pairs = []
    for i, b in enumerate(blocks):
        if not isinstance(b, dict):
            return None, None, f"第{i}块须为对象{{direction, hex}}"
        d = b.get("direction")
        h = b.get("hex")
        if d not in DIRECTIONS:
            return None, None, f"第{i}块方向非法：须为{'/'.join(DIRECTIONS)}"
        if not isinstance(h, str):
            return None, None, f"第{i}块hex须为字符串"
        pairs.append((d, h))
    return audit_id, pairs, None


def make_handler(store, static_dir):
    class Handler(BaseHTTPRequestHandler):
        server_version = "T1Audit/1.0"

        # ---------------- 工具 ---------------- #
        def _json(self, code, obj):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):  # 静默访问日志
            pass

        # ---------------- GET ---------------- #
        def do_GET(self):
            path = urlparse(self.path).path
            if path in ("/", "/index.html"):
                return self._serve_page()
            if path == "/health":
                return self._json(200, {
                    "status": "ok",
                    "service": "t1-audit",
                    "audits": len(store),
                })
            if path == "/api/audits":
                return self._json(200, {"audits": store.list()})
            if path.startswith("/api/audits/"):
                audit_id = unquote(path[len("/api/audits/"):])
                result = store.get(audit_id)
                if result is None:
                    return self._json(404, {"error": "not_found", "audit_id": audit_id})
                return self._json(200, with_roundtrips(result))
            return self._json(404, {"error": "not_found"})

        def _serve_page(self):
            page = os.path.join(static_dir, "index.html")
            try:
                with open(page, "rb") as f:
                    body = f.read()
            except OSError:
                return self._json(500, {"error": "page_missing"})
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # ---------------- POST ---------------- #
        def do_POST(self):
            path = urlparse(self.path).path
            if path != "/api/audits":
                return self._json(404, {"error": "not_found"})
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_BODY:
                return self._json(400, {"error": "bad_request", "message": "请求体缺失或过大"})
            try:
                payload = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return self._json(400, {"error": "bad_request", "message": "JSON解析失败"})

            audit_id, pairs, err = validate_payload(payload)
            if err:
                return self._json(400, {"error": "bad_request", "message": err})

            outcome = Engine().run(pairs)
            result = {
                "audit_id": audit_id,
                "frozen": True,
                "block_count": len(pairs),
                "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                **outcome,
            }
            stored, replayed, conflict = store.submit(audit_id, pairs, result)
            if conflict:
                return self._json(409, {
                    "error": "conflict",
                    "audit_id": audit_id,
                    "message": "审计标识已冻结且捕获内容不一致，原冻结结果保持不变",
                })
            if replayed:
                return self._json(200, {**with_roundtrips(stored), "replayed": True})
            return self._json(201, stored)

    return Handler


def make_server(host, port, store=None, static_dir=STATIC_DIR):
    store = store if store is not None else AuditStore()
    return ThreadingHTTPServer((host, port), make_handler(store, static_dir))


def main():
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    store = AuditStore(os.environ.get("STORE_PATH") or None)
    httpd = make_server(host, port, store)
    print(f"t1-audit listening on {host}:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
