"""冻结审计存储：同一审计标识的首次提交被冻结。

- 相同标识 + 相同捕获（规范化后逐块一致）→ 返回原冻结结果；
- 相同标识 + 任一块改动 → 冲突，原结果保留且仍可读取；
- 可选 JSON 文件持久化（STORE_PATH），缺省纯内存。
"""

from __future__ import annotations

import json
import os
import re
import threading

_WS_RE = re.compile(r"\s+")


def normalize_hex(h: str) -> str:
    """规范化十六进制串：去空白、统一大写；可解码则按字节规范化。"""
    s = _WS_RE.sub("", h)
    try:
        return bytes.fromhex(s).hex().upper()
    except ValueError:
        return s.upper()


def fingerprint(blocks) -> str:
    """捕获指纹：规范化后的 (方向, 块) 序列，逐块敏感。"""
    return json.dumps(
        [[d, normalize_hex(h)] for d, h in blocks],
        ensure_ascii=False,
        separators=(",", ":"),
    )


class AuditStore:
    def __init__(self, path: str | None = None):
        self._lock = threading.Lock()
        self._path = path or None
        self._items: dict = {}
        if self._path and os.path.exists(self._path):
            with open(self._path, "r", encoding="utf-8") as f:
                self._items = json.load(f)

    def _save(self):
        if not self._path:
            return
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._items, f, ensure_ascii=False)
        os.replace(tmp, self._path)

    def submit(self, audit_id: str, blocks, result: dict):
        """提交捕获。返回 (result, replayed, conflict)。"""
        fp = fingerprint(blocks)
        with self._lock:
            existing = self._items.get(audit_id)
            if existing is not None:
                if existing["fingerprint"] == fp:
                    return existing["result"], True, False
                return existing["result"], False, True
            self._items[audit_id] = {"fingerprint": fp, "result": result}
            self._save()
            return result, False, False

    def get(self, audit_id: str):
        with self._lock:
            item = self._items.get(audit_id)
            return None if item is None else item["result"]

    def list(self):
        with self._lock:
            return [
                {
                    "audit_id": aid,
                    "verdict": item["result"].get("verdict"),
                    "block_count": item["result"].get("block_count"),
                    "created_at": item["result"].get("created_at"),
                }
                for aid, item in self._items.items()
            ]

    def __len__(self):
        with self._lock:
            return len(self._items)
