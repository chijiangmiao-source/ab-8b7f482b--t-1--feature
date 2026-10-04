# 机载维护站 · 隔离读卡器升级指令复核（T=1 捕获审计）

审查员填写审计标识，按捕获顺序录入不超过 64 条带方向的十六进制 T=1 原始块；
系统重放捕获并输出**冻结裁决**、**完整 APDU**、**逐步序号**、**重传依据**与**状态快照**。

## 协议规则（ISO/IEC 7816-3 T=1）

- 逐块校验 NAD（保留位 + 方向半字节互换映射）、PCB（保留位/类型）、LEN 与实际 INF 一致性、LRC；
- I 块：链式组装（M 位），双向独立发送序号 N(S)，逐方向维护最近未确认块；
- R 块：R(ACK) 确认对向未确认块（N(R) 须等于对向下一期望序号），R(NAK-EDC/OTHER) 要求重传；
- S 块：S(IFS)/S(WTX) 请求须由对向以同类型、同参数（IFS 值 / WTX 倍率）的应答配对，
  等待期间收到非 S 块即**非法等待扩展**；匹配的 WTX 往返后可继续处理后续块；
- 最近未确认 I 块的**合法重复**通过且不重复拼接 APDU；对向新 I 块隐式确认；
- LRC 错误、非最近块重复、错误 R 块序号、越界 INF（超出接收方 IFS，缺省 IFSC=32/IFSD=254）、
  错误 WTX 应答、不可能序号推进等，均**稳定定位首个违规原始块**（序号、方向、错误码、原文）。

## 冻结语义

- 提交即冻结：相同审计标识 + 相同捕获（规范化后逐块一致）→ 返回原冻结结果（200, `replayed`）；
- 相同标识 + 改动任一块 → 409 冲突，原结果保持可读取（`GET /api/audits/{id}`）。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 健康响应 `{"status":"ok",...}` |
| GET | `/` | 复核页面（经真实 API 读取结果） |
| POST | `/api/audits` | 提交 `{audit_id, blocks:[{direction,hex}]}` → 201 冻结 / 200 重放 / 409 冲突 / 400 校验失败 |
| GET | `/api/audits` | 已冻结审计列表 |
| GET | `/api/audits/{id}` | 读取冻结结果（404 未知） |
| GET | `/api/audits/{id}/roundtrips` | 只读派生的**往返证据**（仅 PASS；FAIL→400，未知→404），不改动冻结结果 |

### 往返证据（命令—应答对）

审查员选择一份**已冻结且通过**的审计后，系统在冻结裁决之上按**已确认的 I 块链边界**
（新接受 I 块围成的完整 APDU；合法重传不贡献）派生命令—应答对，逐对返回：

- `command`/`response`：两侧 APDU 十六进制及各自**首、末原始块序号**；
- `between`：命令结束块到应答首块之间严格穿插的 **R/S 控制块**（序号/方向/标签/原文）；
  WTX 或 IFS 往返、链路层 R(ACK) 可出现在此而不改变配对；
- 读卡器在**下一条维护站命令首块开始前**未完成应答时，该命令 `status="unanswered"`
  （`reason`：`NEXT_COMMAND`/`CAPTURE_END`）；
- 读卡器**先发 APDU**、连续出现第二个 APDU（`EXTRA_RESPONSE`）、或应答链跨下一条命令
  边界才完成（`LATE_RESPONSE`）时，该 APDU 进入 `unassigned` 并在 `first_unassignable`
  中**稳定标出首个**，绝不借给后续命令。

该派生不重新裁决任何块：提交、冻结重放（200 `replayed`）、冲突（409）与逐块裁决结果
（verdict/error/steps/apdus/final_state）均保持不变。

方向：`TX`=维护站→读卡器，`RX`=读卡器→维护站。块数 1..64。

## 运行

```bash
# 本地（Python ≥ 3.10，纯标准库，无第三方依赖）
PORT=8080 python3 -m app.server          # 端口经 PORT 配置
# 可选持久化：STORE_PATH=/data/audits.json

# Docker
docker compose up app                    # http://localhost:8080
```

## 验收（verify 入口）

```bash
docker compose run --rm verify           # 容器内：测试→构建检查→冒烟，完成后退出
# 或无 Docker 环境直接执行：
bash scripts/verify.sh
```

verify 依次执行：
1. **代码测试**：`python3 -m unittest discover -s tests -v`
   覆盖合法重传（不重复拼接 APDU）、非法等待扩展（方向/类型/倍率不符、等待期 I 块、
   无请求应答、请求未应答）、冻结审计（重放/冲突/原结果可读）及 LRC/序号/R 块/INF 定位；
   另覆盖往返配对（首末块序号、穿插 R/S、未应答、连续/抢先读卡器 APDU 稳定标出且不转借）；
2. **构建检查**：`py_compile` 全部模块 + 导入检查；
3. **API/HTTP 冒烟**：真实启动服务（`VERIFY_PORT`，默认 18080），
   经 `/health`、页面、提交/重放/冲突/读取/404/上限 逐项检查。

执行完成后退出，**退出码 0=验收通过，非 0=失败**。

## 结构

```
app/t1proto.py    T=1 协议引擎（状态机 + 首错定位）
app/roundtrip.py 往返证据派生（只读：命令—应答对/未应答/无法归属）
app/server.py     HTTP 服务（API + 页面 + 健康，PORT 可配）
app/store.py      冻结存储（指纹比对，可选 JSON 持久化）
app/static/index.html  复核页面
tests/            单元/集成测试
scripts/verify.sh 验收入口（可执行）
scripts/smoke.py  API/HTTP 冒烟
```
