# 机载维护站 · 隔离读卡器升级指令复核（T=1 捕获审计）

审查员填写审计标识，按捕获顺序录入不超过 64 条带方向的十六进制 T=1 原始块；
系统重放捕获并输出**冻结裁决**、**完整 APDU**、**逐步序号**、**重传依据**、**状态快照**
与**往返证据（命令—应答对）**。结果页可选择一个已冻结且裁决通过的审计读取往返证据。

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

冻结结果的新增字段只做只读增强：读取缺字段的旧冻结结果时，按其已冻结的
`steps`/`apdus` 现场补算 `roundtrips`，不写回存储，不改变裁决、步骤与原冻结时间。

## 往返证据（命令—应答对）

为避免只凭双向 APDU 拼接摘要把缺失或乱序应答误作完整升级交互，`roundtrips` 严格依据
引擎**已确认的 I 块链边界**（`chain-segment`/`apdu-complete` 步骤）配对：

- 逐对给出维护站命令与读卡器应答两侧 APDU，及各自**首末原始块序号**；
- 列出命令结束到应答开始之间穿插的 **R/S 控制块**（R(ACK/NAK)、S(WTX)/S(IFS) 往返），
  它们只作证据，**不改变配对**；
- 读卡器未在**下一条维护站命令开始前**完成应答 → 该命令标记 `unanswered`（未应答）；
- 连续两个读卡器 APDU、或读卡器在任何命令之前先发出 APDU → 稳定标出**首个无法归属**
  的读卡器 APDU（`orphan_response`，含首末块序号与原因），且**不借给后续命令**；
  乱序一旦出现，后续命令的应答窗口仍按 FIFO 判定，不会把窗口外 APDU 抓来凑对；
- **合法重传**步骤不是链边界，只贡献一次 APDU；
- 配对为纯只读重放：审计提交、冻结重放与原有逐块裁决结果（`verdict`/`steps`/`error`）保持不变。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 健康响应 `{"status":"ok",...}` |
| GET | `/` | 复核页面（经真实 API 读取结果） |
| POST | `/api/audits` | 提交 `{audit_id, blocks:[{direction,hex}]}` → 201 冻结 / 200 重放 / 409 冲突 / 400 校验失败 |
| GET | `/api/audits` | 已冻结审计列表 |
| GET | `/api/audits/{id}` | 读取冻结结果（404 未知） |

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
2. **构建检查**：`py_compile` 全部模块 + 导入检查；
3. **API/HTTP 冒烟**：真实启动服务（`VERIFY_PORT`，默认 18080），
   经 `/health`、页面、提交/重放/冲突/读取/404/上限 逐项检查。

执行完成后退出，**退出码 0=验收通过，非 0=失败**。

## 结构

```
app/t1proto.py    T=1 协议引擎（状态机 + 首错定位）
app/server.py     HTTP 服务（API + 页面 + 健康，PORT 可配）
app/store.py      冻结存储（指纹比对，可选 JSON 持久化）
app/static/index.html  复核页面
tests/            单元/集成测试
scripts/verify.sh 验收入口（可执行）
scripts/smoke.py  API/HTTP 冒烟
```
