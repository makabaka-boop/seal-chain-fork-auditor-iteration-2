# 证物封签哈希链审计服务（sealaudit）

离线工作站各自登记证物封签事件，回传批次的**上传顺序与真实封签顺序无关**。
本服务只依赖 `id / parentId` 构成的图与事件声明的摘要做核对——绝不信任数组顺序——
因此能发现仅按上传顺序比对哈希会漏掉的三类问题：

- **分叉（FORK）**：同一个前驱被多个子事件引用；
- **缺失前驱（MISSING_PARENT）**：`parentId` 指向批次内不存在的事件；
- **环（CYCLE）**：前驱关系闭合，没有可追溯的根；
- 以及根不唯一、根锚点非零、`prevDigest` 链接断裂、正文/签名字段篡改。

纯 Go 1.23 + 标准库 `net/http`，无任何第三方依赖。

> **跨馆交接（有限披露）**：部分证物正文不能向审计员披露时，使用
> `POST /audit/limited`：`payload` 写成显式 `null` 表示**未披露**。缺正文
> 不会被当作整链验真——见下文[有限披露审计](#有限披露审计-post-auditlimited)。
> 证物从一座馆转交另一座馆、两馆各自上传一批乱序事件时，使用
> `POST /audit/handoff` 同时核对两批：第二批的根锚点必须等于第一批图重建
> 得到的尾摘要——见下文[双批次交接审计](#双批次交接审计-post-audithandoff)。

## 目录结构

```
cmd/sealaudit/        main 入口（HTTP 服务、结构化日志、优雅退出、-healthcheck 自检）
internal/audit/       核心审计：摘要定义 + 与顺序无关的图/链核对
internal/httpapi/     请求解析、字段校验（422）、HTTP 处理器
Dockerfile            多阶段构建（golang:1.23 构建，distroless/static 运行）
docker-compose.yml    compose 运行，服务名 api，端口 8080
Makefile              build/test/cover/docker-* 等快捷目标
```

## 运行

```bash
make docker-up          # docker compose up -d --build
# 或本地：
go run ./cmd/sealaudit  # 默认监听 :8080，可用 SEAL_AUDIT_ADDR 或 -addr 覆盖
```

健康检查：`GET /healthz` → `200 {"status":"ok"}`。

## API

### `POST /audit`

请求体：

```json
{
  "events": [
    {
      "id": "evt-0",
      "parentId": "",
      "payload": "封签正文",
      "prevDigest": "0000…0000（64 个 0）",
      "digest": "<64 位小写十六进制 SHA-256>"
    }
  ]
}
```

- `events` 必须包含 **1 至 2000** 条事件；
- 每条事件**必须且只能**包含 `id`、`parentId`、`payload`、`prevDigest`、`digest`
  五个字段（出现未知字段 → 422）；
- `id` 非空且在批次内唯一；根事件的 `parentId` 为空字符串 `""`；
- `prevDigest`、`digest` 必须是 **64 位小写**十六进制（`[0-9a-f]`，大写/超长/非十六进制 → 422）；
- `payload` 必填（允许空字符串）；`id`/`payload` 按 UTF-8 字节计入长度前缀；
- 请求体必须是合法 UTF-8 的单一 JSON 值（尾随数据 → 422），上限 16 MiB。

#### 摘要的逐字节定义

对每条事件，按下列顺序拼接后计算 SHA-256，输出为 64 位小写十六进制：

1. **4 字节大端**：`id` 的 UTF-8 字节长度；
2. `id` 的 UTF-8 字节；
3. **32 字节原始** `prevDigest`（根事件为 32 个零字节）；
4. **4 字节大端**：`payload` 的 UTF-8 字节长度；
5. `payload` 的 UTF-8 字节。

```
| len(id) BE32 | id bytes | prevDigest[32 raw] | len(payload) BE32 | payload bytes |
```

> `parentId` **不**参与摘要。前驱关系的真实性由“子事件的 `prevDigest`
> 必须等于父事件声明的 `digest`”单独认证，因此改父引用与改正文可以被区分。

长度均以 **UTF-8 字节数**计（多字节字符占多个字节）。

### 核对规则（与输入顺序无关）

1. 恰好一个根（`parentId == ""`）；
2. 每个非根事件的 `parentId` 都能在批次内找到前驱；
3. 前驱图无环（三色 DFS，环上每个事件都报告一次）；
4. 每个前驱至多一个子事件（否则分叉）；
5. 根事件的 `prevDigest` 为全零；
6. 非根事件的 `prevDigest` 等于其前驱声明的 `digest`；
7. 用上面的字节定义重算每条事件的 `digest`，与声明值比对。

### 响应

**链结构或摘要异常（HTTP 200，审计结论而非请求错误）：**

```json
{
  "valid": false,
  "errors": [
    {"code": "DIGEST_MISMATCH", "eventId": "evt-7"},
    {"code": "FORK", "eventId": "evt-3"},
    {"code": "PREV_DIGEST_MISMATCH", "eventId": "evt-8"}
  ]
}
```

`errors` 按 **`code` 字典序、再按 `eventId` 字典序**排序并去重。
审计员可据此区分损坏类型：正文被改 → `DIGEST_MISMATCH`；父引用被改 →
`MISSING_PARENT` / `FORK` / `PREV_DIGEST_MISMATCH`；结构被毁 → `CYCLE` / 根异常。

**仅当唯一单链完整无缺时**，返回从根到尾的事件序列与尾摘要（HTTP 200）：

```json
{
  "valid": true,
  "errors": [],
  "events": [ { ... 根 }, { ... }, { ... 尾 } ],
  "tailDigest": "<尾事件 digest>"
}
```

`events` 的顺序由图重建，与上传顺序无关，可直接用于逐字节复算整条证据链。

### 错误码

审计错误码（`errors[].code`）：

| code | eventId 指向 | 含义 |
|---|---|---|
| `NO_ROOT` | 空串 | 批次无根事件 |
| `MULTIPLE_ROOTS` | 每个根事件 | 根多于一个 |
| `MISSING_PARENT` | 缺前驱的子事件 | `parentId` 在批次内不存在 |
| `FORK` | 被分叉的**父事件** | 同一前驱有多个子事件 |
| `CYCLE` | 环上的每个事件 | 前驱关系成环（含自环） |
| `ROOT_PREV_DIGEST_NOT_ZERO` | 根事件 | 根的 `prevDigest` 非全零 |
| `PREV_DIGEST_MISMATCH` | 子事件 | `prevDigest` ≠ 前驱声明的 `digest` |
| `DIGEST_MISMATCH` | 该事件 | 重算摘要与声明 `digest` 不符 |

请求格式错误（HTTP 422，顶层 `code`）：`MALFORMED_JSON`、`BODY_TOO_LARGE`、
`REQUEST_VALIDATION_FAILED`（附 `fields[]`，带 0 基 `index`/`field`/`reason`）。
另有 405（非 POST 调 `/audit`）、415（非 JSON Content-Type）、404（未知路由）。

### curl 示例

```bash
curl -sS localhost:8080/audit -H 'Content-Type: application/json' -d '{
  "events": [
    {"id":"a","parentId":"","payload":"root body",
     "prevDigest":"0000000000000000000000000000000000000000000000000000000000000000",
     "digest":"<按定义计算>"},
    {"id":"b","parentId":"a","payload":"child body",
     "prevDigest":"<a 的 digest 原始 32 字节的十六进制>","digest":"<按定义计算>"}
  ]
}'
```

## 有限披露审计 `POST /audit/limited`

跨馆交接时某些证物正文依法不能向审计员披露。有限披露入口与 `/audit`
共用完全相同的事件结构与摘要字节定义，**唯一区别**是：

- 任意事件的 `payload` 可写成显式 JSON **`null`**，表示“正文未披露”；
  未披露正文从不进入服务、也**绝不会被回显**（响应里该字段仍是 `null`）；
- 已披露事件仍按同一条字节定义**逐字节重算** `digest`；
- 结构检查一条不松：唯一根、可解析前驱、无分叉、无环、根锚点全零、
  每条 `prevDigest` 等于父事件声明的 `digest`；
- `payload` **字段缺失**仍是 422（只有显式 `null` 才表示未披露），
  `null` 之外的非字符串类型也是 422；`/audit` 的严格五字段规则保持不变
  （在 `/audit` 上写 `payload: null` 仍返回 422）。

未披露事件的声明 `digest` **无法重算**，因此它是一个不可验证的锚点，
而不是任何形式的证据：

- 结构或任一**已披露**摘要/链接有错 → HTTP 200，`valid:false`，返回
  排序去重后的 `errors`（与 `/audit` 完全相同的排序与错误码），**不输出链**；
- 结构完整时依图重建根→尾顺序，并给出逐事件结论：
  - 第一条未披露事件**之前**的连续段：`VERIFIED_PREFIX`（正文与身后每条
    链接都重算过）；
  - 第一条未披露事件及其后**所有**事件：`ANCHOR_UNVERIFIED`——即使后继
    正文本身可重算，也只锚在未验证摘要上，不得标为已验证；
  - 全部披露且通过：每条 `VERIFIED`，整链 `VERIFIED`；
  - 存在任何未披露事件：整链 `PARTIAL`（永远不会是 `VERIFIED`）。

```json
{
  "valid": true,
  "status": "PARTIAL",
  "errors": [],
  "events": [
    {"id":"v0","parentId":"","payload":"body-0","prevDigest":"000…000",
     "digest":"…","status":"VERIFIED_PREFIX"},
    {"id":"v1","parentId":"v0","payload":null,"prevDigest":"…",
     "digest":"…","status":"ANCHOR_UNVERIFIED"},
    {"id":"v2","parentId":"v1","payload":"body-2","prevDigest":"…",
     "digest":"…","status":"ANCHOR_UNVERIFIED"}
  ],
  "tailDigest": "<尾事件声明 digest>"
}
```

`events` 顺序由图重建，与上传顺序无关；结构损坏时 `events`、`status`、
`tailDigest` 均省略，形态与严格入口一致。

## 双批次交接审计 `POST /audit/handoff`

证物从一座馆转交另一座馆后，两馆各自上传**一批**（批内同样乱序）封签
事件。新接口在一次审计中证明第二批确实接在第一批尾部，原两个入口
（`/audit`、`/audit/limited`）及其错误顺序均不改变。

请求体为两个批次，批内事件沿用有限披露的完全相同结构、摘要字节定义与
`payload: null` 隐藏规则：

```json
{
  "firstBatch":  [ { ... 第一批事件 } ],
  "secondBatch": [ { ... 第二批事件 } ]
}
```

- 每批各须包含 **1 至 2000** 条事件；字段级校验与 `/audit/limited` 完全
  相同，字段错误在原有 `index`/`field`/`reason` 之外附 `batch`
  （`"firstBatch"` / `"secondBatch"`，原两个入口不输出该字段）；
- **第一批**仍由全零根锚开始：其唯一根的 `prevDigest` 必须全零；
- **第二批的根**在批内没有 `parentId`（仍为空串，且批内仍须恰好一个根），
  它的 `prevDigest` **必须等于第一批经图重建得到的尾摘要**——而不是全零；
- 两批事件 **ID 不得重复**：跨批重复的 id 由审计结论
  `DUPLICATE_ID_ACROSS_BATCHES` 报告（批内重复仍是 422，二者不混同）；
- 两批各自完成与单批完全相同的批内核查：唯一根、可解析前驱、无分叉、
  无环、每条 `prevDigest` 等于批内父事件声明的 `digest`、已披露事件摘要
  逐字节复算。

**交接检查与批内核查一并完成**：第一批无效、第二批无效、跨批重复 ID、
锚点不符中的任何一项成立，都只返回按 `(code, eventId)` 排序去重的错误，
**不输出可信拼接链**（无 `events`/`status`/`tailDigest`）。当第一批本身
无效时其尾摘要不存在，锚点比对无定义因而跳过（不会凭空产生
`HANDOFF_ANCHOR_MISMATCH`），但第二批批内核查与跨批重复 ID 检查照常进行。

新增审计错误码：

| code | eventId 指向 | 含义 |
|---|---|---|
| `HANDOFF_ANCHOR_MISMATCH` | 第二批的根事件 | 第二批根的 `prevDigest` ≠ 第一批重建尾摘要 |
| `DUPLICATE_ID_ACROSS_BATCHES` | 重复的事件 id（每 id 一次） | 同一 id 在两批中均出现 |

结构全部成立时，返回跨两批拼接的**单一**根→尾序列（第一批根到第二批尾）
与第二批尾摘要，形态与有限披露响应一致，并沿拼接后的完整序列传播信任：

- 从首事件到末事件**全部披露且逐字节复算**才标为 `VERIFIED`；
- **第一批只要存在未披露正文，第二批即使全部披露也只能继承
  “锚点未验证”**：第一个未披露事件及其后（含整个第二批）均为
  `ANCHOR_UNVERIFIED`，整链永远是 `PARTIAL`；
- 未披露正文同样**绝不回显**，响应中固定为 `"payload":null`。

```json
{
  "valid": true,
  "status": "PARTIAL",
  "errors": [],
  "events": [
    {"id":"h0","parentId":"","payload":"body-0","prevDigest":"000…000",
     "digest":"…","status":"VERIFIED_PREFIX"},
    {"id":"h1","parentId":"h0","payload":null,"prevDigest":"…",
     "digest":"…","status":"ANCHOR_UNVERIFIED"},
    {"id":"h2","parentId":"","payload":"body-2","prevDigest":"<h1 尾摘要>",
     "digest":"…","status":"ANCHOR_UNVERIFIED"},
    {"id":"h3","parentId":"h2","payload":"body-3","prevDigest":"…",
     "digest":"…","status":"ANCHOR_UNVERIFIED"}
  ],
  "tailDigest": "<第二批尾事件声明 digest>"
}
```

## 测试

```bash
make test       # go test -race ./...
make cover      # 覆盖率报告
```

测试覆盖关键需求：

- **置乱输入**：30 条链随机置乱 50 次，均重建出相同的根→尾序列与尾摘要；
- **改动正文**：中间事件 payload 被改 → 唯一的 `DIGEST_MISMATCH`；
- **改动父引用**：指向不存在 id → 仅 `MISSING_PARENT`；改指到已存在父节点 →
  同时产生 `FORK` 与 `PREV_DIGEST_MISMATCH`，两类损坏可区分；
- **分叉**：同源兄弟事件 → 锚定在父 id 上的单个 `FORK`；
- **环/自环**：环上每个事件标记 `CYCLE`（去重），并报告 `NO_ROOT`；
- **根异常**：多根、无根、根 `prevDigest` 非零各自独立报错；
- **逐字节复算**：绕过生产辅助函数独立拼接签名缓冲区，并用 Go 之外
  （Python）预先算出的固定向量钉死字节布局（含多字节 UTF-8）：

  ```
  id="根-1", payload="α", prev=0×32
  -> b17a3ef4f1ce4ada24925ef39e4b326e163280aef3133399b86ecb95aa93b587
  ```

- HTTP 层：1 条/2000 条边界、各类 422、405/404/415、错误排序等。
- **有限披露**（独立固定向量 v0..v3，Python 预算）：
  - 根 / 中段 / 末尾隐藏 → 前缀与锚点状态逐位正确，整链 `PARTIAL`；
  - 全部隐藏位置组合下，隐藏项**永不**被标成 `VERIFIED`/`VERIFIED_PREFIX`，
    且正文（哨兵串）不出现在任何输出字节中，响应固定为 `"payload":null`；
  - 篡改已披露正文 → 仅 `DIGEST_MISMATCH`，不出链；伪造 `prevDigest`
    链接（即使父事件隐藏）→ `PREV_DIGEST_MISMATCH`；分叉、环（含隐藏成员）
    照常报错；乱序上传 50 轮重建顺序与状态不变；
  - `/audit` 上 `payload:null` 仍 422，`/audit/limited` 上字段缺失/错类型
    仍 422，严格五字段语义不变。
- **双批次交接**（独立固定向量 h0..h3，Python 预算，在 h1/h2 之间切批）：
  - 两批各自乱序上传 50 轮，均拼接重建出相同的 h0→h3 序列、尾摘要与
    `VERIFIED` 状态；
  - 第二批根锚点伪造（全零或外值，自身摘要一致）→ 仅
    `HANDOFF_ANCHOR_MISMATCH`，且全零锚点规则只作用于第一批；
  - 第一批根锚点非零、正文篡改、批内断链、第二批多根等沿用原错误码，
    不出拼接链；第一批无效时跳过锚点比对但跨批重复 ID 仍报；
  - 跨批重复 ID → 仅 `DUPLICATE_ID_ACROSS_BATCHES`；批内重复 ID 仍 422；
  - 隐藏第一批尾事件 → 第二批即使全披露也整段 `ANCHOR_UNVERIFIED`、
    整链 `PARTIAL`；全披露后才 `VERIFIED`；隐藏正文不进输出字节；
  - 两批错误合并为同一列表，仍按 `(code, eventId)` 排序；原两个入口的
    行为与错误顺序保持不变。
