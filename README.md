# State Proof

存储证明与可检索性校验服务：证明生成、抽样挑战与失效判定。

## 范围

本仓库从零开始实现上述方向的可用工具，不依赖外部同类实现。

## 状态

基线实现：`generate` / `challenge` / `status` / `audit` / `reconcile`，
以及离线挑战凭证 `challenge-export` / `challenge-verify`。

## 离线挑战凭证

- `proof challenge-export --proof P --root R --seed S --samples N --output O`
  按与 `challenge` 相同的确定性选样重读被抽中的分块，生成自包含 JSON 凭证
  （`version=1`、`format=state-proof-challenge`，含 `proof_id`、`challenge_id`、
  `seed`、`samples`、`valid`、`failure_reason`、`evidence`）并原子写入 `O`；
  不接触状态文件。`evidence` 按全局块序，每条含 `path`、`chunk_index`、
  `offset`（块偏移）、`size`（块长）、`retrieval_status`、`retrieved_size`、
  `digest`、`data`：`ok` 为完整原块（Base64）及其实际 BLAKE2b-256；
  `missing` 为缺失/非普通文件/读失败（`retrieved_size=0`，`digest=data=null`）；
  `partial` 为短读（短块 Base64 及其实际摘要）。判定：`missing→retrieval_missing`，
  `partial` 或摘要不符`→content_mismatch`，全部一致`→none`。
- `proof challenge-verify --proof P --response R`
  不访问 root、不写文件：仅凭证明重建选样，逐条核对证据的顺序唯一性、字段、
  Base64、长度与摘要，重建议定与 `challenge_id`，输出 `proof_id`、`challenge_id`、
  `seed`、`samples`、`valid`、`failure_reason` 与唯一判定 `verdict`。
  响应缺失/不可解析/版本格式/证据/重建/`challenge_id` 不合法 → `ResponseFormatError`。

## 约定

- 公开行为以 README 与源码为准。
- 后续需求在此基线上增量实现。
