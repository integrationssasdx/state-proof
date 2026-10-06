# State Proof

存储证明与可检索性校验服务：证明生成、抽样挑战与失效判定。

## 范围

本仓库从零开始实现上述方向的可用工具，不依赖外部同类实现。

## 状态

基线实现：`generate` / `challenge` / `status` / `audit` / `reconcile`，
离线挑战凭证 `challenge-export` / `challenge-verify`，以及证明版本对账 `proof-diff`。

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

## 证明版本对账

- `proof proof-diff --before A --after B`
  不读 root、不创建/覆盖/修改任何文件，只比较两份已严格校验的证明，
  stdout 输出 JSON，退出码 0。先校验 before 再校验 after；任一证明缺失、
  不可解析或不合证明格式 → stderr 输出 `ProofFormatError`、退出码 2，
  两份均非法时报 before；缺参数或空路径 → `InputError`。
  结果含 `before_proof_id`、`after_proof_id`、`before_file_count`、
  `after_file_count`、`unchanged_files`、`added_files`、`removed_files`、
  `changed_files`、`valid`、`failure_reason`。
  after 独有路径进 `added_files`，before 独有路径进 `removed_files`；
  同路径的大小、块数、同序号分块摘要全同进 `unchanged_files`；
  大小不同记 `size_changed`，大小相同而摘要不同记 `digest_changed`。
  `changed_files` 每项含 `path`、`reason`、`changed_chunk_indices`
  （共同块序号中摘要不同者，升序）、`added_chunk_count`、
  `removed_chunk_count`（after/before 相对多出的末尾块数）。
  文件数组均按 UTF-8 字节序排序。完全一致（含两份空证明）为
  `valid=true`、`failure_reason=none`，否则 `valid=false`、
  `failure_reason=proof_drift`。

## 约定

- 公开行为以 README 与源码为准。
- 后续需求在此基线上增量实现。
