# State Proof

存储证明与可检索性校验服务：证明生成、抽样挑战与失效判定。

## 范围

本仓库从零开始实现上述方向的可用工具，不依赖外部同类实现。

## 状态

基线实现：`generate` / `challenge` / `status` / `audit` / `reconcile`，
离线挑战凭证 `challenge-export` / `challenge-verify`，
证明版本对账 `proof-diff`，以及只读覆盖率报告 `coverage-report`。

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
  不读 root、不写任何文件：先严格校验 before 证明再校验 after 证明（两者都非法时
  报 before），逐路径比较两份证明的清单，输出 `before_proof_id`、`after_proof_id`、
  `before_file_count`、`after_file_count`、`unchanged_files`、`added_files`、
  `removed_files`、`changed_files`、`valid`、`failure_reason`。
  after 独有路径进 `added_files`，before 独有路径进 `removed_files`；同路径的
  大小、块数与同序号块摘要全同进 `unchanged_files`；大小不同记
  `reason=size_changed`，大小相同但摘要不同记 `reason=digest_changed`。
  `changed_files` 每项含 `path`、`reason`、`changed_chunk_indices`
  （共同序号中摘要不同的升序索引）、`added_chunk_count` / `removed_chunk_count`
  （after、before 各自多出的末尾块数）。文件数组均按 UTF-8 字节序对路径排序。
  全同则 `valid=true`、`failure_reason=none`，否则 `valid=false`、
  `failure_reason=proof_drift`。证明缺失、不可解析或不合证明格式 →
  `ProofFormatError`；缺参数或空路径 → `InputError`。

## 只读覆盖率报告

- `proof coverage-report --proof P --state S`
  只读证明与状态历史，不访问 root、不写任何文件。先严格校验证明，再严格校验
  属于该 `proof_id` 的状态历史；按每条记录的 `seed` 与 `requested_samples`，
  沿用 `challenge` 的确定性选样语义重建互异的全局分块引用，且每条
  `challenge_id` 必须能由选样、`valid`、`failure_reason` 重建一致，否则
  `StateConflict`。输出 `proof_id`、`total_chunks`、`covered_chunks`、
  `uncovered_chunks`、`failed_challenges`、`failure_streak`、`valid`、
  `failure_reason`：
  - `covered_chunks` 为历史上至少被抽中一次的唯一分块数；
  - `uncovered_chunks` 按全局块序列出从未被抽中的分块，每项含
    `path`、`chunk_index`；
  - `failed_challenges` 按历史顺序列出无效记录的 `challenge_id`；
  - `failure_streak` 只统计末尾连续无效记录数，遇有效记录即止。
- 状态文件不存在按空历史处理：`covered_chunks=0`、`failure_streak=0`、
  两个数组为空。空历史时证明含分块 → `valid=false`、
  `failure_reason=coverage_gap`；空证明（无分块）→ `valid=true`、
  `failure_reason=none`。历史存在无效记录时一律
  `valid=false`、`failure_reason=challenge_failure`；否则有未覆盖块时
  `valid=false`、`failure_reason=coverage_gap`；全部覆盖且历史全有效时
  `valid=true`、`failure_reason=none`。
- 历史的 `requested_samples` 超过 `total_chunks`（或空证明仍存在历史）→
  `StateConflict`。缺参数或空路径 → `InputError`；证明非法 →
  `ProofFormatError`；状态不可解析、跨 `proof_id`、计数矛盾或
  `challenge_id` 重建不一致 → `StateConflict`。

## 约定

- 公开行为以 README 与源码为准。
- 后续需求在此基线上增量实现。
