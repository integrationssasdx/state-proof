"""只读覆盖率报告（coverage-report）：仅凭证明与属于该 proof_id 的状态历史，
判断证明的全部分块是否至少被抽中一次，以及末尾连续失效是否仍在持续。

不访问 root、不写任何文件：按每条历史记录的 seed 与 requested_samples，沿用
challenge 的确定性选样语义重建互异全局分块引用，逐条复核样本计数与 challenge_id。

判定优先级：
- 历史非法（计数矛盾、跨 proof_id、challenge_id 重建不一致等）→ StateConflict；
- 空历史：证明含分块时 valid=false、failure_reason=coverage_gap，空证明 true/none；
- 历史存在无效记录 → valid=false、failure_reason=challenge_failure；
- 有未覆盖分块 → valid=false、failure_reason=coverage_gap；
- 全部覆盖且历史全有效 → valid=true、failure_reason=none。
"""

from .challenge import _challenge_id, _flatten_chunks, select_indices
from .errors import StateConflict
from .state import parse_state_file


def _global_refs(flat, chosen):
    """选中下标 → [{path, chunk_index}]，按全局块序（chosen 已升序）。"""
    refs = []
    for gi in chosen:
        fe, chunk_idx, _ = flat[gi]
        refs.append({"path": fe["path"], "chunk_index": chunk_idx})
    return refs


def coverage_report(proof, state_path):
    """生成覆盖率报告 dict；证明须已通过 load_proof 严格校验。"""
    proof_id = proof["proof_id"]
    flat = _flatten_chunks(proof)
    total_chunks = len(flat)

    # 严格校验状态：不存在按空历史处理；损坏/跨 proof_id → StateConflict。
    state = parse_state_file(state_path, expected_proof_id=proof_id)
    history = [] if state is None else state["history"]

    covered = set()
    failed_challenges = []

    for i, rec in enumerate(history):
        seed = rec["seed"]
        samples = rec["requested_samples"]

        # 空证明不可能存在任何挑战历史；requested_samples 非正或超过总分块数
        # 都与 challenge 的选样前提矛盾——均属历史与当前证明冲突。
        if samples <= 0 or samples > total_chunks:
            raise StateConflict(
                f"状态历史第 {i} 条 requested_samples={samples} 超出当前证明的"
                f"可抽样分块数 {total_chunks}"
            )

        chosen = select_indices(total_chunks, samples, proof_id, seed)
        refs = _global_refs(flat, chosen)

        # 样本计数的字段自洽性已由 parse_state_file 校验；此处再按重建选样
        # 复核 challenge_id：选样 + valid + failure_reason 必须复现记录值。
        expected_id = _challenge_id(
            proof_id, seed, samples, chosen, rec["valid"], rec["failure_reason"]
        )
        if rec["challenge_id"] != expected_id:
            raise StateConflict(
                f"状态历史第 {i} 条 challenge_id 重建不一致",
                details={"challenge_id": rec["challenge_id"]},
            )

        covered.update((r["path"], r["chunk_index"]) for r in refs)
        if not rec["valid"]:
            failed_challenges.append(rec["challenge_id"])

    failure_streak = 0
    for rec in reversed(history):
        if rec["valid"]:
            break
        failure_streak += 1

    # 按全局块序列出从未被抽中的分块。
    uncovered = []
    for fe, chunk_idx, _ in flat:
        if (fe["path"], chunk_idx) not in covered:
            uncovered.append({"path": fe["path"], "chunk_index": chunk_idx})

    if history and failed_challenges:
        valid, reason = False, "challenge_failure"
    elif uncovered:
        valid, reason = False, "coverage_gap"
    else:
        valid, reason = True, "none"

    return {
        "proof_id": proof_id,
        "total_chunks": total_chunks,
        "covered_chunks": len(covered),
        "uncovered_chunks": uncovered,
        "failed_challenges": failed_challenges,
        "failure_streak": failure_streak,
        "valid": valid,
        "failure_reason": reason,
    }
