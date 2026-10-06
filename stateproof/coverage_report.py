"""只读覆盖率报告：用历史挑战回答全部分块的覆盖情况与失效是否持续。

不访问 root、不写任何文件，仅凭已校验的证明与属于该 proof_id 的状态历史：
- 沿用 challenge 的确定性选样语义，按每条记录的 seed 与 requested_samples
  重建互异的全局分块引用，取并集得到覆盖集合；
- 每条 challenge_id 必须能由选样、valid、failure_reason 重建一致，
  否则状态不可信，报 StateConflict。

判定优先级：
- 历史中存在无效记录 → valid=false、failure_reason=challenge_failure；
- 否则仍有分块从未被抽中 → valid=false、failure_reason=coverage_gap；
- 全部分块至少被抽中一次且历史全有效（含空证明空历史）→ valid=true、none。

空历史时 covered_chunks 与 failure_streak 为 0、两个数组为空；
空证明仍带历史、历史 requested_samples 超过 total_chunks 等无法重建的
情形一律 StateConflict。
"""

from .challenge import _challenge_id, _flatten_chunks, select_indices
from .errors import StateConflict
from .state import parse_state_file


def build_coverage_report(proof, state_path):
    """重建覆盖率报告，返回规格规定的结果 dict；状态不可信抛 StateConflict。"""
    proof_id = proof["proof_id"]
    flat = _flatten_chunks(proof)
    total_chunks = len(flat)

    # 严格校验状态并锚定 proof_id；文件不存在按空历史处理。
    state = parse_state_file(state_path, expected_proof_id=proof_id)
    history = state["history"] if state is not None else []

    covered = set()
    failed_challenges = []
    for i, rec in enumerate(history):
        try:
            chosen = select_indices(
                total_chunks, rec["requested_samples"], proof_id, rec["seed"]
            )
        except Exception as exc:
            # 空证明仍有历史、requested_samples 为 0 或超过 total_chunks：
            # 选样无法重建，历史与证明互相矛盾。
            raise StateConflict(
                f"状态历史第 {i} 条选样无法重建: requested_samples="
                f"{rec['requested_samples']}, total_chunks={total_chunks}"
            ) from exc
        expected_id = _challenge_id(
            proof_id,
            rec["seed"],
            rec["requested_samples"],
            chosen,
            rec["valid"],
            rec["failure_reason"],
        )
        if rec["challenge_id"] != expected_id:
            raise StateConflict(
                f"状态历史第 {i} 条 challenge_id 与重建结果不一致",
                details={
                    "record_challenge_id": rec["challenge_id"],
                    "rebuilt_challenge_id": expected_id,
                },
            )
        covered.update(chosen)
        if not rec["valid"]:
            failed_challenges.append(rec["challenge_id"])

    # 未覆盖分块按全局块序（证明顺序）列出 path 与文件内 chunk_index。
    uncovered_chunks = [
        {"path": flat[gi][0]["path"], "chunk_index": flat[gi][1]}
        for gi in range(total_chunks)
        if gi not in covered
    ]

    # 末尾连续无效记录数：从最后一条向前数，遇到有效记录即止。
    failure_streak = 0
    for rec in reversed(history):
        if rec["valid"]:
            break
        failure_streak += 1

    if failed_challenges:
        valid, failure_reason = False, "challenge_failure"
    elif uncovered_chunks:
        valid, failure_reason = False, "coverage_gap"
    else:
        valid, failure_reason = True, "none"

    return {
        "proof_id": proof_id,
        "total_chunks": total_chunks,
        "covered_chunks": len(covered),
        "uncovered_chunks": uncovered_chunks,
        "failed_challenges": failed_challenges,
        "failure_streak": failure_streak,
        "valid": valid,
        "failure_reason": failure_reason,
    }
