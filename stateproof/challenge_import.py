"""挑战凭证导入（challenge-import）：把可验证的离线挑战响应记入状态历史。

不访问 root：先严格校验证明，再按 challenge-verify 同一套重建逻辑校验响应
（选样、证据顺序、Base64、长度、摘要、判定与 challenge_id 全部重建一致），
然后把该次挑战的 seed、samples、计数与判定追加进同一证明的状态历史并原子写
state；proof 与 response 全程只读。state 不存在时按空历史创建。

幂等：同一 challenge_id 且计数判定一致时不改写状态，imported=false；
同一 challenge_id 但计数判定不一致即 StateConflict。
"""

from .challenge_export import verify_response
from .errors import StateConflict
from .state import (
    _empty_container,
    _now_iso,
    _same_outcome,
    parse_state_file,
    save_state,
)


def run_challenge_import(proof, response_path, state_path):
    """校验响应并导入状态历史，返回规格规定的结果 dict。"""
    verified = verify_response(proof, response_path)
    proof_id = proof["proof_id"]

    # state 不存在按空历史处理；损坏/跨 proof_id/历史非法 → StateConflict。
    state = parse_state_file(state_path, expected_proof_id=proof_id)
    if state is None:
        state = _empty_container(proof_id)

    record = {
        "challenge_id": verified["challenge_id"],
        "seed": verified["seed"],
        "requested_samples": verified["samples"],
        "checked_samples": verified["checked_samples"],
        "missing_samples": verified["missing_samples"],
        "mismatched_samples": verified["mismatched_samples"],
        "valid": verified["valid"],
        "failure_reason": verified["failure_reason"],
        "challenged_at": _now_iso(),
    }

    previous = next(
        (r for r in state["history"] if r["challenge_id"] == record["challenge_id"]),
        None,
    )
    if previous is not None:
        if not _same_outcome(previous, record):
            raise StateConflict(
                "状态冲突：同一 challenge_id 的既有结果与本次导入不一致",
                details={"challenge_id": record["challenge_id"], "state": state_path},
            )
        # 幂等复导：不改写状态。
        imported = False
    else:
        state["history"].append(record)
        state["total_challenges"] += 1
        state["requested_samples"] += record["requested_samples"]
        state["checked_samples"] += record["checked_samples"]
        state["missing_samples"] += record["missing_samples"]
        state["mismatched_samples"] += record["mismatched_samples"]
        state["last_challenge_id"] = record["challenge_id"]
        state["last_seed"] = record["seed"]
        state["last_valid"] = record["valid"]
        state["last_failure_reason"] = record["failure_reason"]
        state["last_challenge_at"] = record["challenged_at"]
        save_state(state_path, state)
        imported = True

    return {
        "proof_id": proof_id,
        "challenge_id": verified["challenge_id"],
        "seed": verified["seed"],
        "samples": verified["samples"],
        "checked_samples": verified["checked_samples"],
        "missing_samples": verified["missing_samples"],
        "mismatched_samples": verified["mismatched_samples"],
        "valid": verified["valid"],
        "failure_reason": verified["failure_reason"],
        "imported": imported,
    }
