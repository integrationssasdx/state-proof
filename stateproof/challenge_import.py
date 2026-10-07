"""离线挑战凭证导入（challenge-import）。

只读 proof 与 response、不访问 root：先严格校验证明，再沿用 challenge-verify
的全部校验重建选样并逐条核对证据（顺序、字段、Base64、长度、摘要、判定与
challenge_id），随后把可验证的响应以 import 记录形态（samples / imported_at）
原子追加到同一证明的 state.history。

计数按重建选样顺序（全局块序）归类：
- checked_samples = ok + partial；
- missing_samples = missing；
- mismatched_samples = partial 或摘要不符。

同一 challenge_id 且计数判定一致的重复导入幂等：imported=false 且不改写状态；
同一 challenge_id 但结果不同 → StateConflict。
"""

from .challenge_export import verify_response
from .state import import_state, save_state


def run_challenge_import(proof, state_path, response_path):
    """校验响应并把结果导入状态，返回 stdout 摘要 dict。"""
    # 先验证明（load_proof 在 CLI 层完成），再按 challenge-verify 校验响应。
    outcome = verify_response(proof, response_path)

    state, imported = import_state(
        state_path,
        proof["proof_id"],
        outcome["challenge_id"],
        outcome,
    )
    if imported:
        # 仅首次导入才写状态；幂等复跑保持文件不变。
        save_state(state_path, state)

    return {
        "proof_id": outcome["proof_id"],
        "challenge_id": outcome["challenge_id"],
        "seed": outcome["seed"],
        "samples": outcome["samples"],
        "checked_samples": len(outcome["checked_samples"]),
        "missing_samples": len(outcome["missing_samples"]),
        "mismatched_samples": len(outcome["mismatched_samples"]),
        "valid": outcome["valid"],
        "failure_reason": outcome["failure_reason"],
        "imported": imported,
    }
