"""确定性抽样挑战：按 proof_id + seed 抽取分块，重读 root 下文件复核。

判定优先级：
- 任何抽中的分块无法取回（文件缺失/不是普通文件/读失败）→ missing，
  valid=false、failure_reason=retrieval_missing；
- 否则任何分块重读摘要不一致 → mismatched，
  valid=false、failure_reason=content_mismatch；
- 全部命中且一致 → valid=true、failure_reason=none。
"""

import hashlib
import os
import stat

from .errors import ChallengeRangeError, RootUnavailable
from .hashes import hash_file_chunks
from .state import load_state, save_state

CHALLENGE_NAMESPACE = b"stateproof-challenge-v1"


def parse_samples(value):
    """解析正整数样本数；非法抛 InputError。"""
    from .errors import InputError

    if value is None:
        raise InputError("缺少 --samples")
    text = str(value).strip()
    if not text or not text.isdigit():
        raise InputError(f"--samples 必须是正整数: {value!r}")
    n = int(text)
    if n <= 0:
        raise InputError(f"--samples 必须是正整数: {value!r}")
    return n


def _splitmix64_stream(seed8):
    """由 8 字节种子产生确定性的 64 位无符号整数流（SplitMix64）。"""
    state = int.from_bytes(seed8, "big")
    mask = (1 << 64) - 1
    while True:
        state = (state + 0x9E3779B97F4A7C15) & mask
        z = state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & mask
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & mask
        yield z ^ (z >> 31)


def select_indices(total, count, proof_id, seed):
    """从 [0, total) 确定性抽取 count 个互不相同的下标，升序返回。

    以 proof_id 与 seed 的 BLAKE2b-256 摘要播种 SplitMix64，再做部分
    Fisher–Yates 洗牌；同 (proof_id, seed, total, count) 结果恒定，
    且仅取决于根摘要（proof_id），与路径、文件名无关。
    """
    if total <= 0 or count <= 0 or count > total:
        raise ChallengeRangeError(
            f"挑战越界：可抽样分块 {total}，请求样本 {count}"
        )
    material = hashlib.blake2b(
        CHALLENGE_NAMESPACE
        + b"|proof:"
        + proof_id.encode("ascii")
        + b"|seed:"
        + str(seed).encode("utf-8"),
        digest_size=32,
    ).digest()
    rng = _splitmix64_stream(material[:8])
    indices = list(range(total))
    for i in range(count):
        j = i + next(rng) % (total - i)
        indices[i], indices[j] = indices[j], indices[i]
    return sorted(indices[:count])


def _flatten_chunks(proof):
    """返回 [(file_entry, chunk_index_in_file, global_index)]，全局顺序即证明顺序。"""
    flat = []
    global_index = 0
    for fe in proof["files"]:
        for ch in fe["chunks"]:
            flat.append((fe, ch["index"], global_index))
            global_index += 1
    return flat


def _resolve_path(root, rel_posix):
    return os.path.join(root, *rel_posix.split("/"))


def run_challenge(proof, root, seed, samples, state_path):
    """执行一次挑战，更新状态文件，返回规格规定的结果 dict。"""
    if not isinstance(root, str) or not root:
        raise RootUnavailable("root 路径为空")
    if not os.path.isdir(root):
        raise RootUnavailable(f"root 不存在或不是目录: {root}")
    if seed is None or str(seed) == "":
        from .errors import InputError

        raise InputError("缺少 --seed 或 seed 为空")
    seed_text = str(seed)

    flat = _flatten_chunks(proof)
    chosen = select_indices(len(flat), samples, proof["proof_id"], seed_text)

    # 按文件分组，减少重复打开；证明路径已排序，输出顺序稳定。
    by_file = {}
    order = []
    for gi in chosen:
        fe, chunk_idx, _ = flat[gi]
        if fe["path"] not in by_file:
            by_file[fe["path"]] = {"entry": fe, "targets": []}
            order.append(fe["path"])
        by_file[fe["path"]]["targets"].append(chunk_idx)

    missing = []
    mismatched = []
    checked = 0

    for rel in order:
        group = by_file[rel]
        fe = group["entry"]
        targets = sorted(group["targets"])
        abs_path = _resolve_path(root, rel)

        read_hashes = None
        try:
            st = os.lstat(abs_path)
            if stat.S_ISREG(st.st_mode):
                with open(abs_path, "rb") as fh:
                    read_hashes, _size = hash_file_chunks(fh)
        except OSError:
            read_hashes = None

        expected_by_idx = {ch["index"]: ch["digest"] for ch in fe["chunks"]}
        for chunk_idx in targets:
            ref = {"path": rel, "chunk_index": chunk_idx}
            if read_hashes is None:
                missing.append(ref)
            else:
                checked += 1
                if chunk_idx >= len(read_hashes) or \
                        read_hashes[chunk_idx] != expected_by_idx[chunk_idx]:
                    mismatched.append(ref)

    if missing:
        valid, failure_reason = False, "retrieval_missing"
    elif mismatched:
        valid, failure_reason = False, "content_mismatch"
    else:
        valid, failure_reason = True, "none"

    challenge_id = _challenge_id(
        proof["proof_id"], seed_text, samples, chosen, valid, failure_reason
    )
    result = {
        "challenge_id": challenge_id,
        "proof_id": proof["proof_id"],
        "seed": seed_text,
        "requested_samples": samples,
        "checked_samples": checked,
        "missing_samples": missing,
        "mismatched_samples": mismatched,
        "valid": valid,
        "failure_reason": failure_reason,
    }

    state = load_state(state_path, proof["proof_id"], challenge_id, result)
    save_state(state_path, state)

    return {
        "challenge_id": challenge_id,
        "requested_samples": samples,
        "checked_samples": checked,
        "missing_samples": missing,
        "mismatched_samples": mismatched,
        "valid": valid,
        "failure_reason": failure_reason,
    }


def _challenge_id(proof_id, seed, samples, chosen, valid, failure_reason):
    h = hashlib.blake2b(digest_size=32)
    h.update(CHALLENGE_NAMESPACE)
    h.update(b"|proof:")
    h.update(proof_id.encode("ascii"))
    h.update(b"|seed:")
    h.update(seed.encode("utf-8"))
    h.update(f"|n:{samples}|i:{','.join(str(i) for i in chosen)}".encode("ascii"))
    h.update(f"|v:{1 if valid else 0}|r:{failure_reason}".encode("ascii"))
    return h.hexdigest()
