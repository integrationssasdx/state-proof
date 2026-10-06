"""两份证明之间的版本对账：不读 root、不写任何文件。

调用方负责先用 ``load_proof`` 严格校验两份证明（before 先于 after，
ProofFormatError 优先于参数之外的一切）。比较以 POSIX 相对路径为主键：

- after 独有 → added_files；before 独有 → removed_files；
- 同路径且大小、块数、同序号分块摘要全同 → unchanged_files；
- 同路径但大小不同 → changed_files，reason=size_changed；
  大小相同但同序号分块摘要存在差异 → reason=digest_changed。

每个 changed 条目另含：
- changed_chunk_indices：双方共同块序号（``0..min(块数)-1``）中摘要不同的
  序号，按升序排列；
- added_chunk_count / removed_chunk_count：after 比 before 多出 / 少掉的
  末尾块数，即 ``max(0, n_after - n_before)`` 与反向值。

任何增、删、改都记为漂移：valid=false、failure_reason=proof_drift；
完全一致（含两份均为空证明）为 valid=true、failure_reason=none。
路径数组一律按 UTF-8 字节序排序。
"""


def _byte_sorted(values):
    return sorted(values, key=lambda p: p.encode("utf-8"))


def _index_files(proof):
    return {fe["path"]: fe for fe in proof["files"]}


def _compare_common(before_fe, after_fe):
    """比较同路径条目，返回 None（unchanged）或 changed 条目 dict。"""
    before_chunks = before_fe["chunks"]
    after_chunks = after_fe["chunks"]
    n_before = len(before_chunks)
    n_after = len(after_chunks)

    if (
        after_fe["size"] == before_fe["size"]
        and n_after == n_before
        and all(
            after_chunks[i]["digest"] == before_chunks[i]["digest"]
            for i in range(n_before)
        )
    ):
        return None

    reason = (
        "size_changed" if after_fe["size"] != before_fe["size"] else "digest_changed"
    )
    common = min(n_before, n_after)
    changed_indices = [
        i
        for i in range(common)
        if after_chunks[i]["digest"] != before_chunks[i]["digest"]
    ]
    return {
        "path": before_fe["path"],
        "reason": reason,
        "changed_chunk_indices": changed_indices,
        "added_chunk_count": max(0, n_after - n_before),
        "removed_chunk_count": max(0, n_before - n_after),
    }


def run_proof_diff(before_proof, after_proof):
    """比较两份已校验证明，返回规格规定的结果 dict。"""
    before_map = _index_files(before_proof)
    after_map = _index_files(after_proof)

    unchanged_files = []
    added_files = []
    removed_files = []
    changed_files = []

    for rel, after_fe in after_map.items():
        before_fe = before_map.get(rel)
        if before_fe is None:
            added_files.append(rel)
            continue
        changed = _compare_common(before_fe, after_fe)
        if changed is None:
            unchanged_files.append(rel)
        else:
            changed_files.append(changed)

    for rel in before_map:
        if rel not in after_map:
            removed_files.append(rel)

    unchanged_files = _byte_sorted(unchanged_files)
    added_files = _byte_sorted(added_files)
    removed_files = _byte_sorted(removed_files)
    changed_files.sort(key=lambda item: item["path"].encode("utf-8"))

    drifted = bool(added_files or removed_files or changed_files)
    return {
        "before_proof_id": before_proof["proof_id"],
        "after_proof_id": after_proof["proof_id"],
        "before_file_count": before_proof["file_count"],
        "after_file_count": after_proof["file_count"],
        "unchanged_files": unchanged_files,
        "added_files": added_files,
        "removed_files": removed_files,
        "changed_files": changed_files,
        "valid": not drifted,
        "failure_reason": "proof_drift" if drifted else "none",
    }
