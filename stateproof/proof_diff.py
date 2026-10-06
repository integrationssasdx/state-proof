"""证明版本对账：比较两份已校验的证明，不读 root、不写任何文件。

仅以两份证明的清单为输入，以 POSIX 相对路径为主键：
- after 独有 → added_files；before 独有 → removed_files；
- 同路径的大小、块数、同序号块摘要全同 → unchanged_files；
- 同路径大小不同 → changed_files，reason=size_changed；
- 大小相同但块数或某序号块摘要不同 → changed_files，reason=digest_changed。

changed_files 每项给出共同序号（两端都有的块序号）中摘要差异的升序索引
``changed_chunk_indices``，以及 after 比 before 多出的末尾块数
``added_chunk_count``、before 比 after 多出的末尾块数 ``removed_chunk_count``。

全同则 valid=true、failure_reason=none；否则 valid=false、
failure_reason=proof_drift。
"""


def _byte_key(path):
    return path.encode("utf-8")


def diff_proofs(before, after):
    """比较两份已通过 ``load_proof`` 校验的证明，返回规格规定的结果 dict。"""
    before_map = {fe["path"]: fe for fe in before["files"]}
    after_map = {fe["path"]: fe for fe in after["files"]}

    before_paths = set(before_map)
    after_paths = set(after_map)

    unchanged_files = []
    added_files = sorted(after_paths - before_paths, key=_byte_key)
    removed_files = sorted(before_paths - after_paths, key=_byte_key)
    changed_files = []

    for rel in before_paths & after_paths:
        bfe = before_map[rel]
        afe = after_map[rel]
        bchunks = bfe["chunks"]
        achunks = afe["chunks"]

        if bfe["size"] != afe["size"]:
            reason = "size_changed"
        elif len(bchunks) != len(achunks) or any(
            bchunks[i]["digest"] != achunks[i]["digest"] for i in range(len(bchunks))
        ):
            reason = "digest_changed"
        else:
            unchanged_files.append(rel)
            continue

        common = min(len(bchunks), len(achunks))
        changed_indices = [
            i for i in range(common) if bchunks[i]["digest"] != achunks[i]["digest"]
        ]
        changed_files.append(
            {
                "path": rel,
                "reason": reason,
                "changed_chunk_indices": changed_indices,
                "added_chunk_count": max(0, len(achunks) - len(bchunks)),
                "removed_chunk_count": max(0, len(bchunks) - len(achunks)),
            }
        )

    unchanged_files.sort(key=_byte_key)
    changed_files.sort(key=lambda item: _byte_key(item["path"]))

    drifted = bool(added_files or removed_files or changed_files)
    return {
        "before_proof_id": before["proof_id"],
        "after_proof_id": after["proof_id"],
        "before_file_count": before["file_count"],
        "after_file_count": after["file_count"],
        "unchanged_files": unchanged_files,
        "added_files": added_files,
        "removed_files": removed_files,
        "changed_files": changed_files,
        "valid": not drifted,
        "failure_reason": "proof_drift" if drifted else "none",
    }
