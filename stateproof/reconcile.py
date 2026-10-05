"""只读清单对账：比较当前 root 与已生成证明之间的清单漂移。

不生成证明、不写任何文件、不改变既有输出。流程：
- 先由调用方完成证明校验（ProofFormatError 优先于 root 错误）；
- 沿用 generate 的扫描口径（``scan_root``）收集 root 下普通文件，
  空目录、符号链接、FIFO/套接字/设备等一律排除；
- 以证明中的 POSIX 相对路径为主键，重读仍存在的普通文件，
  先比大小再比分块 BLAKE2b-256 摘要。

分类：
- unchanged：证明与当前完全一致（大小与全部分块摘要相同）；
- added：当前存在但证明未列出的普通文件；
- removed：证明列出但当前不存在或已不是普通文件；
- mismatched：大小或摘要不符；大小不符一律记 size_mismatch，
  即使摘要同时不同；仅摘要不符记 digest_mismatch。

root 不存在/不是目录/不可访问，或交集文件复读失败 → RootUnavailable。
"""

import os

from .errors import RootUnavailable
from .hashes import hash_file_chunks
from .manifest import scan_root


def _resolve_path(root, rel_posix):
    return os.path.join(root, *rel_posix.split("/"))


def _byte_sorted(values):
    return sorted(values, key=lambda p: p.encode("utf-8"))


def run_reconcile(proof, root):
    """只读对账，返回规格规定的结果 dict；失败抛 RootUnavailable。"""
    current = {}
    for rel, abs_path in scan_root(root):
        current[rel] = abs_path

    proof_paths = [fe["path"] for fe in proof["files"]]
    proof_set = set(proof_paths)

    unchanged_files = []
    removed_files = []
    mismatched_files = []

    for fe in proof["files"]:
        rel = fe["path"]
        abs_path = current.get(rel)
        if abs_path is None:
            # 已删除，或被替换为符号链接/FIFO/设备等非普通文件。
            removed_files.append(rel)
            continue

        try:
            with open(abs_path, "rb") as fh:
                read_hashes, read_size = hash_file_chunks(fh)
        except OSError as exc:
            raise RootUnavailable(f"文件复读失败: {rel}: {exc}") from exc

        if read_size != fe["size"]:
            # 大小与摘要同时不同也只记 size_mismatch。
            mismatched_files.append({"path": rel, "reason": "size_mismatch"})
            continue

        expected = fe["chunks"]
        if len(read_hashes) != len(expected) or any(
            actual != expected[i]["digest"] for i, actual in enumerate(read_hashes)
        ):
            mismatched_files.append({"path": rel, "reason": "digest_mismatch"})
            continue

        unchanged_files.append(rel)

    added_files = [rel for rel in current if rel not in proof_set]

    unchanged_files = _byte_sorted(unchanged_files)
    added_files = _byte_sorted(added_files)
    removed_files = _byte_sorted(removed_files)
    mismatched_files.sort(key=lambda item: item["path"].encode("utf-8"))

    drifted = bool(added_files or removed_files or mismatched_files)
    return {
        "proof_id": proof["proof_id"],
        "file_count": proof["file_count"],
        "unchanged_files": unchanged_files,
        "added_files": added_files,
        "removed_files": removed_files,
        "mismatched_files": mismatched_files,
        "valid": not drifted,
        "failure_reason": "inventory_drift" if drifted else "none",
    }
