"""只读清单漂移核对：比较 root 当前普通文件清单与证明清单，不写任何文件。

以证明的 POSIX 相对路径为主键（按 UTF-8 字节序）：
- 证明与当前清单都有、大小与 BLAKE2b-256 分块摘要均一致 → unchanged_files；
- 当前存在但证明未列出的普通文件 → added_files；
- 证明列出但当前已不存在或不是普通文件（符号链接/FIFO/设备等）→ removed_files；
- 两边都有但内容漂移 → mismatched_files，reason 仅 size_mismatch /
  digest_mismatch；大小与摘要同时不符只记 size_mismatch。

扫描口径与 generate 完全一致（排除空目录、符号链接及非普通文件）。
added/removed/mismatched 任一非空即 valid=false、
failure_reason=inventory_drift；无漂移为 valid=true、failure_reason=none。
普通文件存在但复读失败视为 root 不可用（RootUnavailable），由调用方先完成证明校验。
"""

import os

from .errors import RootUnavailable
from .hashes import file_digest_from_chunk_hashes, hash_file_chunks
from .manifest import scan_root


def _path_key(path):
    return path.encode("utf-8")


def _resolve_path(root, rel_posix):
    return os.path.join(root, *rel_posix.split("/"))


def run_reconcile(proof, root):
    """只读比对证明清单与 root 当前清单，返回规格规定的结果 dict。"""
    current = dict(scan_root(root))
    proof_paths = {fe["path"] for fe in proof["files"]}

    unchanged_files = []
    added_files = []
    removed_files = []
    mismatched_files = []

    for rel in current:
        if rel not in proof_paths:
            added_files.append(rel)

    for fe in proof["files"]:
        rel = fe["path"]
        if rel not in current:
            # 已缺失，或被符号链接/FIFO/目录等非普通文件取代。
            removed_files.append(rel)
            continue
        abs_path = _resolve_path(root, rel)
        try:
            with open(abs_path, "rb") as fh:
                chunk_hashes, size = hash_file_chunks(fh)
        except OSError as exc:
            raise RootUnavailable(f"文件复读失败: {rel}: {exc}") from exc

        if size != fe["size"]:
            # 大小与摘要同时漂移也只记 size_mismatch。
            mismatched_files.append({"path": rel, "reason": "size_mismatch"})
            continue
        digest = file_digest_from_chunk_hashes(chunk_hashes)
        if digest != fe["digest"]:
            mismatched_files.append({"path": rel, "reason": "digest_mismatch"})
            continue
        unchanged_files.append(rel)

    unchanged_files.sort(key=_path_key)
    added_files.sort(key=_path_key)
    removed_files.sort(key=_path_key)
    mismatched_files.sort(key=lambda item: _path_key(item["path"]))

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
