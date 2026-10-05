"""全量核验：只读复核证明中列出的每一个普通文件，不写状态或任何报告。

逐文件（按证明顺序）判定：
- 文件缺失、lstat 判型不是普通文件、或打开/读取失败 → retrieval_missing；
- 可读但大小或任一分块摘要与证明不符 → content_mismatch；
- 其余计入 verified_files。

root 下清单外的文件、空目录、符号链接/FIFO 等非普通文件一律忽略。
missing 优先于 mismatch：只要有 missing 即 valid=false、
failure_reason=retrieval_missing；否则有 mismatch 即 content_mismatch；
全部一致或空证明（file_count=0）为 valid=true、failure_reason=none。
"""

import os
import stat

from .errors import RootUnavailable
from .hashes import hash_file_chunks


def _resolve_path(root, rel_posix):
    return os.path.join(root, *rel_posix.split("/"))


def ensure_root(root):
    """root 必须存在、是目录且可遍历读取；否则抛 RootUnavailable。"""
    if not isinstance(root, str) or not root:
        raise RootUnavailable("root 路径为空")
    if not os.path.exists(root):
        raise RootUnavailable(f"root 不存在: {root}")
    if not os.path.isdir(root):
        raise RootUnavailable(f"root 不是目录: {root}")
    if not os.access(root, os.R_OK | os.X_OK):
        raise RootUnavailable(f"root 不可访问: {root}")


def run_audit(proof, root):
    """对证明中的全部文件做只读全量复核，返回规格规定的结果 dict。"""
    ensure_root(root)

    missing_files = []
    mismatched_files = []
    verified = 0

    for fe in proof["files"]:
        rel = fe["path"]
        abs_path = _resolve_path(root, rel)

        read_hashes = None
        read_size = None
        try:
            st = os.lstat(abs_path)
            if stat.S_ISREG(st.st_mode):
                with open(abs_path, "rb") as fh:
                    read_hashes, read_size = hash_file_chunks(fh)
        except OSError:
            read_hashes = None

        if read_hashes is None:
            # 缺失 / 非普通文件（符号链接、FIFO、设备等）/ 不可读。
            missing_files.append(rel)
            continue

        expected = fe["chunks"]
        if (
            read_size != fe["size"]
            or len(read_hashes) != len(expected)
            or any(
                actual != expected[i]["digest"]
                for i, actual in enumerate(read_hashes)
            )
        ):
            mismatched_files.append(rel)
        else:
            verified += 1

    if missing_files:
        valid, failure_reason = False, "retrieval_missing"
    elif mismatched_files:
        valid, failure_reason = False, "content_mismatch"
    else:
        valid, failure_reason = True, "none"

    return {
        "proof_id": proof["proof_id"],
        "file_count": proof["file_count"],
        "verified_files": verified,
        "missing_files": missing_files,
        "mismatched_files": mismatched_files,
        "valid": valid,
        "failure_reason": failure_reason,
    }
