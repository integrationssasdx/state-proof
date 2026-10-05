"""全量核验（audit）：按证明顺序只读复核清单列出的每个普通文件。

与抽样挑战不同，audit 覆盖证明中的全部文件：逐文件核对类型、大小与
全部分块摘要。纯只读——不写状态、不写报告，结果只通过返回值（CLI 的
stdout）给出。清单之外的文件、空目录、非普通文件一律忽略。

判定优先级：
- 任一文件缺失/不是普通文件/不可读 → valid=false、failure_reason=retrieval_missing；
- 否则任一文件大小或任一分块摘要不同 → valid=false、failure_reason=content_mismatch；
- 全部一致（含空证明）→ valid=true、failure_reason=none。
"""

import os
import stat

from .errors import RootUnavailable
from .hashes import hash_file_chunks


def run_audit(proof, root):
    """对 proof 清单中的全部文件做只读全量复核，返回规格规定的结果 dict。"""
    if not isinstance(root, str) or not root:
        raise RootUnavailable("root 路径为空")
    if not os.path.exists(root):
        raise RootUnavailable(f"root 不存在: {root}")
    if not os.path.isdir(root):
        raise RootUnavailable(f"root 不是目录: {root}")
    if not os.access(root, os.R_OK | os.X_OK):
        raise RootUnavailable(f"root 不可访问: {root}")

    verified = 0
    missing = []
    mismatched = []

    # proof 已经 load_proof 校验：路径有序且与分块/根摘要自洽，按证明顺序复核。
    for fe in proof["files"]:
        rel = fe["path"]
        abs_path = os.path.join(root, *rel.split("/"))

        read_hashes = None
        size = None
        try:
            st = os.lstat(abs_path)
            if stat.S_ISREG(st.st_mode):
                with open(abs_path, "rb") as fh:
                    read_hashes, size = hash_file_chunks(fh)
        except OSError:
            read_hashes = None

        if read_hashes is None:
            missing.append(rel)
            continue
        expected = [ch["digest"] for ch in fe["chunks"]]
        if size != fe["size"] or read_hashes != expected:
            mismatched.append(rel)
        else:
            verified += 1

    if missing:
        valid, failure_reason = False, "retrieval_missing"
    elif mismatched:
        valid, failure_reason = False, "content_mismatch"
    else:
        valid, failure_reason = True, "none"

    return {
        "proof_id": proof["proof_id"],
        "file_count": proof["file_count"],
        "verified_files": verified,
        "missing_files": missing,
        "mismatched_files": mismatched,
        "valid": valid,
        "failure_reason": failure_reason,
    }
