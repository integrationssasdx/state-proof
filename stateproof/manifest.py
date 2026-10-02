"""证明文件的生成、读取与校验。

扫描规则：以 ``--root`` 为根递归收集**普通文件**（``S_ISREG``，跟随用户显式给出的
目录但不收符号链接本身），按 POSIX 相对路径（``/`` 分隔）排序。空目录、符号链接、
FIFO/套接字/设备等非普通文件一律忽略，文件名中任何字符（含换行、空格、Unicode）
都按字节原样参与，不改变结果。
"""

import json
import os
import stat

from .errors import ProofFormatError, RootUnavailable
from .hashes import (
    CHUNK_SIZE,
    DIGEST,
    file_digest_from_chunk_hashes,
    hash_file_chunks,
    merkle_root,
)

VERSION = 1
PROOF_FORMAT = "state-proof"


def _iter_regular_files(root):
    """生成 (POSIX 相对路径, 绝对路径)，仅普通文件；顺序由调用方排序。

    用 lstat 判型：符号链接（无论指向什么）、FIFO、套接字、设备等一律排除。
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            abs_path = os.path.join(dirpath, name)
            try:
                st = os.lstat(abs_path)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            rel = os.path.relpath(abs_path, root)
            yield rel.replace(os.sep, "/"), abs_path


def scan_root(root):
    """返回排序后的 [(rel_posix, abs_path)]；root 不可用时抛 RootUnavailable。"""
    if not isinstance(root, str) or not root:
        raise RootUnavailable("root 路径为空")
    if not os.path.exists(root):
        raise RootUnavailable(f"root 不存在: {root}")
    if not os.path.isdir(root):
        raise RootUnavailable(f"root 不是目录: {root}")
    if not os.access(root, os.R_OK | os.X_OK):
        raise RootUnavailable(f"root 不可访问: {root}")

    files = list(_iter_regular_files(root))
    files.sort(key=lambda item: item[0].encode("utf-8"))
    return files


def build_proof(root):
    """扫描 root 并构造证明 dict（含文件/分块/根摘要）。"""
    files = scan_root(root)
    file_entries = []
    root_entries = []
    for rel, abs_path in files:
        try:
            with open(abs_path, "rb") as fh:
                chunk_hashes, size = hash_file_chunks(fh)
        except OSError as exc:
            raise RootUnavailable(f"文件无法读取: {rel}: {exc}") from exc
        file_hash = file_digest_from_chunk_hashes(chunk_hashes)
        chunks = _chunks_with_sizes(size, chunk_hashes)
        file_entries.append(
            {
                "path": rel,
                "size": size,
                "digest": file_hash,
                "chunks": chunks,
            }
        )
        root_entries.append((rel, file_hash))
    root_hash = merkle_root(root_entries)
    return {
        "version": VERSION,
        "format": PROOF_FORMAT,
        "hash_algorithm": DIGEST,
        "chunk_size": CHUNK_SIZE,
        "proof_id": root_hash,
        "root": root_hash,
        "file_count": len(file_entries),
        "files": file_entries,
    }


def _chunks_with_sizes(total_size, chunk_hashes):
    """根据总大小与分块数推导每块大小：除最后一块外均为 CHUNK_SIZE。"""
    chunks = []
    n = len(chunk_hashes)
    for i, ch in enumerate(chunk_hashes):
        if i == n - 1:
            size = total_size - (n - 1) * CHUNK_SIZE if n else total_size
        else:
            size = CHUNK_SIZE
        chunks.append({"index": i, "size": size, "digest": ch})
    return chunks


def load_proof(path):
    """读取并严格校验证明文件，返回规范化 dict；非法时抛 ProofFormatError。"""
    if not isinstance(path, str) or not path:
        raise ProofFormatError("proof 路径为空")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError as exc:
        raise ProofFormatError(f"证明文件不存在: {path}") from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProofFormatError(f"证明文件不可解析: {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ProofFormatError("证明顶层结构必须是对象")
    if data.get("version") != VERSION:
        raise ProofFormatError(f"不支持的证明版本: {data.get('version')!r}")
    if data.get("format") != PROOF_FORMAT:
        raise ProofFormatError(f"证明格式标识非法: {data.get('format')!r}")
    if data.get("hash_algorithm") != DIGEST:
        raise ProofFormatError(f"不支持的摘要算法: {data.get('hash_algorithm')!r}")
    if data.get("chunk_size") != CHUNK_SIZE:
        raise ProofFormatError(f"分块大小非法: {data.get('chunk_size')!r}")

    files = data.get("files")
    if not isinstance(files, list):
        raise ProofFormatError("files 必须是数组")

    proof_id = data.get("proof_id")
    if not isinstance(proof_id, str) or not _is_hex32(proof_id):
        raise ProofFormatError("proof_id 缺失或不是 64 位小写十六进制")
    root = data.get("root")
    if not isinstance(root, str) or not _is_hex32(root):
        raise ProofFormatError("root 摘要缺失或不是 64 位小写十六进制")

    norm_files = []
    seen = set()
    for idx, fe in enumerate(files):
        if not isinstance(fe, dict):
            raise ProofFormatError(f"files[{idx}] 必须是对象")
        rel = fe.get("path")
        if not isinstance(rel, str) or not rel:
            raise ProofFormatError(f"files[{idx}].path 非法")
        if rel in seen:
            raise ProofFormatError(f"files[{idx}] 路径重复: {rel}")
        seen.add(rel)
        if not _nonneg_int(fe.get("size")):
            raise ProofFormatError(f"files[{idx}].size 非法")
        digest = fe.get("digest")
        if not isinstance(digest, str) or not _is_hex32(digest):
            raise ProofFormatError(f"files[{idx}].digest 非法")
        chunks = fe.get("chunks")
        if not isinstance(chunks, list):
            raise ProofFormatError(f"files[{idx}].chunks 必须是数组")
        norm_chunks = []
        for ci, ch in enumerate(chunks):
            if not isinstance(ch, dict):
                raise ProofFormatError(f"files[{idx}].chunks[{ci}] 必须是对象")
            if ch.get("index") != ci:
                raise ProofFormatError(f"files[{idx}].chunks[{ci}].index 不连续")
            if not _nonneg_int(ch.get("size")):
                raise ProofFormatError(f"files[{idx}].chunks[{ci}].size 非法")
            cd = ch.get("digest")
            if not isinstance(cd, str) or not _is_hex32(cd):
                raise ProofFormatError(f"files[{idx}].chunks[{ci}].digest 非法")
            norm_chunks.append({"index": ci, "size": ch["size"], "digest": cd})
        expected_chunks = _expected_chunk_count(fe["size"])
        if len(norm_chunks) != expected_chunks:
            raise ProofFormatError(
                f"files[{idx}] 分块数 {len(norm_chunks)} 与大小 {fe['size']} 不符"
            )
        # 每块大小必须与总大小自洽：除最后一块外都是 CHUNK_SIZE，末块为余数（>0）。
        for ci, ch in enumerate(norm_chunks):
            want_size = (
                CHUNK_SIZE
                if ci < expected_chunks - 1
                else fe["size"] - ci * CHUNK_SIZE
            )
            if ch["size"] != want_size:
                raise ProofFormatError(
                    f"files[{idx}].chunks[{ci}].size 与文件总大小不符"
                )
        norm_files.append(
            {"path": rel, "size": fe["size"], "digest": digest, "chunks": norm_chunks}
        )

    # 路径必须有序，且 proof_id/root 必须与内容重算结果一致——防止手改证明。
    paths = [fe["path"] for fe in norm_files]
    if paths != sorted(paths, key=lambda p: p.encode("utf-8")):
        raise ProofFormatError("files 未按 POSIX 相对路径排序")
    for fe in norm_files:
        recomputed = file_digest_from_chunk_hashes(
            [ch["digest"] for ch in fe["chunks"]]
        )
        if recomputed != fe["digest"]:
            raise ProofFormatError(f"文件摘要与分块摘要不一致: {fe['path']}")
    recomputed_root = merkle_root([(fe["path"], fe["digest"]) for fe in norm_files])
    if recomputed_root != root:
        raise ProofFormatError("root 摘要与文件清单重算结果不一致")
    if proof_id != root:
        raise ProofFormatError("proof_id 必须与 root 摘要一致")

    if not _nonneg_int(data.get("file_count")) or data["file_count"] != len(
        norm_files
    ):
        raise ProofFormatError("file_count 与文件清单不一致")

    return {
        "version": VERSION,
        "format": PROOF_FORMAT,
        "hash_algorithm": DIGEST,
        "chunk_size": CHUNK_SIZE,
        "proof_id": proof_id,
        "root": root,
        "file_count": len(norm_files),
        "files": norm_files,
    }


def _expected_chunk_count(size):
    if size == 0:
        return 0
    return (size + CHUNK_SIZE - 1) // CHUNK_SIZE


def _nonneg_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_hex32(value):
    if len(value) != 64:
        return False
    return all(c in "0123456789abcdef" for c in value)
