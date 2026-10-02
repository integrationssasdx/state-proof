"""BLAKE2b-256 摘要与 Merkle 聚合。

- 分块摘要：直接对 64 KiB 数据块做 BLAKE2b-256。
- 文件摘要：对同一文件全部分块摘要按序做 BLAKE2b-256（空文件为对空字节的摘要）。
- Merkle 根：按 POSIX 相对路径排序后，将每个条目的
  ``b"<路径 UTF-8>:<文件摘要>"`` 依次喂入同一个 BLAKE2b-256（空树为对空字节的摘要）。

所有摘要以小写十六进制表示，同输入必得同输出。
"""

import hashlib

DIGEST = "blake2b-256"
CHUNK_SIZE = 64 * 1024


def blake2b_hex(data=b""):
    return hashlib.blake2b(data, digest_size=32).hexdigest()


def file_digest_from_chunk_hashes(chunk_hashes):
    """由有序的分块摘要（hex 字符串）计算文件摘要。"""
    h = hashlib.blake2b(digest_size=32)
    for ch in chunk_hashes:
        h.update(ch.encode("ascii"))
    return h.hexdigest()


def merkle_root(entries):
    """entries: 按 POSIX 相对路径排序的 (path, file_digest_hex) 列表。"""
    h = hashlib.blake2b(digest_size=32)
    for path, digest_hex in entries:
        h.update(path.encode("utf-8"))
        h.update(b":")
        h.update(digest_hex.encode("ascii"))
    return h.hexdigest()


def hash_file_chunks(fh):
    """重读一个已打开的普通文件，返回 (分块摘要列表, 文件大小)。

    调用方负责文件的打开与关闭；任何 OSError 向上抛出。
    """
    chunk_hashes = []
    size = 0
    while True:
        data = fh.read(CHUNK_SIZE)
        if not data:
            break
        size += len(data)
        chunk_hashes.append(blake2b_hex(data))
    return chunk_hashes, size
