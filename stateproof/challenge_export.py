"""离线挑战凭证的导出（challenge-export）与校验（challenge-verify）。

challenge-export 复用与 challenge 相同的确定性选样，按全局块序重读 root 下
被抽中的分块，生成自包含的 JSON 凭证（format=state-proof-challenge）并原子写入
--output；不接触任何状态文件。challenge-verify 不访问 root、不写任何文件，
仅凭证明重建选样，逐条核对证据的字段、顺序、Base64、长度与摘要，重建议定与
challenge_id，任何不一致均判 ResponseFormatError。

证据条目的 retrieval_status：
- ok：完整读回 size 字节，data 为原块 Base64，digest 为实际 BLAKE2b-256；
- missing：文件缺失/非普通文件/读失败，retrieved_size=0，digest=data=null；
- partial：短读，data 为短块 Base64，digest 为短块实际摘要。

判定优先级与 challenge 一致：missing→retrieval_missing；
partial 或摘要不符→content_mismatch；全部一致→none。
"""

import base64
import binascii
import json
import os
import stat

from .atomicio import atomic_write_json
from .challenge import _challenge_id, _flatten_chunks, _resolve_path, select_indices
from .errors import InputError, ResponseFormatError
from .hashes import blake2b_hex
from .manifest import scan_root

VERSION = 1
CHALLENGE_FORMAT = "state-proof-challenge"
_VALID_REASONS = {"none", "retrieval_missing", "content_mismatch"}
_STATUSES = {"ok", "missing", "partial"}


def _judge(statuses_match):
    """statuses_match: [(status, digest_matches_expected)] → (valid, failure_reason)。"""
    if any(status == "missing" for status, _ in statuses_match):
        return False, "retrieval_missing"
    if any(status == "partial" or not match for status, match in statuses_match):
        return False, "content_mismatch"
    return True, "none"


def _read_chunk(root, rel, offset, size):
    """读取一个分块，返回 (status, data|None)；OSError/非普通文件一律 missing。"""
    abs_path = _resolve_path(root, rel)
    try:
        st = os.lstat(abs_path)
        if not stat.S_ISREG(st.st_mode):
            return "missing", None
        with open(abs_path, "rb") as fh:
            fh.seek(offset)
            data = fh.read(size)
    except OSError:
        return "missing", None
    if len(data) == size:
        return "ok", data
    return "partial", data


def run_challenge_export(proof, root, seed, samples, output_path):
    """生成离线挑战凭证并原子写入 output_path，返回 stdout 摘要 dict。"""
    scan_root(root)  # root 不存在/非目录/不可读/扫描失败 → RootUnavailable
    if seed is None or str(seed) == "":
        raise InputError("缺少 --seed 或 seed 为空")
    seed_text = str(seed)

    flat = _flatten_chunks(proof)
    chosen = select_indices(len(flat), samples, proof["proof_id"], seed_text)

    chunk_size = proof["chunk_size"]
    evidence = []
    statuses_match = []
    for gi in chosen:
        fe, chunk_idx, _ = flat[gi]
        chunk = fe["chunks"][chunk_idx]
        offset = chunk_idx * chunk_size
        size = chunk["size"]
        status, data = _read_chunk(root, fe["path"], offset, size)
        digest = blake2b_hex(data) if data is not None else None
        evidence.append(
            {
                "path": fe["path"],
                "chunk_index": chunk_idx,
                "offset": offset,
                "size": size,
                "retrieval_status": status,
                "retrieved_size": len(data) if data is not None else 0,
                "digest": digest,
                "data": base64.b64encode(data).decode("ascii")
                if data is not None
                else None,
            }
        )
        statuses_match.append((status, digest == chunk["digest"]))

    valid, failure_reason = _judge(statuses_match)
    challenge_id = _challenge_id(
        proof["proof_id"], seed_text, samples, chosen, valid, failure_reason
    )
    response = {
        "version": VERSION,
        "format": CHALLENGE_FORMAT,
        "proof_id": proof["proof_id"],
        "challenge_id": challenge_id,
        "seed": seed_text,
        "samples": samples,
        "valid": valid,
        "failure_reason": failure_reason,
        "evidence": evidence,
    }
    atomic_write_json(output_path, response)

    return {
        "proof_id": proof["proof_id"],
        "challenge_id": challenge_id,
        "seed": seed_text,
        "samples": samples,
        "valid": valid,
        "failure_reason": failure_reason,
        "output": output_path,
    }


def _load_response(path):
    if not isinstance(path, str) or not path:
        raise ResponseFormatError("response 路径为空")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError as exc:
        raise ResponseFormatError(f"响应文件不存在: {path}") from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ResponseFormatError(f"响应文件不可解析: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ResponseFormatError("响应顶层结构必须是对象")
    return data


def _is_hex32(value):
    return isinstance(value, str) and len(value) == 64 and all(
        c in "0123456789abcdef" for c in value
    )


def _nonneg_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _decode_data(value, index):
    """校验 Base64 字符串并解码；非法抛 ResponseFormatError。"""
    if not isinstance(value, str):
        raise ResponseFormatError(f"evidence[{index}].data 必须是 Base64 字符串")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ResponseFormatError(f"evidence[{index}].data 不是合法 Base64") from exc


def _check_evidence_entry(entry, index, fe, chunk_idx, chunk_size):
    """逐字段核对一条证据，返回 (status, digest_matches_expected)。"""
    where = f"evidence[{index}]"
    if not isinstance(entry, dict):
        raise ResponseFormatError(f"{where} 必须是对象")
    chunk = fe["chunks"][chunk_idx]
    # 顺序唯一：第 index 条必须恰好对应重建选样的第 index 个全局分块。
    if entry.get("path") != fe["path"] or entry.get("chunk_index") != chunk_idx:
        raise ResponseFormatError(
            f"{where} 的 path/chunk_index 与重建选样顺序不符"
        )
    if entry.get("offset") != chunk_idx * chunk_size:
        raise ResponseFormatError(f"{where}.offset 与块偏移不符")
    if entry.get("size") != chunk["size"]:
        raise ResponseFormatError(f"{where}.size 与证明块长不符")

    status = entry.get("retrieval_status")
    if status not in _STATUSES:
        raise ResponseFormatError(f"{where}.retrieval_status 非法")
    retrieved_size = entry.get("retrieved_size")
    if not _nonneg_int(retrieved_size):
        raise ResponseFormatError(f"{where}.retrieved_size 非法")

    if status == "missing":
        if retrieved_size != 0:
            raise ResponseFormatError(f"{where} missing 但 retrieved_size 非 0")
        if entry.get("digest") is not None or entry.get("data") is not None:
            raise ResponseFormatError(f"{where} missing 时 digest/data 必须为 null")
        return status, False

    raw = _decode_data(entry.get("data"), index)
    if len(raw) != retrieved_size:
        raise ResponseFormatError(f"{where}.retrieved_size 与 data 长度不符")
    if status == "ok" and retrieved_size != chunk["size"]:
        raise ResponseFormatError(f"{where} ok 但长度不等于块长")
    if status == "partial" and not retrieved_size < chunk["size"]:
        raise ResponseFormatError(f"{where} partial 但长度不短于块长")
    digest = entry.get("digest")
    if not _is_hex32(digest):
        raise ResponseFormatError(f"{where}.digest 非法")
    if digest != blake2b_hex(raw):
        raise ResponseFormatError(f"{where}.digest 与 data 实际摘要不符")
    return status, digest == chunk["digest"]


def run_challenge_verify(proof, response_path):
    """校验离线挑战凭证，返回判定 dict；任何不合法抛 ResponseFormatError。"""
    resp = _load_response(response_path)

    if resp.get("version") != VERSION:
        raise ResponseFormatError(f"不支持的响应版本: {resp.get('version')!r}")
    if resp.get("format") != CHALLENGE_FORMAT:
        raise ResponseFormatError(f"响应格式标识非法: {resp.get('format')!r}")
    if resp.get("proof_id") != proof["proof_id"]:
        raise ResponseFormatError("响应 proof_id 与证明不一致")
    seed = resp.get("seed")
    if not isinstance(seed, str) or seed == "":
        raise ResponseFormatError("响应 seed 非法")
    samples = resp.get("samples")
    if not _nonneg_int(samples) or samples <= 0:
        raise ResponseFormatError("响应 samples 必须是正整数")
    valid = resp.get("valid")
    if not isinstance(valid, bool):
        raise ResponseFormatError("响应 valid 非法")
    failure_reason = resp.get("failure_reason")
    if failure_reason not in _VALID_REASONS:
        raise ResponseFormatError("响应 failure_reason 非法")
    if valid != (failure_reason == "none"):
        raise ResponseFormatError("响应 valid 与 failure_reason 矛盾")
    challenge_id = resp.get("challenge_id")
    if not _is_hex32(challenge_id):
        raise ResponseFormatError("响应 challenge_id 非法")
    evidence = resp.get("evidence")
    if not isinstance(evidence, list):
        raise ResponseFormatError("响应 evidence 必须是数组")

    # 仅凭证明重建选样；无分块或 samples 越界 → ChallengeRangeError。
    flat = _flatten_chunks(proof)
    chosen = select_indices(len(flat), samples, proof["proof_id"], seed)
    if len(evidence) != len(chosen):
        raise ResponseFormatError(
            f"evidence 数量 {len(evidence)} 与重建选样 {len(chosen)} 不符"
        )

    statuses_match = []
    for i, gi in enumerate(chosen):
        fe, chunk_idx, _ = flat[gi]
        statuses_match.append(
            _check_evidence_entry(evidence[i], i, fe, chunk_idx, proof["chunk_size"])
        )

    # 重建议定与 challenge_id，响应声明必须与之完全一致。
    rebuilt_valid, rebuilt_reason = _judge(statuses_match)
    if valid != rebuilt_valid or failure_reason != rebuilt_reason:
        raise ResponseFormatError("响应判定与证据重建结果不一致")
    expected_id = _challenge_id(
        proof["proof_id"], seed, samples, chosen, rebuilt_valid, rebuilt_reason
    )
    if challenge_id != expected_id:
        raise ResponseFormatError("响应 challenge_id 与重建结果不一致")

    return {
        "proof_id": proof["proof_id"],
        "challenge_id": challenge_id,
        "seed": seed,
        "samples": samples,
        "valid": rebuilt_valid,
        "failure_reason": rebuilt_reason,
        "verdict": "valid" if rebuilt_valid else "invalid",
    }
