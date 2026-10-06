"""离线挑战凭证的导出与校验。

challenge-export：不接触 --state，按既有选样规则（proof_id + seed）抽出分块，
从 root 重读原块，生成自包含的 JSON 凭证，evidence 按全局块序排列，
由调用方原子写入 --output。

challenge-verify：不访问 root、不写任何文件，仅凭 proof 与凭证重放校验：
字段、Base64、长度、摘要、状态、证据顺序唯一性、判定与 challenge_id
重建全部一致才判通过；任何不符抛 ResponseFormatError。
"""

import base64
import binascii
import json
import os
import stat

from .challenge import _challenge_id, _flatten_chunks, select_indices
from .errors import ResponseFormatError, RootUnavailable
from .hashes import blake2b_hex
from .manifest import _is_hex32, _nonneg_int

RESPONSE_VERSION = 1
RESPONSE_FORMAT = "state-proof-challenge"

_STATUS_OK = "ok"
_STATUS_MISSING = "missing"
_STATUS_PARTIAL = "partial"
_STATUSES = {_STATUS_OK, _STATUS_MISSING, _STATUS_PARTIAL}

_REASONS = {"none", "retrieval_missing", "content_mismatch"}

_EVIDENCE_KEYS = (
    "path",
    "chunk_index",
    "offset",
    "size",
    "retrieval_status",
    "retrieved_size",
    "digest",
    "data",
)


def _resolve_path(root, rel_posix):
    return os.path.join(root, *rel_posix.split("/"))


def _check_root(root):
    if not isinstance(root, str) or not root:
        raise RootUnavailable("root 路径为空")
    if not os.path.exists(root):
        raise RootUnavailable(f"root 不存在: {root}")
    if not os.path.isdir(root):
        raise RootUnavailable(f"root 不是目录: {root}")
    if not os.access(root, os.R_OK | os.X_OK):
        raise RootUnavailable(f"root 不可访问: {root}")


def _read_chunk(abs_path, offset, size):
    """读取一个分块，返回 (retrieval_status, data)。

    文件缺失/不是普通文件/读失败 → (missing, b"")；
    短读（含 0 字节）→ (partial, 实际读到的字节)；完整 → (ok, 原块)。
    """
    try:
        st = os.lstat(abs_path)
        if not stat.S_ISREG(st.st_mode):
            return _STATUS_MISSING, b""
        with open(abs_path, "rb") as fh:
            fh.seek(offset)
            data = fh.read(size)
    except OSError:
        return _STATUS_MISSING, b""
    if len(data) < size:
        return _STATUS_PARTIAL, data
    return _STATUS_OK, data


def _verdict(has_missing, has_mismatch):
    if has_missing:
        return False, "retrieval_missing"
    if has_mismatch:
        return False, "content_mismatch"
    return True, "none"


def run_challenge_export(proof, root, seed_text, samples):
    """生成离线挑战凭证 dict（不更新状态、不写文件）。"""
    _check_root(root)

    flat = _flatten_chunks(proof)
    chosen = select_indices(len(flat), samples, proof["proof_id"], seed_text)

    evidence = []
    has_missing = False
    has_mismatch = False
    chunk_size = proof["chunk_size"]
    for gi in chosen:
        fe, chunk_idx, _ = flat[gi]
        rel = fe["path"]
        chunk = fe["chunks"][chunk_idx]
        offset = chunk_idx * chunk_size
        size = chunk["size"]
        status, data = _read_chunk(_resolve_path(root, rel), offset, size)

        entry = {
            "path": rel,
            "chunk_index": chunk_idx,
            "offset": offset,
            "size": size,
        }
        if status == _STATUS_MISSING:
            has_missing = True
            entry.update(
                {
                    "retrieval_status": _STATUS_MISSING,
                    "retrieved_size": 0,
                    "digest": None,
                    "data": None,
                }
            )
        else:
            digest = blake2b_hex(data)
            if status == _STATUS_PARTIAL or digest != chunk["digest"]:
                has_mismatch = True
            entry.update(
                {
                    "retrieval_status": status,
                    "retrieved_size": len(data),
                    "digest": digest,
                    "data": base64.b64encode(data).decode("ascii"),
                }
            )
        evidence.append(entry)

    valid, failure_reason = _verdict(has_missing, has_mismatch)
    challenge_id = _challenge_id(
        proof["proof_id"], seed_text, samples, chosen, valid, failure_reason
    )
    return {
        "version": RESPONSE_VERSION,
        "format": RESPONSE_FORMAT,
        "proof_id": proof["proof_id"],
        "challenge_id": challenge_id,
        "seed": seed_text,
        "samples": samples,
        "valid": valid,
        "failure_reason": failure_reason,
        "evidence": evidence,
    }


def load_response(path):
    """读取响应文件并做顶层结构校验；任何不符抛 ResponseFormatError。"""
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
    if data.get("version") != RESPONSE_VERSION:
        raise ResponseFormatError(f"不支持的响应版本: {data.get('version')!r}")
    if data.get("format") != RESPONSE_FORMAT:
        raise ResponseFormatError(f"响应格式标识非法: {data.get('format')!r}")
    return data


def _fail(message):
    raise ResponseFormatError(message)


def _check_evidence_entry(entry, index, expect):
    """校验单条证据的字段、Base64、长度、摘要与状态自洽；返回原始字节或 None。"""
    if not isinstance(entry, dict):
        _fail(f"evidence[{index}] 必须是对象")
    for key in _EVIDENCE_KEYS:
        if key not in entry:
            _fail(f"evidence[{index}] 缺少字段 {key}")
    if entry["path"] != expect["path"] or entry["chunk_index"] != expect["chunk_index"]:
        _fail(f"evidence[{index}] 顺序或分块与选样不符")
    if entry["offset"] != expect["offset"] or entry["size"] != expect["size"]:
        _fail(f"evidence[{index}] offset/size 与证明不符")

    status = entry["retrieval_status"]
    if status not in _STATUSES:
        _fail(f"evidence[{index}] retrieval_status 非法: {status!r}")
    retrieved_size = entry["retrieved_size"]
    if not _nonneg_int(retrieved_size):
        _fail(f"evidence[{index}] retrieved_size 非法")
    digest = entry["digest"]
    data = entry["data"]

    if status == _STATUS_MISSING:
        if retrieved_size != 0 or digest is not None or data is not None:
            _fail(f"evidence[{index}] missing 条目的 retrieved_size/digest/data 必须为零值")
        return None

    if not isinstance(digest, str) or not _is_hex32(digest):
        _fail(f"evidence[{index}] digest 必须是 64 位小写十六进制")
    if not isinstance(data, str):
        _fail(f"evidence[{index}] data 必须是 Base64 字符串")
    try:
        raw = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        _fail(f"evidence[{index}] data 不是合法 Base64")
    if len(raw) != retrieved_size:
        _fail(f"evidence[{index}] retrieved_size 与 data 长度不符")
    if blake2b_hex(raw) != digest:
        _fail(f"evidence[{index}] digest 与 data 实际摘要不符")
    if status == _STATUS_OK:
        if retrieved_size != expect["size"]:
            _fail(f"evidence[{index}] ok 条目的 retrieved_size 必须等于 size")
    elif retrieved_size >= expect["size"]:
        _fail(f"evidence[{index}] partial 条目的 retrieved_size 必须小于 size")
    return raw


def run_challenge_verify(proof, response):
    """仅凭 proof 重放校验响应凭证，返回唯一判定的挑战结果 dict。"""
    proof_id = proof["proof_id"]
    if response.get("proof_id") != proof_id:
        _fail("响应 proof_id 与证明不一致")
    seed = response.get("seed")
    if not isinstance(seed, str) or seed == "":
        _fail("响应 seed 非法")
    samples = response.get("samples")
    if (
        not isinstance(samples, int)
        or isinstance(samples, bool)
        or samples <= 0
    ):
        _fail("响应 samples 必须是正整数")
    valid = response.get("valid")
    if not isinstance(valid, bool):
        _fail("响应 valid 非法")
    reason = response.get("failure_reason")
    if reason not in _REASONS:
        _fail(f"响应 failure_reason 非法: {reason!r}")
    evidence = response.get("evidence")
    if not isinstance(evidence, list):
        _fail("evidence 必须是数组")

    flat = _flatten_chunks(proof)
    # 越界（无分块或 samples 超过总分块数）抛 ChallengeRangeError。
    chosen = select_indices(len(flat), samples, proof_id, seed)
    if len(evidence) != len(chosen):
        _fail("evidence 数量与选样数不一致")

    chunk_size = proof["chunk_size"]
    missing_refs = []
    mismatched_refs = []
    checked = 0
    for i, gi in enumerate(chosen):
        fe, chunk_idx, _ = flat[gi]
        chunk = fe["chunks"][chunk_idx]
        expect = {
            "path": fe["path"],
            "chunk_index": chunk_idx,
            "offset": chunk_idx * chunk_size,
            "size": chunk["size"],
        }
        raw = _check_evidence_entry(evidence[i], i, expect)
        ref = {"path": fe["path"], "chunk_index": chunk_idx}
        if raw is None:
            missing_refs.append(ref)
        else:
            checked += 1
            status = evidence[i]["retrieval_status"]
            if status == _STATUS_PARTIAL or evidence[i]["digest"] != chunk["digest"]:
                mismatched_refs.append(ref)

    # 判定由证据唯一重建，响应自报的 valid/failure_reason 必须与之相符。
    r_valid, r_reason = _verdict(bool(missing_refs), bool(mismatched_refs))
    if valid != r_valid or reason != r_reason:
        _fail("响应 valid/failure_reason 与证据重建结果不一致")

    challenge_id = response.get("challenge_id")
    if not isinstance(challenge_id, str) or not _is_hex32(challenge_id):
        _fail("响应 challenge_id 非法")
    expected_id = _challenge_id(proof_id, seed, samples, chosen, r_valid, r_reason)
    if challenge_id != expected_id:
        _fail("响应 challenge_id 与重建结果不一致")

    return {
        "proof_id": proof_id,
        "challenge_id": challenge_id,
        "seed": seed,
        "samples": samples,
        "checked_samples": checked,
        "missing_samples": missing_refs,
        "mismatched_samples": mismatched_refs,
        "valid": r_valid,
        "failure_reason": r_reason,
    }
