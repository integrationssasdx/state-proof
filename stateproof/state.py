"""挑战状态文件的读取、累积与原子写入。

状态文件为单个 proof 私有：用其 proof_id 锚定。拿同一状态文件去跑另一个证明、
文件被损坏（JSON/结构/字段非法）或同一 challenge_id 复跑结果不一致，均判
StateConflict。聚合数以 history 为唯一事实来源，手改汇总字段无效。

history 支持两种记录形态，语义等价、共同排序与计数：
- 在线挑战（challenge）：字段 requested_samples + challenged_at；
- 离线导入（challenge-import）：字段 samples + imported_at。
其余字段（challenge_id/seed/checked/missing/mismatched/valid/failure_reason）
两种形态完全一致。读取时接受字段名不同的同形记录（如手改时间戳键名），写回时
保留首次写入的形态，使复跑/覆盖报告能纳入既有记录。
"""

import json
import os
from datetime import datetime, timezone

from .atomicio import atomic_write_json
from .errors import StateConflict

VERSION = 1
STATE_FORMAT = "state-proof-state"
_VALID_REASONS = {"none", "retrieval_missing", "content_mismatch"}


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _empty_container(proof_id):
    return {
        "version": VERSION,
        "format": STATE_FORMAT,
        "proof_id": proof_id,
        "total_challenges": 0,
        "last_challenge_id": None,
        "last_seed": None,
        "last_valid": None,
        "last_failure_reason": None,
        "requested_samples": 0,
        "checked_samples": 0,
        "missing_samples": 0,
        "mismatched_samples": 0,
        "last_challenge_at": None,
        "history": [],
    }


def _nonneg_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


_COUNT_KEYS = ("checked_samples", "missing_samples", "mismatched_samples")


def _normalize_record(rec, index, path):
    if not isinstance(rec, dict):
        raise StateConflict(f"状态历史第 {index} 条不是对象: {path}")
    cid = rec.get("challenge_id")
    if not isinstance(cid, str) or not cid:
        raise StateConflict(f"状态历史第 {index} 条 challenge_id 非法: {path}")
    # 样本数两种形态恰取其一：在线 requested_samples，导入 samples；
    # 时间戳与之配对：challenged_at / imported_at，混搭或皆缺皆非法。
    has_online_n = "requested_samples" in rec
    has_import_n = "samples" in rec
    if has_online_n == has_import_n:
        raise StateConflict(
            f"状态历史第 {index} 条样本数字段形态非法: {path}"
        )
    shape = "challenge" if has_online_n else "import"
    samples = rec["requested_samples"] if has_online_n else rec["samples"]
    if not _nonneg_int(samples):
        raise StateConflict(f"状态历史第 {index} 条样本数非法: {path}")
    for key in _COUNT_KEYS:
        if not _nonneg_int(rec.get(key)):
            raise StateConflict(f"状态历史第 {index} 条 {key} 非法: {path}")
    if not isinstance(rec.get("valid"), bool):
        raise StateConflict(f"状态历史第 {index} 条 valid 非法: {path}")
    reason = rec.get("failure_reason")
    if reason not in _VALID_REASONS:
        raise StateConflict(f"状态历史第 {index} 条 failure_reason 非法: {path}")
    if not isinstance(rec.get("seed"), str):
        raise StateConflict(f"状态历史第 {index} 条 seed 非法: {path}")
    ts_key = "challenged_at" if shape == "challenge" else "imported_at"
    other_ts = "imported_at" if shape == "challenge" else "challenged_at"
    if other_ts in rec or not isinstance(rec.get(ts_key), str):
        raise StateConflict(f"状态历史第 {index} 条时间戳形态非法: {path}")
    # 跨字段语义一致性：每个抽中的分块要么缺失（missing），要么被读到（checked）；
    # 读到但摘要不符的构成 mismatched（checked 的子集）。
    requested, checked = samples, rec["checked_samples"]
    missing, mismatched = rec["missing_samples"], rec["mismatched_samples"]
    if checked + missing != requested or mismatched > checked:
        raise StateConflict(f"状态历史第 {index} 条样本计数不一致: {path}")
    valid = rec["valid"]
    if valid:
        if reason != "none" or missing or mismatched or checked != requested:
            raise StateConflict(f"状态历史第 {index} 条 valid 与计数矛盾: {path}")
    elif reason == "retrieval_missing":
        if missing == 0:
            raise StateConflict(f"状态历史第 {index} 条缺少缺失计数: {path}")
    elif reason == "content_mismatch":
        if missing != 0 or mismatched == 0:
            raise StateConflict(f"状态历史第 {index} 条不匹配计数矛盾: {path}")
    return {
        "shape": shape,
        "challenge_id": cid,
        "seed": rec["seed"],
        "requested_samples": requested,
        "checked_samples": rec["checked_samples"],
        "missing_samples": rec["missing_samples"],
        "mismatched_samples": rec["mismatched_samples"],
        "valid": rec["valid"],
        "failure_reason": reason,
        "challenged_at": rec[ts_key],
    }


def _serialize_record(rec):
    """内部规范记录 → 落盘形态：导入记录写 samples/imported_at。"""
    out = {
        "challenge_id": rec["challenge_id"],
        "seed": rec["seed"],
    }
    if rec["shape"] == "import":
        out["samples"] = rec["requested_samples"]
    else:
        out["requested_samples"] = rec["requested_samples"]
    out["checked_samples"] = rec["checked_samples"]
    out["missing_samples"] = rec["missing_samples"]
    out["mismatched_samples"] = rec["mismatched_samples"]
    out["valid"] = rec["valid"]
    out["failure_reason"] = rec["failure_reason"]
    if rec["shape"] == "import":
        out["imported_at"] = rec["challenged_at"]
    else:
        out["challenged_at"] = rec["challenged_at"]
    return out


def parse_state_file(path, expected_proof_id=None):
    """读取并规范化状态文件。不存在返回 None；损坏/冲突抛 StateConflict。"""
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StateConflict(f"状态文件不可解析: {path}: {exc}") from exc

    if not isinstance(data, dict) or data.get("format") != STATE_FORMAT:
        raise StateConflict(f"状态文件格式非法: {path}")
    if data.get("version") != VERSION:
        raise StateConflict(f"状态文件版本不受支持: {data.get('version')!r}")
    proof_id = data.get("proof_id")
    if not isinstance(proof_id, str) or len(proof_id) != 64:
        raise StateConflict(f"状态文件 proof_id 非法: {path}")
    if expected_proof_id is not None and proof_id != expected_proof_id:
        raise StateConflict(
            "状态文件属于不同 proof_id",
            details={"state_proof_id": proof_id, "proof_id": expected_proof_id},
        )
    history = data.get("history")
    if not isinstance(history, list):
        raise StateConflict(f"状态文件 history 非法: {path}")

    container = _empty_container(proof_id)
    seen_ids = set()
    for i, raw in enumerate(history):
        rec = _normalize_record(raw, i, path)
        if rec["challenge_id"] in seen_ids:
            raise StateConflict(
                f"状态历史第 {i} 条 challenge_id 重复: {path}"
            )
        seen_ids.add(rec["challenge_id"])
        container["history"].append(rec)
        container["total_challenges"] += 1
        container["requested_samples"] += rec["requested_samples"]
        container["checked_samples"] += rec["checked_samples"]
        container["missing_samples"] += rec["missing_samples"]
        container["mismatched_samples"] += rec["mismatched_samples"]

    if container["history"]:
        last = container["history"][-1]
        container["last_challenge_id"] = last["challenge_id"]
        container["last_seed"] = last["seed"]
        container["last_valid"] = last["valid"]
        container["last_failure_reason"] = last["failure_reason"]
        container["last_challenge_at"] = last["challenged_at"]
    elif (
        data.get("total_challenges") not in (None, 0)
        or data.get("last_challenge_id") is not None
    ):
        raise StateConflict(f"状态汇总与空历史矛盾: {path}")
    return container


def load_state(path, proof_id, challenge_id, result):
    """读取状态并入本次在线挑战结果；幂等：同一 challenge_id 且结果一致不重复计数。"""
    state = parse_state_file(path, expected_proof_id=proof_id)
    if state is None:
        state = _empty_container(proof_id)

    record = {
        "shape": "challenge",
        "challenge_id": challenge_id,
        "seed": result["seed"],
        "requested_samples": result["requested_samples"],
        "checked_samples": result["checked_samples"],
        "missing_samples": len(result["missing_samples"]),
        "mismatched_samples": len(result["mismatched_samples"]),
        "valid": result["valid"],
        "failure_reason": result["failure_reason"],
        "challenged_at": _now_iso(),
    }

    previous = next(
        (r for r in state["history"] if r["challenge_id"] == challenge_id), None
    )
    if previous is not None:
        if not _same_outcome(previous, record):
            raise StateConflict(
                "状态冲突：同一 challenge_id 的既有结果与本次不一致",
                details={"challenge_id": challenge_id, "state": path},
            )
        # 幂等复跑：不重复计数。
    else:
        state["history"].append(record)
        state["total_challenges"] += 1
        state["requested_samples"] += record["requested_samples"]
        state["checked_samples"] += record["checked_samples"]
        state["missing_samples"] += record["missing_samples"]
        state["mismatched_samples"] += record["mismatched_samples"]

    state["last_challenge_id"] = challenge_id
    state["last_seed"] = record["seed"]
    state["last_valid"] = record["valid"]
    state["last_failure_reason"] = record["failure_reason"]
    state["last_challenge_at"] = record["challenged_at"]
    return state


def import_state(path, proof_id, challenge_id, outcome):
    """把一次离线导入结果并入状态，返回 (state, imported)。

    outcome 含 seed、samples、checked_samples、missing_samples、
    mismatched_samples（后两者为引用列表）、valid、failure_reason。
    同一 challenge_id 且计数判定一致：imported=False，不追加、不改写文件；
    同一 challenge_id 但结果不一致：StateConflict。
    """
    state = parse_state_file(path, expected_proof_id=proof_id)
    if state is None:
        state = _empty_container(proof_id)

    record = {
        "shape": "import",
        "challenge_id": challenge_id,
        "seed": outcome["seed"],
        "requested_samples": outcome["samples"],
        "checked_samples": len(outcome["checked_samples"]),
        "missing_samples": len(outcome["missing_samples"]),
        "mismatched_samples": len(outcome["mismatched_samples"]),
        "valid": outcome["valid"],
        "failure_reason": outcome["failure_reason"],
        "challenged_at": _now_iso(),
    }

    previous = next(
        (r for r in state["history"] if r["challenge_id"] == challenge_id), None
    )
    if previous is not None:
        if not _same_outcome(previous, record):
            raise StateConflict(
                "状态冲突：同一 challenge_id 的既有结果与导入响应不一致",
                details={"challenge_id": challenge_id, "state": path},
            )
        return state, False

    state["history"].append(record)
    state["total_challenges"] += 1
    state["requested_samples"] += record["requested_samples"]
    state["checked_samples"] += record["checked_samples"]
    state["missing_samples"] += record["missing_samples"]
    state["mismatched_samples"] += record["mismatched_samples"]
    state["last_challenge_id"] = challenge_id
    state["last_seed"] = record["seed"]
    state["last_valid"] = record["valid"]
    state["last_failure_reason"] = record["failure_reason"]
    state["last_challenge_at"] = record["challenged_at"]
    return state, True


def _same_outcome(a, b):
    keys = (
        "seed",
        "requested_samples",
        "checked_samples",
        "missing_samples",
        "mismatched_samples",
        "valid",
        "failure_reason",
    )
    return all(a.get(k) == b.get(k) for k in keys)


def save_state(path, state):
    """原子写入：同目录临时文件 + fsync + os.replace，失败不留半成品。

    history 按各记录首次写入的形态落盘（requested_samples/challenged_at 或
    samples/imported_at），内部规范字段不直接写出。
    """
    payload = dict(state)
    payload["history"] = [_serialize_record(rec) for rec in state["history"]]
    atomic_write_json(path, payload)


def read_status(path):
    """status 子命令：无状态文件返回 []；否则返回含一个 proof 状态的数组。"""
    state = parse_state_file(path)
    if state is None:
        return []
    status = "unknown"
    if state["last_valid"] is True:
        status = "valid"
    elif state["last_valid"] is False:
        status = "invalid"
    return [
        {
            "proof_id": state["proof_id"],
            "status": status,
            "total_challenges": state["total_challenges"],
            "last_challenge_at": state["last_challenge_at"],
            "last_challenge_id": state["last_challenge_id"],
            "last_seed": state["last_seed"],
            "last_failure_reason": state["last_failure_reason"],
            "requested_samples": state["requested_samples"],
            "checked_samples": state["checked_samples"],
            "missing_samples": state["missing_samples"],
            "mismatched_samples": state["mismatched_samples"],
        }
    ]
