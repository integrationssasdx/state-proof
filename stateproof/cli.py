"""proof 命令行入口：generate / challenge / challenge-export / challenge-verify /
status / audit / reconcile / proof-diff / coverage-report。

成功：stdout 输出 JSON，退出码 0。
受控失败：stderr 输出 {"error": {...}}，error.type 取
InputError / RootUnavailable / ProofFormatError /
ChallengeRangeError / ResponseFormatError / StateConflict，退出码 2。
"""

import argparse
import json
import os
import sys

from . import __version__
from .atomicio import atomic_write_json
from .audit import run_audit
from .challenge import parse_samples, run_challenge
from .challenge_export import run_challenge_export, run_challenge_verify
from .challenge_import import run_challenge_import
from .coverage import coverage_report
from .errors import InputError, StateProofError
from .manifest import build_proof, load_proof
from .proof_diff import diff_proofs
from .reconcile import run_reconcile
from .state import read_status


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError(message)

    def exit(self, status=0, message=None):  # noqa: D401 - argparse 不走到这里
        if status != 0:
            raise InputError((message or "").strip() or "参数错误")
        raise SystemExit(0)


def _emit(obj, stream):
    json.dump(obj, stream, ensure_ascii=False, indent=2)
    stream.write("\n")


def build_parser():
    parser = _Parser(prog="proof", add_help=True)
    parser.add_argument("--version", action="version", version=f"stateproof {__version__}")
    sub = parser.add_subparsers(dest="command")

    g = sub.add_parser("generate", add_help=True)
    g.add_argument("--root", required=True)
    g.add_argument("--proof", required=True)

    c = sub.add_parser("challenge", add_help=True)
    c.add_argument("--proof", required=True)
    c.add_argument("--root", required=True)
    c.add_argument("--state", required=True)
    c.add_argument("--seed", required=True)
    c.add_argument("--samples", required=True)

    ce = sub.add_parser("challenge-export", add_help=True)
    ce.add_argument("--proof", required=True)
    ce.add_argument("--root", required=True)
    ce.add_argument("--seed", required=True)
    ce.add_argument("--samples", required=True)
    ce.add_argument("--output", required=True)

    cv = sub.add_parser("challenge-verify", add_help=True)
    cv.add_argument("--proof", required=True)
    cv.add_argument("--response", required=True)

    ci = sub.add_parser("challenge-import", add_help=True)
    ci.add_argument("--proof", required=True)
    ci.add_argument("--state", required=True)
    ci.add_argument("--response", required=True)

    s = sub.add_parser("status", add_help=True)
    s.add_argument("--state", required=True)

    a = sub.add_parser("audit", add_help=True)
    a.add_argument("--proof", required=True)
    a.add_argument("--root", required=True)

    r = sub.add_parser("reconcile", add_help=True)
    r.add_argument("--proof", required=True)
    r.add_argument("--root", required=True)

    pd = sub.add_parser("proof-diff", add_help=True)
    pd.add_argument("--before", required=True)
    pd.add_argument("--after", required=True)

    cr = sub.add_parser("coverage-report", add_help=True)
    cr.add_argument("--proof", required=True)
    cr.add_argument("--state", required=True)
    return parser


def _require(value, flag):
    if value is None or str(value).strip() == "":
        raise InputError(f"缺少 {flag} 或其值为空")
    return value


def cmd_generate(args):
    root = _require(args.root, "--root")
    proof_path = _require(args.proof, "--proof")
    proof = build_proof(root)
    atomic_write_json(proof_path, proof)
    total_chunks = sum(len(fe["chunks"]) for fe in proof["files"])
    return {
        "version": proof["version"],
        "format": proof["format"],
        "proof_id": proof["proof_id"],
        "root_digest": proof["root"],
        "hash_algorithm": proof["hash_algorithm"],
        "chunk_size": proof["chunk_size"],
        "file_count": proof["file_count"],
        "chunk_count": total_chunks,
        "proof_path": proof_path,
    }


def cmd_challenge(args):
    proof_path = _require(args.proof, "--proof")
    root = _require(args.root, "--root")
    state_path = _require(args.state, "--state")
    seed = _require(args.seed, "--seed")
    samples = parse_samples(args.samples)
    proof = load_proof(proof_path)
    return run_challenge(proof, root, seed, samples, state_path)


def cmd_challenge_export(args):
    proof_path = _require(args.proof, "--proof")
    root = _require(args.root, "--root")
    seed = _require(args.seed, "--seed")
    samples = parse_samples(args.samples)
    output_path = _require(args.output, "--output")
    if os.path.abspath(output_path) == os.path.abspath(proof_path):
        raise InputError("--output 不能与 --proof 指向同一文件")
    proof = load_proof(proof_path)
    return run_challenge_export(proof, root, seed, samples, output_path)


def cmd_challenge_verify(args):
    proof_path = _require(args.proof, "--proof")
    response_path = _require(args.response, "--response")
    proof = load_proof(proof_path)
    return run_challenge_verify(proof, response_path)


def cmd_challenge_import(args):
    proof_path = _require(args.proof, "--proof")
    state_path = _require(args.state, "--state")
    response_path = _require(args.response, "--response")
    # 只读 proof、response，原子写 state；不访问 root。
    proof = load_proof(proof_path)
    return run_challenge_import(proof, state_path, response_path)


def cmd_status(args):
    state_path = _require(args.state, "--state")
    return read_status(state_path)


def cmd_audit(args):
    proof_path = _require(args.proof, "--proof")
    root = _require(args.root, "--root")
    proof = load_proof(proof_path)
    return run_audit(proof, root)


def cmd_reconcile(args):
    proof_path = _require(args.proof, "--proof")
    root = _require(args.root, "--root")
    # 证明校验优先于 root 可用性检查（load_proof 在 scan_root 之前）。
    proof = load_proof(proof_path)
    return run_reconcile(proof, root)


def cmd_proof_diff(args):
    before_path = _require(args.before, "--before")
    after_path = _require(args.after, "--after")
    # 先验 before 再验 after：两者都非法时报 before 的错误。
    before = load_proof(before_path)
    after = load_proof(after_path)
    return diff_proofs(before, after)


def cmd_coverage_report(args):
    proof_path = _require(args.proof, "--proof")
    state_path = _require(args.state, "--state")
    # 只读：先严格校验证明，再按该 proof_id 校验状态历史；不访问 root。
    proof = load_proof(proof_path)
    return coverage_report(proof, state_path)


_HANDLERS = {
    "generate": cmd_generate,
    "challenge": cmd_challenge,
    "challenge-export": cmd_challenge_export,
    "challenge-verify": cmd_challenge_verify,
    "challenge-import": cmd_challenge_import,
    "status": cmd_status,
    "audit": cmd_audit,
    "reconcile": cmd_reconcile,
    "proof-diff": cmd_proof_diff,
    "coverage-report": cmd_coverage_report,
}


def main(argv=None):
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        if not args.command:
            raise InputError(
                "缺少子命令：generate | challenge | challenge-export | "
                "challenge-verify | challenge-import | status | audit | "
                "reconcile | proof-diff | coverage-report"
            )
        result = _HANDLERS[args.command](args)
    except StateProofError as exc:
        _emit({"error": exc.to_dict()}, sys.stderr)
        return 2
    _emit(result, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
