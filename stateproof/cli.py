"""proof 命令行入口：generate / challenge / status / audit / reconcile。

成功：stdout 输出 JSON，退出码 0。
受控失败：stderr 输出 {"error": {...}}，error.type 取
InputError / RootUnavailable / ProofFormatError /
ChallengeRangeError / StateConflict，退出码 2。
"""

import argparse
import json
import sys

from . import __version__
from .atomicio import atomic_write_json
from .audit import run_audit
from .challenge import parse_samples, run_challenge
from .errors import InputError, StateProofError
from .manifest import build_proof, load_proof
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

    s = sub.add_parser("status", add_help=True)
    s.add_argument("--state", required=True)

    a = sub.add_parser("audit", add_help=True)
    a.add_argument("--proof", required=True)
    a.add_argument("--root", required=True)

    r = sub.add_parser("reconcile", add_help=True)
    r.add_argument("--proof", required=True)
    r.add_argument("--root", required=True)
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


_HANDLERS = {
    "generate": cmd_generate,
    "challenge": cmd_challenge,
    "status": cmd_status,
    "audit": cmd_audit,
    "reconcile": cmd_reconcile,
}


def main(argv=None):
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        if not args.command:
            raise InputError("缺少子命令：generate | challenge | status | audit | reconcile")
        result = _HANDLERS[args.command](args)
    except StateProofError as exc:
        _emit({"error": exc.to_dict()}, sys.stderr)
        return 2
    _emit(result, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
