#!/usr/bin/env bash
# 端到端行为验证（非交付单元测试，仅用于本机自检）。
set -u
cd "$(dirname "$0")"
PROOF=./proof
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0

check() { # desc expected actual
  if [ "$2" == "$3" ]; then pass=$((pass+1)); # echo "PASS: $1"
  else fail=$((fail+1)); echo "FAIL: $1"; echo "  expected: $2"; echo "  actual:   $3"; fi
}

# ---------- 构造数据树 ----------
ROOT=$WORK/data
mkdir -p "$ROOT/sub/deep" "$ROOT/empty-dir"
printf 'hello world\n' > "$ROOT/a.txt"
: > "$ROOT/empty.bin"
head -c 200000 /dev/urandom > "$ROOT/sub/big.bin"
head -c 65536 /dev/urandom > "$ROOT/sub/exact64k.bin"
printf 'unicode' > "$ROOT/名字 z$(printf '\t')$(printf 'q\046r') .dat"
printf 'deep' > "$ROOT/sub/deep/c.txt"
# 符号链接 / FIFO / 断链 / 链接目录
ln -s a.txt "$ROOT/link-to-file"
ln -s sub "$ROOT/link-to-dir"
ln -s nowhere "$ROOT/dangling"
mkfifo "$ROOT/fifo"
[ -p "$ROOT/fifo" ] || { echo "FIFO create failed"; exit 1; }

# ---------- generate ----------
OUT=$($PROOF generate --root "$ROOT" --proof "$WORK/p.json")
EC=$?
check "generate exit code" 0 "$EC"
PID1=$(python3 -c "import json,sys;print(json.load(open('$WORK/p.json'))['proof_id'])")
# 再生成一次，proof_id 必须稳定（同数据）
$PROOF generate --root "$ROOT" --proof "$WORK/p2.json" >/dev/null
PID2=$(python3 -c "import json,sys;print(json.load(open('$WORK/p2.json'))['proof_id'])")
check "proof_id stable across runs" "$PID1" "$PID2"

# 独立重算全部摘要（与实现不同的代码路径，直接裸 hashlib）
check "independent digest recompute" "independent-recompute-ok" "$(python3 - "$ROOT" "$WORK/p.json" <<'PY'
import hashlib, json, os, stat, sys
root, proof_path = sys.argv[1], sys.argv[2]
P = json.load(open(proof_path))
def b2(data): return hashlib.blake2b(data, digest_size=32).hexdigest()
paths=[]
for dp,dns,fns in os.walk(root):
    for n in fns:
        ap=os.path.join(dp,n)
        if stat.S_ISREG(os.lstat(ap).st_mode):
            paths.append((os.path.relpath(ap,root).replace(os.sep,'/'),ap))
paths.sort(key=lambda x:x[0].encode())
rh=hashlib.blake2b(digest_size=32)
for rel,ap in paths:
    data=open(ap,'rb').read()
    chs=[b2(data[i:i+65536]) for i in range(0,len(data),65536)]
    fh=hashlib.blake2b(digest_size=32)
    for c in chs: fh.update(c.encode())
    fd=fh.hexdigest(); rh.update(rel.encode()); rh.update(b":"); rh.update(fd.encode())
print("independent-recompute-ok" if rh.hexdigest()==P["proof_id"] else "MISMATCH")
PY
)"

# 证明 JSON 含规格要求的字段
python3 - "$WORK/p.json" <<'PY'
import json, sys
P = json.load(open(sys.argv[1]))
for k in ("version","proof_id","root","files","file_count","chunk_size","hash_algorithm"):
    assert k in P, k
fe = P["files"][0]
for k in ("path","size","digest","chunks"): assert k in fe, k
print("fields-ok")
PY

# ---------- challenge: 全命中 ----------
R=$($PROOF challenge --proof "$WORK/p.json" --root "$ROOT" --state "$WORK/s.json" --seed seed-xyz --samples 4)
EC=$?
check "challenge valid exit" 0 "$EC"
echo "$R" | python3 -c "import json,sys;r=json.load(sys.stdin);assert r['valid'] is True and r['failure_reason']=='none' and r['requested_samples']==4 and r['checked_samples']==4 and r['missing_samples']==[] and r['mismatched_samples']==[] and len(r['challenge_id'])==64, r"
check "challenge valid payload" 0 $?
# 同 seed/samples 再跑：challenge_id 与抽样稳定、状态幂等
CID_A=$(echo "$R" | python3 -c "import json,sys;print(json.load(sys.stdin)['challenge_id'])")
R2=$($PROOF challenge --proof "$WORK/p.json" --root "$ROOT" --state "$WORK/s.json" --seed seed-xyz --samples 4)
CID_B=$(echo "$R2" | python3 -c "import json,sys;print(json.load(sys.stdin)['challenge_id'])")
check "challenge_id deterministic" "$CID_A" "$CID_B"
python3 -c "import json;s=json.load(open('$WORK/s.json'));assert s['total_challenges']==1, s"
check "idempotent rerun counts once" 0 $?

# 不同 seed 结果不同（高概率），不同样本数
R3=$($PROOF challenge --proof "$WORK/p.json" --root "$ROOT" --state "$WORK/s.json" --seed other --samples 4)
CID_C=$(echo "$R3" | python3 -c "import json,sys;print(json.load(sys.stdin)['challenge_id'])")
[ "$CID_A" != "$CID_C" ]; check "different seed => different challenge_id" 0 $?

# 抽样上限：总分块数 = a.txt 1 + empty 0 + big 4 + exact64k 1 + weird 1 + c 1 = 8
R4=$($PROOF challenge --proof "$WORK/p.json" --root "$ROOT" --state "$WORK/s.json" --seed s --samples 8)
echo "$R4" | python3 -c "import json,sys;r=json.load(sys.stdin);assert r['valid'] and r['checked_samples']==8, r"
check "samples == total chunks ok" 0 $?

# ---------- status ----------
$PROOF status --state "$WORK/s.json" | python3 -c "
import json,sys
st=json.load(sys.stdin)
assert isinstance(st,list) and len(st)==1, st
r=st[0]
assert r['proof_id']=='$PID1' and r['status']=='valid', r
assert r['total_challenges']==3 and r['missing_samples']==0 and r['mismatched_samples']==0, r
assert r['last_challenge_at'] and r['last_failure_reason']=='none', r"
check "status valid aggregation" 0 $?
$PROOF status --state "$WORK/nope.json" | python3 -c "import json,sys;assert json.load(sys.stdin)==[]"
check "status missing state => []" 0 $?

# ---------- 缺失：删除文件 ----------
rm "$ROOT/a.txt"
R=$($PROOF challenge --proof "$WORK/p.json" --root "$ROOT" --state "$WORK/s2.json" --seed seed-xyz --samples 8)
echo "$R" | python3 -c "
import json,sys
r=json.load(sys.stdin)
assert r['valid'] is False and r['failure_reason']=='retrieval_missing', r
assert any(x['path']=='a.txt' for x in r['missing_samples']), r
assert r['mismatched_samples']==[] and r['checked_samples']+len(r['missing_samples'])==8, r"
check "missing => retrieval_missing" 0 $?
# 状态记录 invalid
$PROOF status --state "$WORK/s2.json" | python3 -c "import json,sys;r=json.load(sys.stdin)[0];assert r['status']=='invalid' and r['missing_samples']>=1, r"
check "status shows invalid" 0 $?
printf 'hello world\n' > "$ROOT/a.txt"  # 恢复

# ---------- 不匹配：改内容（保持文件存在） ----------
printf 'CHANGED CONTENT' > "$ROOT/sub/deep/c.txt"
R=$($PROOF challenge --proof "$WORK/p.json" --root "$ROOT" --state "$WORK/s3.json" --seed hit-c --samples 8)
echo "$R" | python3 -c "
import json,sys
r=json.load(sys.stdin)
assert r['valid'] is False and r['failure_reason']=='content_mismatch', r
assert any(x['path']=='sub/deep/c.txt' for x in r['mismatched_samples']), r
assert r['missing_samples']==[], r"
check "mismatch => content_mismatch" 0 $?
printf 'deep' > "$ROOT/sub/deep/c.txt"

# 缺失优先于不匹配
rm "$ROOT/a.txt"; printf 'X' > "$ROOT/sub/deep/c.txt"
R=$($PROOF challenge --proof "$WORK/p.json" --root "$ROOT" --state "$WORK/s4.json" --seed seed-xyz --samples 8)
echo "$R" | python3 -c "import json,sys;r=json.load(sys.stdin);assert r['failure_reason']=='retrieval_missing' and r['valid'] is False, r"
check "missing takes priority" 0 $?
printf 'hello world\n' > "$ROOT/a.txt"; printf 'deep' > "$ROOT/sub/deep/c.txt"

# ---------- 后续挑战复核原证明：用新数据重生成 proof 得到不同 id ----------
printf 'more' >> "$ROOT/a.txt"
$PROOF generate --root "$ROOT" --proof "$WORK/p3.json" >/dev/null
PID3=$(python3 -c "import json;print(json.load(open('$WORK/p3.json'))['proof_id'])")
[ "$PID3" != "$PID1" ]; check "changed data => new proof_id" 0 $?
# 用旧状态文件跑新证明 => StateConflict
ERR=$($PROOF challenge --proof "$WORK/p3.json" --root "$ROOT" --state "$WORK/s.json" --seed z --samples 1 2>&1)
EC=$?
check "cross-proof state => exit 2" 2 "$EC"
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='StateConflict'"
check "cross-proof state => StateConflict" 0 $?
printf 'hello world\n' > "$ROOT/a.txt"

# ---------- 空目录树：generate 合法，challenge 越界 ----------
mkdir -p "$WORK/empty-tree"
$PROOF generate --root "$WORK/empty-tree" --proof "$WORK/pe.json" | python3 -c "import json,sys;r=json.load(sys.stdin);assert r['file_count']==0 and len(r['proof_id'])==64, r"
check "empty tree generate ok" 0 $?
ERR=$($PROOF challenge --proof "$WORK/pe.json" --root "$WORK/empty-tree" --state "$WORK/se.json" --seed s --samples 1 2>&1)
EC=$?
check "empty tree challenge => exit 2" 2 "$EC"
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='ChallengeRangeError'"
check "empty tree challenge => ChallengeRangeError" 0 $?

# 越界 samples
ERR=$($PROOF challenge --proof "$WORK/p.json" --root "$ROOT" --state "$WORK/x.json" --seed s --samples 9 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='ChallengeRangeError'"
check "samples over total => ChallengeRangeError" 0 $?

# ---------- 参数非法 ----------
for bad in "0" "-3" "1.5" "abc" ""; do
  ERR=$($PROOF challenge --proof "$WORK/p.json" --root "$ROOT" --state "$WORK/x.json" --seed s --samples "$bad" 2>&1)
  EC=$?
  [ $EC -eq 2 ] && echo "$ERR" | grep -q InputError
  check "bad samples '$bad' => InputError/2" 0 $?
done
$PROOF challenge --proof "$WORK/p.json" --root "$ROOT" 2>/dev/null; check "missing flags => exit 2" 2 $?
$PROOF bogus 2>/dev/null; check "bad subcommand => exit 2" 2 $?

# ---------- root 不可用 ----------
ERR=$($PROOF generate --root "$WORK/nope" --proof "$WORK/x.json" 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='RootUnavailable'"
check "missing root => RootUnavailable" 0 $?
printf x > "$WORK/afile"
ERR=$($PROOF generate --root "$WORK/afile" --proof "$WORK/x.json" 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='RootUnavailable'"
check "file as root => RootUnavailable" 0 $?

# ---------- 证明不可解析 ----------
echo '{not json' > "$WORK/bad.json"
ERR=$($PROOF challenge --proof "$WORK/bad.json" --root "$ROOT" --state "$WORK/x.json" --seed s --samples 1 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='ProofFormatError'"
check "corrupt proof => ProofFormatError" 0 $?
ERR=$($PROOF challenge --proof "$WORK/missing-proof.json" --root "$ROOT" --state "$WORK/x.json" --seed s --samples 1 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='ProofFormatError'"
check "missing proof => ProofFormatError" 0 $?
# 手改 proof_id => 重算不一致 => ProofFormatError
python3 -c "
import json
p=json.load(open('$WORK/p.json')); p['proof_id']='0'*64
json.dump(p,open('$WORK/tampered.json','w'))"
ERR=$($PROOF challenge --proof "$WORK/tampered.json" --root "$ROOT" --state "$WORK/x.json" --seed s --samples 1 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='ProofFormatError'"
check "tampered proof => ProofFormatError" 0 $?

# ---------- 状态损坏 => StateConflict ----------
echo '???' > "$WORK/badstate.json"
ERR=$($PROOF status --state "$WORK/badstate.json" 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='StateConflict'"
check "corrupt state => StateConflict" 0 $?

# ---------- 原子写：失败不留半成品 ----------
ERR=$($PROOF generate --root "$ROOT" --proof "$WORK/afile/cannot/be/here/p.json" 2>&1)
EC=$?
check "write failure => exit 2" 2 "$EC"
ls "$WORK/afile" >/dev/null 2>&1 && ! ls -d "$WORK/afile/cannot" 2>/dev/null | grep -q .
check "write failure leaves no partial output" 0 $?
ls -a "$WORK" | grep -q '\.p\.json\..*\.tmp' && check "no tmp leftovers" 1 0 || check "no tmp leftovers" 0 0
# 原子写自动建目录
$PROOF generate --root "$ROOT" --proof "$WORK/newdir/nested/p.json" >/dev/null
check "atomic write creates dirs" 0 $?

# ---------- 输出只有 JSON 到 stdout，错误到 stderr ----------
$PROOF generate --root "$ROOT" --proof "$WORK/q.json" 2>/dev/null | python3 -m json.tool >/dev/null
check "stdout is valid JSON" 0 $?

# ---------- 抽样确定性：独立实现复算抽中的全局分块下标，并与工具实测交叉验证 ----------
python3 - "$WORK/p.json" "$ROOT" <<'PY'
import hashlib, json, os, sys
proof_path, root = sys.argv[1], sys.argv[2]
P = json.load(open(proof_path))
flat = [(f["path"], c["index"]) for f in P["files"] for c in f["chunks"]]
total = len(flat)
proof_id, seed, n = P["proof_id"], "seed-xyz", 4
m = hashlib.blake2b(b"stateproof-challenge-v1|proof:"+proof_id.encode()+b"|seed:"+seed.encode(), digest_size=32).digest()
state = int.from_bytes(m[:8], "big"); mask=(1<<64)-1
def nxt():
    global state
    state=(state+0x9E3779B97F4A7C15)&mask; z=state
    z=((z^(z>>30))*0xBF58476D1CE4E5B9)&mask
    z=((z^(z>>27))*0x94D049BB133111EB)&mask
    return z^(z>>31)
idx=list(range(total))
for i in range(n):
    j=i+nxt()%(total-i); idx[i],idx[j]=idx[j],idx[i]
want=sorted(idx[:n])
selected=[flat[g] for g in want]
unselected=flat[next(g for g in range(total) if g not in want)]
json.dump({"selected":selected,"unselected":unselected},
          open(os.path.join(os.path.dirname(proof_path),"sel.json"),"w"))
PY
# 翻转某文件第 k 块首字节
flip_chunk() { python3 - "$1" "$2" <<'PY'
import sys, os
path, k = sys.argv[1], int(sys.argv[2])
off = k*65536
with open(path,"r+b") as f:
    f.seek(off); b=f.read(1); f.seek(off); f.write(bytes([b[0]^0xFF]))
PY
}
SEL0=$(python3 -c "import json;d=json.load(open('$WORK/sel.json'));print(d['selected'][0][0])")
SEL0K=$(python3 -c "import json;d=json.load(open('$WORK/sel.json'));print(d['selected'][0][1])")
UNS=$(python3 -c "import json;d=json.load(open('$WORK/sel.json'));print(d['unselected'][0])")
UNSK=$(python3 -c "import json;d=json.load(open('$WORK/sel.json'));print(d['unselected'][1])")
# 抽中的块被改 => 必在 mismatched
flip_chunk "$ROOT/$SEL0" "$SEL0K"
$PROOF challenge --proof "$WORK/p.json" --root "$ROOT" --state "$WORK/det1.json" --seed seed-xyz --samples 4 \
 | python3 -c "
import json,sys
r=json.load(sys.stdin)
p,k='$SEL0',$SEL0K
assert r['valid'] is False and r['failure_reason']=='content_mismatch', r
assert any(x['path']==p and x['chunk_index']==k for x in r['mismatched_samples']), r"
check "independently-selected chunk is what tool checks" 0 $?
flip_chunk "$ROOT/$SEL0" "$SEL0K"  # 还原
# 未抽中的块被改 => 全命中
flip_chunk "$ROOT/$UNS" "$UNSK"
$PROOF challenge --proof "$WORK/p.json" --root "$ROOT" --state "$WORK/det2.json" --seed seed-xyz --samples 4 \
 | python3 -c "import json,sys;r=json.load(sys.stdin);assert r['valid'] and r['checked_samples']==4, r"
check "non-selected chunk corruption not seen" 0 $?
flip_chunk "$ROOT/$UNS" "$UNSK"  # 还原
# 最终恢复原状态，再挑战必须 valid
$PROOF challenge --proof "$WORK/p.json" --root "$ROOT" --state "$WORK/det4.json" --seed seed-xyz --samples 4 \
 | python3 -c "import json,sys;assert json.load(sys.stdin)['valid']"
check "restored tree valid again" 0 $?

# ---------- 挑战只复核原证明：root 中新增文件不影响 ----------
printf 'new file not in proof' > "$ROOT/brand-new.txt"
mkdir -p "$ROOT/newdir"; printf x > "$ROOT/newdir/x"
$PROOF challenge --proof "$WORK/p.json" --root "$ROOT" --state "$WORK/det3.json" --seed seed-xyz --samples 4 \
  | python3 -c "import json,sys;r=json.load(sys.stdin);assert r['valid'] and r['checked_samples']==4, r"
check "new files under root ignored" 0 $?
rm -f "$ROOT/brand-new.txt" "$ROOT/newdir/x"; rmdir "$ROOT/newdir"

# ---------- challenge 时 root 不可用 ----------
ERR=$($PROOF challenge --proof "$WORK/p.json" --root "$WORK/nope" --state "$WORK/x.json" --seed s --samples 1 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='RootUnavailable'"
check "challenge bad root => RootUnavailable" 0 $?

# ---------- 空 seed ----------
ERR=$($PROOF challenge --proof "$WORK/p.json" --root "$ROOT" --state "$WORK/x.json" --seed "" --samples 1 2>&1)
EC=$?
[ $EC -eq 2 ] && echo "$ERR" | grep -q InputError
check "empty seed => InputError/2" 0 $?

# ---------- help / version 退出码 0 ----------
$PROOF --help >/dev/null 2>&1; check "proof --help exit 0" 0 $?
$PROOF generate --help >/dev/null 2>&1; check "generate --help exit 0" 0 $?
$PROOF --version >/dev/null 2>&1; check "proof --version exit 0" 0 $?

# ---------- status 错误参数 ----------
$PROOF status 2>/dev/null; check "status without --state => exit 2" 2 $?

# ---------- challenge-export / challenge-verify ----------
# 导出凭证并与 challenge 的 challenge_id 交叉一致
OUT=$($PROOF challenge-export --proof "$WORK/p.json" --root "$ROOT" --seed seed-xyz --samples 4 --output "$WORK/resp.json")
EC=$?
check "challenge-export exit 0" 0 "$EC"
echo "$OUT" | python3 -c "
import json,sys
r=json.load(sys.stdin)
assert r['valid'] is True and r['failure_reason']=='none' and r['samples']==4, r
assert r['challenge_id']=='$CID_A' and r['proof_id']=='$PID1', r"
check "export challenge_id matches challenge" 0 $?
check "export evidence fields/data/digest" "export-evidence-ok" "$(python3 - "$WORK/resp.json" "$WORK/p.json" <<'PY'
import base64, hashlib, json, sys
R = json.load(open(sys.argv[1])); P = json.load(open(sys.argv[2]))
ok = (R["version"] == 1 and R["format"] == "state-proof-challenge"
      and R["proof_id"] == P["proof_id"] and R["samples"] == 4
      and "requested_samples" not in R and len(R["challenge_id"]) == 64
      and len(R["evidence"]) == 4)
for e in R["evidence"]:
    ok = ok and set(e) == {"path","chunk_index","offset","size","retrieval_status",
                           "retrieved_size","digest","data"}
    raw = base64.b64decode(e["data"], validate=True)
    ok = ok and e["retrieval_status"] == "ok" and e["retrieved_size"] == e["size"] \
        and len(raw) == e["size"] and e["offset"] == e["chunk_index"] * 65536 \
        and hashlib.blake2b(raw, digest_size=32).hexdigest() == e["digest"]
print("export-evidence-ok" if ok else "BAD")
PY
)"
# 证据按全局块序
python3 - "$WORK/resp.json" "$WORK/p.json" <<'PY'
import json, sys
R = json.load(open(sys.argv[1])); P = json.load(open(sys.argv[2]))
flat = [(f["path"], c["index"]) for f in P["files"] for c in f["chunks"]]
order = [flat.index((e["path"], e["chunk_index"])) for e in R["evidence"]]
assert order == sorted(order) and len(set(order)) == len(order), order
print("evidence-order-ok")
PY
check "evidence in global chunk order" 0 $?

# verify 接受合法凭证
OUT=$($PROOF challenge-verify --proof "$WORK/p.json" --response "$WORK/resp.json")
EC=$?
check "challenge-verify exit 0" 0 "$EC"
echo "$OUT" | python3 -c "
import json,sys
r=json.load(sys.stdin)
assert r['proof_id']=='$PID1' and r['challenge_id']=='$CID_A', r
assert r['valid'] is True and r['failure_reason']=='none' and r['verdict']=='valid', r
assert r['samples']==4 and r['seed']=='seed-xyz', r"
check "verify valid response payload" 0 $?

# 缺失：删文件后导出 → retrieval_missing，verify 判 invalid
rm "$ROOT/a.txt"
$PROOF challenge-export --proof "$WORK/p.json" --root "$ROOT" --seed seed-xyz --samples 8 --output "$WORK/resp-miss.json" \
  | python3 -c "import json,sys;r=json.load(sys.stdin);assert r['valid'] is False and r['failure_reason']=='retrieval_missing', r"
check "export missing => retrieval_missing" 0 $?
python3 -c "
import json
r=json.load(open('$WORK/resp-miss.json'))
ms=[e for e in r['evidence'] if e['retrieval_status']=='missing']
assert ms and all(e['retrieved_size']==0 and e['digest'] is None and e['data'] is None for e in ms), ms"
check "missing evidence fields" 0 $?
$PROOF challenge-verify --proof "$WORK/p.json" --response "$WORK/resp-miss.json" \
  | python3 -c "import json,sys;r=json.load(sys.stdin);assert r['verdict']=='invalid' and r['failure_reason']=='retrieval_missing', r"
check "verify missing => invalid" 0 $?
printf 'hello world\n' > "$ROOT/a.txt"

# partial：截短文件 → 短读
head -c 10 "$ROOT/sub/big.bin" > "$ROOT/sub/big.bin.tmp" && mv "$ROOT/sub/big.bin.tmp" "$ROOT/sub/big.bin"
$PROOF challenge-export --proof "$WORK/p.json" --root "$ROOT" --seed s --samples 8 --output "$WORK/resp-part.json" \
  | python3 -c "import json,sys;r=json.load(sys.stdin);assert r['valid'] is False and r['failure_reason']=='content_mismatch', r"
check "export partial => content_mismatch" 0 $?
python3 -c "
import json
r=json.load(open('$WORK/resp-part.json'))
ps=[e for e in r['evidence'] if e['retrieval_status']=='partial']
assert ps and all(0<=e['retrieved_size']<e['size'] and e['digest'] and e['data'] is not None for e in ps), ps"
check "partial evidence fields" 0 $?
$PROOF challenge-verify --proof "$WORK/p.json" --response "$WORK/resp-part.json" \
  | python3 -c "import json,sys;r=json.load(sys.stdin);assert r['verdict']=='invalid' and r['failure_reason']=='content_mismatch', r"
check "verify partial => invalid" 0 $?
head -c 200000 /dev/urandom > "$ROOT/sub/big.bin"  # 长度恢复但内容已变

# 等长改写：ok 但摘要不符 → content_mismatch
$PROOF challenge-export --proof "$WORK/p.json" --root "$ROOT" --seed s --samples 8 --output "$WORK/resp-mod.json" \
  | python3 -c "import json,sys;r=json.load(sys.stdin);assert r['valid'] is False and r['failure_reason']=='content_mismatch', r"
check "export modified => content_mismatch" 0 $?
$PROOF challenge-verify --proof "$WORK/p.json" --response "$WORK/resp-mod.json" \
  | python3 -c "import json,sys;r=json.load(sys.stdin);assert r['verdict']=='invalid' and r['failure_reason']=='content_mismatch', r"
check "verify modified => invalid" 0 $?
# 恢复 big.bin 并重新生成证明，保持后续用例一致
printf 'hello world\n' > "$ROOT/a.txt"
$PROOF generate --root "$ROOT" --proof "$WORK/p.json" >/dev/null
PID1=$(python3 -c "import json;print(json.load(open('$WORK/p.json'))['proof_id'])")
$PROOF challenge-export --proof "$WORK/p.json" --root "$ROOT" --seed seed-xyz --samples 4 --output "$WORK/resp.json" >/dev/null

# 篡改响应：data / digest / 顺序 / challenge_id / 判定 → ResponseFormatError
python3 -c "
import base64, json
r=json.load(open('$WORK/resp.json'))
e=next(x for x in r['evidence'] if x['retrieval_status']=='ok')
e['data']=base64.b64encode(b'X'+base64.b64decode(e['data'])[1:]).decode()
json.dump(r,open('$WORK/t1.json','w'))"
ERR=$($PROOF challenge-verify --proof "$WORK/p.json" --response "$WORK/t1.json" 2>&1)
[ $? -eq 2 ] && echo "$ERR" | grep -q ResponseFormatError
check "tampered data => ResponseFormatError" 0 $?
python3 -c "
import json
r=json.load(open('$WORK/resp.json'))
r['evidence'][0],r['evidence'][1]=r['evidence'][1],r['evidence'][0]
json.dump(r,open('$WORK/t2.json','w'))"
ERR=$($PROOF challenge-verify --proof "$WORK/p.json" --response "$WORK/t2.json" 2>&1)
[ $? -eq 2 ] && echo "$ERR" | grep -q ResponseFormatError
check "reordered evidence => ResponseFormatError" 0 $?
python3 -c "
import json
r=json.load(open('$WORK/resp.json')); r['challenge_id']='0'*64
json.dump(r,open('$WORK/t3.json','w'))"
ERR=$($PROOF challenge-verify --proof "$WORK/p.json" --response "$WORK/t3.json" 2>&1)
[ $? -eq 2 ] && echo "$ERR" | grep -q ResponseFormatError
check "tampered challenge_id => ResponseFormatError" 0 $?
python3 -c "
import json
r=json.load(open('$WORK/resp.json')); r['valid']=False; r['failure_reason']='content_mismatch'
json.dump(r,open('$WORK/t4.json','w'))"
ERR=$($PROOF challenge-verify --proof "$WORK/p.json" --response "$WORK/t4.json" 2>&1)
[ $? -eq 2 ] && echo "$ERR" | grep -q ResponseFormatError
check "tampered verdict => ResponseFormatError" 0 $?
python3 -c "
import json
r=json.load(open('$WORK/resp.json')); r['format']='state-proof'
json.dump(r,open('$WORK/t5.json','w'))"
ERR=$($PROOF challenge-verify --proof "$WORK/p.json" --response "$WORK/t5.json" 2>&1)
[ $? -eq 2 ] && echo "$ERR" | grep -q ResponseFormatError
check "wrong format => ResponseFormatError" 0 $?
# 响应缺失 / 不可解析
ERR=$($PROOF challenge-verify --proof "$WORK/p.json" --response "$WORK/no-resp.json" 2>&1)
[ $? -eq 2 ] && echo "$ERR" | grep -q ResponseFormatError
check "missing response => ResponseFormatError" 0 $?
echo '{not json' > "$WORK/badresp.json"
ERR=$($PROOF challenge-verify --proof "$WORK/p.json" --response "$WORK/badresp.json" 2>&1)
[ $? -eq 2 ] && echo "$ERR" | grep -q ResponseFormatError
check "corrupt response => ResponseFormatError" 0 $?
# 拿别的证明核对响应 → ResponseFormatError
printf 'other' > "$WORK/other-root-file"; mkdir -p "$WORK/other-root"; mv "$WORK/other-root-file" "$WORK/other-root/f"
$PROOF generate --root "$WORK/other-root" --proof "$WORK/p-other.json" >/dev/null
ERR=$($PROOF challenge-verify --proof "$WORK/p-other.json" --response "$WORK/resp.json" 2>&1)
[ $? -eq 2 ] && echo "$ERR" | grep -q ResponseFormatError
check "response vs other proof => ResponseFormatError" 0 $?

# export 参数与边界
ERR=$($PROOF challenge-export --proof "$WORK/p.json" --root "$ROOT" --seed s --samples 1 --output "$WORK/p.json" 2>&1)
[ $? -eq 2 ] && echo "$ERR" | grep -q InputError
check "output == proof => InputError" 0 $?
ERR=$($PROOF challenge-export --proof "$WORK/p.json" --root "$ROOT" --seed s --samples 0 --output "$WORK/x.json" 2>&1)
[ $? -eq 2 ] && echo "$ERR" | grep -q InputError
check "export bad samples => InputError" 0 $?
ERR=$($PROOF challenge-export --proof "$WORK/p.json" --root "$ROOT" --seed s --samples 99 --output "$WORK/x.json" 2>&1)
[ $? -eq 2 ] && echo "$ERR" | grep -q ChallengeRangeError
check "export overrange => ChallengeRangeError" 0 $?
ERR=$($PROOF challenge-export --proof "$WORK/p.json" --root "$WORK/nope" --seed s --samples 1 --output "$WORK/x.json" 2>&1)
[ $? -eq 2 ] && echo "$ERR" | grep -q RootUnavailable
check "export bad root => RootUnavailable" 0 $?
ERR=$($PROOF challenge-export --proof "$WORK/missing-p.json" --root "$ROOT" --seed s --samples 1 --output "$WORK/x.json" 2>&1)
[ $? -eq 2 ] && echo "$ERR" | grep -q ProofFormatError
check "export missing proof => ProofFormatError" 0 $?
$PROOF challenge-export --proof "$WORK/p.json" --root "$ROOT" --seed s 2>/dev/null
check "export missing flags => exit 2" 2 $?
$PROOF challenge-verify --proof "$WORK/p.json" 2>/dev/null
check "verify missing flags => exit 2" 2 $?
# export 不产生状态文件，也不读 --state
$PROOF challenge-export --proof "$WORK/p.json" --root "$ROOT" --seed s --samples 1 --output "$WORK/e1.json" >/dev/null
ls "$ROOT"/*.json >/dev/null 2>&1 && check "export writes no state into root" 1 0 || check "export writes no state into root" 0 0
# verify 越界 samples（响应声称超出总分块）
python3 -c "
import json
r=json.load(open('$WORK/resp.json')); r['samples']=99
json.dump(r,open('$WORK/t6.json','w'))"
ERR=$($PROOF challenge-verify --proof "$WORK/p.json" --response "$WORK/t6.json" 2>&1)
[ $? -eq 2 ] && echo "$ERR" | grep -q ChallengeRangeError
check "verify overrange samples => ChallengeRangeError" 0 $?

# ---------- proof-diff：证明版本对账 ----------
mkdir -p "$WORK/v1/sub"
: > "$WORK/v1/empty.bin"
printf 'hello\n' > "$WORK/v1/a.txt"
head -c 200000 /dev/zero > "$WORK/v1/sub/big.bin"
head -c 65536 /dev/zero > "$WORK/v1/sub/exact.bin"
printf 'uni 名\tz' > "$WORK/v1/u.dat"
printf 'nl\n' > "$WORK/v1/weird
name.txt"
$PROOF generate --root "$WORK/v1" --proof "$WORK/pb.json" >/dev/null
PB=$(python3 -c "import json;print(json.load(open('$WORK/pb.json'))['proof_id'])")

# 独立生成同数据 => 全同
$PROOF generate --root "$WORK/v1" --proof "$WORK/pa-same.json" >/dev/null
$PROOF proof-diff --before "$WORK/pb.json" --after "$WORK/pa-same.json" | python3 -c "
import json,sys
b=json.load(open('$WORK/pb.json')); d=json.load(sys.stdin)
paths=sorted((f['path'] for f in b['files']), key=lambda p:p.encode())
assert d['before_proof_id']==d['after_proof_id']=='$PB'
assert d['before_file_count']==d['after_file_count']==len(paths)
assert d['unchanged_files']==paths and d['added_files']==d['removed_files']==d['changed_files']==[]
assert d['valid'] is True and d['failure_reason']=='none', d"
check "proof-diff identical" 0 $?

# 增 / 删 / 改
mkdir -p "$WORK/v2"; cp -a "$WORK/v1/." "$WORK/v2/"
rm "$WORK/v2/a.txt"
printf 'new' > "$WORK/v2/new.txt"
printf 'longer hello\n' > "$WORK/v2/empty.bin"
python3 -c "
p='$WORK/v2/sub/exact.bin'
with open(p,'r+b') as f: b=f.read(1); f.seek(0); f.write(bytes([b[0]^0xFF]))
p='$WORK/v2/sub/big.bin'
with open(p,'r+b') as f: f.seek(65536); b=f.read(1); f.seek(65536); f.write(bytes([b[0]^0xFF]))"
$PROOF generate --root "$WORK/v2" --proof "$WORK/pa.json" >/dev/null
$PROOF proof-diff --before "$WORK/pb.json" --after "$WORK/pa.json" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['valid'] is False and d['failure_reason']=='proof_drift', d
assert d['added_files']==['new.txt'] and d['removed_files']==['a.txt'], d
assert d['unchanged_files']==['u.dat','weird\nname.txt'], d
ch={c['path']:c for c in d['changed_files']}
assert set(ch)=={'empty.bin','sub/big.bin','sub/exact.bin'}, ch
assert ch['empty.bin']['reason']=='size_changed'
assert ch['empty.bin']['changed_chunk_indices']==[]
assert ch['empty.bin']['added_chunk_count']==1 and ch['empty.bin']['removed_chunk_count']==0
assert ch['sub/exact.bin']['reason']=='digest_changed'
assert ch['sub/exact.bin']['changed_chunk_indices']==[0]
assert ch['sub/big.bin']['reason']=='digest_changed'
assert ch['sub/big.bin']['changed_chunk_indices']==[1]
assert ch['sub/big.bin']['added_chunk_count']==0 and ch['sub/big.bin']['removed_chunk_count']==0
assert [c['path'] for c in d['changed_files']]==sorted(ch, key=lambda p:p.encode())
assert 'weird\nname.txt' in d['unchanged_files'] and 'u.dat' in d['unchanged_files'], d"
check "proof-diff added/removed/changed" 0 $?

# 追加末尾块（200000->300000，4 块->5 块，原末块变满块）
head -c 300000 /dev/zero > "$WORK/v2/sub/big.bin"
$PROOF generate --root "$WORK/v2" --proof "$WORK/pa3.json" >/dev/null
$PROOF proof-diff --before "$WORK/pb.json" --after "$WORK/pa3.json" | python3 -c "
import json,sys
c=[x for x in json.load(sys.stdin)['changed_files'] if x['path']=='sub/big.bin'][0]
assert c['reason']=='size_changed' and c['added_chunk_count']==1 and c['removed_chunk_count']==0
assert c['changed_chunk_indices']==[3], c"
check "proof-diff appended chunk" 0 $?
$PROOF proof-diff --before "$WORK/pa3.json" --after "$WORK/pb.json" | python3 -c "
import json,sys
c=[x for x in json.load(sys.stdin)['changed_files'] if x['path']=='sub/big.bin'][0]
assert c['added_chunk_count']==0 and c['removed_chunk_count']==1, c"
check "proof-diff removed chunk reverse" 0 $?

# 空证明互比 / 空对非空
mkdir -p "$WORK/ve1" "$WORK/ve2"
$PROOF generate --root "$WORK/ve1" --proof "$WORK/pbe.json" >/dev/null
$PROOF generate --root "$WORK/ve2" --proof "$WORK/pae.json" >/dev/null
$PROOF proof-diff --before "$WORK/pbe.json" --after "$WORK/pae.json" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['before_file_count']==d['after_file_count']==0
assert d['unchanged_files']==d['added_files']==d['removed_files']==d['changed_files']==[]
assert d['valid'] is True and d['failure_reason']=='none' and d['before_proof_id']==d['after_proof_id'], d"
check "proof-diff empty vs empty" 0 $?
$PROOF proof-diff --before "$WORK/pbe.json" --after "$WORK/pb.json" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['valid'] is False and d['failure_reason']=='proof_drift'
assert len(d['added_files'])==d['after_file_count'] and d['removed_files']==d['unchanged_files']==[], d"
check "proof-diff empty vs nonempty" 0 $?

# 错误路径
ERR=$($PROOF proof-diff --before "$WORK/no-pf.json" --after "$WORK/pb.json" 2>&1)
EC=$?
check "proof-diff missing before => 2" 2 "$EC"
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='ProofFormatError'"
check "proof-diff missing before type" 0 $?
echo '{nope' > "$WORK/badpf.json"
ERR=$($PROOF proof-diff --before "$WORK/pb.json" --after "$WORK/badpf.json" 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='ProofFormatError'"
check "proof-diff corrupt after type" 0 $?
ERR=$($PROOF proof-diff --before "$WORK/no-pf.json" --after "$WORK/badpf.json" 2>&1)
echo "$ERR" | grep -q "no-pf.json"
check "proof-diff both invalid reports before" 0 $?
$PROOF proof-diff --before "$WORK/pb.json" 2>/dev/null; check "proof-diff missing flag => 2" 2 $?
ERR=$($PROOF proof-diff --before " " --after "$WORK/pb.json" 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='InputError'"
check "proof-diff blank path => InputError" 0 $?

# 不读 root、不写文件
SNAP1=$(ls -a "$WORK" | sort)
$PROOF proof-diff --before "$WORK/pb.json" --after "$WORK/pa.json" >/dev/null
SNAP2=$(ls -a "$WORK" | sort)
[ "$SNAP1" == "$SNAP2" ]; check "proof-diff writes no files" 0 $?
$PROOF proof-diff --help >/dev/null 2>&1; check "proof-diff --help exit 0" 0 $?

# ---------- coverage-report：只读覆盖率报告 ----------
mkdir -p "$WORK/cov"
printf 'hello\n' > "$WORK/cov/a.txt"                 # 1 块
head -c 200000 /dev/urandom > "$WORK/cov/b.bin"     # 4 块
head -c 65536 /dev/urandom > "$WORK/cov/c.bin"      # 1 块
$PROOF generate --root "$WORK/cov" --proof "$WORK/pcov.json" >/dev/null
PCOV=$(python3 -c "import json;print(json.load(open('$WORK/pcov.json'))['proof_id'])")

# 状态不存在 => 空历史：covered=0、streak=0、数组空，uncovered 为全局块序全表
$PROOF coverage-report --proof "$WORK/pcov.json" --state "$WORK/scov.json" | python3 -c "
import json,sys
P=json.load(open('$WORK/pcov.json'))
flat=[{'path':f['path'],'chunk_index':c['index']} for f in P['files'] for c in f['chunks']]
r=json.load(sys.stdin)
assert r['proof_id']=='$PCOV' and r['total_chunks']==6 and r['covered_chunks']==0, r
assert r['failure_streak']==0 and r['failed_challenges']==[], r
assert r['uncovered_chunks']==flat, r
assert r['valid'] is False and r['failure_reason']=='coverage_gap', r"
check "coverage empty history => coverage_gap" 0 $?

# 多条部分抽样：用独立实现复算选样并集，与报告交叉验证
for sd in c1 c2 c3 c4; do
  $PROOF challenge --proof "$WORK/pcov.json" --root "$WORK/cov" --state "$WORK/scov.json" --seed "$sd" --samples 2 >/dev/null
done
# 同 seed 复跑：历史不增加，覆盖集合不变
$PROOF challenge --proof "$WORK/pcov.json" --root "$WORK/cov" --state "$WORK/scov.json" --seed c1 --samples 2 >/dev/null
$PROOF coverage-report --proof "$WORK/pcov.json" --state "$WORK/scov.json" | python3 -c "
import hashlib,json,sys
P=json.load(open('$WORK/pcov.json')); S=json.load(open('$WORK/scov.json'))
flat=[(f['path'],c['index']) for f in P['files'] for c in f['chunks']]
total=len(flat); pid=P['proof_id']
def select(seed,n):
  m=hashlib.blake2b(b'stateproof-challenge-v1|proof:'+pid.encode()+b'|seed:'+seed.encode(),digest_size=32).digest()
  st=int.from_bytes(m[:8],'big'); mask=(1<<64)-1
  def nxt():
    nonlocal st
    st=(st+0x9E3779B97F4A7C15)&mask; z=st
    z=((z^(z>>30))*0xBF58476D1CE4E5B9)&mask
    z=((z^(z>>27))*0x94D049BB133111EB)&mask
    return z^(z>>31)
  idx=list(range(total))
  for i in range(n):
    j=i+nxt()%(total-i); idx[i],idx[j]=idx[j],idx[i]
  return sorted(idx[:n])
covered=set()
for h in S['history']:
  covered.update(select(h['seed'],h['requested_samples']))
expect_un=[{'path':flat[g][0],'chunk_index':flat[g][1]} for g in range(total) if g not in covered]
r=json.load(sys.stdin)
assert len(S['history'])==4, S['history']
assert r['covered_chunks']==len(covered), r
assert r['uncovered_chunks']==expect_un, r
assert r['failed_challenges']==[] and r['failure_streak']==0, r
assert r['valid'] is (len(covered)==total), r
assert r['failure_reason']==('none' if len(covered)==total else 'coverage_gap'), r"
check "coverage partial history cross-recomputed" 0 $?

# 全量抽样 => 全覆盖、true/none
$PROOF challenge --proof "$WORK/pcov.json" --root "$WORK/cov" --state "$WORK/scov.json" --seed full --samples 6 >/dev/null
$PROOF coverage-report --proof "$WORK/pcov.json" --state "$WORK/scov.json" | python3 -c "
import json,sys
r=json.load(sys.stdin)
assert r['covered_chunks']==6 and r['uncovered_chunks']==[], r
assert r['valid'] is True and r['failure_reason']=='none' and r['failure_streak']==0, r"
check "coverage full => valid none" 0 $?

# 失效历史：invalid, valid, invalid（末尾 streak=1，failed 按历史顺序共 2 条）
rm "$WORK/cov/a.txt"
$PROOF challenge --proof "$WORK/pcov.json" --root "$WORK/cov" --state "$WORK/scov.json" --seed f1 --samples 6 >/dev/null
printf 'hello\n' > "$WORK/cov/a.txt"
$PROOF challenge --proof "$WORK/pcov.json" --root "$WORK/cov" --state "$WORK/scov.json" --seed g1 --samples 6 >/dev/null
rm "$WORK/cov/a.txt"
$PROOF challenge --proof "$WORK/pcov.json" --root "$WORK/cov" --state "$WORK/scov.json" --seed f2 --samples 6 >/dev/null
$PROOF coverage-report --proof "$WORK/pcov.json" --state "$WORK/scov.json" | python3 -c "
import json,sys
S=json.load(open('$WORK/scov.json'))
bad=[h['challenge_id'] for h in S['history'] if not h['valid']]
r=json.load(sys.stdin)
assert r['valid'] is False and r['failure_reason']=='challenge_failure', r
assert r['failed_challenges']==bad and len(bad)==2, r
assert r['failure_streak']==1, r"
check "coverage failures ordered with trailing streak" 0 $?
# 再追加一条失效 => streak=2；历史中任何无效都判 challenge_failure
$PROOF challenge --proof "$WORK/pcov.json" --root "$WORK/cov" --state "$WORK/scov.json" --seed f3 --samples 6 >/dev/null
$PROOF coverage-report --proof "$WORK/pcov.json" --state "$WORK/scov.json" | python3 -c "
import json,sys
r=json.load(sys.stdin)
assert r['failure_streak']==2 and r['failure_reason']=='challenge_failure' and not r['valid'], r"
check "coverage streak grows" 0 $?
printf 'hello\n' > "$WORK/cov/a.txt"

# 空证明：空历史 => true/none
$PROOF coverage-report --proof "$WORK/pe.json" --state "$WORK/scov-empty.json" | python3 -c "
import json,sys
r=json.load(sys.stdin)
assert r['total_chunks']==0 and r['covered_chunks']==0 and r['failure_streak']==0
assert r['uncovered_chunks']==[] and r['failed_challenges']==[]
assert r['valid'] is True and r['failure_reason']=='none', r"
check "coverage empty proof empty history" 0 $?
# 空证明但状态属于别的 proof_id（有历史）=> StateConflict
ERR=$($PROOF coverage-report --proof "$WORK/pe.json" --state "$WORK/scov.json" 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='StateConflict'"
check "coverage empty proof with history => StateConflict" 0 $?

# 错误路径
ERR=$($PROOF coverage-report --proof "$WORK/p-other.json" --state "$WORK/scov.json" 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='StateConflict'"
check "coverage cross proof_id => StateConflict" 0 $?
echo '???' > "$WORK/badcov.json"
ERR=$($PROOF coverage-report --proof "$WORK/pcov.json" --state "$WORK/badcov.json" 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='StateConflict'"
check "coverage corrupt state => StateConflict" 0 $?
python3 -c "
import json
s=json.load(open('$WORK/scov.json'))
s['history'][0]['challenge_id']='0'*64
json.dump(s,open('$WORK/covtamper.json','w'))"
ERR=$($PROOF coverage-report --proof "$WORK/pcov.json" --state "$WORK/covtamper.json" 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='StateConflict'"
check "coverage rebuilt challenge_id mismatch => StateConflict" 0 $?
python3 -c "
import json
s=json.load(open('$WORK/scov.json'))
s['history'][0]['requested_samples']=99; s['history'][0]['checked_samples']=99
json.dump(s,open('$WORK/covover.json','w'))"
ERR=$($PROOF coverage-report --proof "$WORK/pcov.json" --state "$WORK/covover.json" 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='StateConflict'"
check "coverage samples over total => StateConflict" 0 $?
ERR=$($PROOF coverage-report --proof "$WORK/no-pf.json" --state "$WORK/scov.json" 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='ProofFormatError'"
check "coverage missing proof => ProofFormatError" 0 $?
ERR=$($PROOF coverage-report --proof " " --state "$WORK/scov.json" 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='InputError'"
check "coverage blank proof path => InputError" 0 $?
$PROOF coverage-report --proof "$WORK/pcov.json" 2>/dev/null
check "coverage missing --state => exit 2" 2 $?

# 只读、不访问 root：root 移走后仍可报告，且无文件写入
SNAPC=$(ls -a "$WORK" | sort)
mv "$WORK/cov" "$WORK/cov-moved"
$PROOF coverage-report --proof "$WORK/pcov.json" --state "$WORK/scov.json" >/dev/null
EC=$?
mv "$WORK/cov-moved" "$WORK/cov"
check "coverage runs without root access" 0 "$EC"
SNAPD=$(ls -a "$WORK" | sort)
[ "$SNAPC" == "$SNAPD" ]; check "coverage-report writes no files" 0 $?
$PROOF coverage-report --help >/dev/null 2>&1; check "coverage-report --help exit 0" 0 $?

echo "----------------------------------------"
echo "PASS=$pass FAIL=$fail"
[ $fail -eq 0 ]
