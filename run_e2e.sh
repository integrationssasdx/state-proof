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

# ---------- audit：全量核验（此刻数据树与 p.json 一致） ----------
A=$($PROOF audit --proof "$WORK/p.json" --root "$ROOT")
EC=$?
check "audit valid exit" 0 "$EC"
FC=$(python3 -c "import json;print(json.load(open('$WORK/p.json'))['file_count'])")
echo "$A" | python3 -c "
import json,sys
r=json.load(sys.stdin)
assert r['proof_id']=='$PID1' and r['file_count']==$FC, r
assert r['verified_files']==$FC, r
assert r['missing_files']==[] and r['mismatched_files']==[], r
assert r['valid'] is True and r['failure_reason']=='none', r"
check "audit valid payload" 0 $?
# 确定性：再跑输出完全一致
A2=$($PROOF audit --proof "$WORK/p.json" --root "$ROOT")
check "audit deterministic" "$A" "$A2"
# 只读：root 下不产生/不改动任何文件
SNAP_BEFORE=$(find "$ROOT" | sort)
$PROOF audit --proof "$WORK/p.json" --root "$ROOT" >/dev/null
SNAP_AFTER=$(find "$ROOT" | sort)
check "audit is read-only on root" "$SNAP_BEFORE" "$SNAP_AFTER"
# 成功时 stderr 为空
ERR=$($PROOF audit --proof "$WORK/p.json" --root "$ROOT" 2>&1 >/dev/null)
check "audit success stderr empty" "" "$ERR"

# 缺失：移走文件 => retrieval_missing
mv "$ROOT/sub/big.bin" "$WORK/big.bin.bak"
A=$($PROOF audit --proof "$WORK/p.json" --root "$ROOT")
echo "$A" | python3 -c "
import json,sys
r=json.load(sys.stdin)
assert r['valid'] is False and r['failure_reason']=='retrieval_missing', r
assert r['missing_files']==['sub/big.bin'] and r['mismatched_files']==[], r
assert r['verified_files']+len(r['missing_files'])==r['file_count'], r"
check "audit missing => retrieval_missing" 0 $?
mv "$WORK/big.bin.bak" "$ROOT/sub/big.bin"

# 证明路径上是非普通文件（符号链接）=> 同样记 missing
rm "$ROOT/a.txt"; ln -s sub "$ROOT/a.txt"
A=$($PROOF audit --proof "$WORK/p.json" --root "$ROOT")
echo "$A" | python3 -c "
import json,sys
r=json.load(sys.stdin)
assert r['valid'] is False and r['failure_reason']=='retrieval_missing', r
assert r['missing_files']==['a.txt'], r"
check "audit non-regular at proof path => missing" 0 $?
rm "$ROOT/a.txt"; printf 'hello world\n' > "$ROOT/a.txt"

# 不匹配：改内容 => content_mismatch
printf 'CHANGED CONTENT' > "$ROOT/sub/deep/c.txt"
A=$($PROOF audit --proof "$WORK/p.json" --root "$ROOT")
echo "$A" | python3 -c "
import json,sys
r=json.load(sys.stdin)
assert r['valid'] is False and r['failure_reason']=='content_mismatch', r
assert r['mismatched_files']==['sub/deep/c.txt'] and r['missing_files']==[], r
assert r['verified_files']+len(r['mismatched_files'])==r['file_count'], r"
check "audit mismatch => content_mismatch" 0 $?
# 缺失优先于不匹配
rm "$ROOT/a.txt"
A=$($PROOF audit --proof "$WORK/p.json" --root "$ROOT")
echo "$A" | python3 -c "
import json,sys
r=json.load(sys.stdin)
assert r['valid'] is False and r['failure_reason']=='retrieval_missing', r
assert r['missing_files']==['a.txt'] and r['mismatched_files']==['sub/deep/c.txt'], r"
check "audit missing takes priority over mismatch" 0 $?
printf 'hello world\n' > "$ROOT/a.txt"; printf 'deep' > "$ROOT/sub/deep/c.txt"

# 清单外新增文件忽略；空证明合法
printf 'new file not in proof' > "$ROOT/audit-new.txt"
$PROOF audit --proof "$WORK/p.json" --root "$ROOT" \
  | python3 -c "import json,sys;r=json.load(sys.stdin);assert r['valid'] and r['verified_files']==$FC, r"
check "audit ignores files not in proof" 0 $?
rm -f "$ROOT/audit-new.txt"
$PROOF audit --proof "$WORK/pe.json" --root "$WORK/empty-tree" \
  | python3 -c "
import json,sys
r=json.load(sys.stdin)
assert r['file_count']==0 and r['verified_files']==0, r
assert r['valid'] is True and r['failure_reason']=='none', r"
check "audit empty proof valid" 0 $?

# audit 参数与错误
ERR=$($PROOF audit --proof "" --root "$ROOT" 2>&1); EC=$?
[ $EC -eq 2 ] && echo "$ERR" | grep -q InputError
check "audit empty --proof => InputError/2" 0 $?
ERR=$($PROOF audit --proof "$WORK/p.json" --root "" 2>&1); EC=$?
[ $EC -eq 2 ] && echo "$ERR" | grep -q InputError
check "audit empty --root => InputError/2" 0 $?
$PROOF audit --proof "$WORK/p.json" 2>/dev/null; check "audit missing flags => exit 2" 2 $?
$PROOF audit --proof "$WORK/p.json" --root "$ROOT" --samples 3 2>/dev/null
check "audit rejects --samples => exit 2" 2 $?
ERR=$($PROOF audit --proof "$WORK/nope.json" --root "$ROOT" 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='ProofFormatError'"
check "audit missing proof => ProofFormatError" 0 $?
ERR=$($PROOF audit --proof "$WORK/bad.json" --root "$ROOT" 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='ProofFormatError'"
check "audit corrupt proof => ProofFormatError" 0 $?
ERR=$($PROOF audit --proof "$WORK/tampered.json" --root "$ROOT" 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='ProofFormatError'"
check "audit tampered proof => ProofFormatError" 0 $?
ERR=$($PROOF audit --proof "$WORK/p.json" --root "$WORK/nope" 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='RootUnavailable'"
check "audit missing root => RootUnavailable" 0 $?
ERR=$($PROOF audit --proof "$WORK/p.json" --root "$WORK/afile" 2>&1)
echo "$ERR" | python3 -c "import json,sys;assert json.load(sys.stdin)['error']['type']=='RootUnavailable'"
check "audit file as root => RootUnavailable" 0 $?
# 受控失败时 stdout 为空
OUT=$($PROOF audit --proof "$WORK/nope.json" --root "$ROOT" 2>/dev/null)
check "audit error stdout empty" "" "$OUT"

echo "----------------------------------------"
echo "PASS=$pass FAIL=$fail"
[ $fail -eq 0 ]
