#!/usr/bin/env bash
# Go 도달성 분석 (govulncheck v1.9.0, 로컬 DB, 네트워크 없는 네임스페이스에서 실행)
#
# 사용: cd lotte/innovate && bash reach/run.sh
# 출력: results/reach/ (설명은 reach/NOTES.md)
# 임시: /home/user/work/reachtmp/ (매번 지우고 새로 만든다)
# 캐시: /home/user/work/reachcache/ (지우지 않는다: golang/vulndb 고정 커밋, go1.27.0으로 빌드한 govulncheck)
#
# 단계
#   0. 도구 버전, Dockerfile golang 이미지 버전 확인
#   1. govulncheck DB: (주) OSV Go all.zip의 GO-* -> builddb, (대조1) 같은 파일을 평평한 폴더로(govulncheck 자체 색인),
#      (대조2) golang/vulndb 고정 커밋 data/osv -> builddb
#   2. 대조 실험: 취약 심볼을 부르는 모듈(양성)과 import만 하는 모듈(음성), 오프라인 증명(strace)
#   3. Online Boutique 3개 커밋 x Go 서비스 4개
#      - 온라인: go mod download, go list -deps (모듈 캐시 채우기)
#      - 오프라인(unshare -n, GOPROXY=off): 주 실행 1번 + 민감도 2번 + DB 대조 2번 + go.mod 조회 1번
#   4. reach/analyze.py: levels.csv, summary.json, cve_2023_44487.md 등
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)   # lotte/innovate/reach
ROOT=$(dirname "$HERE")                              # lotte/innovate
OUT="$ROOT/results/reach"
TMP=/home/user/work/reachtmp
CACHE=/home/user/work/reachcache
TOOLS_BIN=/home/user/tools/bin
GOBIN_DIR=/usr/local/go/bin
PY="$ROOT/.venv/bin/python"

# govulncheck v1.9.0 를 go1.27.0 으로 빌드한 것 하나를 모든 커밋에 쓴다.
# 이유: go1.26.10 빌드(공용 $TOOLS_BIN/govulncheck)는 main 커밋의 go1.27 전용 파일을 타입 검사하지 못한다
#   (x/net@v0.58.0/http2/server_wrap.go: file requires newer Go version go1.27)
GV_BUILD_TC=go1.27.0
GV="$CACHE/bin-$GV_BUILD_TC/govulncheck"
GV_SHARED="$TOOLS_BIN/govulncheck"

OSV_ZIP=/home/user/work/osvdb/osv-scalibr/Go/all.zip
OSV_ZIP_URL=https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip
VULNDB_URL=https://github.com/golang/vulndb.git
VULNDB_COMMIT=8f7e390a0ff7345d74ecd7a056a1073214466db9
VULNDB_TIMEOUT=300

export GOPATH=/home/user/tools/gopath
export GOMAXPROCS=2
export PATH="$GOBIN_DIR:$PATH"
export GOFLAGS=
unset GOVERSION GOOS GOARCH 2>/dev/null || true

# 분석 대상: 라벨 | 워크트리 | 기대 커밋 | 주 로더 툴체인 | 표준 라이브러리 판정 버전(Dockerfile) | 민감도용 로더
#   주 로더: Dockerfile 버전으로 패키지를 읽을 수 있으면 그 버전, 안 되면 가장 가까운 버전
#     v0.5.0: go1.19.4의 go list에 -pgo 플래그가 없어 govulncheck(x/tools)가 실패 -> go1.20.4로 읽고 GOVERSION=go1.19.4
#   민감도 로더: 로컬 go1.24.7. main은 go.mod가 go 1.25 이상이라 go1.26.10
TARGETS=(
  "v0.5.0-3c0d659|/home/user/work/ob_v0.5.0|3c0d6597809d1f40dccd24b757b7ca67d40cadf8|go1.20.4|go1.19.4|local"
  "v0.8.0-d54af3d|/home/user/work/ob_v0.8.0|d54af3d2510995d33521ac543dd885b150213f95|go1.20.4|go1.20.4|local"
  "main-c7cb6d5|/home/user/work/ob_main|c7cb6d5bfd6ea3aed768634ebbcb98cb7a523712|go1.27.0|go1.27.0|go1.26.10"
)

log() { printf '[reach %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

# 네트워크 없는 네임스페이스에서 실행 (lo만 있다). 모듈과 툴체인은 캐시에서만 읽는다
offline() { unshare -n env GOPROXY=off "$@"; }

# 프록시 주소가 오류 메시지에 섞여 나오면 가린다 (값은 출력하지 않는다)
mask_proxy() { "$PY" -I -c 'import os,sys
s=sys.stdin.read()
for k in ("HTTPS_PROXY","https_proxy","HTTP_PROXY","http_proxy"):
    v=os.environ.get(k)
    if v: s=s.replace(v,"<proxy>")
sys.stdout.write(s)'; }

rm -rf "$TMP"
mkdir -p "$TMP" "$OUT" "$CACHE"

# ---------------------------------------------------------------- 0. 도구 버전, Dockerfile 확인
log "0. 도구 버전"
if [ ! -x "$GV" ]; then
  log "govulncheck v1.9.0 을 $GV_BUILD_TC 로 빌드 (온라인)"
  mkdir -p "$(dirname "$GV")"
  (cd "$CACHE" && GOTOOLCHAIN=$GV_BUILD_TC GOBIN="$(dirname "$GV")" nice -n 10 go install golang.org/x/vuln/cmd/govulncheck@v1.9.0)
fi
{
  echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "go_local: $($GOBIN_DIR/go version)"
  echo "govulncheck_used: $GV"
  echo "govulncheck_used_buildinfo: $($GOBIN_DIR/go version "$GV")"
  echo "govulncheck_used_module: $($GOBIN_DIR/go version -m "$GV" | awk '$1=="mod"{print $2, $3, $4}')"
  echo "govulncheck_shared: $GV_SHARED"
  echo "govulncheck_shared_buildinfo: $($GOBIN_DIR/go version "$GV_SHARED" 2>&1)"
  echo "govulncheck_shared_module: $($GOBIN_DIR/go version -m "$GV_SHARED" 2>/dev/null | awk '$1=="mod"{print $2, $3, $4}')"
  echo "strace: $(strace -V 2>&1 | head -1)"
  echo "unshare: $(unshare --version 2>&1 | head -1)"
  echo "repo_commit: $(git -C "$ROOT" rev-parse HEAD)"
  echo "repo_reach_dirty_files: $(git -C "$ROOT" status --porcelain -- reach | wc -l)"
} > "$OUT/tool_versions.txt"

# Dockerfile 의 golang 빌더 이미지 버전을 파일에서 직접 읽어 TARGETS 와 맞는지 본다
echo "commit_label,service,dockerfile_from_golang,go_mod_go,go_mod_toolchain,targets_goversion,match" > "$OUT/dockerfile_go_versions.csv"
for t in "${TARGETS[@]}"; do
  IFS='|' read -r label wt want loader gover alt <<< "$t"
  for gm in "$wt"/src/*/go.mod; do
    sd=$(dirname "$gm"); svc=$(basename "$sd")
    img=$(grep -oE '^FROM .*golang:[0-9]+\.[0-9]+(\.[0-9]+)?' "$sd/Dockerfile" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?$' | head -1)
    gomod_go=$(awk '$1=="go"{print $2}' "$gm")
    gomod_tc=$(awk '$1=="toolchain"{print $2}' "$gm")
    m=no; [ "go$img" = "$gover" ] && m=yes
    echo "$label,$svc,$img,$gomod_go,$gomod_tc,$gover,$m" >> "$OUT/dockerfile_go_versions.csv"
    if [ "$m" != yes ]; then echo "Dockerfile 버전 불일치: $label $svc golang:$img vs $gover" >&2; exit 1; fi
  done
done

# 공식 golang 이미지가 GOTOOLCHAIN=local 인지 (main go.mod 의 toolchain go1.27.1 줄을 무시하는지) 템플릿에서 확인
DL_SHA=$(git ls-remote https://github.com/docker-library/golang.git HEAD | cut -f1)
(cd "$ROOT" && "$PY" -c "from common.fetch import fetch; fetch('https://raw.githubusercontent.com/docker-library/golang/$DL_SHA/Dockerfile-linux.template', 'reach/docker-library-golang-$DL_SHA-Dockerfile-linux.template', manifest='reach')" > /dev/null)
{
  echo "docker_library_golang_commit: $DL_SHA"
  echo "template_lines:"
  grep -n 'GOTOOLCHAIN' "$ROOT/data/raw/reach/docker-library-golang-$DL_SHA-Dockerfile-linux.template" || echo "(GOTOOLCHAIN 없음)"
} > "$OUT/docker_image_gotoolchain.txt"

# ---------------------------------------------------------------- 1. DB
log "1. DB 만들기"
if [ ! -f "$OSV_ZIP" ]; then
  # 원래 파일이 없으면 지금 받는다 (내용이 바뀌므로 sha256이 달라진다)
  log "OSV zip 없음. 새로 받는다"
  (cd "$ROOT" && "$PY" -c "from common.fetch import fetch; fetch('$OSV_ZIP_URL', 'reach/Go_all.zip', manifest='reach')")
  OSV_ZIP="$ROOT/data/raw/reach/Go_all.zip"
fi
mkdir -p "$TMP/osvzip_go"
unzip -q "$OSV_ZIP" 'GO-*' -d "$TMP/osvzip_go"
(cd "$HERE/builddb" && GOTOOLCHAIN=$GV_BUILD_TC go run . -src "$TMP/osvzip_go" -out "$TMP/db_osvzip") > "$OUT/db_build_osvzip.txt"
ZIP_STATS=$("$PY" -I -c 'import json,sys,zipfile
z=zipfile.ZipFile(sys.argv[1]); n=0; ng=0; mx=""
for i in z.namelist():
    n+=1
    m=json.loads(z.read(i)).get("modified","")
    if m>mx: mx=m
    if i.startswith("GO-"): ng+=1
print(json.dumps({"records_all": n, "records_go": ng, "max_modified_all": mx}))' "$OSV_ZIP")

# 대조2: golang/vulndb 고정 커밋 (깊이 1 전체 받기. blob:none 은 파일을 하나씩 받아서 느리다)
VULNDB_OK=0
VDIR="$CACHE/vulndb"
if [ -d "$VDIR/.git" ] && [ "$(git -C "$VDIR" rev-parse HEAD 2>/dev/null)" = "$VULNDB_COMMIT" ]; then
  VULNDB_OK=1
else
  rm -rf "$VDIR"
  git init -q "$VDIR"
  git -C "$VDIR" remote add origin "$VULNDB_URL"
  if timeout "$VULNDB_TIMEOUT" git -C "$VDIR" fetch -q --depth 1 origin "$VULNDB_COMMIT" \
     && git -C "$VDIR" checkout -q FETCH_HEAD; then
    VULNDB_OK=1
  else
    log "golang/vulndb 받기 실패 또는 ${VULNDB_TIMEOUT}s 초과. 대조2 생략"
  fi
fi
if [ $VULNDB_OK = 1 ]; then
  VULNDB_TIME=$(git -C "$VDIR" log -1 --format=%cI)
  VULNDB_TIME_UTC=$(date -u -d "$VULNDB_TIME" +%Y-%m-%dT%H:%M:%SZ)
  (cd "$HERE/builddb" && GOTOOLCHAIN=$GV_BUILD_TC go run . -src "$VDIR/data/osv" -out "$TMP/db_vulndb" -modified-fallback "$VULNDB_TIME_UTC") > "$OUT/db_build_vulndb.txt"
  "$PY" -I "$HERE/compare_db_sources.py" "$TMP/osvzip_go" "$VDIR/data/osv" "$OUT/db_source_compare.json" > /dev/null
fi

"$PY" -I - "$OUT/db_provenance.json" <<EOF
import json, sys
d = {
 "primary_db": {"kind": "builddb v1 DB", "path": "$TMP/db_osvzip", "source_url": "$OSV_ZIP_URL", "filter": "GO-* only",
   "local_file": "$OSV_ZIP", "sha256": "$(sha256sum "$OSV_ZIP" | cut -d' ' -f1)", "bytes": $(stat -c %s "$OSV_ZIP"),
   "file_mtime_utc": "$(date -u -r "$OSV_ZIP" +%Y-%m-%dT%H:%M:%SZ)", "zip_stats": $ZIP_STATS,
   "index_db_json": $(cat "$TMP/db_osvzip/index/db.json"), "build": "$(tr '\n' ' ' < "$OUT/db_build_osvzip.txt")"},
 "check_db_flat": {"kind": "same GO-* files as a flat folder; govulncheck builds its own in-memory index (hybrid source)", "path": "$TMP/osvzip_go"},
 "check_db_vulndb": None,
}
if $VULNDB_OK:
    d["check_db_vulndb"] = {"kind": "builddb v1 DB", "path": "$TMP/db_vulndb", "source": "$VULNDB_URL data/osv", "commit": "$VULNDB_COMMIT",
      "commit_time": "${VULNDB_TIME:-}", "index_db_json": json.loads(open("$TMP/db_vulndb/index/db.json").read()),
      "build": open("$OUT/db_build_vulndb.txt").read().replace("\n", " ").strip()}
open(sys.argv[1], "w").write(json.dumps(d, indent=1, ensure_ascii=False) + "\n")
EOF
DB_MAIN="file://$TMP/db_osvzip"
DB_FLAT="file://$TMP/osvzip_go"
DB_CHECK="file://$TMP/db_vulndb"

# ---------------------------------------------------------------- 2. 대조 실험, 오프라인 증명
log "2. 대조 실험 (testmod)"
C="$OUT/controls"
rm -rf "$C"
mkdir -p "$C"
cp -r "$HERE/testmod" "$TMP/testmod"
(cd "$TMP/testmod" && GOTOOLCHAIN=local go mod download && GOTOOLCHAIN=local go list -deps ./... > /dev/null)
for pkg in called imported; do
  rc=0
  (cd "$TMP/testmod" && offline GOTOOLCHAIN=local nice -n 10 "$GV" -db "$DB_MAIN" -format json "./$pkg") \
    > "$TMP/control.$pkg.json" 2> "$C/$pkg.stderr.txt" || rc=$?
  echo "rc=$rc" >> "$C/$pkg.stderr.txt"
  gzip -n -9 -c "$TMP/control.$pkg.json" > "$C/$pkg.json.gz"
  "$GV" -mode convert -show verbose < "$TMP/control.$pkg.json" > "$C/$pkg.txt" 2>&1 || true
done

# 네임스페이스 안에 정말 네트워크가 없는지
{
  echo "## unshare -n 안의 네트워크 장치 (/proc/net/dev)"
  unshare -n cat /proc/net/dev
  echo
  echo "## unshare -n 안에서 curl https://proxy.golang.org (실패해야 정상)"
  crc=0; unshare -n curl -sS -m 10 -o /dev/null https://proxy.golang.org/ > "$TMP/netns_curl.txt" 2>&1 || crc=$?
  mask_proxy < "$TMP/netns_curl.txt"
  echo "curl_rc=$crc"
  echo
  echo "## unshare -n 안에서 IP로 직접 TCP 연결 1.1.1.1:443 (DNS 없이. 실패해야 정상)"
  trc=0; unshare -n bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' > "$TMP/netns_tcp.txt" 2>&1 || trc=$?
  cat "$TMP/netns_tcp.txt"
  echo "tcp_rc=$trc"
} > "$TMP/netns_check.txt" 2>&1 || true

# connect() 시스템 호출 기록 (자식 프로세스 go list 까지 -f 로 따라간다)
strace_run() {  # $1 이름, $2 작업 폴더, 나머지: 명령
  local name=$1 dir=$2; shift 2
  local rc=0
  (cd "$dir" && unshare -n env GOPROXY=off strace -f -qq -e trace=connect -o "$TMP/strace.$name.txt" "$@" > "$TMP/strace.$name.out.json" 2> "$TMP/strace.$name.err") || rc=$?
  local tot inet unix
  tot=$(grep -c 'connect(' "$TMP/strace.$name.txt" || true)
  inet=$(grep -cE 'connect\(.*AF_INET6?[,}]' "$TMP/strace.$name.txt" || true)
  unix=$(grep -cE 'connect\(.*AF_UNIX' "$TMP/strace.$name.txt" || true)
  local nf
  nf=$(grep -c '"finding"' "$TMP/strace.$name.out.json" || true)
  echo "$name: rc=$rc connect_total=$tot connect_inet=$inet connect_unix=$unix findings=$nf"
}
{
  echo "# 오프라인 증명 ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
  echo "방법: unshare -n (새 네트워크 네임스페이스, lo만), GOPROXY=off, strace -f -e trace=connect"
  echo
  cat "$TMP/netns_check.txt"
  echo
  echo "## strace connect 집계"
  strace_run control_called "$TMP/testmod" env GOTOOLCHAIN=local "$GV" -db "$DB_MAIN" -format json ./called
} > "$C/offline_proof.txt"

# 기본 DB(https://vuln.go.dev)로 돌리면: 이 환경에서는 프록시가 막는다 (온라인, 실패가 기대값)
drc=0
(cd "$TMP/testmod" && GOTOOLCHAIN=local timeout 120 "$GV" ./called > "$TMP/default_db.txt" 2>&1) || drc=$?
mask_proxy < "$TMP/default_db.txt" > "$C/default_db_attempt.txt"
echo "rc=$drc" >> "$C/default_db_attempt.txt"

# ---------------------------------------------------------------- 2b. 평문 서버가 HTTP/2를 말하나 (frontend 해석용)
# frontend v0.5.0 은 http.ListenAndServe(평문). go1.19.4 net/http 로 평문과 TLS 서버에 HTTP/2 서문을 보내 본다 (127.0.0.1 만)
log "2b. h2probe (go1.19.4)"
rm -rf "$TMP/h2probe"
cp -r "$HERE/h2probe" "$TMP/h2probe"
GOTOOLCHAIN=go1.19.4 go version > /dev/null   # (온라인) 툴체인이 캐시에 없으면 받는다
hrc=0
(cd "$TMP/h2probe" && GOPROXY=off GOTOOLCHAIN=go1.19.4 go build -o h2probe . && ./h2probe) > "$OUT/h2probe.jsonl" 2> "$TMP/h2probe.err" || hrc=$?
[ $hrc = 0 ] || { log "h2probe 실패 rc=$hrc"; cp "$TMP/h2probe.err" "$OUT/h2probe.err.txt"; }

# ---------------------------------------------------------------- 3. 서비스
log "3. 서비스 분석"
run_gv() {  # $1 출력 json, $2 작업 폴더, 나머지: env 설정과 govulncheck 인자
  local outj=$1 dir=$2; shift 2
  local rc=0
  (cd "$dir" && offline "$@") > "$outj" 2> "$outj.err" || rc=$?
  echo $rc
}
for t in "${TARGETS[@]}"; do
  IFS='|' read -r label wt want loader gover alt <<< "$t"
  got=$(git -C "$wt" rev-parse HEAD)
  if [ "$got" != "$want" ]; then
    echo "워크트리 커밋 불일치: $wt $got != $want" >&2
    exit 1
  fi
  d="$OUT/$label"
  rm -rf "$d"
  mkdir -p "$d" "$TMP/src/$label" "$TMP/runs/$label"
  for gm in "$wt"/src/*/go.mod; do
    svc=$(basename "$(dirname "$gm")")
    work="$TMP/src/$label/$svc"
    R="$TMP/runs/$label/$svc"
    cp -r "$(dirname "$gm")" "$work"
    log "$label $svc (loader=$loader, GOVERSION=$gover, alt=$alt)"
    # (온라인) 모듈과 툴체인 받기, 패키지 목록으로 캐시 채우기
    dl_rc=0
    {
      for tc in "$loader" "$alt"; do
        echo "## GOTOOLCHAIN=$tc"
        (cd "$work" && GOTOOLCHAIN=$tc go version && GOTOOLCHAIN=$tc go mod download && GOTOOLCHAIN=$tc go list -deps ./... > /dev/null) || dl_rc=$?
      done
    } > "$d/$svc.download.log" 2>&1 || true
    (cd "$work" && GOTOOLCHAIN=$loader go mod edit -json) > "$R.gomod.json"
    # (오프라인) 주 실행: 심볼 수준, 모듈과 패키지 수준 결과도 JSON에 함께 나온다
    t0=$(date +%s)
    gv_rc=$(run_gv "$R.primary.json" "$work" GOTOOLCHAIN=$loader GOVERSION=$gover nice -n 10 "$GV" -db "$DB_MAIN" -format json ./...)
    t1=$(date +%s)
    cp "$R.primary.json.err" "$d/$svc.stderr.txt"
    gzip -n -9 -c "$R.primary.json" > "$d/$svc.json.gz"
    cv_rc=0
    "$GV" -mode convert -format openvex < "$R.primary.json" > "$d/$svc.openvex.json" 2>> "$d/$svc.stderr.txt" || cv_rc=$?
    "$GV" -mode convert < "$R.primary.json" > "$R.txt" 2>&1 || true   # 사람이 읽는 텍스트 (결과 폴더에는 안 둔다)
    # (오프라인) 민감도: 같은 로더(민감도용)에서 GOVERSION 있음/없음
    a1_rc=$(run_gv "$R.alt_gover.json" "$work" GOTOOLCHAIN=$alt GOVERSION=$gover nice -n 10 "$GV" -db "$DB_MAIN" -format json ./...)
    a2_rc=$(run_gv "$R.alt_nogover.json" "$work" GOTOOLCHAIN=$alt nice -n 10 "$GV" -db "$DB_MAIN" -format json ./...)
    # (오프라인) DB 대조: 평평한 폴더(govulncheck 자체 색인), golang/vulndb 고정 커밋
    f_rc=$(run_gv "$R.flatdb.json" "$work" GOTOOLCHAIN=$loader GOVERSION=$gover nice -n 10 "$GV" -db "$DB_FLAT" -format json ./...)
    ck_rc=-1
    if [ $VULNDB_OK = 1 ]; then
      ck_rc=$(run_gv "$R.vulndb.json" "$work" GOTOOLCHAIN=$loader GOVERSION=$gover nice -n 10 "$GV" -db "$DB_CHECK" -format json ./...)
    fi
    # (오프라인) go.mod require 목록 + 표준 라이브러리 버전 조회 (패키지 사용과 무관한 기준선)
    mapfile -t reqs < <("$PY" -I -c 'import json,sys; [print(r["Path"]+"@"+r["Version"]) for r in json.load(open(sys.argv[1])).get("Require") or []]' "$R.gomod.json")
    q_rc=$(run_gv "$R.query.json" "$work" "$GV" -db "$DB_MAIN" -mode query -format json "${reqs[@]}" "stdlib@$gover")
    cat > "$d/$svc.status.json" <<EOF
{"label": "$label", "service": "$svc", "commit": "$want", "loader_gotoolchain": "$loader", "goversion_for_stdlib": "$gover",
 "alt_loader_gotoolchain": "$alt", "go_mod_download_rc": $dl_rc, "govulncheck_rc": $gv_rc, "govulncheck_wall_s": $((t1 - t0)),
 "openvex_convert_rc": $cv_rc, "alt_gover_rc": $a1_rc, "alt_nogover_rc": $a2_rc, "flatdb_rc": $f_rc, "vulndb_rc": $ck_rc,
 "query_rc": $q_rc, "query_n_require": ${#reqs[@]}}
EOF
  done
  find "$d" -name '*.stderr.txt' -empty -delete
done

# frontend v0.5.0 에 h2c(평문 HTTP/2)가 있나: 소스 grep 과 의존 패키지 목록
{
  echo "## grep -rn h2c src/frontend (*.go), v0.5.0"
  grep -rn 'h2c' --include='*.go' "/home/user/work/ob_v0.5.0/src/frontend" || echo "(없음)"
  echo
  echo "## go list -deps ./... 중 net/http, x/net/http2, h2c (GOTOOLCHAIN=go1.20.4, 오프라인)"
  (cd "$TMP/src/v0.5.0-3c0d659/frontend" && offline GOTOOLCHAIN=go1.20.4 go list -deps ./...) | grep -E '^net/http$|x/net/http2$|h2c' || true
  echo "(h2c 줄이 없으면 의존 그래프에 h2c 패키지가 없다)"
} > "$OUT/frontend_h2c_check.txt" 2>&1

# 실제 서비스 1개도 strace 로 확인 (go list 자식 프로세스 포함)
{
  echo
  strace_run v050_checkoutservice "$TMP/src/v0.5.0-3c0d659/checkoutservice" env GOTOOLCHAIN=go1.20.4 GOVERSION=go1.19.4 "$GV" -db "$DB_MAIN" -format json ./...
  strace_run main_frontend "$TMP/src/main-c7cb6d5/frontend" env GOTOOLCHAIN=go1.27.0 GOVERSION=go1.27.0 "$GV" -db "$DB_MAIN" -format json ./...
} >> "$C/offline_proof.txt"

# govulncheck 빌드 툴체인 확인: 공용 바이너리(go1.26.10 빌드)로 같은 설정을 한 번씩 (결정 1 의 근거)
mkdir -p "$TMP/buildcheck"
b1=$(run_gv "$TMP/buildcheck/v050_frontend.json" "$TMP/src/v0.5.0-3c0d659/frontend" GOTOOLCHAIN=go1.20.4 GOVERSION=go1.19.4 nice -n 10 "$GV_SHARED" -db "$DB_MAIN" -format json ./...)
b2=$(run_gv "$TMP/buildcheck/main_frontend.json" "$TMP/src/main-c7cb6d5/frontend" GOTOOLCHAIN=go1.27.0 GOVERSION=go1.27.0 nice -n 10 "$GV_SHARED" -db "$DB_MAIN" -format json ./...)
echo "{\"v050_frontend_rc\": $b1, \"main_frontend_rc\": $b2}" > "$TMP/buildcheck/rc.json"

# ---------------------------------------------------------------- 4. 집계
log "4. 집계"
"$PY" -I "$HERE/analyze.py" --out "$OUT" --tmp "$TMP" --db "$TMP/db_osvzip"
log "끝"
