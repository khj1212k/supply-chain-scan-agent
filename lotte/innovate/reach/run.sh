#!/usr/bin/env bash
# Go 도달성 분석 (govulncheck v1.9.0, 로컬 DB, 네트워크 차단 상태로 실행)
#
# 사용: cd lotte/innovate && bash reach/run.sh
# 출력: results/reach/ (요약은 reach/NOTES.md)
# 임시: /home/user/work/reachtmp/ (매번 지우고 새로 만든다)
#
# 단계
#   0. 도구 버전 기록
#   1. govulncheck DB 2개 만들기: (주) OSV Go all.zip의 GO-*, (대조) golang/vulndb 고정 커밋
#   2. 대조 실험: 취약 심볼을 부르는 작은 모듈(양성)과 import만 하는 모듈(음성)
#   3. Online Boutique 3개 커밋 x Go 서비스 4개: govulncheck source 모드 (JSON, OpenVEX, 텍스트)
#      + go.mod require 목록을 같은 DB에 조회 (govulncheck -mode query)
#      + 대조 DB로 한 번 더 (결과가 같은지)
#      + osv-scanner --call-analysis=go (오프라인 DB)
#   4. reach/analyze.py: levels.csv, summary.json, cve_2023_44487.md 등
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)   # lotte/innovate/reach
ROOT=$(dirname "$HERE")                              # lotte/innovate
OUT="$ROOT/results/reach"
TMP=/home/user/work/reachtmp
GOVULNCHECK=/home/user/tools/bin/govulncheck
OSVSCANNER=/home/user/tools/bin/osv-scanner
GOBIN_DIR=/usr/local/go/bin
PY="$ROOT/.venv/bin/python"

OSV_ZIP=/home/user/work/osvdb/osv-scalibr/Go/all.zip
OSV_ZIP_URL=https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip
VULNDB_URL=https://github.com/golang/vulndb.git
VULNDB_COMMIT=8f7e390a0ff7345d74ecd7a056a1073214466db9

export GOPATH=/home/user/tools/gopath
export GOMAXPROCS=2
export PATH="$GOBIN_DIR:$PATH"
export GOFLAGS=
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/home/user/work/osvdb

# 분석 대상: 라벨 | 워크트리 | 기대 커밋 | 패키지 로딩 툴체인 | 표준 라이브러리 판정 버전(Dockerfile golang 이미지)
TARGETS=(
  "v0.5.0-3c0d659|/home/user/work/ob_v0.5.0|3c0d6597809d1f40dccd24b757b7ca67d40cadf8|local|go1.19.4"
  "v0.8.0-d54af3d|/home/user/work/ob_v0.8.0|d54af3d2510995d33521ac543dd885b150213f95|local|go1.20.4"
  "main-c7cb6d5|/home/user/work/ob_main|c7cb6d5bfd6ea3aed768634ebbcb98cb7a523712|go1.26.10|go1.27.0"
)

log() { printf '[reach %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

# 네트워크 없는 네임스페이스에서 실행 (DB와 모듈 캐시만 쓴다는 증명)
offline() { unshare -n env GOPROXY=off "$@"; }

mkdir -p "$TMP" "$OUT"

# ---------------------------------------------------------------- 0. 도구 버전
log "0. 도구 버전"
{
  echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "go_local: $($GOBIN_DIR/go version)"
  echo "govulncheck_buildinfo: $($GOBIN_DIR/go version "$GOVULNCHECK")"
  echo "govulncheck_module: $($GOBIN_DIR/go version -m "$GOVULNCHECK" | awk '$1=="mod"{print $2, $3}')"
  echo "osv_scanner: $($OSVSCANNER --version 2>&1 | tr '\n' ' ')"
  echo "repo_commit: $(git -C "$ROOT" rev-parse HEAD)"
} > "$OUT/tool_versions.txt"

# ---------------------------------------------------------------- 1. DB
log "1. DB 만들기"
if [ ! -f "$OSV_ZIP" ]; then
  # 원래 파일이 없으면 지금 받는다 (내용이 바뀌므로 sha256이 달라진다)
  log "OSV zip 없음. 새로 받는다"
  (cd "$ROOT" && "$PY" -c "from common.fetch import fetch; fetch('$OSV_ZIP_URL', 'reach/Go_all.zip', manifest='reach')")
  OSV_ZIP="$ROOT/data/raw/reach/Go_all.zip"
fi
rm -rf "$TMP/osvzip_go" "$TMP/db_osvzip" "$TMP/db_vulndb" "$TMP/vulndb"
mkdir -p "$TMP/osvzip_go"
unzip -q "$OSV_ZIP" 'GO-*' -d "$TMP/osvzip_go"
(cd "$HERE/builddb" && go run . -src "$TMP/osvzip_go" -out "$TMP/db_osvzip") > "$OUT/db_build_osvzip.txt"

git init -q "$TMP/vulndb"
git -C "$TMP/vulndb" remote add origin "$VULNDB_URL"
git -C "$TMP/vulndb" config core.sparseCheckout true
echo "data/osv/" > "$TMP/vulndb/.git/info/sparse-checkout"
git -C "$TMP/vulndb" fetch -q --depth 1 --filter=blob:none origin "$VULNDB_COMMIT"
git -C "$TMP/vulndb" checkout -q FETCH_HEAD
VULNDB_TIME=$(git -C "$TMP/vulndb" log -1 --format=%cI)
VULNDB_TIME_UTC=$(date -u -d "$VULNDB_TIME" +%Y-%m-%dT%H:%M:%SZ)
(cd "$HERE/builddb" && go run . -src "$TMP/vulndb/data/osv" -out "$TMP/db_vulndb" -modified-fallback "$VULNDB_TIME_UTC") > "$OUT/db_build_vulndb.txt"

"$PY" -I "$HERE/compare_db_sources.py" "$TMP/osvzip_go" "$TMP/vulndb/data/osv" "$OUT/db_source_compare.json" > /dev/null

{
  echo "{"
  echo "  \"primary_db\": {\"path\": \"$TMP/db_osvzip\", \"source\": \"$OSV_ZIP_URL (GO-* only)\", \"local_file\": \"$OSV_ZIP\","
  echo "    \"sha256\": \"$(sha256sum "$OSV_ZIP" | cut -d' ' -f1)\", \"bytes\": $(stat -c %s "$OSV_ZIP"), \"file_mtime_utc\": \"$(date -u -r "$OSV_ZIP" +%Y-%m-%dT%H:%M:%SZ)\","
  echo "    \"index_db_json\": $(cat "$TMP/db_osvzip/index/db.json"), \"build\": \"$(cat "$OUT/db_build_osvzip.txt" | tr '\n' ' ')\"},"
  echo "  \"check_db\": {\"path\": \"$TMP/db_vulndb\", \"source\": \"$VULNDB_URL data/osv\", \"commit\": \"$(git -C "$TMP/vulndb" rev-parse HEAD)\", \"commit_time\": \"$VULNDB_TIME\","
  echo "    \"index_db_json\": $(cat "$TMP/db_vulndb/index/db.json"), \"build\": \"$(cat "$OUT/db_build_vulndb.txt" | tr '\n' ' ')\"}"
  echo "}"
} > "$OUT/db_provenance.json"
DB_MAIN="file://$TMP/db_osvzip"
DB_CHECK="file://$TMP/db_vulndb"

# ---------------------------------------------------------------- 2. 대조 실험
log "2. 대조 실험 (testmod)"
C="$OUT/controls"
rm -rf "$C" "$TMP/testmod"
mkdir -p "$C"
cp -r "$HERE/testmod" "$TMP/testmod"
(cd "$TMP/testmod" && GOTOOLCHAIN=local go mod download)
for pkg in called imported; do
  for db in main check; do
    dburl=$DB_MAIN; [ "$db" = check ] && dburl=$DB_CHECK
    (cd "$TMP/testmod" && offline GOTOOLCHAIN=local nice -n 10 "$GOVULNCHECK" -db "$dburl" -format json "./$pkg") \
      > "$C/${pkg}.${db}db.json" 2> "$C/${pkg}.${db}db.err" || echo "rc=$?" >> "$C/${pkg}.${db}db.err"
  done
  "$GOVULNCHECK" -mode convert < "$C/${pkg}.maindb.json" > "$C/${pkg}.txt" 2>&1 || true
done
# connect() 시스템 호출 기록: 네트워크 네임스페이스 안에서 inet 연결 시도가 있는지
(cd "$TMP/testmod" && unshare -n env GOPROXY=off GOTOOLCHAIN=local \
  strace -f -qq -e trace=connect -o "$TMP/strace_called.txt" "$GOVULNCHECK" -db "$DB_MAIN" -format json ./called > /dev/null 2>&1) || true
{
  echo "connect_calls_total: $(grep -c 'connect(' "$TMP/strace_called.txt" || true)"
  echo "connect_calls_inet: $(grep -cE 'connect\(.*AF_INET' "$TMP/strace_called.txt" || true)"
  echo "note: strace -f -e trace=connect, unshare -n, -db $DB_MAIN"
} > "$C/strace_connect_summary.txt"
# 기본 DB(https://vuln.go.dev)로 돌리면 어떻게 되나: 이 환경에서는 프록시가 막는다
(cd "$TMP/testmod" && GOTOOLCHAIN=local timeout 120 "$GOVULNCHECK" ./called > "$C/default_db_attempt.txt" 2>&1) \
  && echo "rc=0" >> "$C/default_db_attempt.txt" || echo "rc=$?" >> "$C/default_db_attempt.txt"

# ---------------------------------------------------------------- 3. 서비스
log "3. 서비스 분석"
for t in "${TARGETS[@]}"; do
  IFS='|' read -r label wt want loader gover <<< "$t"
  got=$(git -C "$wt" rev-parse HEAD)
  if [ "$got" != "$want" ]; then
    echo "워크트리 커밋 불일치: $wt $got != $want" >&2
    exit 1
  fi
  d="$OUT/$label"
  rm -rf "$d" "$TMP/src/$label"
  mkdir -p "$d" "$TMP/src/$label"
  for gm in "$wt"/src/*/go.mod; do
    svc=$(basename "$(dirname "$gm")")
    work="$TMP/src/$label/$svc"
    cp -r "$(dirname "$gm")" "$work"
    log "$label $svc (loader=$loader, GOVERSION=$gover)"
    # (온라인) 모듈과 툴체인 받기
    dl_rc=0
    (cd "$work" && GOTOOLCHAIN=$loader go mod download) > "$d/$svc.download.log" 2>&1 || dl_rc=$?
    (cd "$work" && GOTOOLCHAIN=$loader go version) >> "$d/$svc.download.log" 2>&1 || true
    (cd "$work" && GOTOOLCHAIN=$loader go mod edit -json) > "$d/$svc.gomod.json"
    # (오프라인) govulncheck source 모드, 심볼 수준
    t0=$(date +%s)
    gv_rc=0
    (cd "$work" && offline GOTOOLCHAIN=$loader GOVERSION=$gover nice -n 10 "$GOVULNCHECK" -db "$DB_MAIN" -format json ./...) \
      > "$TMP/$label.$svc.json" 2> "$d/$svc.stderr.txt" || gv_rc=$?
    t1=$(date +%s)
    gzip -n -9 -c "$TMP/$label.$svc.json" > "$d/$svc.json.gz"
    cv_rc=0
    "$GOVULNCHECK" -mode convert -format openvex < "$TMP/$label.$svc.json" > "$d/$svc.openvex.json" 2>> "$d/$svc.stderr.txt" || cv_rc=$?
    "$GOVULNCHECK" -mode convert < "$TMP/$label.$svc.json" > "$d/$svc.txt" 2>&1 || true
    # 대조 DB로 한 번 더 (JSON만, 커밋하지 않는 임시 위치)
    ck_rc=0
    (cd "$work" && offline GOTOOLCHAIN=$loader GOVERSION=$gover nice -n 10 "$GOVULNCHECK" -db "$DB_CHECK" -format json ./...) \
      > "$TMP/$label.$svc.checkdb.json" 2> "$TMP/$label.$svc.checkdb.err" || ck_rc=$?
    # go.mod require 목록 전체를 같은 DB에 조회 (패키지 사용 여부와 무관한 '모듈 수준' 기준선)
    mapfile -t reqs < <("$PY" -I -c 'import json,sys; [print(r["Path"]+"@"+r["Version"]) for r in json.load(open(sys.argv[1])).get("Require") or []]' "$d/$svc.gomod.json")
    q_rc=0
    offline "$GOVULNCHECK" -db "$DB_MAIN" -mode query -format json "${reqs[@]}" > "$TMP/$label.$svc.query.json" 2> "$d/$svc.query.stderr.txt" || q_rc=$?
    gzip -n -9 -c "$TMP/$label.$svc.query.json" > "$d/$svc.gomod_query.json.gz"
    # osv-scanner 호출 분석 (같은 OSV zip, GO-*와 GHSA-* 둘 다 쓴다)
    os_rc=0
    (cd "$TMP/src/$label" && offline GOTOOLCHAIN=$loader nice -n 10 "$OSVSCANNER" scan source --offline-vulnerabilities \
       --call-analysis=go --format json -r "$svc") > "$d/$svc.osvscanner.json" 2> "$d/$svc.osvscanner.stderr.txt" || os_rc=$?
    cat > "$d/$svc.status.json" <<EOF
{"label": "$label", "service": "$svc", "commit": "$want", "loader_gotoolchain": "$loader", "goversion_for_stdlib": "$gover",
 "go_mod_download_rc": $dl_rc, "govulncheck_rc": $gv_rc, "govulncheck_wall_s": $((t1 - t0)), "openvex_convert_rc": $cv_rc,
 "checkdb_rc": $ck_rc, "query_rc": $q_rc, "query_n_require": ${#reqs[@]}, "osvscanner_rc": $os_rc}
EOF
  done
done

# ---------------------------------------------------------------- 4. 집계
log "4. 집계"
"$PY" -I "$HERE/analyze.py" --out "$OUT" --tmp "$TMP"
log "끝"
