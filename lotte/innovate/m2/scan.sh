#!/usr/bin/env bash
# M2 스캔: Syft 소스 트리 SBOM + OSV-Scanner 오프라인 (잠금 파일 경로, SBOM 경로, 표준 라이브러리 변형)
#
# 사용: cd lotte/innovate && bash m2/scan.sh        (전체는 bash m2/run.sh)
# 출력
#   - 큰 원본: $M2TMP/<라벨>/ (SBOM, 스캔 JSON, 로그). 기본 /home/user/work/m2tmp
#   - 작은 기록: results/m2/scan_runs.csv (명령, 종료 코드, 시간), results/m2/tool_versions.txt, results/m2/logs/
# 단계 (커밋마다). [격리] = unshare -n (네트워크 이름공간 없음)에서 실행해 네트워크 없이 도는 것을 증명
#   syft              [격리] Syft 1.55.0, dir:<워크트리>/src, CycloneDX 1.6 JSON
#   lock              [격리] osv-scanner scan source -r --offline --no-call-analysis=go (잠금 파일 직접. 주 경로)
#   lock_call         osv-scanner 기본값 그대로 (Go 호출 분석 켜짐). go 명령이 proxy.golang.org 에서 모듈을 받을 수 있다. 참고용
#   lock_resolve      osv-scanner --offline-vulnerabilities (전이 해석 시도. deps.dev 403 확인용)
#   sbom              [격리] osv-scanner scan source -L sbom.cdx.json --offline (Syft SBOM 경로)
#   lock_std_gomod    [격리] 표준 라이브러리 포함 (ScanGoModVersion=true: go.mod 의 toolchain 또는 go 지시어 버전)
#   lock_std_override [격리] GoVersionOverride=<Dockerfile 버전>. 2.7.0 은 매칭 뒤에 버전 표시만 바꾼다 (동작 확인용)
#   std_probe         [격리] go 지시어만 Dockerfile 버전으로 둔 빈 모듈. 표준 라이브러리를 실제 빌드 버전으로 매칭
# DB 적재 오류('could not load db', 'no offline version')가 하나라도 있으면 실패로 끝난다 (빈 결과를 '취약점 없음'으로 읽지 않게)
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)   # lotte/innovate/m2
ROOT=$(dirname "$HERE")                              # lotte/innovate
OUT="$ROOT/results/m2"
TMP=${M2TMP:-/home/user/work/m2tmp}
TOOLS=${M2TOOLS:-/home/user/tools/bin}
SYFT="$TOOLS/syft"
OSV="$TOOLS/osv-scanner"
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=${OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY:-/home/user/work/osvdb}
export GOMAXPROCS=2
export SYFT_CHECK_FOR_APP_UPDATE=false
export PATH="/usr/local/go/bin:$PATH"

# 라벨 | 워크트리 | 기대 커밋
TARGETS=(
  "v0.5.0|/home/user/work/ob_v0.5.0|3c0d6597809d1f40dccd24b757b7ca67d40cadf8"
  "main|/home/user/work/ob_main|c7cb6d5bfd6ea3aed768634ebbcb98cb7a523712"
  "v0.8.0|/home/user/work/ob_v0.8.0|d54af3d2510995d33521ac543dd885b150213f95"
)

mkdir -p "$TMP" "$OUT/logs"
RUNS="$OUT/scan_runs.csv"
echo "label,step,commit,started_utc,seconds,exit_code,output,log,command" > "$RUNS"

# 0. 도구 버전 (go install 빌드라 syft version 은 '[not provided]'. 모듈 버전은 go version -m 으로)
{
  echo "# 기록 시각 $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "## syft"; go version -m "$SYFT" | sed -n '1,3p'
  echo "## osv-scanner --version"; "$OSV" --version
  echo "## osv-scanner 빌드 모듈 (osv-scalibr 실제 버전)"; go version -m "$OSV" | grep -E "^\s+(path|mod)\s|osv-scalibr\s"
  echo "## go (lock_call 의 호출 분석이 쓰는 툴체인. GOTOOLCHAIN=auto 면 go.mod toolchain 지시어 버전으로 바뀔 수 있다)"; go version; go env GOTOOLCHAIN GOPROXY
  echo "## OSV DB 폴더"; echo "$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"
  ls -l --time-style=+%Y-%m-%dT%H:%M "$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"/osv-scalibr/*/all.zip | awk '{print $5, $6, $7, $8, $9}'
} > "$OUT/tool_versions.txt" 2>&1

run() {  # run <라벨> <단계> <커밋> <출력> <명령...>
  local label=$1 step=$2 sha=$3 out=$4; shift 4
  local log="$TMP/$label/$step.log" t0 t1 rc started
  started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  t0=$(date +%s.%N)
  nice -n 10 "$@" > "$log" 2>&1
  rc=$?
  t1=$(date +%s.%N)
  local sec; sec=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')
  # 명령 기록: 절대 경로는 그대로 둔다 (비밀값 없음)
  local cmd; cmd=$(printf '%q ' "$@" | sed 's/"/""/g')
  echo "$label,$step,$sha,$started,$sec,$rc,$out,$log,\"$cmd\"" >> "$RUNS"
  cp "$log" "$OUT/logs/${label}_${step}.log"
  echo "[$label $step] exit=$rc ${sec}s"
  # osv-scanner: 0=취약점 없음, 1=취약점 있음, 그 밖은 오류
  if [[ $rc -gt 1 ]]; then echo "  !! 오류 종료: $log"; FAILED=1; fi
  if grep -qiE "could not load db|no offline version|unable to fetch OSV database|failed to load" "$log"; then
    echo "  !! DB 적재 오류: $log"; grep -iE "could not load db|no offline version|unable to fetch OSV database|failed to load" "$log" | head -3
    FAILED=1
  fi
}

FAILED=0
for t in "${TARGETS[@]}"; do
  IFS='|' read -r label wt sha <<< "$t"
  got=$(git -C "$wt" rev-parse HEAD)
  if [[ "$got" != "$sha" ]]; then echo "커밋 불일치 $label: $got != $sha"; exit 1; fi
  d="$TMP/$label"; rm -rf "$d"; mkdir -p "$d"
  # Dockerfile golang 이미지 버전 (frontend 기준. 4개 Go 서비스가 같은지 확인)
  gov=$(grep -h "^FROM.*golang:" "$wt"/src/{frontend,checkoutservice,productcatalogservice,shippingservice}/Dockerfile \
        | sed -E 's/.*golang:([0-9.]+).*/\1/' | sort -u)
  if [[ $(echo "$gov" | wc -l) -ne 1 ]]; then echo "Go 이미지 버전이 서비스마다 다르다 ($label): $gov"; exit 1; fi
  echo "$label go_image=$gov" >> "$OUT/tool_versions.txt"
  printf 'ScanGoModVersion = true\n' > "$d/std_gomod.toml"
  printf 'ScanGoModVersion = true\nGoVersionOverride = "%s"\n' "$gov" > "$d/std_override.toml"
  mkdir -p "$d/stdprobe"; printf 'module stdlibprobe\n\ngo %s\n' "$gov" > "$d/stdprobe/go.mod"
  ISO=(unshare -n)

  run "$label" syft "$sha" "$d/sbom.cdx.json" \
    "${ISO[@]}" "$SYFT" scan "dir:$wt/src" --source-name online-boutique-src --source-version "$label" \
    -o "cyclonedx-json@1.6=$d/sbom.cdx.json"
  run "$label" lock "$sha" "$d/lock.json" \
    "${ISO[@]}" "$OSV" scan source -r --offline --no-call-analysis=go --format json --all-packages --output-file "$d/lock.json" "$wt/src"
  run "$label" lock_call "$sha" "$d/lock_call.json" \
    "$OSV" scan source -r --offline --format json --all-packages --output-file "$d/lock_call.json" "$wt/src"
  run "$label" lock_resolve "$sha" "$d/lock_resolve.json" \
    "$OSV" scan source -r --offline-vulnerabilities --no-call-analysis=go --format json --all-packages --output-file "$d/lock_resolve.json" "$wt/src"
  run "$label" sbom "$sha" "$d/sbom.json" \
    "${ISO[@]}" "$OSV" scan source -L "$d/sbom.cdx.json" --offline --format json --all-packages --output-file "$d/sbom.json"
  run "$label" lock_std_gomod "$sha" "$d/lock_std_gomod.json" \
    "${ISO[@]}" "$OSV" scan source -r --offline --no-call-analysis=go --config "$d/std_gomod.toml" --format json --all-packages --output-file "$d/lock_std_gomod.json" "$wt/src"
  run "$label" lock_std_override "$sha" "$d/lock_std_override.json" \
    "${ISO[@]}" "$OSV" scan source -r --offline --no-call-analysis=go --config "$d/std_override.toml" --format json --all-packages --output-file "$d/lock_std_override.json" "$wt/src"
  run "$label" std_probe "$sha" "$d/std_probe.json" \
    "${ISO[@]}" "$OSV" scan source -r --offline --no-call-analysis=go --config "$d/std_gomod.toml" --format json --all-packages --output-file "$d/std_probe.json" "$d/stdprobe"
done

# 작은 원본만 results 에 gzip 으로 남긴다 (SBOM, 주 경로 스캔). 2MB 넘으면 남기지 않는다
mkdir -p "$OUT/raw"
for t in "${TARGETS[@]}"; do
  IFS='|' read -r label wt sha <<< "$t"
  for f in sbom.cdx.json lock.json; do
    gzip -9 -n -c "$TMP/$label/$f" > "$OUT/raw/${label}_${f}.gz"
    if [[ $(stat -c %s "$OUT/raw/${label}_${f}.gz") -gt 2000000 ]]; then rm "$OUT/raw/${label}_${f}.gz"; echo "$label $f.gz 2MB 초과, 남기지 않음"; fi
  done
done

if [[ $FAILED -ne 0 ]]; then echo "스캔 실패가 있다. 위 로그를 보고 다시 돌린다"; exit 2; fi
echo "scan ok -> $TMP, $RUNS"
