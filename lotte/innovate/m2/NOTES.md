# M2 스캔 깔때기 노트

## 결론 세 줄
1. 도구 경로(Syft 1.55.0, OSV-Scanner 2.7.0, 네트워크 없이)로 v0.5.0 보고 545행, main 200행이 나왔다. 기획안(609, 208)과의 차이는 전부 Maven(adservice) 행이다. 두 도구 다 `build.gradle`을 읽지 않는다
2. Go, npm, PyPI 보고 수는 기획안과 같다. v0.5.0은 164, 262, 119, main은 38, 42, 120. main 신호 큐 10행(Go 9, PyPI 1)과 KEV 1행(loadgenerator brotli, CVE-2026-111497)도 같다
3. v0.5.0 신호 큐는 37행(Go 36)이다. 기획안 38행에서 adservice의 KEV 1행이 빠졌다. Go 표준 라이브러리를 실제 빌드 버전(go1.19.4)으로 넣으면 큐는 102행이 된다(헤드라인 아님)

## 재현
```bash
cd lotte/innovate && bash m2/run.sh     # 약 7~8분 (439~484초)
```
- 순서: `m2/scan.sh`(스캔) -> `m2/funnel.py`(깔때기) -> `m2/vex_example.py`(VEX) -> `m2/figs.py`(그림)
- 미리 필요한 것
  - 도구: `/home/user/tools/bin/{syft,osv-scanner}`
  - OSV DB: `/home/user/work/osvdb/osv-scalibr/<생태계>/all.zip` (`m2/prepare.py --osvdb /home/user/work/osvdb`)
  - 워크트리: `/home/user/work/ob_{v0.5.0,main,v0.8.0}` (scan.sh가 커밋 해시를 대조하고 다르면 멈춘다)
  - 신호: `data/raw/kev`, `data/raw/epss/epss_scores-2026-11-01.csv.gz`, `data/raw/derived/nvd_table.csv.gz` (m1)
- 코드 커밋: 마지막 실행 때 저장소 HEAD는 `2f3e995`(summary.json `git.repo_head`), m2 코드는 미커밋이었다. 리드가 커밋한 해시를 RESULTS.md에 붙인다
- 네 번 돌렸다 (2026-11-02 UTC 시작 08:51, 09:08, 09:22, 09:42). 수치 CSV와 summary.json의 커밋별 값이 전부 같다 (마지막은 최종 코드)
  - 08:51 판은 `lock`에 호출 분석이 켜져 있었고 네트워크를 막지 않았다. 그래도 권고 목록과 수치가 같다
  - 실행 시간 484초, 439초, 445초 (다른 작업과 CPU를 나눠 씀)

## 헤드라인 수치 (잠금 파일 경로, Go 표준 라이브러리 제외)
| 항목 | v0.5.0 | main | v0.8.0 | 출처 |
|---|---|---|---|---|
| 서비스 (osv-scanner 패키지가 나온 서비스) | 10 | 11 | 10 | summary.json `services` |
| 서비스 (Syft 위치 기준) | 10 | 11 | 10 | summary.json `syft_services` |
| 구성요소 (osv-scanner 잠금 파일 항목) | 823 | 857 | 843 | funnel.csv |
| 구성요소 (Syft SBOM, 파일 항목 제외) | 827 | 898 | 842 | summary.json `syft_components`, services.csv |
| 취약 구성요소 | 135 | 61 | 133 | funnel.csv |
| 권고 보고 (구성요소 x 권고 ID) | 735 | 280 | 717 | funnel.csv |
| 보고 (구성요소 x CVE, 기획안 정의) | 545 | 200 | 536 | funnel.csv |
| 보고 생태계 Go / npm / PyPI / NuGet | 164 / 262 / 119 / 0 | 38 / 42 / 120 / 0 | 159 / 261 / 115 / 1 | summary.json `reported_by_eco` |
| 패키지 버전 (보고 행 기준) | 61 | 36 | 62 | summary.json `package_versions` |
| 상위 5개 점유 | 39.6% | 60.0% | 38.4% | summary.json `top5_share_pct` |
| 조인 별칭 / related 후보 / CVE 없음 | 532 / 4 / 9 | 191 / 0 / 9 | 523 / 4 / 9 | summary.json `join` |
| 고유 CVE (후보 포함) | 183 | 107 | 179 | funnel.csv |
| EPSS>=0.1 고유 CVE | 3 | 1 | 3 | funnel.csv |
| KEV 고유 CVE / 행 | 2 / 9 | 1 / 1 | 2 / 9 | funnel.csv, summary.json `kev_rows` |
| GHSA Critical(A) / KEV 또는 EPSS>=0.1(B) / 겹침 | 20 / 13 / 1 | 9 / 1 / 1 | 20 / 13 / 1 | summary.json |
| 신호 큐 (Go) | 37 (36) | 10 (9) | 37 (36) | funnel.csv, summary.json `queue_by_eco` |
| 신호 큐 중 Go 비중 | 97.3% (36/37) | 90.0% (9/10) | 97.3% (36/37) | 위 두 값으로 계산 |
| 신호 큐 비율 (CVE 붙은 행 대비) | 6.9% (37/536) | 5.2% (10/191) | 7.0% (37/527) | summary.json `queue_share_of_rows_with_cve_pct`, `rows_with_cve` |
| 신호 큐 중 frontend 행 | 27 | 9 | 27 | summary.json `queue_by_service` |
| 큐 밖 (60일, 업그레이드 시) | 499 (274, 225) | 181 (112, 69) | 490 (269, 221) | summary.json `out_by_due` |
| 큐 밖 패키지 버전 | 60 | 32 | 61 | summary.json |
| 표본 (생태계별 5, 시드 20261102) | 15 (Go, PyPI, npm 5씩) | 15 (Go, PyPI, npm 5씩) | 16 (NuGet 1 더함) | summary.json `sample_rows`, findings_*.csv `in_sample` |
| 악성 권고 MAL- | 0 | 0 | 0 | summary.json `mal_ids` |
| Go 도달 확인: 큐 Go 행 중 symbol 수준 (govulncheck, reach) | 14 / 36 | 5 / 9 | 13 / 36 | funnel.csv, summary.json `go_reachable_detail` |
| 참고: osv-scanner 내장 호출 분석, 큐 Go 행 중 called | 14 / 36 | 5 / 9 | 13 / 36 | funnel.csv 마지막 행 |

- KEV 행: v0.5.0은 x/net 0.4.0과 grpc 1.51.0 (Go 서비스 4개 x 2, CVE-2023-44487)과 loadgenerator brotli 1.0.9 (CVE-2026-111497)
- EPSS>=0.1 CVE: v0.5.0 CVE-2023-44487, CVE-2023-45288, CVE-2026-111497. main은 CVE-2026-111497 하나
- 노출 가정: LoadBalancer는 `kubernetes-manifests/frontend.yaml` 하나 (v0.5.0, main 둘 다 확인)

**노출 가정별 기한 (보고 행 중 CVE 있는 것. 3일+포렌식, 3일, 14일, 60일, 업그레이드 시)**
| 가정 | v0.5.0 | main | v0.8.0 |
|---|---|---|---|
| 전부 내부 | 0, 0, 9, 282, 245 | 0, 0, 1, 119, 71 | 0, 0, 9, 277, 241 |
| 프런트엔드만 공개 (기본) | 0, 3, 31, 277, 225 | 0, 1, 9, 112, 69 | 0, 3, 31, 272, 221 |
| 전부 공개 | 1, 22, 353, 160, 0 | 1, 13, 140, 37, 0 | 1, 23, 350, 153, 0 |
- 출처: summary.json `due_all_internal`, `due_frontend_only`, `due_all_public`

## 기획안 3-2 대조
- 숫자: `results/m2/compare_proposal.csv`. 이유 기호는 표 아래
| 항목 | 기획안 v0.5.0 | 이번 v0.5.0 | 기획안 main | 이번 main | 이유 |
|---|---|---|---|---|---|
| 서비스 | 11 | 10 | 12 | 11 | M, S |
| 구성요소 | 859 | 823 | 903 | 857 | M, T |
| 보고 | 609 | 545 | 208 | 200 | M |
| 보고 npm, Go, PyPI | 262, 164, 119 | 262, 164, 119 | 42, 38, 120 | 42, 38, 120 | 같음 |
| 보고 Maven | 64 | 0 | 8 | 0 | M |
| 패키지 버전 | 74 | 61 | 41 | 36 | M |
| 상위 5개 점유 | 35.5% | 39.6% | 57.7% | 60.0% | D |
| 조인 별칭 / related / 없음 | 595 / 5 / 9 | 532 / 4 / 9 | 199 / 0 / 9 | 191 / 0 / 9 | M |
| 고유 CVE | 244 | 183 | 115 | 107 | M |
| GHSA Critical(A) | 21 | 20 | 10 | 9 | M |
| KEV 행 | 10 | 9 | 1 | 1 | M (netty) |
| B / A와 B 겹침 | 14 / 1 | 13 / 1 | 1 / 1 | 1 / 1 | M (netty) |
| 전부 내부 기한 | 0, 0, 10, 323, 267 | 0, 0, 9, 282, 245 | 0, 0, 1, 124, 74 | 0, 0, 1, 119, 71 | M |
| 프런트엔드만 공개 기한 | 0, 3, 32, 318, 247 | 0, 3, 31, 277, 225 | 0, 1, 9, 117, 72 | 0, 1, 9, 112, 69 | M |
| 전부 공개 기한 | 1, 23, 400, 176, 0 | 1, 22, 353, 160, 0 | 1, 13, 146, 39, 0 | 1, 13, 140, 37, 0 | M |
| 신호 큐 (Go) | 38 (36) | 37 (36) | 10 (9) | 10 (9) | M (netty) |
| 신호 큐 비율 (CVE 붙은 행) | 6.3% (38/600) | 6.9% (37/536) | 5.0% (10/199) | 5.2% (10/191) | M |
| 큐 밖 / 패키지 버전 | 562 / 73 | 499 / 60 | 189 / 37 | 181 / 32 | M |
| 표본 | 20 | 15 | 20 | 15 | M (Maven 층 없음) |
| SSVC 없는 CVE | 16 | 15 | (기획안 값 없음) | 6 | M, V |
| GHSA 등급 없는 행 | 80 | 80 | (기획안 값 없음) | 38 | 같음 |
| MAL- | 0 | 0 | 0 | 0 | 같음 |

**이유**
- M (Maven 미스캔): adservice에는 `build.gradle`만 있고 잠금 파일(`gradle.lockfile`)이 없다
  - OSV-Scanner 2.7.0(osv-scalibr)과 Syft 1.55.0 모두 `build.gradle`을 읽지 않는다. Syft는 `gradle-wrapper.jar` 1개(버전 UNKNOWN)만 낸다
  - 기획안은 `dependencies` 블록을 손으로 읽고 deps.dev 해석 그래프를 더했다. deps.dev는 막혔다(403)
  - Gradle로 잠금 파일을 만드는 시도는 권한 분류기가 거부했다(외부 빌드 스크립트 실행). 아래 '막힌 것'
  - 확인: 기한 칸의 차이 합이 v0.5.0 64행(1+41+22), main 8행(5+3)으로 기획안 Maven 행 수와 같다
  - 빠진 KEV 1행은 기획안 부록 B VEX 예시의 adservice netty-codec-http2 4.1.79.Final (CVE-2023-44487, related 연결)로 보인다 (추정. 기획안 원 출력이 없어 행 단위 대조는 못 함)
- T (tests csproj): 도구는 `cartservice/tests/cartservice.tests.csproj` 5개도 센다. 기획안은 뺐다. 빼면 818(v0.5.0), 852(main). 기획안과의 나머지 41, 51개는 Maven 구성요소로 추정 (산술, 미확인)
- S (서비스 수): osv-scanner는 패키지가 나온 서비스만 센다. adservice가 빠진다. Syft는 adservice를 넣지만 cartservice(.csproj)를 못 읽어 역시 10, 11
- D (분모): 이번 상위 5개 건수 합은 v0.5.0 216행, main 120행이다. 기획안 값으로 역산해도 216, 120이다 (35.5% x 609, 57.7% x 208. 산술). 분자는 그대로고 분모(보고 행)가 줄어서 점유가 오른다
- V (SSVC 출처): 기획안은 cveawg.mitre.org의 CISA ADP, 여기는 NVD 미러의 `ssvcV203`(m1/nvd_table.py). cveawg는 막혀 있다
- 영향이 안 보인 차이
  - DB 시점: 기획안은 api.osv.dev(2026-11-02 조회), 여기는 GCS 덤프(2026-11-02 08:41 UTC 받음). 생태계별 보고 수가 같아 이번에는 차이가 안 보였다
  - deps.dev 막힘(Python 전이 해석): `requirements.txt`가 pip-compile로 전부 고정이라 영향 없음. 해석을 시도한 실행(`lock_resolve`)과 패키지, 권고가 같다

## Go 표준 라이브러리
- 헤드라인은 **제외**. 이유
  - osv-scanner 2.7.0 기본값이 go.mod에서 나온 `stdlib`를 버린다 (소스 `pkg/osvscanner/osvscanner.go`의 `filterAndOverrideGoVersion`. go 지시어는 최소 언어 버전이지 빌드 툴체인이 아니라는 주석)
  - 기획안도 제외했다
  - 실제 판정은 같은 툴체인 버전으로 govulncheck가 하는 것이 맞다 (reach 작업)

| 변형 | v0.5.0 | main | v0.8.0 |
|---|---|---|---|
| 제외 (헤드라인): 보고 / 고유 CVE / 큐(Go) | 545 / 183 / 37 (36) | 200 / 107 / 10 (9) | 536 / 179 / 37 (36) |
| ScanGoModVersion: stdlib 버전, 권고 | 1.19.99, 88 | 1.27.1, 14 | 1.19.99, 88 |
| 위 변형: 보고 / 고유 CVE / 큐(Go) | 897 / 261 / 95 (94) | 256 / 116 / 22 (21) | 888 / 257 / 95 (94) |
| Dockerfile 버전 탐침: stdlib 버전, 권고 | 1.19.4, 103 | 1.27.0, 14 | 1.20.4, 90 |
| 위 변형: 보고 / 고유 CVE / 큐(Go) | 957 / 275 / 102 (101) | 256 / 116 / 22 (21) | 896 / 259 / 95 (94) |
- 출처: `results/m2/stdlib_variants.csv`. 권고 수는 Go 서비스 4개의 고유 권고 ID
- 관찰
  - `go 1.19`(패치 없음)는 `1.19.99`로 매칭된다. 그 줄의 마지막 패치로 본다. main은 `toolchain go1.27.1`이 쓰였다
  - **`GoVersionOverride`는 2.7.0에서 무효다.** `DoScan`이 `scan()`(매칭) 뒤에 버전을 바꿔서 표시만 바뀐다
    - 증거: 1.19.4로 표시되는데 권고 집합이 1.19.99와 같고(88), 1.19.6에서 고친 GO-2023-1570이 없다
    - 그래서 `lock_std_override`는 동작 확인용으로만 남기고 숫자로 쓰지 않는다
  - 실제 빌드 버전은 탐침으로 쟀다: `go <Dockerfile 버전>` 한 줄짜리 빈 모듈을 `ScanGoModVersion=true`로 스캔하고, 그 stdlib 결과를 Go 서비스 4개에 붙였다
  - v0.5.0에서 stdlib를 넣으면 보고가 412행(545 -> 957), 큐가 65행(37 -> 102) 는다. main은 12행 는다(10 -> 22)

## 두 경로 비교 (잠금 파일 직접 vs Syft SBOM)
| 생태계 | v0.5.0 패키지 버전 잠금 / SBOM / 둘 다 | 취약 잠금 / SBOM | 권고 ID 잠금 / SBOM | main 패키지 버전 잠금 / SBOM / 둘 다 | 취약 잠금 / SBOM | 권고 ID 잠금 / SBOM |
|---|---|---|---|---|---|---|
| Go | 40 / 45 / 40 | 12 / 14 | 61 / 65 | 82 / 107 / 82 | 4 / 6 | 10 / 15 |
| npm | 303 / 305 / 303 | 32 / 32 | 86 / 86 | 262 / 264 / 262 | 8 / 8 | 18 / 18 |
| PyPI | 58 / 58 / 58 | 17 / 17 | 116 / 116 | 132 / 132 / 132 | 24 / 24 | 133 / 133 |
| NuGet | 10 / 0 / 0 | 0 / 0 | 0 / 0 | 11 / 0 / 0 | 0 / 0 | 0 / 0 |
- 출처: `results/m2/path_compare.csv`, 차이 목록 `path_compare_diff.csv`. 단위는 (생태계, 이름, 버전), 서비스 무시
- 겹치는 패키지 버전은 권고 ID가 전부 같다 (`same_ids_on_shared` = 겹친 수)
- 차이 이유
  - Go: Syft는 go.mod에 없는 go.sum 모듈(h1 해시 줄)도 낸다. v0.5.0 5개, main 25개, 전부 go.sum에서 확인
    - 취약한 것: v0.5.0 `github.com/golang/glog 1.0.0`(GO-2025-3372), `gopkg.in/yaml.v3`(GO-2022-0603). main `go-jose/v4 4.1.4`, `otel/sdk 1.44.0`
    - 빌드에 들어가는지는 모른다
  - npm: Syft는 루트 프로젝트 패키지(`grpc-currency-service`, `paymentservice`)도 낸다. 취약 없음
  - NuGet: Syft 1.55.0은 `.csproj`를 읽지 않는다
  - Maven: 둘 다 없음 (위 M)
- SBOM 경로로 같은 깔때기를 돌리면 (Syft 위치로 서비스를 붙임): v0.5.0 보고 549 (Go 168), 큐 38 (Go 37). main 보고 204 (Go 42), 큐 10 (summary.json `sbom_path`)
- 앞 세션의 SBOM 경로 값(패키지 416, 취약 7, 권고 9)은 DB가 빠진 상태의 값이었다. 이번에는 패키지 413, 취약 63 (v0.5.0, 스캔 범위 `src/`)

## Go 도달 확인 (reach 결과를 읽기만 함)
- 원본: `results/reach/levels.csv` (다른 작업이 만든다). 읽은 판: sha256 앞 12자 `af8786389b04` (09:20 판과 09:32 판이 같은 내용)
  - reach가 다시 돌면 값이 바뀔 수 있다. 그때 `.venv/bin/python m2/funnel.py && .venv/bin/python m2/figs.py`만 다시 돌린다
- 연결: 커밋 해시 + 서비스 + GO- 권고 ID + 모듈(= 보고 행 패키지). 행마다 가장 높은 수준
- 보조 연결: x/net 0.4.0의 CVE-2023-44487 행(서비스 4개)은 GHSA-qppj-fm5r-hxr3로만 붙어서 GO- ID가 없다
  - Go DB는 같은 수정을 GO-2023-2102(별칭 CVE-2023-39325, related CVE-2023-44487)로 둔다
  - 그래서 같은 모듈의 GO- 레코드 중 aliases나 related에 그 CVE가 있는 것으로 이었다. 이렇게 이은 행은 `via_related_cve`로 따로 센다 (v0.5.0 4행, v0.8.0 4행)

| 커밋 | 큐 Go 행 | symbol (호출 경로) | package (import만) | module (모듈만) | 못 이음 | 보조 연결로 이음 |
|---|---|---|---|---|---|---|
| v0.5.0 | 36 | 14 | 14 | 8 | 0 | 4 (전부 package) |
| main | 9 | 5 | 0 | 4 | 0 | 0 |
| v0.8.0 | 36 | 13 | 15 | 8 | 0 | 4 |
- 출처: summary.json `go_reachable_detail`, findings_*.csv `reach_level`
- 두 도구 대조: 큐 Go 행에서 reach의 symbol 행과 osv-scanner 내장 분석의 called 행이 행 단위로 같다 (v0.5.0 14 = 14, main 5 = 5). package와 module 행은 전부 not_called (보조 연결 4행은 osv-scanner 쪽 결과 없음)
  - 같은 govulncheck 계열이라 독립 검증은 아니다. DB(reach는 GO-만 담은 로컬 DB, osv-scanner는 매칭된 권고)와 실행 경로가 다른 두 실행이 같은 답을 냈다는 뜻이다

## 참고: osv-scanner 내장 Go 호출 분석
- 2.7.0은 소스 스캔에서 Go 호출 분석을 **기본으로 켠다**. `--offline`이어도 켜진다. `go` 명령으로 패키지를 읽고, 모듈이 캐시에 없으면 proxy.golang.org에서 받는다
- 그래서 헤드라인 스캔(`lock`)은 `--no-call-analysis=go`를 주고 `unshare -n`(네트워크 없음)에서 돌렸다. 기본값 실행(`lock_call`)과 권고 목록이 같다 (summary.json `lock_call_identical_vulns` = true, 세 커밋 모두)
- `lock_call`의 called 표시 (참고만. 도달성 판정은 reach 작업)
| 커밋 | 보고 Go 행 중 called | 신호 큐 Go 행 중 called | 분석 결과 없는 Go 행 |
|---|---|---|---|
| v0.5.0 | 48 / 164 | 14 / 36 | 16 |
| main | 20 / 38 | 5 / 9 | 0 |
| v0.8.0 | 44 / 159 | 13 / 36 | 16 |
- 출처: summary.json `osv_call_analysis`, findings_*.csv `osv_call_analysis`
- 행 규칙: 그 행의 권고 중 GO- 권고 하나라도 called면 called. 분석 결과는 GO- 권고에만 붙는다
- 툴체인: `/usr/local/go/bin/go` go1.24.7, `GOTOOLCHAIN=auto`. main은 go.mod `toolchain go1.27.1`로 바뀌었을 것이다 (미확인)
- 모듈 캐시(`/root/go/pkg/mod`)는 다른 작업도 같이 쓴다. 이 실행이 무엇을 받았는지는 따로 기록하지 않았다

## 스캔 로그 경고와 오류 (전부)
| 실행 | 내용 | 줄 수 (v0.5.0 / main / v0.8.0) | 처리 |
|---|---|---|---|
| 모든 osv-scanner 실행 | DB 적재 오류 ('could not load db', 'no offline version') | 0 / 0 / 0 | scan.sh가 찾으면 실패로 끝남. funnel.py가 생태계마다 'Loaded ... local db'를 대조 (`scan_integrity.csv`) |
| lock_resolve | deps.dev 403 ('failed resolution ... api.deps.dev') | 6 / 8 / 6 | Python 전이 해석 실패. 패키지와 권고가 `lock`과 같아서 영향 없음 |
| lock_resolve | 'Error during extraction (transitivedependency/requirements)' | 1 / 1 / 1 | 위와 같은 원인 |
| sbom | 'Neither CPE nor PURL found for package' | 10 / 11 / 10 | Syft의 file 항목(매니페스트 파일 자체, gradle-wrapper.jar). 패키지 아님 |
| syft | 경고 없음 | 0 | 첫 시험의 '이름 없는 dir 소스' WARN은 `--source-name`으로 없앰 |
| figs.py | matplotlib 'findfont: ... WenQuanYi Zen Hei, now using 500' | 5 | 글꼴 굵기 대체. 수치 영향 없음 |
- 전체 목록: `results/m2/log_issues.csv`, 원 로그 `results/m2/logs/`
- 종료 코드: syft 0, osv-scanner 1(취약점 있음). 2 이상(오류)은 0건 (`scan_runs.csv`)
- 지난 실행의 함정은 재현 안 됨: 이번에는 처음부터 `/home/user/work/osvdb`를 썼다

## 도구 버전과 실행 시간
| 도구 | 버전 | 근거 |
|---|---|---|
| Syft | v1.55.0 (go1.26.10 빌드) | `go version -m` (`syft version`은 '[not provided]') |
| OSV-Scanner | 2.7.0 | `--version` |
| osv-scalibr | v0.5.4-0.20261009010329-5be78a00e3c2 | 빌드 모듈. `--version`은 0.5.3이라고 나온다 |
| Go (호출 분석, 탐침 아님) | go1.24.7, GOTOOLCHAIN=auto | `go version` |
| jsonschema | 4.26.0 | VEX 검증 |
- 기록: `results/m2/tool_versions.txt`, 명령 전체와 종료 코드와 초: `results/m2/scan_runs.csv`
- 시간: 전체 439~484초. osv-scanner 1회 17~24초, 호출 분석을 켜면 41~59초, 탐침 1초 안쪽, Syft 3~10초

## 데이터 기준 시점 (`results/m2/data_asof.csv`)
| 자료 | 기준 | 비고 |
|---|---|---|
| OSV Go | 레코드 최대 modified 2026-10-30T23:30Z | 9,815건 |
| OSV npm | 2026-11-02T06:30Z | 231,019건 |
| OSV PyPI | 2026-11-02T04:45Z | 26,778건 |
| OSV NuGet | 2026-10-28T20:00Z | 1,967건 |
| OSV Maven | 2026-10-31T10:55Z | 7,224건. 스캔에는 안 쓰임 |
| OSV Bitnami | 2026-10-30T20:56Z | 10,074건. 별칭(BIT-) 조회만 |
| KEV | 2026.10.30 (dateReleased 2026-10-30T17:02Z) | 1,766건 |
| EPSS | score_date 2026-11-01T12:00Z, model v2026.06.15 | |
| NVD 표 (CVSS, SSVC) | fkie-cad 미러 커밋 1b66e03 (2026-11-02T07:05Z) | m1/nvd_table.py. 복제가 지워진 뒤에는 `results/m1/REPRO_CHECK.md`의 고정 커밋을 적는다 |
| Online Boutique | v0.5.0 3c0d659, main c7cb6d5, v0.8.0 d54af3d | 워크트리 HEAD 대조 |

## VEX 예시 (CycloneDX 1.6)
- 파일: `results/m2/vex_CVE-2023-44487.cdx.json`, 검증: `results/m2/vex_validation.json`
- 대상: v0.5.0에서 CVE-2023-44487로 조인된 행 전부. 구성요소 8개 = Go 서비스 4개 x (`golang.org/x/net 0.4.0`, `google.golang.org/grpc 1.51.0`)
- 상태 `in_triage`. 사람 승인 전이라 바꾸지 않았다
- 판단 재료 (findings_v0.5.0.csv `reach_level`, reach의 levels.csv를 읽은 값)
  - grpc 1.51.0 (GO-2023-2153): checkoutservice, productcatalogservice, shippingservice는 symbol(호출 경로 있음), frontend는 package(import만)
  - x/net 0.4.0: 서비스 4개 모두 package (GO-2023-2102로 보조 연결)
  - 기획안 3-3의 주장(frontend는 grpc 클라이언트뿐, 나머지 셋은 grpc 서버)과 방향이 맞는다. 판정은 reach 작업과 사람 몫
- 점수: NVD CVSS 3.1 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`). EPSS, KEV, 서비스별 기한은 properties
  - 출처: NVD 미러 레코드 1건, m1 nvd_table과 같은 커밋 `1b66e03`으로 고정해 받음. nvd_table의 `cvss3_nvd`(7.5)와 같음 (`vex_validation.json` `score_check`)
  - 처음에는 로컬 미러 복제(`/home/user/work/nvd`)를 읽었는데, 작업 중 복제가 지워져서(디스크 정리로 보임) 이렇게 바꿨다
- 검증
  - enum 4종(state, ratings.method, ratings.severity, components.type) 1.6 스키마와 일치
  - jsonschema 4.26.0 Draft7 전체 검증 통과 (spdx, jsf 참조 포함)
  - date-time 형식 검사는 건너뜀 (rfc3339-validator 없음)
- 기획안 예시는 adservice netty였다. 이번 스캔에 Maven이 없어서 Go 구성요소로 만들었다
- x/net 행은 GHSA-qppj-fm5r-hxr3로 붙었다. GO-2023-2102는 첫 CVE 별칭이 CVE-2023-39325라서 그쪽 행이 된다 (기획안 규칙 그대로)

## 만든 파일
| 파일 | 내용 |
|---|---|
| `m2/run.sh` | 한 명령 실행 |
| `m2/scan.sh` | Syft, OSV-Scanner 실행, 로그, 버전, 원본 gzip |
| `m2/funnel.py` | 정규화, 조인, 신호, 기한, 큐, 표본, 깔때기, 경로 비교, stdlib 변형, 기획안 대조 |
| `m2/vex_example.py` | VEX 1건과 검증 |
| `m2/figs.py` | `figs/m2_funnel.png` |
| `results/m2/summary.json` | 커밋별 전체 수치 (표본 행, KEV 행, CVE 없는 권고 포함) |
| `results/m2/funnel.csv` | 깔때기 단계별 값 |
| `results/m2/findings_<라벨>.csv` | 보고 행 전부 (CVE, 신호, 세 가정의 기한, 큐, 표본, 호출 분석, reach 수준) |
| `results/m2/services.csv` | 서비스별 Syft 구성요소, 패키지, 취약, 보고, 큐 |
| `results/m2/path_compare.csv`, `path_compare_diff.csv` | 두 경로 비교 |
| `results/m2/stdlib_variants.csv` | 표준 라이브러리 변형 |
| `results/m2/compare_proposal.csv` | 기획안 3-2 대조 숫자 |
| `results/m2/scan_runs.csv`, `tool_versions.txt`, `logs/` | 명령, 시간, 버전, 원 로그 |
| `results/m2/scan_integrity.csv`, `log_issues.csv` | DB 적재 대조, 로그 경고 분류 |
| `results/m2/data_asof.csv` | 데이터 기준 시점 |
| `results/m2/raw/` | SBOM(CycloneDX 1.6)과 잠금 파일 스캔 JSON, gzip (각 0.7MB 이하) |
| `results/m2/vex_CVE-2023-44487.cdx.json`, `vex_validation.json` | VEX와 검증 |
- 큰 원본(스캔 JSON 7종 x 3커밋, 로그): `/home/user/work/m2tmp/<라벨>/` (커밋 안 함)
- `results/m2/osv_db_inventory.csv`는 prepare.py가 만든 것이다 (이번에 안 바꿈)

## 결정
| 번호 | 정할 것 | 안 | 고른 기본값과 근거 |
|---|---|---|---|
| M2-1 | 헤드라인 경로 | (a) 잠금 파일 직접 (b) Syft SBOM (c) 합집합 | (a). 서비스 정보가 그대로 있고 NuGet을 읽는다. (b)는 비교로 |
| M2-2 | Go 표준 라이브러리 | (a) 제외 (b) go.mod 버전 (c) Dockerfile 버전 탐침 | (a). 도구 기본값, 기획안과 같은 정의. (c)는 별도 표. 판정은 govulncheck |
| M2-3 | 오프라인 증명 | (a) `unshare -n` + `--no-call-analysis=go` (b) 기본값 | (a). 호출 분석 기본값은 모듈을 받을 수 있다. 기본값 실행은 참고로 남김 |
| M2-4 | tests csproj | (a) 포함(도구 그대로) (b) 기획안처럼 제외 | (a). 취약 0건이라 보고 수는 같다 |
| M2-5 | 스캔 범위 | (a) `src/` (b) 저장소 루트 | (a). 기획안과 같은 범위. 루트는 .github 워크플로(GitHub Actions) 등이 더해진다 |
| M2-6 | Maven | (a) 미스캔으로 둠 (b) Gradle로 잠금 파일 생성 후 스캔 (c) 손 파서 | (a). (b)는 권한 거부, (c)는 도구 경로가 아니다 |
| M2-7 | SBOM 형식 | (a) CycloneDX 1.6 (b) Syft 기본 1.7 | (a). VEX 스키마 1.6과 맞춤 |
| M2-8 | 다중 CVE 권고 | (a) 첫 CVE만 (기획안) (b) 전부 | (a). 기획안과 같게. 영향은 고유 CVE -2 (v0.5.0), -1 (main) |
| M2-9 | 별칭의 별칭 조회 원본 | (a) 받은 생태계 zip + Bitnami zip (b) api.osv.dev | (a). api.osv.dev 막힘. 별칭 레코드 못 찾은 것 0건 |

## 데이터 출처
| 자료 | URL | 받은 시각 (UTC) | sha256 앞 12자 | 라이선스 |
|---|---|---|---|---|
| NVD 레코드 1건 (CVE-2023-44487, VEX 점수용) | https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/1b66e035d87d0ddf83705ff01b4382889755f89a/CVE-2023/CVE-2023-444xx/CVE-2023-44487.json | 2026-11-02T09:41:40Z | f12ff7bc6855 | NVD 자료 (공공), 미러는 fkie-cad (DATA.md 기존 NVD 항목 따름) |
| OSV Bitnami 덤프 (별칭 조회만) | https://osv-vulnerabilities.storage.googleapis.com/Bitnami/all.zip | 2026-11-02T08:57:07Z | ed67a6ad69e8 | Apache-2.0 (bitnami/vulndb `LICENSE.md`, 2026-11-02 확인) |
| OSV Go, npm, PyPI, NuGet, Maven, GitHub Actions 덤프 | 같은 버킷 `<생태계>/all.zip` | 2026-11-02T08:41Z (prepare.py) | `data/manifest_m2.json` | 원본 DB마다 다름 (DATA.md 기존 OSV 항목 따름) |
| CycloneDX 1.6 스키마 3종 | raw.githubusercontent.com/CycloneDX/specification/1.6/schema/ | 2026-11-02T08:41Z (prepare.py) | `data/manifest_m2.json` | Apache-2.0 (CycloneDX specification 저장소, 미확인) |
| Online Boutique | github.com/GoogleCloudPlatform/microservices-demo (git clone) | 앞 세션 | 커밋 해시 | Apache-2.0 (워크트리 LICENSE 확인) |

## 한계
- Maven(adservice)을 못 봤다. Java 서비스의 KEV 행(netty, CVE-2023-44487)이 이 경로에서는 안 보인다. 잠금 파일 없는 Java 서비스는 SCA 도구가 놓친다는 사례다
- 소스 트리 스캔이다. 컨테이너 이미지, 베이스 이미지, OS 패키지는 안 봤다
- go.mod의 indirect 모듈까지 다 센다. 실제 바이너리에 들어가는지는 모른다 (도달성은 reach)
- 보고 건수는 위험 건수가 아니다
- 첫 CVE 규칙 (기획안과 같음, 양쪽 공통이라 차이 원인은 아님): 권고마다 첫 CVE 별칭 하나만 쓴다
  - 별칭 CVE가 둘 이상인 권고: v0.5.0 3개, main 1개. 그래서 고유 CVE에서 2개, 1개가 빠진다
  - 빠진 것 중 KEV, EPSS>=0.1은 없다 (2026-11-02 별도 점검, 코드 밖 일회성 확인)
- SSVC가 없는 CVE는 기획안처럼 automatable no, technical total로 둔다 (v0.5.0 15개, main 6개)
- main CVE 2개는 NVD 표에 없다 (summary.json `nvd_missing_cves`). CVSS 칸이 비고 SSVC는 기본값
- 노출 가정은 매니페스트의 LoadBalancer만 본다. Ingress, 메시 설정은 안 봤다
- 'Go 도달 확인'은 reach 작업의 `results/reach/levels.csv`를 읽은 그 시점 값이다. reach가 바뀌면 `m2/funnel.py`를 다시 돌린다. 형식이 다르면 그 칸에 '형식 미확인'과 열 이름이 찍힌다
- 도달 수준은 서비스 코드에서 취약 심볼까지의 정적 호출 경로다. 실제 공격 가능 여부(설정, 노출)는 따로 본다
