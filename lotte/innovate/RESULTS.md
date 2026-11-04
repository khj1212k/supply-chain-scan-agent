# RESULTS: 이노베이트 사전 프로토타입 (수치 동결 2026-11-02, 태그 lotte-innovate-freeze 커밋 시각 23:39 KST)

## 결론 세 줄
1. 연결과 우선순위: v0.5.0 스캔 보고 545행(Maven 제외)이 '프런트엔드만 공개' 가정에서 신호 큐 37행(Go 36)으로 줄고(전부 공개 가정이면 3일, 14일 기한만 376행), 그중 Go 14행만 govulncheck 호출 경로가 있다. 백테스트에서는 상위 1,000건에서 EPSS 순 6, 2, 3건, CVSS 순 약 1, 0, 1건(시드 100개 평균 1.02, 0.00, 0.79건)을 찾았다(정답 29, 23, 31건 중). 정답은 T 전에 공개된 KEV 추가로 한정해 시점을 분리했다(창의 KEV 추가 중 T 뒤 공개 47~65%는 제외)
2. 조치안: 에이전트(Claude Sonnet 5.5), LLM 1회 호출, LLM 없는 최소 수정을 같은 평가 사례 10건으로 비교했고 세 정책 모두 6건이 기계 판정(빌드, 테스트, 재스캔)을 통과했다. 통과 수가 같고 에이전트 비용이 1회 호출의 약 2.3배라, 기획안에 미리 적은 규칙('이득이 없으면 고정 흐름으로 낮춘다')대로 조치안을 고정 흐름으로 정했다. 정한 구조(D14 B)는 코드가 최소 수정 버전을 판정에 넣고 LLM이 선택 이유와 위험을 쓴다. 실측한 1회 호출은 코드가 만든 후보 안에서 LLM이 버전을 골랐다(후보 밖 제안 0회)
3. 영향도 판정 시범(VEX-Bench Go 8건 x 3회): 놓침 0, 잘못 지움 0을 지키면서 not_affected 정답 5건 중 3~4건을 가려냈다('항상 exploitable' 기준선 0건). 근거 검사(파일 줄 존재, 0건 검색 재실행)는 24회 모두 통과했다

- 수치는 전부 이 저장소 코드로 2026-11-02에 돌린 실행 결과다. 정의와 범위는 각 절 끝

## 핵심 수치 요약
| 항목 | 값 | 재현 명령 (lotte/innovate) | 기준 시점 | 정의와 범위 |
|---|---|---|---|---|
| M1-a 임계값 적중 | EPSS>=0.1이 정답의 62.1%, 47.8%, 51.6% (18/29, 11/23, 16/31). CVSS>=9는 37.9%, 39.1%, 22.6% (11/29, 9/23, 7/31) | `results/m1/REPRO_CHECK.md` | T=2025-06-01, 2025-12-01, 2026-03-31, 각 약 90일 창. KEV 2026.10.30판, NVD 미러 1b66e03 | 정답은 T 전 공개된 KEV 추가(시점 분리). 95% 구간은 1절 표 |
| M1-b 같은 작업량 | 상위 1,000건에서 EPSS 순 6, 2, 3건, CVSS 순 약 1, 0, 1건 (정답 29, 23, 31건 중. 정답 대비 20.7%, 8.7%, 9.7% 대 3.5%, 0.0%, 2.5%, 평균 13.0% 대 2.0%. 창의 KEV 추가 전체 55, 65, 75건이 분모면 평균 6.0% 대 1.0%) | 같음 (`results/m1/topk_table.csv`) | 같음 | CVSS 동점은 시드 100개 평균. CVSS는 현재 값 |
| M1-c CVSS>=9 건수만큼 보면 | EPSS 순 65.5%, 52.2%, 54.8% 대 CVSS 순 37.9%, 39.1%, 22.6% (작업량 31,867~37,604건) | 같음 | 같음 | 작업량은 CVSS>=9 건수(3만 건대)에 맞춤 |
| M1-d 시점 분리로 뺀 몫 | 창의 KEV 추가 중 T 뒤 공개 47.3%, 64.6%, 58.7% (26/55, 42/65, 44/75) | 같음 (`summary.json`) | 같음 | 공개일은 NVD 미러 기준 |
| M2-a 깔때기 v0.5.0 | 행 사슬: 구성요소 823 -> 보고 545행(구성요소 x CVE) -> 신호 큐 37행(Go 36, 프런트엔드만 공개 가정) -> Go 호출 경로 14행. CVE 사슬: 고유 CVE 183 -> EPSS>=0.1 3개 -> KEV 2개 CVE(9행). 큐 37행 중 24행은 기한(3일, 14일)만으로 들어왔다 | `bash m2/run.sh` (약 8분) | OSV 덤프 6개 생태계 2026-11-02 08:41 UTC 받음(Go는 sha256 71e545db, 최대 modified 2026-10-30T23:30Z), EPSS 2026-11-01, KEV 2026.10.30 | Go, npm, PyPI, NuGet 잠금 파일. Maven(adservice)은 확장 계획. Go 표준 라이브러리 제외(기획안 정의) |
| M2-b 깔때기 main | 행 사슬: 보고 200행 -> 신호 큐 10행(Go 9) -> Go 호출 경로 5행. CVE 사슬: 고유 CVE 107 -> KEV 1개 CVE(1행, loadgenerator brotli) | 같음 | 같음 | 같음 |
| M2-c 기한 분포 v0.5.0 | 3일+14일 행(3일+포렌식 포함): 전부 내부 9, 프런트엔드만 공개 34, 전부 공개 376. 기준은 CVE가 붙은 536행(보고 545행 중 CVE 없는 9행 제외) | 같음 (`summary.json`) | 같음 | BOD 26-04 표는 CERT/CC 정리표 기준. 노출은 매니페스트 LoadBalancer로 판정 |
| M2-d 기획안 대조 | Go 164, npm 262, PyPI 119행이 기획안과 같다. 차이(609 -> 545)는 전부 Maven 64행 | 같음 (`compare_proposal.csv`) | 같음 | 차이 64행은 Maven(adservice, build.gradle). build.gradle 해석은 확장 계획 |
| 도달성-a CVE-2023-44487 | v0.5.0 Go 4개 서비스 6칸이 기획안 판정 초안과 모두 같음. gRPC 서버 3곳 GO-2023-2153 symbol(호출 경로 있음, 수정 1.56.3), frontend grpc, x/net은 package(import만) | `bash reach/run.sh` | OSV Go 덤프(2026-11-02 08:41 UTC 받음, sha256 71e545db, 레코드 최대 modified 2026-10-30T23:30Z)의 GO-* 4,731건(그 부분 최대 modified 10:55Z), govulncheck 1.9.0 | symbol은 정적 호출 경로 기준. 공격 조건(노출, 설정)은 영향도 판정 단계에서 본다 |
| 도달성-b v0.5.0 수준별 | 표준 라이브러리 제외 서로 다른 ID 40개: module 17, package 8, symbol 15 | 같음 (`results/reach/summary.json`) | 같음. 표준 라이브러리는 Dockerfile go1.19.4 가정 | 동적 디스패치 경로 줄 98/333은 `dynamic_dispatch_hint`로 따로 표시 |
| 조치안-a 통과 | 평가 사례 10건 중 기계 판정 통과: 에이전트 6, LLM 1회 호출 6, LLM 없는 최소 수정 6, 최신 버전 3 | `.venv/bin/python -m agent.run_eval ...` (`agent/NOTES.md`) | OSV Go 덤프(2026-11-02 08:41 UTC 받음, sha256 71e545db, 레코드 최대 modified 2026-10-30T23:30Z), proxy.golang.org 2026-11-02 08:50~09:16 UTC | Go 4개 서비스 10건. 정답은 기계 판정(빌드, 테스트, 재스캔) |
| 조치안-b 비용 | 건당 토큰 23,557 대 8,198, 건당 $0.066 대 $0.028 (에이전트 대 1회 호출, Sonnet 5.5 공식 단가) | 같음 (`results/agent/runs/*/summary.csv`) | 같음 | 토큰 x 공식 단가 |
| 조치안-c 게이트 | 빌드, 테스트를 통과한 서로 다른 조합 4개(시도 6회: Sonnet 에이전트 2, 1회 호출 1, Opus 3)가 같은 새 HIGH/CRITICAL 권고 12묶음(x/crypto 11, otel/sdk 1)을 끌어왔고 판정이 6회 모두 막음 (C03, C04) | 같음 (`results/agent/verdicts/`) | 같음 | go.mod 기준 재스캔. 이미지, 표준 라이브러리 제외 |
| 조치안-d 지금 이미지 버전으로 | 에이전트 통과 6건 중 4건은 Dockerfile과 같은 버전 go1.19.4 툴체인으로도 빌드, 테스트 통과 | `.venv/bin/python -m agent.go119_check` | 같음 | 나머지 2건은 go 지시어가 1.23, 1.25로 오르며, 이 상향을 PR 초안의 'go 지시어' 줄과 판정 기록(raises_go_directive)에 함께 표시 |
| 영향도 시범 | VEX-Bench Go 8건 x 3회: 놓침 0, 잘못 지움 0. not_affected 정답 4, 3, 4 / 5 ('항상 exploitable' 기준선 0/5) | `vexpilot/NOTES.md` 재현 명령 | 라벨 vex-bench 80cddea, 실행 2026-11-02 09:35~09:42 UTC | 조정용 8건(큰 저장소 6개 제외 규칙, 실행 전 커밋 b85f460). 시험용 50건 x 3회는 확장 계획 |

## 1. M1 우선순위: KEV 시점 분리 백테스트
- 코드 b067a20, 결과 4c64386, 새 컨테이너 재현 39de8a0(바이트 동일, `results/m1/REPRO_CHECK.md`)
- 정의: 창 T <= dateAdded <= T+약 90일의 KEV 추가 중 NVD 공개일 < T 가 정답. 모집단은 T 날짜 EPSS 파일에 있고 T 전에 KEV에 없던 CVE (DECISIONS D4)

| T (창 끝) | KEV 추가 | 정답 | EPSS>=0.1 적중 (95% 구간) | CVSS>=9 적중 (95% 구간) | 상위 1,000건 EPSS 순 (건수, 정답 대비) | 상위 1,000건 CVSS 순 (시드 평균 건수, 정답 대비) | T 뒤 공개 |
|---|---|---|---|---|---|---|---|
| 2025-06-01 (08-29) | 55 | 29 | 18, 62.1% (44.0~77.3) | 11, 37.9% (22.7~56.0) | 6, 20.7% | 1.02, 3.5% | 26 (47.3%) |
| 2025-12-01 (02-28) | 65 | 23 | 11, 47.8% (29.2~67.0) | 9, 39.1% (22.2~59.2) | 2, 8.7% | 0.00, 0.0% | 42 (64.6%) |
| 2026-03-31 (06-29) | 75 | 31 | 16, 51.6% (34.8~68.0) | 7, 22.6% (11.4~39.8) | 3, 9.7% | 0.79, 2.5% | 44 (58.7%) |

- 기준선: 무작위 순서 상위 1,000건 기대 적중 0.36%, 0.33%, 0.31%
- 비율의 분모는 '정답'(T 전에 공개되고 창 안에 KEV에 오른 건)이다. 창의 KEV 추가 전체(55, 65, 75건)를 분모로 하면 상위 1,000건 평균 EPSS 순 6.0%, CVSS 순 1.0%
- 기획안 3-1의 적중 건수와 95% 구간이 전부 같다. 표시 비중은 분모 정의가 달라 조금 다르다(D4)
- 그림: `figs/m1_coverage_curve.png`
- 정의: KEV는 CISA가 확인한 악용 목록, CVSS는 NVD 미러 값. 비교는 같은 작업량(상위 1,000건) 기준

## 2. M2 연결: Online Boutique 스캔 깔때기
- 코드와 결과: `m2/`, `results/m2/` (커밋 54bc18c), 세부 `m2/NOTES.md`. 6절 재실행 2회(커밋 596ee4b 코드 포함)에서 값 파일이 같았다
- 도구: Syft 1.55.0, OSV-Scanner 2.7.0(osv-scalibr: `--version` 표시는 0.5.3, 빌드 모듈은 v0.5.4-0.20261009010329-5be78a00e3c2) 오프라인 DB. 헤드라인 스캔은 `unshare -n`(네트워크 없음)으로 돌렸다. 모든 실행에서 DB 로드 오류 0 (`scan_integrity.csv`)
- 정규화와 신호는 기획안 부록 B와 같은 규칙: 별칭 -> 별칭의 별칭 -> related 후보. KEV, EPSS(2026-11-01), SSVC(NVD 미러의 CISA ADP 값), BOD 26-04 16칸 표

| 단계 (단위) | v0.5.0 | main | v0.8.0 |
|---|---|---|---|
| 구성요소 (서비스 x 패키지 버전) | 823 | 857 | 843 |
| 취약 구성요소 | 135 | 61 | 133 |
| 권고 보고 (구성요소 x 권고 ID) | 735 | 280 | 717 |
| 보고 (구성요소 x CVE, 기획안 정의) | 545 | 200 | 536 |
| 고유 CVE (related 후보 포함) | 183 | 107 | 179 |
| EPSS>=0.1 고유 CVE | 3 | 1 | 3 |
| KEV 고유 CVE | 2 | 1 | 2 |
| 신호 큐 (프런트엔드만 공개 가정) | 37 (Go 36, PyPI 1) | 10 (Go 9, PyPI 1) | 37 |
| 큐 Go 행 중 govulncheck symbol | 14 / 36 | 5 / 9 | 13 / 36 |

- 보고 생태계(v0.5.0): Go 164, npm 262, PyPI 119. npm은 보고의 48%인데 신호 큐 0행이다. 공개 서비스가 Go(frontend) 하나라 표가 Go를 밀어 올린다
- 패키지 버전 61개, 상위 5개가 보고의 39.6%. MAL- 0건. CVE 없는 보고 9행. GHSA 등급 없는 80행
- GHSA Critical 20행(CVE 붙은 536행 기준. 545행 전체 기준 23행)과 신호(KEV 또는 EPSS>=0.1) 13행이 겹치는 것은 1행
- 기한 (v0.5.0, 행 수: 3일+F, 3일, 14일, 60일, 업그레이드 시)
  - 전부 내부: 0, 0, 9, 282, 245
  - 프런트엔드만 공개: 0, 3, 31, 277, 225
  - 전부 공개: 1, 22, 353, 160, 0
- 기획안 3-2 대조 (`compare_proposal.csv`): Go, npm, PyPI 보고 수, main 큐 10행과 KEV 1행, CVE 없음 9행, MAL 0은 같다. 차이는 전부 Maven 행(v0.5.0 64, main 8)이다. KEV 행 차이 1행도 Maven 쪽이다(기획안 부록 B의 adservice netty, CVE-2023-44487)
- 두 경로 비교: npm, PyPI는 잠금 파일 직접과 Syft SBOM 경로가 같다. Syft는 go.sum에만 있는 모듈을 더하고(v0.5.0 5개) .csproj를 안 읽는다
- Go 표준 라이브러리를 Dockerfile go1.19.4로 넣으면 v0.5.0 큐가 37 -> 102행, main 10 -> 22행 (`stdlib_variants.csv`, 헤드라인 아님)
- VEX 예시: CVE-2023-44487, Go 4개 서비스의 x/net, grpc 8개 구성요소, state in_triage. CycloneDX 1.6 스키마 전체 검증 통과(jsonschema Draft7, spdx, jsf 참조 포함) (`vex_CVE-2023-44487.cdx.json`)
- 그림: `figs/m2_funnel.png`
- 범위: 소스 트리 잠금 파일(Go, npm, PyPI, NuGet), indirect 모듈 포함. 보고 건수는 위험 건수가 아니라서 신호와 기한으로 좁힌다. SSVC 없는 CVE 15개는 기획안 기본값. 노출은 매니페스트 LoadBalancer 기준

## 3. 도달성: govulncheck 오프라인
- 코드와 결과: 커밋 f9cd533 (`reach/NOTES.md`). 실행 2026-11-02 09:24~09:32 UTC, `bash reach/run.sh` 약 8분. 6절 재실행에서 값 파일(levels.csv, cve_2023_44487.md)이 같았다
- DB: OSV Go 덤프(2026-11-02 08:41 UTC 받음, sha256 71e545db, 레코드 최대 modified 2026-10-30T23:30Z)의 GO-* 4,731건(최대 modified 2026-10-30T10:55Z)을 govulncheck v1 DB로 변환(`reach/builddb`). golang/vulndb 8f7e390과 서비스 12개 결과가 같았다
- 네트워크 없이 돈다: `unshare -n` + `GOPROXY=off`에서 12개 서비스 x 5회 실행 rc 0, strace connect 0회(3개 표본). 모듈과 툴체인은 준비 단계에서 받았다
- 네트워크 차단 실행: govulncheck와 M2 주 스캔. 조치안 판정(`go get`, proxy.golang.org), LLM 호출, 데이터 받기는 네트워크를 쓰며, 본 설계는 받기를 허용 목록 미러로, 실행을 네트워크 차단 환경으로 나눈다
- 대조 실험: 취약 심볼을 부르는 모듈은 symbol, import만 하는 모듈은 package로 나왔다(GO-2021-0113, GO-2022-1059)

**커밋별 서로 다른 OSV ID 수 (module / package / symbol, 각 ID는 가장 높은 수준으로 셈)**
| 커밋 | 표준 라이브러리 판정 버전 | 전체 | 표준 라이브러리 제외 | 표준 라이브러리만 |
|---|---|---|---|---|
| v0.5.0 | go1.19.4 | 29 / 13 / 90 (132) | 17 / 8 / 15 (40) | 13 / 9 / 81 (103) |
| v0.8.0 | go1.20.4 | 28 / 13 / 78 (119) | 17 / 8 / 14 (39) | 12 / 9 / 69 (90) |
| main | go1.27.0 | 5 / 1 / 13 (19) | 5 / 0 / 5 (10) | 0 / 1 / 13 (14) |

**CVE-2023-44487 (v0.5.0)** 전체: `results/reach/cve_2023_44487.md`
| 서비스 | ID, 모듈 | 수준 | 호출 경로 [앱 줄] | 기획안 초안 | 일치 |
|---|---|---|---|---|---|
| frontend | GO-2023-2153 grpc v1.51.0 | package | - | not_affected 후보 | 같음 |
| frontend | GO-2023-2102 x/net v0.4.0 | package | - | not_affected 후보 | 같음 |
| frontend | GO-2023-2102 표준 라이브러리 1.19.4 | symbol | main -> http.ListenAndServe [main.go:157] | in_triage | 같음 |
| checkoutservice | GO-2023-2153 grpc v1.51.0 | symbol | main -> grpc.NewServer [main.go:131] | exploitable 후보, 수정 1.56.3 | 같음 |
| productcatalogservice | GO-2023-2153 grpc v1.51.0 | symbol | main -> run -> grpc.NewServer [server.go:140] | 같음 | 같음 |
| shippingservice | GO-2023-2153 grpc v1.51.0 | symbol | main -> grpc.NewServer [main.go:85] | 같음 | 같음 |

- GO-2023-2102를 이 표에 넣은 근거: 별칭은 CVE-2023-39325(Go의 HTTP/2 rapid reset 수정)이고 related에 CVE-2023-44487이 있다(오프라인 OSV 레코드). GO-2023-2153(grpc)도 CVE-2023-44487이 related에만 있다
- frontend의 표준 라이브러리 symbol은 `ListenAndServe`가 취약 심볼 목록에 있어서 나온 것이다. go1.19.4로 만든 시험 서버(`reach/h2probe`)에서 평문 서버는 HTTP/2 서문에 HTTP/1.1로 답했고, TLS 서버만 h2를 협상했다. frontend 소스와 의존성에 h2c가 없다. 그래서 frontend 자체 서버 경로로는 Rapid Reset이 닿지 않는다고 보고, 표준 라이브러리 symbol은 not_affected 후보(VEX 상태 in_triage, 사람 확인)로 둔다
- 표준 라이브러리는 Dockerfile 버전(GOVERSION=go1.19.4)으로 판정했다. 같은 로더(go1.24.7)에서 GOVERSION을 빼면 v0.5.0 frontend 표준 라이브러리 symbol이 79에서 45로 줄어든다(`goversion_sensitivity.csv`). 헤드라인(로더 go1.20.4 + GOVERSION=go1.19.4)의 frontend는 81
- 범위: Go 서비스 4개, 소스 모드. 동적 디스패치 경로(fmt.pp.handleMethods 등)를 지나는 symbol 줄(v0.5.0 98/333)은 `dynamic_dispatch_hint`로, 플랫폼 해당 여부는 `applies_linux_amd64` 열로 따로 표시

## 4. 조치안 에이전트
- 코드 `agent/`, 결과 `results/agent/`, 세부와 판정 분석 `agent/NOTES.md`. 사례 규칙은 첫 실행 전에 고정(`agent/CASES_RULE.md`, 33a542f)
- 실행 2026-11-02 08:48~09:20 UTC (08:48 스모크, 08:56 C07 배관 확인 포함. 본 평가는 08:57:41부터). 모델 claude-sonnet-5-5(기본), claude-opus-5-5(otel 계열 4건 승격만). LiteLLM 어댑터, 키는 `LAB_ANTHROPIC_API_KEY`
- 정답 = 기계 판정 통과: go get, tidy, build, test 성공 + 재스캔에서 대상 권고 묶음 소멸 + 새 HIGH/CRITICAL 0 (D10, D15)

| 정책 | 모델 | 건수 | 최종 통과 | 첫 시도 통과 | 평균 시도 | 가드레일 트립 | 같은 버전 go1.19.4 툴체인으로도 통과 | 건당 토큰 | 건당 비용 | 건당 LLM 시간 |
|---|---|---|---|---|---|---|---|---|---|---|
| 최소 수정 1회 (min_target) | 없음 | 10 | 6 | 6 | 1.0 | 0 | 4 | 0 | $0 | 0초 |
| 최소 수정 + 다음 후보 (min_target_retry) | 없음 | 10 | 6 | 6 | 1.8 | 0 | 4 | 0 | $0 | 0초 |
| 모듈 권고 전부 고치는 최소 (min_all) | 없음 | 10 | 4 | 4 | 1.0 | 0 | 2 | 0 | $0 | 0초 |
| 최신 (latest) | 없음 | 10 | 3 | 3 | 1.0 | 0 | 0 | 0 | $0 | 0초 |
| LLM 1회 호출 (llm_single, 고정 흐름. 기획안 5절 규칙을 조치안에 적용) | Sonnet 5.5 | 10 | 6 | 6 | 1.8 | 1 | 4 | 8,198 | $0.0283 | 13.6초 |
| 에이전트 (도구 탐색) | Sonnet 5.5 | 10 | 6 | 6 | 1.8 | 1 | 4 | 23,557 | $0.0658 | 22.1초 |
| 에이전트 승격 (otel 계열 4건만. 위 행과 건수 다름) | Opus 5.5 | 4 | 0 | 0 | 3.0 | 2 | 0 | 48,992.5 | $0.2933 | 63.0초 |

- 기준선 대비: 에이전트는 최소 수정 기준선과 통과 여부가 10건 모두 같았다. 고른 버전이 다른 것은 C07(v1.9.3 대 v1.9.1), C08(v0.41.0 대 v0.39.0, 모듈 권고 전부 해소)
- 판정이 걸러낸 4건(otel 계열 C03, C04, C09, C10): 시도한 조합은 앱 코드 수정이 필요하거나(`otelgrpc.UnaryClientInterceptor` 제거) 새 HIGH 권고를 끌어와, 기획안 범위(호출부 코드 수정 없음)대로 사람에게 넘길 건으로 분류했다(존재 확인 3조합, `results/agent/oracle_check.json`)
- 가드레일 트립 4회: 형식 오류 1회(Sonnet 에이전트 C04, `submit_plan` 인자를 JSON 문자열로 한 번 더 감쌈), also_bump를 6개 이상 넣은 계획 3회(1회 호출 C03, Opus C03, Opus C09. 상한 5개). 후보 밖 버전 제안 0회
- 사람 승인: 통과 6건마다 `open_fix_pr`에서 승인 대기(interruptions)로 멈췄고, 일괄 평가라 `--auto-approve`로 승인 건수를 기록했다
- 모델 교체 구조: `LAB_MODEL` 한 줄로 OpenAI(`openai:gpt-6-luna`), 로컬 오픈 모델(`local:<이름>@<URL>`)로 바꾼다. 본선 전 OpenAI 모델로 같은 평가를 돌린다
- 그림: `figs/agent_results.png`, `figs/arch.png`
- 2026-11-02 실행의 Claude API 사용 합계: 조치안 $2.14 + 영향도 시범 $0.74 = $2.88 (토큰 x 공식 단가)
- 범위: Online Boutique Go 4개 서비스 10건. 정답은 기계 판정(빌드, 테스트, 재스캔). 새 권고 게이트 기준은 max_severity 7.0 이상(HIGH/CRITICAL). 판정 시간은 캐시를 재사용해 정책 비교 지표로 쓰지 않는다

## 5. 영향도 판정 시범: VEX-Bench Go
- 코드와 결과: `vexpilot/`, `results/vexpilot/`, 세부 `vexpilot/NOTES.md`. 사례 규칙은 LLM 호출 전 커밋(b85f460)
- 사례: Go 30건 중 큰 저장소 6개를 빼고 exploitable 3건 전부 + not_exploitable 5건(task_id 순). 모델 Sonnet 5.5, 읽기 전용 도구(코드 검색, 파일 읽기, 오프라인 권고, go.mod), 코드 근거 검사

| 회차 | exploitable 찾음 (/3) | 놓침 | 잘못 지움 | in_triage | not_affected 정답 (/5) | 오경보 (/5) | 비용 |
|---|---|---|---|---|---|---|---|
| 기준선 '항상 exploitable' | 3 | 0 | 0 | 0 | 0 | 5 | $0 |
| 1회차 | 3 | 0 | 0 | 0 | 4 | 1 | $0.3906 |
| 2회차 | 3 | 0 | 0 | 0 | 3 | 2 | $0.1274 |
| 3회차 | 3 | 0 | 0 | 0 | 4 | 1 | $0.1986 |

- 3회 비용 합 $0.7167 (+캐시 확인용 $0.0254). 2, 3회차가 싼 것은 프롬프트 캐시 덕이다. 비용은 보수적으로 셈(캐시에서 안 읽은 입력 전부를 캐시 쓰기 1.25배로 계산)
- 일관성: 8건 중 7건은 3회 같은 판정. podman CVE-2024-37298은 not_affected, exploitable, not_affected. 본 설계는 not_affected를 반복 판정이 같을 때만 사람에게 보낸다
- 오경보는 안전 쪽(exploitable)으로만 났다: trivy CVE-2024-24791은 3회 모두 exploitable. 이유문에 '실제 악용 가능성은 낮다'가 있어, 근거 내용 대조(이유문과 판정)를 더하면 다시 볼 건이다
- 근거 검사: 24회 모두 통과, 강등 0 (파일 줄 존재, 0건 검색 재실행). 다음 단계로 근거 내용 대조를 더한다
- 형식 오류: 24회 중 2회는 '형식만 다시' 재요청 1회로 모두 회복했다(판정 변화 없음)
- 범위: 조정용 8건(exploitable 3건)이라 건수로 적는다. 버전 범위 계산은 코드(get_advisory)가 하고 LLM은 코드 근거로 판정한다. 기획안 7절 합격선은 시험용 50건 x 3회로 잰다(확장 계획)

## 6. 숫자 재확인 (2026-11-02 09:44~10:05 UTC, 같은 컨테이너)
| 대상 | 다시 돌린 것 | 결과 |
|---|---|---|
| M1 | 새 컨테이너에서 처음부터 전부(08:39~08:43), 그 뒤 `m1/backtest.py` 한 번 더 | `results/m1/` 바이트 동일 |
| M2 | `bash m2/run.sh` (424초) | funnel, compare_proposal, findings 3개, stdlib_variants, path_compare CSV 동일. 바뀐 것은 생성 시각, HEAD, 로그의 메모리 주소뿐 |
| M2 (커밋 596ee4b 코드) | `bash m2/run.sh` (586초, 10:49 UTC) | `m2_dirty: false`. 값 파일 12개 동일. 바뀐 것은 메타데이터, 로그, VEX 예시의 시각뿐 |
| 도달성 | `bash reach/run.sh` | levels.csv, cve_2023_44487.md 동일, summary.json은 실행 초만 다름. OpenVEX 12개는 (취약점, 제품, 상태) 집합이 같고 시각, ID, 순서만 다름 |
| 조치안 | `agent.cases`, `agent.export`, 배관 시험 | cases.json, case_table.csv 동일. 시험 18개 통과(agent 6, vexpilot 12). LLM 실행 결과는 실행 ID별 결과 파일(`results/agent/runs/`, `results/vexpilot/`)로 확인한다 |
| 영향도 시범 | `vexpilot.report` | summary.csv, per_task.csv 동일 |
- 재실행 결과 파일은 커밋본으로 되돌렸다(값이 같고 시각만 달라서)

## 7. 재현 명령 모음
```bash
cd lotte/innovate
# M1 (약 5분, NVD 미러 4.1GB): results/m1/REPRO_CHECK.md
bash m2/run.sh                     # M2, 약 8분
bash reach/run.sh                  # 도달성, 약 8분
.venv/bin/python -m pytest -q agent/tests
.venv/bin/python -m agent.cases --rescan
.venv/bin/python -m agent.run_eval --policies min_target,min_target_retry,min_all,latest --run-id baselines_v1
LAB_MODEL=anthropic:claude-sonnet-5-5 .venv/bin/python -m agent.run_eval --policies agent --auto-approve --run-id sonnet_v1
LAB_MODEL=anthropic:claude-sonnet-5-5 .venv/bin/python -m agent.run_eval --policies llm_single --auto-approve --run-id sonnet_single_v1
.venv/bin/python -m agent.run_eval --policies agent --cases C03,C04,C09,C10 --model anthropic:claude-opus-5-5 --auto-approve --run-id opus_escalation_v1
.venv/bin/python -m agent.go119_check
# 영향도 시범: vexpilot/NOTES.md '재현 명령' (저장소 스냅숏 약 850MB)
```
- LLM 실행은 같은 입력에도 결과가 조금 다를 수 있다(샘플링). 판정은 캐시를 지우면 처음부터 다시 빌드한다
