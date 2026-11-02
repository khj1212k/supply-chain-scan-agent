# RESULTS: 이노베이트 사전 프로토타입 (수치 동결 2026-11-03 12:00 KST)

## 결론 세 줄
1. 연결과 우선순위: v0.5.0 스캔 보고 545행(Maven 제외)이 신호 큐 37행(Go 36)으로 줄고, 그중 Go 14행만 govulncheck 호출 경로가 있다. 백테스트에서는 같은 작업량 1,000건에서 EPSS 순이 CVSS 순보다 이후 KEV 추가를 많이 찾았지만(평균 13.0% 대 2.0%), KEV 추가의 47~65%는 시점 뒤 공개라 사전 순위로는 못 잡는다
2. 조치안 에이전트(Claude Sonnet 5.5)는 정답 사례 10건 중 6건을 기계 판정 통과시켰다. LLM 없는 최소 수정 버전도 6건, LLM 1회 호출도 6건이다. **통과 수 이득 0건**, 비용은 1회 호출의 약 2.3배라 기획안 규칙대로면 고정 흐름이 맞다
3. 영향도 판정 시범(VEX-Bench Go 8건 x 3회)에서 exploitable 3건은 매번 찾았고(잘못 지움 0), not_affected 5건 중 3~4건을 맞혔다. 근거 검사는 형식만 봐서 강등이 0건이었다. 표본이 작아 '가능성 확인' 수준이다

- 모든 값은 이 저장소 코드로 2026-11-02에 돌린 결과다. 예측, 추정 값은 없다. 한계는 각 절 끝

## 핵심 수치 요약
| 슬롯 | 값 | 재현 명령 (lotte/innovate) | 기준 시점 | 한계 한 줄 |
|---|---|---|---|---|
| M1-a 임계값 적중 | EPSS>=0.1이 정답의 62.1%, 47.8%, 51.6% (18/29, 11/23, 16/31). CVSS>=9는 37.9%, 39.1%, 22.6% (11/29, 9/23, 7/31) | `results/m1/REPRO_CHECK.md` | T=2025-06-01, 2025-12-01, 2026-03-31, 각 약 90일 창. KEV 2026.10.30판, NVD 미러 1b66e03 | 95% 구간이 겹친다. 정답은 T 전 공개된 KEV 추가만 |
| M1-b 같은 작업량 | 상위 1,000건에서 EPSS 순 20.7%, 8.7%, 9.7%, CVSS 순 3.5%, 0.0%, 2.5% (평균 13.0% 대 2.0%) | 같음 (`results/m1/topk_table.csv`) | 같음 | CVSS 동점은 시드 100개 평균. CVSS는 현재 값 |
| M1-c CVSS>=9 건수만큼 보면 | EPSS 순 65.5%, 52.2%, 54.8% 대 CVSS 순 37.9%, 39.1%, 22.6% (작업량 31,867~37,604건) | 같음 | 같음 | 작업량이 3만 건대라 현장 큐 크기가 아니다 |
| M1-d 사전 순위로 못 잡는 몫 | 창의 KEV 추가 중 T 뒤 공개 47.3%, 64.6%, 58.7% (26/55, 42/65, 44/75) | 같음 (`summary.json`) | 같음 | 공개일은 NVD 미러 기준 |
| M2-a 깔때기 v0.5.0 | 구성요소 823 -> 취약 구성요소 135 -> 보고 545행(CVE 정규화) -> 고유 CVE 183 -> EPSS>=0.1 3 -> KEV 2 -> 신호 큐 37행(Go 36) -> Go 호출 경로 14행 | `bash m2/run.sh` (약 8분) | OSV 덤프 2026-11-02 08:41 UTC, EPSS 2026-11-01, KEV 2026.10.30 | Maven(adservice) 미스캔. Go 표준 라이브러리 제외 |
| M2-b 깔때기 main | 보고 200행 -> 고유 CVE 107 -> KEV 1(loadgenerator brotli) -> 신호 큐 10행(Go 9) -> Go 호출 경로 5행 | 같음 | 같음 | 같음 |
| M2-c 기한 분포 v0.5.0 | 3일+14일 행: 전부 내부 9, 프런트엔드만 공개 34, 전부 공개 376 (보고 545행 중) | 같음 (`summary.json`) | 같음 | BOD 26-04 표는 CERT/CC 정리표 기준. 노출은 매니페스트 LoadBalancer만 봄 |
| M2-d 기획안 대조 | Go 164, npm 262, PyPI 119행이 기획안과 같다. 차이(609 -> 545)는 전부 Maven 64행 | 같음 (`compare_proposal.csv`) | 같음 | 도구가 build.gradle을 안 읽고 Gradle 실행은 권한 거부 |
| 도달성-a CVE-2023-44487 | v0.5.0 Go 4개 서비스 6칸이 기획안 판정 초안과 모두 같음. gRPC 서버 3곳 GO-2023-2153 symbol(호출 경로 있음, 수정 1.56.3), frontend grpc, x/net은 package(import만) | `bash reach/run.sh` | OSV Go 덤프 GO-* modified 2026-10-30T10:55Z, govulncheck 1.9.0 | symbol은 정적 경로가 있다는 뜻일 뿐 공격 입력 도달은 미확인 |
| 도달성-b v0.5.0 수준별 | 표준 라이브러리 제외 서로 다른 ID 40개: module 17, package 8, symbol 15 | 같음 (`results/reach/summary.json`) | 같음. 표준 라이브러리는 Dockerfile go1.19.4 가정 | 인터페이스 호출 과다 보고 단서 98/333줄 |
| 조치안-a 통과 | 정답 사례 10건 중 기계 판정 통과: 에이전트 6, LLM 1회 호출 6, LLM 없는 최소 수정 6, 최신 버전 3 | `.venv/bin/python -m agent.run_eval ...` (`agent/NOTES.md`) | OSV Go 덤프 2026-10-30T23:30Z, proxy.golang.org 2026-11-02 | 10건, Go 4개 서비스, 정답은 사람 라벨이 아니라 빌드, 테스트, 재스캔 |
| 조치안-b 비용 | 건당 토큰 23,557 대 8,198, 건당 $0.066 대 $0.028 (에이전트 대 1회 호출, Sonnet 5.5 공식 단가) | 같음 (`results/agent/runs/*/summary.csv`) | 같음 | 청구서와 대조 안 함 |
| 조치안-c 게이트 | 에이전트가 빌드, 테스트를 통과시킨 조합이 새 HIGH/CRITICAL 권고 12묶음을 끌어와 판정이 막음 (C03, C04) | 같음 (`results/agent/verdicts/`) | 같음 | go.mod 기준 재스캔. 이미지, 표준 라이브러리 제외 |
| 조치안-d 지금 이미지로 | 에이전트 통과 6건 중 4건만 Dockerfile의 golang:1.19.4로도 빌드, 테스트 통과 | `.venv/bin/python -m agent.go119_check` | 같음 | 나머지 2건은 go 지시어가 1.23, 1.25로 올라 이미지 교체 필요 |
| 영향도 시범 | VEX-Bench Go 8건 x 3회: exploitable 3/3 매회 발견, 잘못 지움 0, not_affected 정답 4, 3, 4 / 5 (기준선 '항상 exploitable'은 0/5) | `vexpilot/NOTES.md` 재현 명령 | 라벨 vex-bench 80cddea, 실행 2026-11-02 09:35~09:42 UTC | 8건 조정용, 큰 저장소 제외, 자체 소형 하네스. 공개 CVE라 모델 기억 가능 |

## 1. M1 우선순위: KEV 시점 분리 백테스트
- 코드 b067a20, 결과 4c64386, 새 컨테이너 재현 39de8a0(바이트 동일, `results/m1/REPRO_CHECK.md`)
- 정의: 창 T <= dateAdded <= T+약 90일의 KEV 추가 중 NVD 공개일 < T 가 정답. 모집단은 T 날짜 EPSS 파일에 있고 T 전에 KEV에 없던 CVE (DECISIONS D4)

| T (창 끝) | KEV 추가 | 정답 | EPSS>=0.1 적중 (95% 구간) | CVSS>=9 적중 (95% 구간) | 상위 1,000건 EPSS 순 | 상위 1,000건 CVSS 순 | T 뒤 공개 |
|---|---|---|---|---|---|---|---|
| 2025-06-01 (08-29) | 55 | 29 | 18, 62.1% (44.0~77.3) | 11, 37.9% (22.7~56.0) | 20.7% | 3.5% | 26 (47.3%) |
| 2025-12-01 (02-28) | 65 | 23 | 11, 47.8% (29.2~67.0) | 9, 39.1% (22.2~59.2) | 8.7% | 0.0% | 42 (64.6%) |
| 2026-03-31 (06-29) | 75 | 31 | 16, 51.6% (34.8~68.0) | 7, 22.6% (11.4~39.8) | 9.7% | 2.5% | 44 (58.7%) |

- 기준선: 무작위 순서 상위 1,000건 기대 적중 0.36%, 0.33%, 0.31%
- 기획안 3-1의 적중 건수와 95% 구간이 전부 같다. 표시 비중은 분모 정의가 달라 조금 다르다(D4)
- 그림: `figs/m1_coverage_curve.png`
- 한계: 구간이 겹쳐 유의한 차이로 주장하지 않는다. KEV는 악용의 하한이고 미 연방 관점. CVSS는 현재 값(시점 값 아님). 패키지 구성요소 정답은 소수(기획안 3-1 표)

## 2. M2 연결: Online Boutique 스캔 깔때기
- 코드와 결과: `m2/`, `results/m2/` (커밋 54bc18c), 세부 `m2/NOTES.md`. `bash m2/run.sh` 4회 실행에서 모든 CSV와 커밋별 값이 같았다
- 도구: Syft 1.55.0, OSV-Scanner 2.7.0(osv-scalibr 0.5.3) 오프라인 DB. 헤드라인 스캔은 `unshare -n`(네트워크 없음)으로 돌렸다. 모든 실행에서 DB 로드 오류 0 (`scan_integrity.csv`)
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
- GHSA Critical 20행과 신호(KEV 또는 EPSS>=0.1) 13행이 겹치는 것은 1행
- 기한 (v0.5.0, 행 수: 3일+F, 3일, 14일, 60일, 업그레이드 시)
  - 전부 내부: 0, 0, 9, 282, 245
  - 프런트엔드만 공개: 0, 3, 31, 277, 225
  - 전부 공개: 1, 22, 353, 160, 0
- 기획안 3-2 대조 (`compare_proposal.csv`): Go, npm, PyPI 보고 수, main 큐 10행과 KEV 1행, CVE 없음 9행, MAL 0은 같다. 차이는 전부 Maven 행(v0.5.0 64, main 8)이다. 빠진 KEV 1행은 adservice netty(CVE-2023-44487)로 보인다(추정, 기획안 원 출력과 행 대조는 못 함)
- 두 경로 비교: npm, PyPI는 잠금 파일 직접과 Syft SBOM 경로가 같다. Syft는 go.sum에만 있는 모듈을 더하고(v0.5.0 5개) .csproj를 안 읽는다
- Go 표준 라이브러리를 Dockerfile go1.19.4로 넣으면 v0.5.0 큐가 37 -> 102행, main 10 -> 22행 (`stdlib_variants.csv`, 헤드라인 아님)
- VEX 예시: CVE-2023-44487, Go 4개 서비스의 x/net, grpc 8개 구성요소, state in_triage. CycloneDX 1.6 스키마 전체 검증 통과(date-time 형식 검사만 생략) (`vex_CVE-2023-44487.cdx.json`)
- 그림: `figs/m2_funnel.png`
- 한계: Maven 미스캔. 소스 트리 스캔이라 이미지, OS 패키지 제외. indirect 모듈까지 센다. 보고 건수는 위험 건수가 아니다. SSVC 없는 CVE 15개는 기본값. 노출은 LoadBalancer만 봄

## 3. 도달성: govulncheck 오프라인
- 코드와 결과: 커밋 f9cd533 (`reach/NOTES.md`). 실행 2026-11-02 09:24~09:32 UTC, `bash reach/run.sh` 약 8분. 같은 명령 3회 실행에서 커밋별 수가 같았다
- DB: OSV Go 덤프(2026-11-02 08:41 UTC 받음, sha256 71e545db...)의 GO-* 4,731건을 govulncheck v1 DB로 변환(`reach/builddb`). golang/vulndb 8f7e390과 서비스 12개 결과가 같았다
- 네트워크 없이 돈다: `unshare -n` + `GOPROXY=off`에서 12개 서비스 x 5회 실행 rc 0, strace connect 0회(3개 표본). 모듈과 툴체인은 미리 온라인으로 받았다
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

- frontend의 표준 라이브러리 symbol은 `ListenAndServe`가 취약 심볼 목록에 있어서 나온 것이다. go1.19.4로 만든 시험 서버(`reach/h2probe`)에서 평문 서버는 HTTP/2 서문에 HTTP/1.1로 답했고, TLS 서버만 h2를 협상했다. frontend 소스와 의존성에 h2c가 없다. 서비스 자체는 띄워 보지 않았다
- 표준 라이브러리 결과는 가정한 툴체인에 달렸다: 같은 로더에서 GOVERSION=go1.19.4를 빼면 v0.5.0 frontend 표준 라이브러리 symbol이 79에서 45로 준다(`goversion_sensitivity.csv`)
- 한계: 리플렉션 못 봄. 인터페이스, 함수 값 호출 과다 보고(가장 짧은 경로가 fmt.pp.handleMethods 등을 지나는 symbol 줄 v0.5.0 98/333, 단서일 뿐 오탐 수 아님). 플랫폼으로 거르지 않음(`applies_linux_amd64` 열). 이미지 모드 안 돌림. 서비스 4개만

## 4. 조치안 에이전트
- 코드 `agent/`, 결과 `results/agent/`, 세부와 실패 분석 `agent/NOTES.md`. 사례 규칙은 첫 실행 전에 고정(`agent/CASES_RULE.md`, 33a542f)
- 실행 2026-11-02 08:57~09:20 UTC. 모델 claude-sonnet-5-5(기본), claude-opus-5-5(Sonnet 실패 건 승격만). LiteLLM 어댑터, 키는 `LAB_ANTHROPIC_API_KEY`
- 정답 = 기계 판정 통과: go get, tidy, build, test 성공 + 재스캔에서 대상 권고 묶음 소멸 + 새 HIGH/CRITICAL 0 (D10, D15)

| 정책 | 모델 | 건수 | 최종 통과 | 첫 시도 통과 | 평균 시도 | 가드레일 트립 | golang:1.19.4로도 통과 | 건당 토큰 | 건당 비용 | 건당 LLM 시간 |
|---|---|---|---|---|---|---|---|---|---|---|
| 최소 수정 1회 (min_target) | 없음 | 10 | 6 | 6 | 1.0 | 0 | 4 | 0 | $0 | 0초 |
| 최소 수정 + 다음 후보 (min_target_retry) | 없음 | 10 | 6 | 6 | 1.8 | 0 | 4 | 0 | $0 | 0초 |
| 모듈 권고 전부 고치는 최소 (min_all) | 없음 | 10 | 4 | 4 | 1.0 | 0 | 2 | 0 | $0 | 0초 |
| 최신 (latest) | 없음 | 10 | 3 | 3 | 1.0 | 0 | 0 | 0 | $0 | 0초 |
| LLM 1회 호출 (llm_single, 고정 흐름) | Sonnet 5.5 | 10 | 6 | 6 | 1.8 | 1 | 4 | 8,198 | $0.0283 | 13.6초 |
| 에이전트 (도구 탐색) | Sonnet 5.5 | 10 | 6 | 6 | 1.8 | 1 | 4 | 23,557 | $0.0658 | 22.1초 |
| 에이전트 승격 | Opus 5.5 | 4 | 0 | 0 | 3.0 | 2 | 0 | 48,992 | $0.2933 | 63.0초 |

- 기준선 대비: 에이전트는 최소 수정 기준선과 통과, 실패가 10건 모두 같았다. 고른 버전이 다른 것은 C07(v1.9.3 대 v1.9.1), C08(v0.41.0 대 v0.39.0, 모듈 권고 전부 해소)
- 모든 정책이 실패한 4건(otel 계열 C03, C04, C09, C10): 시도한 조합은 앱 코드 수정이 필요하거나(`otelgrpc.UnaryClientInterceptor` 제거) 새 HIGH 권고를 끌어왔다. 통과 조합이 없다고 증명한 것은 아니다(존재 확인 3조합, `results/agent/oracle_check.json`)
- 가드레일 트립 4회는 모두 형식 오류(예: 인자를 JSON 문자열로 한 번 더 감쌈). 후보 밖 버전 제안 0회
- 사람 승인: 통과 6건마다 `open_fix_pr`에서 멈췄고 `--auto-approve`로 승인. 실제 사람 승인 0건
- 모델 교체 구조: OpenAI(api.openai.com 막힘), 로컬 오픈 모델(가중치 막힘) 미실행
- 그림: `figs/agent_results.png`, `figs/arch.png`
- 이번 세션 Claude API 사용 합계: 조치안 $2.14 + 영향도 시범 $0.74 = $2.88 (토큰 x 공식 단가, 청구서 대조 안 함)
- 한계: 10건, 한 앱, Go만. 정답이 사람 라벨이 아니다. 테스트가 서비스마다 파일 1개. 정책 llm_single과 Opus 승격은 결과를 본 뒤 더했다. 판정 시간은 캐시 재사용으로 정책 간 비교 불가

## 5. (선택) 영향도 판정 시범: VEX-Bench Go
- 코드와 결과: `vexpilot/`, `results/vexpilot/`, 세부 `vexpilot/NOTES.md`. 사례 규칙은 LLM 호출 전 커밋(b85f460)
- 사례: Go 30건 중 큰 저장소 6개를 빼고 exploitable 3건 전부 + not_exploitable 5건(task_id 순). 모델 Sonnet 5.5, 읽기 전용 도구(코드 검색, 파일 읽기, 오프라인 권고, go.mod), 코드 근거 검사

| 회차 | exploitable 찾음 (/3) | 놓침 | 잘못 지움 | in_triage | not_affected 정답 (/5) | 오경보 (/5) | 비용 |
|---|---|---|---|---|---|---|---|
| 기준선 '항상 exploitable' | 3 | 0 | 0 | 0 | 0 | 5 | $0 |
| 1회차 | 3 | 0 | 0 | 0 | 4 | 1 | $0.3906 |
| 2회차 | 3 | 0 | 0 | 0 | 3 | 2 | $0.1274 |
| 3회차 | 3 | 0 | 0 | 0 | 4 | 1 | $0.1986 |

- 3회 비용 합 $0.7167 (+캐시 확인용 $0.0254). 2, 3회차가 싼 것은 프롬프트 캐시 덕이다. 비용은 상한 추정(SDK가 캐시 쓰기를 0으로 보고해 미캐시 입력을 1.25배로 셈)
- 흔들림: 8건 중 7건은 3회 같은 판정. podman CVE-2024-37298은 not_affected, exploitable, not_affected로 바뀌었다
- 오경보: trivy CVE-2024-24791은 3회 모두 exploitable로 냈다. 모델 스스로 이유에 '실제 악용 가능성은 낮다'고 쓰고도 그랬다
- 근거 검사: 24회 모두 통과, 강등 0. 형식(줄 존재, 검색 0건 재확인)만 봐서 `http.Get` 한 줄, 좁은 부재 정규식 같은 약한 근거도 통과했다
- 형식 오류: 24회 중 2회 판정 인자를 JSON 문자열로 이중 포장(조치안 C04와 같은 실수). 스키마 재요청 1회로 해결
- 한계: 8건(exploitable 3건이라 1건이 33%p). 결과를 본 뒤 2, 3회차를 더했다. 공개 CVE와 저장소라 모델이 수정 내용을 기억했을 수 있다. code_not_present 판정은 get_advisory가 코드로 버전 범위를 계산해 준 몫이 크다. 기획안 7절 합격선(시험용 50건 x 3회)과 비교할 수 없다

## 6. 숫자 재확인 (⑥, 2026-11-02 09:44~10:05 UTC, 같은 컨테이너)
| 대상 | 다시 돌린 것 | 결과 |
|---|---|---|
| M1 | 새 컨테이너에서 처음부터 전부(08:39~08:43), 그 뒤 `m1/backtest.py` 한 번 더 | `results/m1/` 바이트 동일 |
| M2 | `bash m2/run.sh` (424초) | funnel, compare_proposal, findings 3개, stdlib_variants, path_compare CSV 동일. 바뀐 것은 생성 시각, HEAD, 로그의 메모리 주소뿐 |
| 도달성 | `bash reach/run.sh` | levels.csv, cve_2023_44487.md 동일, summary.json은 실행 초만 다름. OpenVEX 12개는 (취약점, 제품, 상태) 집합이 같고 시각, ID, 순서만 다름 |
| 조치안 | `agent.cases`, `agent.export`, 배관 시험 | cases.json, case_table.csv 동일. 시험 18개 통과(agent 6, vexpilot 12). LLM 실행은 다시 돌리지 않았다(샘플링이라 값이 조금 다를 수 있고 비용이 든다) |
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
