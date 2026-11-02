# agent: 조치안 에이전트 (과제 2번, 3번)

## 결론
1. Claude Sonnet 5.5 조치안 에이전트는 평가 사례 10건 중 6건을 기계 판정 통과시켰다. LLM 없는 '최소 수정 버전' 기준선도 6건이다. **통과 수 이득은 0건**이다
2. 도구 없이 1회 호출(고정 흐름)도 6건이고 비용은 건당 $0.028로 에이전트($0.066)의 43%다. 기획안 규칙('이득이 없으면 고정 흐름으로 낮춘다')대로면 고정 흐름으로 낮춘다. 통과 수로는 LLM 없는 최소 수정과도 같다. LLM을 남길지는 설명 품질로 정할 일이고 재지 않았다
3. 4건(otel 계열)은 모든 정책과 Opus 5.5 승격이 실패했다. 시도한 조합은 앱 코드 수정이 필요하거나(시도한 범위, 전수 탐색 아님), 같은 새 HIGH/CRITICAL 권고 12묶음을 끌어왔다. 그런 조합 4개, 시도 6회를 기계 판정이 모두 막았다

- 기준 시점: OSV Go 덤프 레코드 최대 modified 2026-10-30T23:30Z, proxy.golang.org 목록 2026-11-02 08:5x UTC(`data/manifest_agent.json`), 실행 2026-11-02 08:57~09:20 UTC
- 이 표본은 10건이고 Go 4개 서비스, 한 앱이다. 비율로 일반화하지 않는다

## 무엇을 하나
- 입력: v0.5.0 Go 서비스 1개, 취약 모듈 1개, 대상 권고 묶음 1개
- 출력: 올릴 버전(코드가 만든 후보 중 하나), 같이 올릴 모듈, 이유, 위험, 대안
- 판정: 코드가 서비스 사본에 적용해 `go get`, `go mod tidy`, `go build`, `go test`, 오프라인 재스캔
- 실패하면 판정 로그를 붙여 다시 만든다. 최대 3회
- 통과하면 PR 작성 단계에서 사람 승인(`needs_approval`)을 받고 로컬 패치 파일만 쓴다. 실제 PR은 없다

## 구조 (그림: `figs/arch.png`)
| 단계 | 주체 | 파일 |
|---|---|---|
| 후보 생성 | 코드 | `candidates.py` (proxy.golang.org `@v/list`, `@v/<v>.mod`, 오프라인 OSV) |
| 조치안 작성 | LLM | `remediation.py` 에이전트 `remediation` |
| 입력 가드레일 | 코드 | 코드가 만든 요청의 형식 점검(`REMEDIATION_REQUEST case=.. service=.. module=..`와 사례 일치). 외부 입력 방어가 아니다. 어긋나면 모델을 부르기 전에 차단 |
| 출력 가드레일 | 코드 | target_version이 보여 준 후보 안인지, also_bump 버전이 proxy에 있는 안정 버전인지 |
| 기계 판정 | 코드 | `judge.py` |
| PR 작성 | LLM | 에이전트 `pr_writer`, 도구 `open_fix_pr(needs_approval=True)` |
| 사람 승인 | 사람 | `result.interruptions` -> `state.approve/reject` -> 재개. 일괄 평가는 `--auto-approve`로 자동 승인하고 건수를 센다 |
| 트레이스 | 코드 | `tracing_local.py`. `set_trace_processors`로 기본(OpenAI 내보내기)을 교체, 로컬 JSONL만 |

**도구 (전부 읽기 전용, 마지막 2개 제외)**
| 도구 | 하는 일 |
|---|---|
| list_candidates | 코드가 만든 후보 표 (버전, go 지시어, 1.19 초과 여부, 남는 권고 묶음 수) |
| get_advisory | 오프라인 OSV 권고 1건 (신뢰하지 않는 입력으로 다룬다고 지시문에 적음) |
| read_go_mod | 서비스 go.mod |
| search_code | 서비스 .go 파일 정규식 검색, 40줄 상한 |
| list_module_versions | 다른 모듈의 버전 목록 (also_bump 전에 확인) |
| get_last_failure | 직전 시도의 판정 로그 |
| submit_plan | 최종 제출. `StopAtTools`로 여기서 실행이 끝난다 |
| open_fix_pr | 로컬 PR 초안 (부작용). LLM은 제목만 넘기고, 본문과 패치는 코드 템플릿이 쓴다. `needs_approval=True` |

**LLM에 주지 않는 것**: KEV, EPSS 값(사례 고르기에만 씀), 키, 다른 서비스 코드

## 모델 교체 구조 (설정 한 줄)
| LAB_MODEL | 연결 | 이번 실행 |
|---|---|---|
| `anthropic:claude-sonnet-5-5` (기본) | Agents SDK LiteLLM 어댑터 `LitellmModel(model="anthropic/<ID>", api_key=os.environ["LAB_ANTHROPIC_API_KEY"])` | 실행 |
| `anthropic:claude-opus-5-5` | 같음 | 실행 (Sonnet 실패 4건만 승격) |
| `openai:gpt-6-luna` | SDK 기본 OpenAI 공급자(Responses). 키는 network secret | 미실행: api.openai.com 이 프록시에서 막힘 (`model_config.availability()`) |
| `local:<이름>@http://127.0.0.1:8080/v1` | `OpenAIChatCompletionsModel` + `AsyncOpenAI(base_url=...)` (llama.cpp 서버 등) | 미실행: 오픈 모델 가중치를 받을 곳(huggingface 등)이 막힘 |

- 에이전트 코드, 도구, 가드레일, 판정은 공급자와 무관하다. 바뀌는 것은 `model_config.make_model()` 한 함수뿐
- 근거: Agents SDK v0.24.0 `docs/models/index.md` 'Non-OpenAI models', 'Third-party adapters' (GitHub 원문. openai.github.io 문서 사이트는 이 환경에서 막혀 원문 md를 읽었다)

**공급자를 바꿀 때 실제로 부딪힌 것 (이번에 겪음)**
- LiteLLM 1.83은 `output_type`(JSON 스키마)을 Anthropic에 보낼 때, 모델 이름이 자기 목록(sonnet-4-5, opus-4-6 등)에 없으면 '강제 도구 호출'(`tool_choice: tool`)로 바꾼다
- Claude Sonnet 5.5는 강제 도구 호출을 400으로 거부한다 (`tool_choice: type "tool" and "any" are not supported for this model.`)
- 그래서 `output_type` 대신 최종 제출 도구(`submit_plan`, 인자가 Pydantic 모델) + `tool_use_behavior=StopAtTools`로 바꿨다. OpenAI, 로컬 모델에서도 같은 코드로 돈다
- 출력 가드레일은 최종 도구 출력에도 돈다. 다만 트립하면 SDK가 `output_info`를 비운다(docs/guardrails.md). 사유는 실행 컨텍스트에 따로 남긴다
- 교훈: '모델만 바꾸면 된다'는 말은 어댑터 층의 기능 차이를 확인한 뒤에만 할 수 있다

## 결과 (10건, 사례 규칙 `CASES_RULE.md`, 표 `results/agent/runs/*/summary.csv`)
| 정책 | 모델 | 건수 | 최종 통과 | 첫 시도 통과 | 평균 시도 | 가드레일 트립 | 후보 밖 제안 | 통과 중 go1.19.4 빌드, 테스트 통과 | 통과 중 모듈 권고 0 | 건당 토큰 | 건당 비용 | 건당 LLM 시간 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| min_target | 없음 | 10 | 6 | 6 | 1.0 | 0 | 0 | 4 | 3 | 0 | $0 | 0초 |
| min_target_retry | 없음 | 10 | 6 | 6 | 1.8 | 0 | 0 | 4 | 3 | 0 | $0 | 0초 |
| min_all | 없음 | 10 | 4 | 4 | 1.0 | 0 | 0 | 2 | 4 | 0 | $0 | 0초 |
| latest | 없음 | 10 | 3 | 3 | 1.0 | 0 | 0 | 0 | 3 | 0 | $0 | 0초 |
| llm_single (고정 흐름) | Sonnet 5.5 | 10 | 6 | 6 | 1.8 | 1 | 0 | 4 | 4 | 8,198 | $0.0283 | 13.6초 |
| agent (도구 탐색) | Sonnet 5.5 | 10 | 6 | 6 | 1.8 | 1 | 0 | 4 | 4 | 23,557 | $0.0658 | 22.1초 |
| agent 승격 | Opus 5.5 | 4 (Sonnet 실패 건만) | 0 | 0 | 3.0 | 2 | 0 | 0 | 0 | 48,992 | $0.2933 | 63.0초 |

- 비용은 토큰 x 공식 단가(Sonnet 5.5 $2/$10, Opus 5.5 $4/$20 per 100만 토큰, `model_config.PRICES`). Claude API 실제 청구서와 대조하지 않았다
- 이번 세션의 Claude API 사용 합계: $2.14 (스모크 $0.007, 배관 확인 $0.022, Sonnet 에이전트 $0.658, 고정 흐름 $0.283, Opus 승격 $1.173). 상한 $10 안
- 판정 1회 벽시계: 판정 기록 46개 중앙값 8.1초 (0.3~59.0초). 모듈 캐시가 데워진 뒤 값이 섞여 있다. 정책별 '판정 시간' 열은 캐시 재사용 때문에 비교 지표로 쓰지 않는다
- 사람 승인: 통과 6건마다 `open_fix_pr`에서 실행이 멈췄고(interruptions 1회), `--auto-approve`로 6건 자동 승인했다. 실제 사람 승인 0건. 거절 경로는 배관 시험에서 코드로 흉내 냈다

**사례별 (O 통과, X 실패, 마지막 시도의 버전)** 전체는 `results/agent/case_table.csv`
| 사례 | 서비스 | 모듈 | 대상 권고 | min_target | min_all | latest | 고정 흐름 | 에이전트 | Opus |
|---|---|---|---|---|---|---|---|---|---|
| C01 | frontend | golang.org/x/net 0.4.0 | GO-2023-2102 (CVE-2023-44487, KEV) | O v0.17.0 | X v0.62.0 (vet) | X v0.62.0 | O | O v0.17.0 | - |
| C02 | checkoutservice | google.golang.org/grpc 1.51.0 | GO-2023-2153 (CVE-2023-44487 related, KEV) | O v1.56.3 | X v1.83.2 (tidy) | X | O | O v1.56.3 | - |
| C03 | frontend | otelhttp 0.37.0 | GO-2023-2113 | X (tidy) | X | X | X | X | X |
| C04 | productcatalogservice | otelgrpc 0.37.0 | GO-2023-2331 | X (tidy) | X | X | X | X | X |
| C05 | shippingservice | google.golang.org/protobuf 1.28.1 | GO-2024-2611 | O v1.33.0 | O | O | O | O v1.33.0 | - |
| C06 | checkoutservice | golang.org/x/oauth2 (2022 의사 버전) | GO-2025-3488 | O v0.27.0 (go 1.23) | O | X | O | O v0.27.0 | - |
| C07 | productcatalogservice | github.com/sirupsen/logrus 1.9.0 | GO-2025-4188 | O v1.9.1 | O | O | O | O v1.9.3 | - |
| C08 | shippingservice | golang.org/x/text 0.5.0 | GO-2026-5970 | O v0.39.0 | O v0.41.0 | O | O | O v0.41.0 (go 1.25) | - |
| C09 | frontend | otlptrace 1.11.2 | GO-2026-6505 | X (build) | X | X | X | X | X |
| C10 | checkoutservice | otlptracegrpc 1.11.2 | GO-2026-6505 | X (build) | X | X | X | X | X |

**실패에서 본 것**
- C01 min_all, latest: x/net v0.62.0은 go 1.26 툴체인을 요구하고, 그 vet가 앱 코드 `main.go:156`의 비상수 포맷 문자열(logrus `Infof`)을 잡아 `go test`가 실패한다. 대상 권고만 고치는 v0.17.0은 go 1.19 그대로 통과
- C03, C04: 새 otel이 들어오면 옛 otlptrace가 사라진 내부 패키지(`otel/exporters/otlp/internal/envconfig`)를 찾아 `go mod tidy`가 실패한다
  - 에이전트는 2~3회째에 otel 계열을 함께 올려(also_bump) 빌드와 테스트를 통과시켰다. 그러나 그 조합이 `golang.org/x/crypto` 옛 버전을 새로 끌어와 재스캔에서 **새 HIGH/CRITICAL 권고 묶음 12개**(x/crypto 11, otel/sdk 1)가 생겼고 판정이 막았다. 서로 다른 조합 4개, 시도 6회(Sonnet 에이전트 2, 1회 호출 1, Opus 3)가 모두 같은 12묶음이었다 (`new_high`)
  - 존재 확인(`oracle_check.py`, 정책 비교 아님): otel 1.43 + x/crypto v0.58.0 조합은 `google.golang.org/api` v0.126.0 빌드가 깨졌고, api 최신(v0.310.0)은 otelgrpc v0.67.0 이상을 요구했다. 앱이 쓰는 `otelgrpc.UnaryServerInterceptor` 등은 그 버전에 없다. 시도한 범위에서는 앱 코드 수정 없이 통과하는 조합을 못 찾았다(전수 탐색 아님)
- C09, C10: 대상 권고를 고치는 가장 낮은 otlptrace v1.45.0은 go 1.25를 요구하고, `go get` 메시지대로 otelgrpc v0.61.0 이상을 끌어온다. 그 버전에는 앱이 부르는 인터셉터 함수가 없다(`undefined: otelgrpc.UnaryClientInterceptor`). 호출부 코드를 안 고치는 범위(기획안 2-2)에서는 사람에게 넘길 건이다
- 가드레일 트립 4회: 형식 오류 1회(Sonnet 에이전트 C04, `submit_plan` 인자를 JSON 문자열로 한 번 더 감쌈), also_bump를 6개 이상 넣은 계획 3회(1회 호출 C03, Opus C03, Opus C09. 상한 5개). 후보 밖 버전 제안 0회. 원자료: 각 실행 `results.jsonl`의 `guardrail_errors`
- 통과 6건에서 에이전트가 기준선과 다른 버전을 고른 것은 2건: C07(v1.9.3, 기준선 v1.9.1), C08(v0.41.0, 이 모듈 권고 전부 해소. 기준선 v0.39.0은 1묶음 남김. 둘 다 go 1.25로 오른다)

- 대상 권고만 고치면 같은 모듈의 다른 권고가 남는다: C01 x/net v0.17.0 뒤 21묶음, C02 grpc v1.56.3 뒤 5묶음. 이 실습의 통과 기준은 '대상 묶음 소멸'이라 통과로 셌다

**해석과 한계**
- 이 10건에서는 '버전 고르기'가 어렵지 않았다. 통과 가능한 6건은 최소 수정 버전이 곧 답이었고, 어려운 4건은 버전 선택이 아니라 앱 코드 수정이 필요했다. 그래서 LLM이 더할 자리가 작았다
- 에이전트가 낸 이득은 통과 수가 아니라 실패 건의 '사람에게 넘길 초안'(어디까지 해 봤고 무엇이 막혔나)이다. 이 초안의 품질은 재지 않았다
- 사례 고르기 규칙은 실행 전에 고정했지만, 정책 llm_single과 Opus 승격, 존재 확인은 결과를 본 뒤 더했다 (`CASES_RULE.md` 기록)
- 판정은 go 1.24.7(필요하면 자동으로 받은 상위 툴체인)으로 했다. 통과한 조합 11개는 Dockerfile과 같은 go1.19.4로 다시 빌드, 테스트했다(`go119_check.py`, `results/agent/go119_check.csv`). go 지시어가 1.19로 남은 5개는 전부 통과, 오른 6개는 전부 빌드 실패. 표의 'go1.19.4' 열은 이 실측이다
  - 예: C06 oauth2 v0.27.0(go 1.23), C08 x/text v0.39.0, v0.41.0(go 1.25)은 go1.24.7 판정은 통과했지만 지금 이미지로는 빌드가 안 된다. 이미지 교체가 같이 필요하다
- 재스캔은 go.mod 기준 OSV-Scanner다. 컨테이너 이미지, 표준 라이브러리는 보지 않는다
- 비교 대상인 OpenAI 모델과 로컬 오픈 모델은 미실행

**실행별 코드 커밋**
| 실행 | 시각 (UTC) | meta의 HEAD | 실제 코드 |
|---|---|---|---|
| baselines_v1 | 08:57~09:04 | 33a542f | 33a542f (judge, candidates 이후 안 바뀜) |
| sonnet_v1 | 09:04~09:09 | 33a542f | f701f86 (가드레일 사유 보관 수정이 커밋 7초 전 작업 트리에 있었다) |
| opus_escalation_v1 | 09:10~09:15 | a1eab35 | f701f86과 같음 |
| sonnet_single_v1 | 09:18~09:20 | c930a6c | f920a7a (llm_single 모드가 작업 트리에 있었다) |
- f920a7a 이후 코드로 네 실행을 모두 다시 돌릴 수 있다. agent 모드 동작은 f701f86과 같다. 이후 실행은 meta.json에 커밋 안 된 파일 목록(`dirty_files`)을 남긴다

## 실행
```bash
cd lotte/innovate
.venv/bin/python -m pytest -q agent/tests                         # 배관 시험 6개 (가짜 모델, 정확도 아님)
.venv/bin/python -m agent.cases --rescan                          # 사례 10건 (규칙: CASES_RULE.md)
.venv/bin/python -m agent.run_eval --policies min_target,min_target_retry,min_all,latest --run-id baselines_v1
LAB_MODEL=anthropic:claude-sonnet-5-5 .venv/bin/python -m agent.run_eval --policies agent --auto-approve --run-id sonnet_v1
LAB_MODEL=anthropic:claude-sonnet-5-5 .venv/bin/python -m agent.run_eval --policies llm_single --auto-approve --run-id sonnet_single_v1
.venv/bin/python -m agent.run_eval --policies agent --cases C03,C04,C09,C10 --model anthropic:claude-opus-5-5 --auto-approve --run-id opus_escalation_v1
.venv/bin/python -m agent.oracle_check                            # 존재 확인 (정책 비교 아님)
.venv/bin/python -m agent.export --runs baselines_v1,sonnet_v1,sonnet_single_v1,opus_escalation_v1
.venv/bin/python -m agent.figs --results baselines_v1,sonnet_single_v1,sonnet_v1
```
- 사전 준비: Go 1.24.7, osv-scanner 2.7.0 (`/home/user/tools/bin`), OSV 오프라인 DB (`m2/prepare.py --osvdb /home/user/work/osvdb`), Online Boutique v0.5.0 worktree (`/home/user/work/ob_v0.5.0`)
- 판정 결과는 `/home/user/work/agenttmp/judge_cache/<키>.json`에 캐시한다. 같은 (서비스, 변경 목록)은 다시 빌드하지 않는다. 처음부터 재려면 그 폴더를 지운다
