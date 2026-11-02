# agent: 조치안 에이전트 (과제 2번, 3번)

## 결론
- (결과 표는 아래 '결과'. 실행 뒤 채운다)

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
| 입력 가드레일 | 코드 | 요청 형식(`REMEDIATION_REQUEST case=.. service=.. module=..`)과 사례 일치. 아니면 모델을 부르기 전에 차단 |
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
| open_fix_pr | PR 초안 (부작용). `needs_approval=True` |

**LLM에 주지 않는 것**: KEV, EPSS 값(사례 고르기에만 씀), 키, 다른 서비스 코드

## 모델 교체 구조 (설정 한 줄)
| LAB_MODEL | 연결 | 이번 실행 |
|---|---|---|
| `anthropic:claude-sonnet-5-5` (기본) | Agents SDK LiteLLM 어댑터 `LitellmModel(model="anthropic/<ID>", api_key=os.environ["LAB_ANTHROPIC_API_KEY"])` | 실행 |
| `anthropic:claude-opus-5-5` | 같음 | (결과에 적음) |
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

## 실행
```bash
cd lotte/innovate
.venv/bin/python -m pytest -q agent/tests                         # 배관 시험 6개 (가짜 모델, 정확도 아님)
.venv/bin/python -m agent.cases --rescan                          # 사례 10건 (규칙: CASES_RULE.md)
.venv/bin/python -m agent.run_eval --policies min_target,min_target_retry,min_all,latest --run-id baselines_v1
LAB_MODEL=anthropic:claude-sonnet-5-5 .venv/bin/python -m agent.run_eval --policies agent --auto-approve --run-id sonnet_v1
.venv/bin/python -m agent.figs --results baselines_v1,sonnet_v1
```
- 사전 준비: Go 1.24.7, osv-scanner 2.7.0 (`/home/user/tools/bin`), OSV 오프라인 DB (`m2/prepare.py --osvdb /home/user/work/osvdb`), Online Boutique v0.5.0 worktree (`/home/user/work/ob_v0.5.0`)
- 판정 결과는 `/home/user/work/agenttmp/judge_cache/<키>.json`에 캐시한다. 같은 (서비스, 변경 목록)은 다시 빌드하지 않는다. 처음부터 재려면 그 폴더를 지운다
