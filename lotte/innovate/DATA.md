# DATA: 쓴 데이터, 출처, 라이선스, 받은 시각

- 전부 공개 데이터. 개인정보 없음. 로그인, 유료 벽, 봇 차단 우회 없음
- 원본 API 몇 곳은 이 환경의 네트워크 정책이 막았다. 그래서 미러를 커밋으로 고정해 썼다
- 받은 파일의 URL, 시각, sha256은 `data/manifest*.json`. 원자료는 커밋하지 않는다(`data/raw/`는 .gitignore)
- 시각은 UTC. 한국 시각은 +9시간

## 1. M1 백테스트

| 자료 | 어디서 | 고정 | 받은 시각 | 라이선스, 조건 |
|---|---|---|---|---|
| CISA KEV | GitHub `cisagov/kev-data` (CISA 공식 미러) | 커밋 7ccba8e, catalogVersion 2026.10.30, 1,766건 | 2026-11-02 08:10 | KEV 본문 CC0 1.0(기획안 기록). 미러 저장소 표기 NOASSERTION |
| EPSS 일별 파일 4개 | GitHub `RogoLabs/EPSS-History` (제3자 미러) | 커밋 9b88cf4. 2025-06-01, 2025-12-01, 2026-03-31, 2026-11-01 | 2026-11-02 08:10 | 원자료 FIRST EPSS. 인용 조건 미확인. 미러 저장소 Apache-2.0 |
| NVD CVE 41만 건 | GitHub `fkie-cad/nvd-json-data-feeds` (NVD API 재구성 미러) | 커밋 1b66e03 (2026-11-02 07:05 UTC 동기화), 417,788건 | 2026-11-02 08:12 (git 얕은 복제) | NVD 공개 자료. 미러 저장소 라이선스 표기 없음 |

- 고지: This product uses data from the NVD API but is not endorsed or certified by the NVD. (미러 저장소도 같은 문구를 쓴다)

**미러 무결성 확인 (원본과 직접 대조는 못 했다)**
- EPSS 파일 첫 줄 머리말: `model_version`, `score_date`가 날짜와 맞음
- 행 수: 2025-06-01 280,762행, 2025-12-01 303,485행, 2026-11-01 398,784행
  - 계획 문서와 기획안(6절)에 적힌, 원본에서 받은 행 수와 같다
- KEV: catalogVersion 2026.10.30, 1,766건. 계획 문서 2.2의 원본 값과 같다
- NVD: 원본 API와 대조 못 함. 공개일과 CVSS로 낸 백테스트 적중 수가 기획안 3-1(원본 NVD API로 낸 값)과 전부 같았다(RESULTS.md M1)

## 2. M2 스캔, 도달성, 조치안 에이전트 (이 세션, 새 컨테이너에서 다시 받음)

| 자료 | 어디서 | 고정 | 받은 시각 (UTC) | 라이선스, 조건 |
|---|---|---|---|---|
| Online Boutique | GitHub `GoogleCloudPlatform/microservices-demo` (git clone, 커밋별 worktree) | v0.5.0 3c0d659, v0.8.0 d54af3d, main c7cb6d5 | 2026-11-02 08:40 | Apache-2.0 |
| OSV 오프라인 DB 6개 생태계 | OSV 공식 GCS 덤프 `osv-vulnerabilities.storage.googleapis.com/<생태계>/all.zip` | Go, npm, PyPI, NuGet, Maven, GitHub Actions. 레코드 최대 modified와 sha256은 `results/m2/osv_db_inventory.csv` | 08:41~08:42 (`data/manifest_m2.json`) | 소스별(GHSA CC-BY 4.0, Go 취약점 DB CC-BY 4.0 등) |
| CycloneDX 1.6 스키마 | raw.githubusercontent.com/CycloneDX/specification/1.6 | bom-1.6, spdx, jsf | 08:4x (`manifest_m2`) | Apache-2.0 |
| Go 모듈 버전 목록, go.mod | proxy.golang.org `@v/list`, `@v/<v>.mod` | 처음 받은 파일을 캐시해 같은 스냅샷을 씀. 100개 | 08:50~09:16 (`data/manifest_agent.json`) | 모듈별 |
| Go 모듈 소스 (빌드, 판정용) | proxy.golang.org, sum.golang.org | Go 모듈 캐시 (커밋 안 함) | 실행 때 | 모듈별 |
| Go 툴체인 | proxy.golang.org `golang.org/toolchain` | go1.19.4, go1.20.4, go1.25.0, go1.26.0, go1.26.10, go1.27.0, go1.27.3 | 08:48~09:2x | BSD |
| golang/vulndb data/osv | github.com/golang/vulndb 커밋 8f7e390 (git fetch --depth 1) | 도달성 DB 대조용 | 08:50:53 | CC-BY 4.0 (data), BSD (코드) |
| docker-library golang 템플릿 | raw.githubusercontent.com/docker-library/golang/236db66 | 공식 이미지의 GOTOOLCHAIN=local 확인용 | 08:58:08 (`data/manifest_reach.json`) | BSD 스타일 |
| VEX-Bench 라벨 | raw.githubusercontent.com/steven1518/vex-bench/80cddea/benchmark/tasks/vex_bench.jsonl | 75건 (Go 30) | 09:23:13 (`data/manifest_vexbench.json`) | MIT (저장소 표기 '공사 중') |

| OSV Bitnami 덤프 (별칭 조회만) | `osv-vulnerabilities.storage.googleapis.com/Bitnami/all.zip` | 별칭의 별칭 조회 | 08:57:07 (`manifest_m2`) | Apache-2.0 (bitnami/vulndb) |
| NVD 레코드 1건 CVE-2023-44487 | fkie-cad/nvd-json-data-feeds 1b66e03의 raw 파일 | VEX 예시 점수용 (nvd_table 7.5와 대조) | 09:41:40 (`manifest_m2`) | NVD 공공 자료 |
| VEX-Bench 저장소 스냅숏 8개 | 각 repo_url의 commit_sha (git fetch --depth 1) | 시범 8건 (`vexpilot/CASES_RULE.md`) | 09:2x | 저장소별 (caddy Apache-2.0, podman Apache-2.0, testify MIT, trivy Apache-2.0) |

- OSV 덤프는 앞 세션(08:12 UTC)이 아니라 이 세션에서 08:41 UTC에 새로 받은 것이다. 그래서 앞 세션 중간 관찰과 숫자가 조금 다를 수 있다
- 모듈별 세부: `m2/NOTES.md`, `reach/NOTES.md`, `agent/NOTES.md`, `vexpilot/NOTES.md`

## 3. 안 쓴 것
- api.osv.dev, api.first.org, nvd.nist.gov, www.cisa.gov 원본 호출: 네트워크 정책이 막음
- api.deps.dev: 막힘. Python requirements.txt 전이 의존성 해석이 안 된다
- 오픈 모델 가중치(Hugging Face 등): 막힘
- vuln.go.dev(govulncheck 기본 DB): 막힘. OSV Go 덤프로 만든 로컬 DB를 썼다
- api.openai.com: 막힘. OpenAI 모델 비교 미실행
