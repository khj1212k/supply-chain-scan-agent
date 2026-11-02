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

## 2. M2 스캔, 도달성, 에이전트

| 자료 | 어디서 | 고정 | 받은 시각 | 라이선스 |
|---|---|---|---|---|
| Online Boutique | GitHub `GoogleCloudPlatform/microservices-demo` (git) | v0.5.0 3c0d659, v0.8.0 d54af3d, main c7cb6d5 | 2026-11-02 08:11 | Apache-2.0 |
| OSV 취약점 DB | OSV 공식 GCS 덤프 `osv-vulnerabilities.storage.googleapis.com/<생태계>/all.zip` | Go, npm, PyPI, NuGet. OSV-Scanner 오프라인 DB | 2026-11-02 08:12 | 소스별(GHSA CC-BY 4.0, Go vulndb CC-BY 4.0 등) |
| Go 모듈과 버전 목록 | proxy.golang.org, sum.golang.org | 빌드할 때 받음 | 실행 때 | 모듈별 라이선스 |

- 모듈별 추가 자료와 받은 시각: `m2/NOTES.md`, `reach/NOTES.md`, `agent/NOTES.md`, `data/manifest_*.json`

## 3. 안 쓴 것
- api.osv.dev, api.first.org, nvd.nist.gov, www.cisa.gov 원본 호출: 네트워크 정책이 막음
- api.deps.dev: 막힘. Python requirements.txt 전이 의존성 해석이 안 된다
- 오픈 모델 가중치(Hugging Face 등): 막힘
