# 외부 데이터와 코드 고지

이 저장소의 결과 파일에는 아래 외부 데이터가 도구 출력 형식(OSV-Scanner, govulncheck, CycloneDX VEX, CSV 집계)으로 변환되어 들어 있습니다. 원자료 파일은 커밋하지 않았고, 받은 URL, 시각, sha256은 `lotte/innovate/data/manifest*.json`에 있습니다.

## 취약점 권고

| 데이터 | 들어 있는 곳 | 라이선스 | 표기 |
|---|---|---|---|
| GitHub Advisory Database | `lotte/innovate/results/m2/raw/`, `results/reach/` | CC-BY 4.0 ([LICENSE](https://github.com/github/advisory-database/blob/main/LICENSE.md)) | GitHub Advisory Database. OSV-Scanner 출력 형식으로 변환 |
| Go Vulnerability Database | `results/reach/`, `results/agent/verdicts/`, `results/m2/raw/` | 데이터 CC-BY 4.0, 코드 BSD-3-Clause ([golang/vulndb](https://github.com/golang/vulndb#license)) | Go Vulnerability Database. OSV, govulncheck 출력 형식으로 변환 |
| PyPA Advisory Database | `results/m2/raw/` | CC-BY 4.0 ([LICENSE](https://github.com/pypa/advisory-database/blob/main/LICENSE)) | PyPA Advisory Database. OSV-Scanner 출력 형식으로 변환 |
| Bitnami Vulnerability Database | `results/m2/raw/`, `results/reach/` (별칭 ID만) | Apache-2.0 | Bitnami vulndb |

## 악용 신호와 점수

| 데이터 | 들어 있는 곳 | 라이선스 | 표기 |
|---|---|---|---|
| CISA Known Exploited Vulnerabilities | `results/m1/`, `results/m2/` | CC0 1.0 (미러 [cisagov/kev-data](https://github.com/cisagov/kev-data) 7ccba8e) | CISA KEV catalogVersion 2026.10.30 |
| FIRST EPSS | `results/m1/`, `results/m2/` | 무료 공개, 출처 표기 요청 | EPSS data provided by FIRST.org (https://www.first.org/epss). 미러 RogoLabs/EPSS-History 9b88cf4 (Apache-2.0) |
| NVD | `results/m1/` | 미국 정부 공개 자료 | This product uses data from the NVD API but is not endorsed or certified by the NVD. 미러 fkie-cad/nvd-json-data-feeds 1b66e03 |

## 평가 데이터와 대상 앱

| 데이터 | 들어 있는 곳 | 라이선스 | 표기 |
|---|---|---|---|
| VEX-Bench | `lotte/innovate/vexpilot/CASES_RULE.md`, `results/vexpilot/` | MIT, Copyright (c) 2026 Jiahao Shi | [steven1518/vex-bench](https://github.com/steven1518/vex-bench) 80cddea, arXiv:2609.08040 |
| Google Online Boutique | `results/m2/raw/` (SBOM), `results/agent/runs/*/patches/` | Apache-2.0 | [GoogleCloudPlatform/microservices-demo](https://github.com/GoogleCloudPlatform/microservices-demo) 3c0d659(v0.5.0), d54af3d(v0.8.0), c7cb6d5(main) |
| VEX-Bench 과제 저장소의 코드 발췌 | `results/vexpilot/**/trace.jsonl` | caddy, podman, trivy: Apache-2.0. testify: MIT | caddyserver/caddy 8dc7667, containers/podman 38ccfa2 5ae6347 6541fc4 6a65597, aquasecurity/trivy 37da98d 98e136e, stretchr/testify 285adcc |
| docker-library/golang | `results/reach/docker_image_gotoolchain.txt` | BSD-3-Clause | docker-library/golang 236db66 |

Go 모듈 목록(proxy.golang.org)은 모듈 경로, 버전, 해시만 있고 소스는 들어 있지 않습니다.
