# 사례 고르기 규칙 (LLM 실행 전에 고정)

- 고정 시각: 2026-11-02 09:25:41 UTC (파일 시각). 첫 LLM 호출(캐시 확인 probe, 09:28쯤. 사례와 무관한 장난감 입력) 전, 첫 판정 실행(09:35:33) 전
  - 처음에 '09:27'로 잘못 적었다가 파일 시각으로 고쳤다. 규칙과 목록은 바꾸지 않았다
- 고정 시점 저장소 HEAD: c60ac51723abe69d40589806d02169842951684e
- 라벨 파일: `data/raw/vexbench/vex_bench.jsonl`
  - sha256 06c58010defd28a3165598072b36fd56e986bc4c39c91f3c0095dc82b2800ddf
  - 출처: steven1518/vex-bench 커밋 80cddea, MIT. 받은 시각 2026-11-02T09:23:13Z (`data/manifest_vexbench.json`)
- 이 규칙과 목록은 결과를 본 뒤 바꾸지 않는다. 프롬프트도 이 8건 결과를 보고 고치지 않는다

## 규칙
1. 언어 Go만 (`metadata`의 language 값, 정규식으로 읽음). 30건 (exploitable 7, not_exploitable 23)
2. 저장소 제외 (아주 큰 단일 저장소, 디스크와 시간 때문):
   - kubernetes/kubernetes, kubernetes/minikube, rancher/rancher, cilium/cilium, moby/moby, istio/istio
   - 남는 Go 과제 14건 (exploitable 3, not_exploitable 11)
3. 남은 것 중 exploitable 전부
4. 그다음 not_exploitable을 task_id 사전 순으로, 합계 8건이 될 때까지

## 결과 목록 (8건)
| # | task_id | 라벨 | 라벨 사유 |
|---|---|---|---|
| 1 | caddyserver-caddy-8dc7667-CVE-2025-29785 | exploitable | vulnerable |
| 2 | containers-podman-6a65597-CVE-2023-48795 | exploitable | vulnerable |
| 3 | stretchr-testify-285adcc-CVE-2022-28948 | exploitable | vulnerable |
| 4 | aquasecurity-trivy-37da98d-CVE-2024-32473 | not_exploitable | code_not_reachable |
| 5 | aquasecurity-trivy-98e136e-CVE-2024-24791 | not_exploitable | code_not_reachable |
| 6 | containers-podman-38ccfa2-CVE-2024-37298 | not_exploitable | code_not_reachable |
| 7 | containers-podman-5ae6347-CVE-2025-47914 | not_exploitable | code_not_present |
| 8 | containers-podman-6541fc4-CVE-2025-58181 | not_exploitable | code_not_reachable |

- 목록 다시 만들기: `.venv/bin/python -m vexpilot.cases` (lotte/innovate 에서). 코드가 이 표와 같은지 확인한다
- 이 8건은 조정용(시범)이다. 시험용 정확도가 아니다
- 표본이 작다: exploitable 3건이라 1건이 33%p다. 비율보다 건수로 쓴다
