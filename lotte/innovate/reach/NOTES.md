# reach: Go 도달성 (govulncheck, 로컬 DB, 네트워크 없이)

## 결론 (세 줄)
1. 로컬 DB로 govulncheck가 네트워크 없이 돈다. 양성 대조는 called, 음성 대조는 package 수준만 나왔다
2. CVE-2023-44487: grpc 서버 3곳은 GO-2023-2153이 called, frontend는 grpc가 package 수준이다. 기획안 3-3 판정 초안 6칸과 모두 일치
3. 다만 frontend의 표준 라이브러리 net/http는 ListenAndServe 때문에 called로 나온다. 직접 돌려 보니 go1.19.4 평문 서버는 HTTP/2로 답하지 않았다

- 수치 기준: 실행 2026-11-02T09:24:14Z~09:32:17Z (UTC), DB modified 2026-10-30T10:55:54Z
- 코드 커밋: 9d234e9 (수치를 낸 reach 코드와 git diff 0). 실행 시 HEAD는 68242d2였다
- 결과 폴더는 9d234e9에 실행 도중 상태로 들어갔다. 지금 `results/reach/` 전체를 다시 커밋해야 수치와 맞는다
- run.sh를 세 번 돌렸다 (08:58, 09:10, 09:24 UTC 시작). 커밋별 집계는 세 번 같았고, 서비스별 수치는 뒤 두 번이 같았다
- 재현: 아래 '실행' 한 줄

## 실행
```
cd lotte/innovate && bash reach/run.sh
```
- 약 8분 (4 vCPU 공유, GOMAXPROCS=2, nice 10)
- 온라인이 필요한 단계: go mod download, 툴체인 받기, golang/vulndb 받기. govulncheck 실행은 모두 오프라인
- 결과: `results/reach/`. 임시: `/home/user/work/reachtmp` (매번 지움). 캐시: `/home/user/work/reachcache` (안 지움)
- 집계만 다시: `.venv/bin/python -I reach/analyze.py --out results/reach --tmp /home/user/work/reachtmp --db /home/user/work/reachtmp/db_osvzip`

## 무엇을 재나 (세 수준)
| 수준 | 뜻 | OpenVEX 변환 결과 |
|---|---|---|
| module | 취약 버전 모듈이 빌드에 있다. 취약 패키지는 안 쓴다 | not_affected / vulnerable_code_not_present |
| package | 취약 패키지를 import 한다. 취약 함수 호출 경로는 없다 | not_affected / vulnerable_code_not_in_execute_path |
| symbol | 앱 코드에서 취약 함수까지 정적 호출 경로가 있다 (called) | affected |

- 한 OSV ID와 모듈 쌍마다 govulncheck finding 중 가장 높은 수준을 쓴다 (`levels.csv` 한 줄)
- OpenVEX 상태 개수는 수준 개수와 같았다 (예: v0.5.0 frontend affected 87, 16, 29. `summary.json` openvex)

## 도구 버전 (`results/reach/tool_versions.txt`)
| 도구 | 버전 | 비고 |
|---|---|---|
| govulncheck | v1.9.0 (h1:12VaqnI9...) | go1.27.0으로 직접 빌드한 것 하나를 모든 커밋에 썼다 (결정 1) |
| 공용 govulncheck | v1.9.0, go1.26.10 빌드 | main 커밋에서 실패해서 안 씀 (오류 2) |
| go (로컬) | go1.24.7 | |
| 패키지 로딩 툴체인 | go1.20.4, go1.27.0 | 민감도용 go1.24.7, go1.26.10 |
| strace | 6.8 | |
| unshare | util-linux 2.39.3 | |

## DB 출처 (`results/reach/db_provenance.json`)
| 항목 | 값 |
|---|---|
| 주 DB 원본 | https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip |
| 받은 시각 | 2026-11-02T08:41:01Z (data/manifest_m2.json, 리드가 받음) |
| sha256 | 71e545dbaca20a60937a081582ac704f08cc96e65ebc0dd76644261fbce9303a |
| 크기 | 12,701,800 바이트 |
| 레코드 | 전체 9,815, 그중 GO-* 4,731 (모듈 1,449) |
| 가장 늦은 modified | 전체 2026-10-30T23:30:04Z, GO-* 2026-10-30T10:55:54Z (db.json) |
| 변환 | `reach/builddb` (Go). v1 DB: index/db.json, index/modules.json, ID/<ID>.json |
| 대조1 | 같은 GO-* 파일을 평평한 폴더로. govulncheck가 스스로 색인을 만든다 |
| 대조2 | golang/vulndb 8f7e390 (2026-10-27T14:16:18-07:00) data/osv 4,712건 |

## 커밋별 요약 (`results/reach/summary.json` per_commit)
- 값: 서로 다른 OSV ID 수, module/package/symbol (합). 서비스 4개 합집합, ID마다 가장 높은 수준

| 커밋 | stdlib 판정 | 전체 | 표준 라이브러리 제외 | 표준 라이브러리만 |
|---|---|---|---|---|
| v0.5.0 (3c0d659) | go1.19.4 | 29/13/90 (132) | 17/8/15 (40) | 13/9/81 (103) |
| v0.8.0 (d54af3d) | go1.20.4 | 28/13/78 (119) | 17/8/14 (39) | 12/9/69 (90) |
| main (c7cb6d5) | go1.27.0 | 5/1/13 (19) | 5/0/5 (10) | 0/1/13 (14) |

## 서비스별 (`results/reach/summary.json` per_service)
| 커밋 | 서비스 | 전체 m/p/s (합) | 표준 라이브러리 제외 | 표준 라이브러리만 | linux/amd64 아님 m/p/s |
|---|---|---|---|---|---|
| v0.5.0 | checkoutservice | 29/29/73 (131) | 17/7/15 (39) | 13/26/64 (103) | 1/1/4 |
| v0.5.0 | frontend | 29/16/87 (132) | 17/11/12 (40) | 13/9/81 (103) | 1/1/4 |
| v0.5.0 | productcatalogservice | 29/29/73 (131) | 17/7/15 (39) | 13/26/64 (103) | 1/1/4 |
| v0.5.0 | shippingservice | 29/29/70 (128) | 17/7/12 (36) | 13/26/64 (103) | 1/1/4 |
| v0.8.0 | checkoutservice | 28/24/66 (118) | 17/7/14 (38) | 12/21/57 (90) | 1/1/3 |
| v0.8.0 | frontend | 28/16/75 (119) | 17/11/11 (39) | 12/9/69 (90) | 1/1/3 |
| v0.8.0 | productcatalogservice | 28/24/66 (118) | 17/7/14 (38) | 12/21/57 (90) | 1/1/3 |
| v0.8.0 | shippingservice | 28/23/63 (114) | 17/6/11 (34) | 12/21/57 (90) | 1/1/3 |
| main | checkoutservice | 5/4/10 (19) | 5/0/5 (10) | 0/5/9 (14) | 0/1/0 |
| main | frontend | 5/1/13 (19) | 5/0/5 (10) | 0/1/13 (14) | 0/1/0 |
| main | productcatalogservice | 5/4/10 (19) | 5/0/5 (10) | 0/5/9 (14) | 0/1/0 |
| main | shippingservice | 3/4/10 (17) | 3/0/5 (8) | 0/5/9 (14) | 0/1/0 |

- 'linux/amd64 아님': OSV에 goos, goarch 제한이 있어 이 빌드 대상에는 해당 없는 ID. 위 수치에 포함돼 있다
  - 예: GO-2025-3447 (ppc64le 전용)이 v0.5.0 frontend에서 symbol로 나왔다
- go.mod 기준선: go.mod require 목록과 표준 라이브러리 버전을 같은 DB 범위에 맞춘 ID 수가 서비스마다 govulncheck 합계와 같았다
  - 예: v0.5.0 checkoutservice 131 = 131. govulncheck 결과가 기준선 밖에 있는 경우 0건, 버전 불일치 0건
  - 그래서 깔때기는 '버전 매칭 131 -> import 102 -> 호출 73' (v0.5.0 checkoutservice)

## CVE-2023-44487 (`results/reach/cve_2023_44487.md`)
| 서비스 | ID, 모듈 | 수준 | 호출 경로 [앱 코드 줄] | 기획안 주장 | 대조 |
|---|---|---|---|---|---|
| frontend | GO-2023-2153 grpc v1.51.0 | package | - | not_affected 후보 (DialContext만) | 일치 |
| frontend | GO-2023-2102 x/net v0.4.0 | package | - | not_affected 후보 | 일치 |
| frontend | GO-2023-2102 stdlib v1.19.4 | symbol | frontend.main -> http.ListenAndServe [main.go:157] | in_triage. 심볼에 ListenAndServe 있음 | 일치 (아래 주의) |
| checkoutservice | GO-2023-2153 grpc v1.51.0 | symbol | checkoutservice.main -> grpc.NewServer [main.go:131] | exploitable 후보, 수정 1.56.3 | 일치. 수정 v1.56.3, 호출 줄 131, 142 |
| productcatalogservice | GO-2023-2153 grpc v1.51.0 | symbol | main -> run -> grpc.NewServer [server.go:140] | exploitable 후보, 수정 1.56.3 | 일치. 호출 줄 140, 151 |
| shippingservice | GO-2023-2153 grpc v1.51.0 | symbol | shippingservice.main -> grpc.NewServer [main.go:85] | exploitable 후보, 수정 1.56.3 | 일치. 호출 줄 85, 97 |

- grpc 서버 3곳의 x/net, 표준 라이브러리 GO-2023-2102는 package 수준이다. 기획안은 이 칸을 판정하지 않았다
- **주의 (frontend 표준 라이브러리)**: GO-2023-2102 심볼 목록에 ListenAndServe가 있어서 평문 HTTP/1 서버도 called다
  - go1.19.4 net/http는 TLS의 ALPN에서만 HTTP/2를 켠다 (server.go 1892~1899줄)
  - h2probe를 직접 돌렸다 (`results/reach/h2probe.jsonl`): 평문 서버는 HTTP/2 서문에 `HTTP/1.1 200 OK`로 답했고, TLS 서버는 ALPN h2와 SETTINGS 프레임으로 답했다
  - frontend 소스와 `go list -deps`에 h2c가 없다 (`results/reach/frontend_h2c_check.txt`)
  - 그래서 '도구는 called, 사람 판단은 not_affected 후보'가 맞다. frontend 서비스 자체는 띄워 보지 않았다
- symbol은 exploitable의 필요 조건일 뿐이다. grpc 3곳의 '실제 공격 가능'은 확인하지 않았다
- 참고: v0.8.0도 grpc v1.55.0으로 3곳 symbol, main은 grpc v1.83.2, x/net v0.58.0(shipping v0.59.0), go1.27.0이라 두 ID 모두 해당 없음

## 대조 실험 (`results/reach/controls_check.json`)
| 모듈 | 코드 | 기대 | 결과 |
|---|---|---|---|
| testmod/called | `language.ParseAcceptLanguage` 호출 (x/text v0.3.6) | GO-2021-0113, GO-2022-1059 symbol | 둘 다 symbol. 경로 called.main -> language.ParseAcceptLanguage [called/main.go:12]. 통과 |
| testmod/imported | `language.Korean.String()`만 | 같은 두 ID가 package만 | 둘 다 package, symbol 0건. 통과 |

- 두 모듈 모두 x/text의 GO-2026-5970, GO-2026-6629는 module 수준 (취약 패키지 미사용)

## 오프라인 증명 (`results/reach/controls/offline_proof.txt`)
| 확인 | 결과 |
|---|---|
| unshare -n 허용 | 됐다. 네임스페이스 안 장치는 lo 하나 |
| 안에서 curl https://proxy.golang.org | 실패 (rc 6, 이름 못 찾음) |
| 안에서 1.1.1.1:443 TCP 직접 연결 | 실패 (Network is unreachable) |
| 대조 called, strace -f connect | rc 0, connect 0회, finding 76 |
| v0.5.0 checkoutservice, strace -f connect | rc 0, connect 0회, finding 1,289 |
| main frontend, strace -f connect | rc 0, connect 0회, finding 333 |
| 서비스 12개 x 실행 5번 | 모두 unshare -n, GOPROXY=off 안에서 rc 0 (`*.status.json`) |

- 증명한 것: govulncheck와 자식 go list가 네트워크 없이 끝까지 돌았고 connect 시도도 없었다
- 증명 안 한 것: 모듈 캐시와 툴체인은 그 전에 온라인으로 받았다 (go mod download)
- 기본 DB(vuln.go.dev)로 돌리면 `Forbidden`으로 실패한다 (`controls/default_db_attempt.txt`, rc 1). 이 환경 프록시가 막는다
- govulncheck가 x/telemetry 자식 프로세스를 띄운다. 모드는 local (업로드 안 함), connect도 0회

## GOVERSION과 로더 민감도 (`results/reach/goversion_sensitivity.csv`)
- govulncheck는 표준 라이브러리 버전을 `GOVERSION` 환경 변수, 없으면 `go env GOVERSION`에서 읽는다 (x/vuln v1.9.0 internal/scan/run.go 87~98줄)
- frontend 표준 라이브러리만, module/package/symbol

| 커밋 | 실행 | 로더 | GOVERSION | 판정 버전 | stdlib m/p/s |
|---|---|---|---|---|---|
| v0.5.0 | 주 | go1.20.4 | go1.19.4 | go1.19.4 | 13/9/81 |
| v0.5.0 | 민감도 | go1.24.7 | go1.19.4 | go1.19.4 | 15/9/79 |
| v0.5.0 | 민감도 | go1.24.7 | 없음 | go1.24.7 | 7/7/45 |
| v0.8.0 | 주 | go1.20.4 | go1.20.4 | go1.20.4 | 12/9/69 |
| v0.8.0 | 민감도 | go1.24.7 | 없음 | go1.24.7 | 7/7/45 |
| main | 주 | go1.27.0 | go1.27.0 | go1.27.0 | 0/1/13 |
| main | 민감도 | go1.26.10 | go1.27.0 | go1.27.0 | 5/1/8 |
| main | 민감도 | go1.26.10 | 없음 | go1.26.10 | 0/0/0 |

- 같은 로더(go1.24.7)에서 GOVERSION=go1.19.4를 빼면 v0.5.0 frontend 표준 라이브러리 symbol이 79에서 45로 준다. 로더 툴체인 버전(go1.24.7)으로 판정하기 때문이다
- 그래서 GOVERSION 없이 돌리면 표준 라이브러리 취약점을 크게 놓친다
- 로더도 영향이 있다. 로더 소스에 없는 함수는 호출 경로를 못 찾고 module 수준으로 내려간다
  - v0.5.0: go1.24.7 로더면 GO-2023-1621, GO-2025-3447이 symbol에서 module로. 취약 패키지 crypto/internal/nistec가 go1.24.7 소스에서는 crypto/internal/fips140/nistec로 옮겨져 있다 (두 툴체인 src 폴더로 확인)
  - main: go1.26.10 로더면 표준 라이브러리 symbol 5개가 module로 (go1.27 전용 코드를 못 봄)
- 비 표준 라이브러리 수치는 세 실행에서 같았다

## DB 대조 (`results/reach/db_check_compare.csv`, `db_source_compare.json`)
| 비교 | 결과 |
|---|---|
| builddb DB 대 평평한 폴더(govulncheck 자체 색인) | 서비스 12개 모두 (ID, 모듈, 수준) 집합 같음. 차이 0 |
| builddb DB 대 golang/vulndb 8f7e390 | 서비스 12개 모두 같음. 차이 0 |
| 원본 레코드 비교 (GO-*) | 공통 4,712건의 affected(패키지, 범위, 심볼) 차이 0 |
| zip에만 있는 ID | 19건, 모두 철회(withdrawn). govulncheck는 철회 항목을 무시한다 (vulncheck.go 137줄) |
| 별칭 차이 | 911건. zip에만 있는 별칭 접두어 BIT 852, CVE 148, GHSA 86 등. OSV.dev가 붙인다 |

- 뜻: 원본을 어디서 받든 govulncheck 결과는 같았다. CVE로 조인하면 원본에 따라 결과가 달라질 수 있다 (CVE 별칭 148건 차이)

## 한계
- 리플렉션, plugin, cgo로 부르는 경로는 못 본다
- 인터페이스 메서드와 함수 값 호출을 넓게 잡아 과다 보고할 수 있다. 실제 예:
  - main checkoutservice의 x/net symbol 5건 중 4건: 가장 짧은 경로가 `checkoutservice.main -> fmt.Sprintf -> fmt.pp.handleMethods -> http2.ConnectionError.Error`. 나머지 1건(GO-2026-6610)은 sync.Once.Do를 지난다
  - v0.5.0 checkoutservice GO-2026-6809: `genproto.init -> proto.RegisterFile -> ... -> tls...readServerCertificate` (proto 등록이 TLS 핸드셰이크로 이어지는 경로)
  - v0.5.0 frontend GO-2025-3447 (ppc64le 전용): `os.Getenv -> syscall.Getenv -> sync.Once.Do -> sync.Once.doSlow -> ecdh.PublicKey$1 -> ...`
  - 가장 짧은 예시 경로가 fmt.pp.handleMethods나 sync.Once.doSlow를 지나는 symbol 줄: v0.5.0 98/333, v0.8.0 88/296, main 31/60 (`summary.json` dynamic_dispatch_hint). 단서일 뿐 오탐 수가 아니다
- 플랫폼으로 거르지 않는다 (소스 모드는 affectingVulnerabilities(mv, "", "")). linux/amd64에 해당 없는 ID도 센다. `levels.csv` applies_linux_amd64 열로 따로 표시
- 표준 라이브러리는 가정한 툴체인 버전에 달렸다. Dockerfile golang 이미지 버전을 썼다
  - main은 go.mod에 toolchain go1.27.1이 있지만 공식 이미지가 GOTOOLCHAIN=local이라 go1.27.0으로 봤다 (docker-library/golang 236db66 템플릿 247줄. 그 이미지 자체는 안 열어 봄)
  - v0.5.0은 go1.19.4로 패키지를 못 읽어 go1.20.4 소스로 경로를 찾았다
- DB는 2026-10-30 스냅숏이다. 그 뒤 공개된 취약점은 없다
- govulncheck는 빌드되는 모듈이 필요하다. 테스트 코드는 안 본다 (-test 끔)
- symbol은 '정적 경로가 있다'일 뿐 공격 입력이 닿는지는 모른다. 서비스를 띄워 보지 않았다
- 서비스 4개만. 이미지(바이너리) 모드는 안 돌렸다
- `-mode query`는 버전으로 거르지 않은 목록을 돌려준다 (x/vuln v1.9.0 client.go byModule). 그래서 go.mod 기준선은 DB 파일에서 직접 계산했다. 예: v0.5.0 checkoutservice query 145, 거른 뒤 131

## 결정
| # | 결정 | 고른 기본값 | 다른 안 | 근거 |
|---|---|---|---|---|
| 1 | govulncheck 바이너리 | v1.9.0을 go1.27.0으로 빌드한 것 하나 | 공용 go1.26.10 빌드 + main 제외 / 커밋별 바이너리 | go1.26 빌드는 main의 go1.27 파일을 타입 검사 못 함. v0.5.0 frontend는 두 빌드 결과가 같았다 (`govulncheck_build_check.json`) |
| 2 | 표준 라이브러리 판정 | 로더 = Dockerfile 버전(안 되면 가장 가까운 go1.20.4), GOVERSION = Dockerfile 버전 | 로컬 go1.24.7 + GOVERSION (앞 워커 안) / GOVERSION 없음 | 민감도 표처럼 로더도 결과를 바꾼다 |
| 3 | 수준 집계 | (ID, 모듈)마다 최고 수준, 개수는 서로 다른 ID | finding 줄 수 | 사람이 다루는 단위가 ID다 |
| 4 | 플랫폼 | 거르지 않고 세되 열과 개수로 따로 표시 | linux/amd64 아닌 ID 제외 | 도구 출력 그대로가 재현 가능하다 |
| 5 | osv-scanner 호출 분석 | run.sh에서 뺐다 | 두 번째 도구로 비교 | 명세 밖, 시간 |
| 6 | golang/vulndb 대조 | 깊이 1 전체 받기 (3초) | 생략 | blob:none 희소 받기는 느리다 |
| 7 | 결과 크기 | JSON은 gzip, 텍스트 출력은 임시 폴더에만 | 텍스트도 커밋 | 서비스당 텍스트 약 150KB, JSON과 중복 |

## 데이터 출처
| 데이터 | 출처 | 라이선스 | 받은 시각 (UTC) |
|---|---|---|---|
| OSV Go all.zip | osv-vulnerabilities.storage.googleapis.com/Go/all.zip | CC-BY 4.0 (Go 취약점 DB 항목) | 2026-11-02T08:41:01Z (리드, manifest_m2) |
| golang/vulndb data/osv | github.com/golang/vulndb 8f7e390 (git fetch --depth 1) | CC-BY 4.0 (data/LICENSE), BSD (코드) | 2026-11-02T08:50:53Z (reachcache/vulndb FETCH_HEAD, 매니페스트 없음) |
| docker-library golang 템플릿 | raw.githubusercontent.com/docker-library/golang/236db66.../Dockerfile-linux.template | BSD 스타일 (LICENSE: Copyright 2014 Docker, Inc.) | 2026-11-02T08:58:08Z (data/manifest_reach.json) |
| Go 툴체인 go1.19.4, go1.20.4, go1.27.0 | proxy.golang.org golang.org/toolchain | BSD | 2026-11-02 08:48쯤 (모듈 캐시) |
| Online Boutique 소스 | 리드가 만든 워크트리 3c0d659, d54af3d, c7cb6d5 | Apache-2.0 | 리드 기록 참고 |

- 라이선스 칸은 각 저장소 LICENSE 파일 첫 줄을 본 것이다. OSV zip의 Go 항목은 Go 취약점 DB(CC-BY 4.0)에서 온다고 이해한다

## 겪은 오류와 처리
| # | 오류 | 처리 |
|---|---|---|
| 1 | /home/user/tools, /home/user/work/ob_* 없음 ($HOME이 /root) | 리드가 심볼릭 링크를 만들었다 |
| 2 | go1.26.10 빌드 govulncheck + main: `x/net@v0.58.0/http2/server_wrap.go: file requires newer Go version go1.27 (application built with go1.26)`, `internal/poll/splice_linux.go:237:21: unknown field rfd` | go1.27.0으로 다시 빌드 (결정 1). run.sh가 매번 재현해 `govulncheck_build_check.json`에 남긴다 |
| 3 | GOTOOLCHAIN=go1.19.4: `unsupported version of go: ... -pgo` | 로더 go1.20.4 + GOVERSION=go1.19.4 |
| 4 | builddb go.mod가 go 1.26.0 요구. 원래 run.sh의 GOTOOLCHAIN=local이면 실패 | go1.27.0으로 실행 |
| 5 | h2probe 모듈 이름 labreach/h2probe가 go1.19, 1.20에서 `import "": import of unknown directory` | 점 있는 이름 lab.local/h2probe로 |
| 6 | 기본 DB: `Get "https://vuln.go.dev/index/modules.json.gz": Forbidden` | 기대한 실패. 기록만 |
| 7 | x/vuln query 모드가 거르지 않은 목록을 돌려줌 | 기준선은 직접 계산 |
| 8 | 앞 워커 run.sh: analyze.py 없음, blob:none 희소 받기, osv-scanner 단계 미검증 | analyze.py 새로 씀, 깊이 1 받기, osv-scanner 단계 뺌 |

## 파일
- 코드: `reach/run.sh`(다시 씀), `reach/analyze.py`(새로), `reach/h2probe/`(새로), `reach/compare_db_sources.py`(별칭 접두어, 철회 수 추가), `reach/builddb/`(검토만. x/vuln v1.9.0 색인 규칙과 같다), `reach/testmod/`(그대로)
- 결과 (`results/reach/`)
  - `levels.csv`: 1,181줄. (커밋, 서비스, OSV ID, 모듈)마다 수준, 별칭, 버전, 예시 경로, 플랫폼
  - `summary.json`, `cve_2023_44487.md`, `goversion_sensitivity.csv`, `db_check_compare.csv`, `controls_check.json`
  - `<커밋>/<서비스>.json.gz` (govulncheck 원본), `.openvex.json`, `.status.json`, `.download.log`
  - `controls/` (대조 원본, 오프라인 증명, 기본 DB 시도), `h2probe.jsonl`, `frontend_h2c_check.txt`
  - `db_provenance.json`, `db_source_compare.json`, `dockerfile_go_versions.csv`, `docker_image_gotoolchain.txt`, `tool_versions.txt`, `govulncheck_build_check.json`

## 만든 방식
- 구현과 실행은 AI 코딩 에이전트(Claude Code 클라우드 세션). 앞 세션 워커 코드를 검토하고 고쳤다
- 설계 결정은 위 '결정' 표
