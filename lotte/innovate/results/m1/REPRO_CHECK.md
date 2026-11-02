# M1 재현 확인 (새 컨테이너)

## 결론
- 새 컨테이너에서 처음부터 다시 돌린 결과가 커밋본과 **바이트까지 같다**
- 비교 대상: `results/m1/` 7개 파일, `figs/m1_coverage_curve.png` (git diff 없음)
- 입력 5개 파일(KEV 1, EPSS 4)의 sha256도 `data/manifest.json`과 같다

## 언제, 무엇으로
| 항목 | 값 |
|---|---|
| 실행 | 2026-11-02 08:39:19~08:43:44 UTC (265초) |
| 코드 커밋 | be31de6 (앞 세션 브랜치 끝) 위 그대로 |
| NVD 미러 | fkie-cad/nvd-json-data-feeds `1b66e035d87d0ddf83705ff01b4382889755f89a` (커밋 고정으로 받음) |
| KEV | cisagov/kev-data `7ccba8e` |
| EPSS | RogoLabs/EPSS-History `9b88cf4` |
| 파이썬 | uv venv 3.12, openai-agents[litellm] 0.24.0, pandas, numpy, matplotlib |

## 재현 명령
```bash
cd lotte/innovate
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python "openai-agents[litellm]==0.24.0" pandas numpy matplotlib pydantic pytest
.venv/bin/python m1/fetch_feeds.py
mkdir -p $HOME/work/nvd && cd $HOME/work/nvd && git init -q && git remote add origin https://github.com/fkie-cad/nvd-json-data-feeds.git \
  && git fetch -q --depth 1 origin 1b66e035d87d0ddf83705ff01b4382889755f89a && git checkout -q FETCH_HEAD && cd -
.venv/bin/python m1/nvd_table.py $HOME/work/nvd
.venv/bin/python m1/backtest.py
.venv/bin/python m1/figs.py
git status --short results/m1 figs   # 아무것도 안 나오면 같다
```

## 결과 파일 sha256 앞 16자 (재현 뒤)
| 파일 | sha256 |
|---|---|
| curve_2025-06-01.csv | 4c208ed4ba91865c |
| curve_2025-12-01.csv | 02392b75ddf2aea0 |
| curve_2026-03-31.csv | ed6ff1509e718812 |
| gold_list.csv | 0196fa1d7940ea95 |
| summary.json | d2fd3c11f7dcad6e |
| threshold_table.csv | 022f0cb210855cdb |
| topk_table.csv | 39d10173982793fd |
| figs/m1_coverage_curve.png | 9989c716b35ccda6 |

## 참고
- `fetch_feeds.py`가 `data/manifest.json`의 받은 시각을 새로 적는다. sha256이 같아서 원래 기록(08:10 UTC)으로 되돌렸다
- 그림 생성 때 글꼴 경고(`Failed to find font weight normal for WenQuanYi Zen Hei`)가 나오지만 PNG는 같다
