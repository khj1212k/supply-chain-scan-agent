"""M1 데이터 받기: KEV(CISA 공식 GitHub 미러), EPSS 일별 파일(제3자 미러).

환경 네트워크 정책이 www.cisa.gov, api.first.org, epss.empiricalsecurity.com 을 막아서
아래 미러를 커밋 고정으로 쓴다 (BLOCKED.md, DATA.md).

NVD 는 fkie-cad/nvd-json-data-feeds 를 git 으로 따로 받는다 (Makefile 의 nvd 대상).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.fetch import fetch  # noqa: E402

KEV_COMMIT = "7ccba8e1223ccec82d12c7736bf3fae11e5bee86"  # cisagov/kev-data, 2026-10-30 push
EPSS_COMMIT = "9b88cf4309f762ccfa830069501ef588a9cfe3cc"  # RogoLabs/EPSS-History, 2026-11-01 push

# 기획안 3-1 의 세 시점 + 현재값(M2 조인용)
EPSS_DATES = ["2025-06-01", "2025-12-01", "2026-03-31", "2026-11-01"]


def kev() -> Path:
    url = f"https://raw.githubusercontent.com/cisagov/kev-data/{KEV_COMMIT}/known_exploited_vulnerabilities.json"
    return fetch(url, "kev/known_exploited_vulnerabilities.json")


def epss(date: str) -> Path:
    y, m, _ = date.split("-")
    url = (f"https://raw.githubusercontent.com/RogoLabs/EPSS-History/{EPSS_COMMIT}/"
           f"data/{y}/{m}/epss_scores-{date}.csv.gz")
    return fetch(url, f"epss/epss_scores-{date}.csv.gz")


if __name__ == "__main__":
    print(kev())
    for d in EPSS_DATES:
        print(epss(d))
