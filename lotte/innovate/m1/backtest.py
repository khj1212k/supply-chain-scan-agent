"""M1. KEV 시점 분리 백테스트 (LLM 없음).

질문: T 시점에 알 수 있던 점수(EPSS 그날 파일, CVSS)로 순위를 매기면
      T 이후 약 90일에 KEV 에 새로 오른 CVE 를 얼마나 앞에 두었나.

규칙 (결과 보기 전에 고정. DECISIONS.md D4)
- 창: 기획안 3-1 의 세 개. T <= dateAdded <= end
- 측정 양성(정답): 창 안에 KEV 에 추가됐고 NVD 공개일 < T
- 모집단 U_T: T 날짜 EPSS 파일에 있고, T 이전에 KEV 에 오르지 않은 CVE
- 임계값 방식: EPSS >= 0.5, 0.1, 0.01 / CVSS >= 9, 7 (CVSS 는 v3 최대값, 오늘 값)
- 같은 작업량 방식: 상위 k 건 (k = 100, 1000, U_T 안 CVSS>=9 건수)
  CVSS 동점과 EPSS 동점은 시드 고정 난수로 깨고 100회 평균. 무작위는 기댓값 k/|U_T|
- 95% 구간: Wilson
출력: results/m1/*.csv, results/m1/summary.json
"""
from __future__ import annotations

import gzip
import json
import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
OUT = ROOT / "results" / "m1"

WINDOWS = [("2025-06-01", "2025-08-29"), ("2025-12-01", "2026-02-28"), ("2026-03-31", "2026-06-29")]
EPSS_TH = [0.5, 0.1, 0.01]
CVSS_TH = [9.0, 7.0]
SEEDS = 100


def wilson(h: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = h / n
    c = (p + z * z / (2 * n)) / (1 + z * z / n)
    hw = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (100 * (c - hw), 100 * (c + hw))


def load_kev() -> pd.DataFrame:
    d = json.loads((RAW / "kev" / "known_exploited_vulnerabilities.json").read_text())
    k = pd.DataFrame(d["vulnerabilities"])[["cveID", "dateAdded", "vendorProject", "product"]]
    return k.rename(columns={"cveID": "cve"})


def load_epss(date: str) -> tuple[pd.DataFrame, str]:
    p = RAW / "epss" / f"epss_scores-{date}.csv.gz"
    with gzip.open(p, "rt") as f:
        head = f.readline().strip()
    e = pd.read_csv(p, comment="#")
    return e[["cve", "epss"]], head


def load_nvd() -> pd.DataFrame:
    n = pd.read_csv(RAW / "derived" / "nvd_table.csv.gz", dtype={"cve": str})
    n["pub_date"] = n["published"].str[:10]
    return n


def topk_coverage(score: np.ndarray, pos: np.ndarray, ks: list[int], seeds: int) -> dict[int, float]:
    """score 내림차순 상위 k 에 든 양성 수의 평균. 동점은 난수로 깬다. NaN 은 맨 뒤."""
    s = np.where(np.isnan(score), -np.inf, score)
    res = {k: 0.0 for k in ks}
    for seed in range(seeds):
        rng = np.random.default_rng(seed)
        tie = rng.random(len(s))
        order = np.lexsort((tie, -s))  # 마지막 키가 1순위
        cum = np.cumsum(pos[order])
        for k in ks:
            res[k] += cum[min(k, len(s)) - 1]
    return {k: v / seeds for k, v in res.items()}


def run() -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    kev = load_kev()
    nvd = load_nvd().set_index("cve")
    summary, thr_rows, k_rows, gold_rows = {}, [], [], []
    for T, end in WINDOWS:
        e, head = load_epss(T)
        added = kev[(kev.dateAdded >= T) & (kev.dateAdded <= end)].copy()
        prior_kev = set(kev[kev.dateAdded < T].cve)
        added["pub"] = added.cve.map(nvd["pub_date"])
        gold = added[added.pub < T].copy()
        U = e[~e.cve.isin(prior_kev)].copy()
        U["cvss"] = U.cve.map(nvd["cvss3_max"]).astype(float)
        U["pos"] = U.cve.isin(set(gold.cve)).astype(int)
        gold["epss_T"] = gold.cve.map(dict(zip(e.cve, e.epss)))
        gold["cvss3_max"] = gold.cve.map(nvd["cvss3_max"]).astype(float)
        gold["in_U"] = gold.cve.isin(set(U.cve))
        n_gold = len(gold)
        n_pos_U = int(U.pos.sum())
        info = {
            "T": T, "end": end, "epss_header": head, "epss_rows": int(len(e)), "U_T": int(len(U)),
            "kev_added": int(len(added)), "gold_published_before_T": n_gold, "gold_in_U": n_pos_U,
            "added_published_on_or_after_T": int((added.pub >= T).sum()),
            "added_missing_in_nvd": int(added.pub.isna().sum()),
            "U_missing_cvss3": int(U.cvss.isna().sum()),
            "gold_missing_cvss3": int(gold.cvss3_max.isna().sum()),
        }
        info["not_rankable_share_of_added_pct"] = round(100 * (len(added) - n_pos_U) / len(added), 1)
        # 임계값 방식
        for name, col, ths in (("EPSS", "epss", EPSS_TH), ("CVSS", "cvss", CVSS_TH)):
            for th in ths:
                shown = U[U[col] >= th]
                hits = int(shown.pos.sum())
                lo, hi = wilson(hits, n_gold)
                thr_rows.append({
                    "T": T, "rule": f"{name}>={th}", "hits": hits, "gold": n_gold,
                    "hit_pct_of_gold": round(100 * hits / n_gold, 1), "ci95_lo": round(lo, 1), "ci95_hi": round(hi, 1),
                    "hit_pct_of_added": round(100 * hits / len(added), 1),
                    "shown": int(len(shown)), "shown_pct_of_U": round(100 * len(shown) / len(U), 2),
                    "efficiency_pct": round(100 * hits / len(shown), 3) if len(shown) else float("nan"),
                })
        # 같은 작업량 방식
        n9 = int((U.cvss >= 9).sum())
        ks = sorted({100, 1000, n9, 5000, 10000, 30000})
        pos = U.pos.to_numpy()
        cov_e = topk_coverage(U.epss.to_numpy(dtype=float), pos, ks, SEEDS)
        cov_c = topk_coverage(U.cvss.to_numpy(dtype=float), pos, ks, SEEDS)
        for k in ks:
            k_rows.append({
                "T": T, "k": k, "k_is_cvss9_count": k == n9, "gold": n_gold,
                "random_hits_expected": round(n_pos_U * k / len(U), 3),
                "cvss_hits_mean": round(cov_c[k], 2), "epss_hits_mean": round(cov_e[k], 2),
                "random_cov_pct": round(100 * n_pos_U * k / len(U) / n_gold, 2),
                "cvss_cov_pct": round(100 * cov_c[k] / n_gold, 1), "epss_cov_pct": round(100 * cov_e[k] / n_gold, 1),
            })
        info["cvss9_count_in_U"] = n9
        # 곡선용: k 를 로그 간격으로
        grid = sorted(set(int(x) for x in np.unique(np.logspace(1, math.log10(len(U)), 60).astype(int))))
        ce = topk_coverage(U.epss.to_numpy(dtype=float), pos, grid, 20)
        cc = topk_coverage(U.cvss.to_numpy(dtype=float), pos, grid, 20)
        pd.DataFrame({"k": grid, "epss_hits": [ce[k] for k in grid], "cvss_hits": [cc[k] for k in grid],
                      "random_hits": [n_pos_U * k / len(U) for k in grid], "gold": n_gold, "U": len(U)}
                     ).to_csv(OUT / f"curve_{T}.csv", index=False)
        for _, r in gold.sort_values("cve").iterrows():
            gold_rows.append({"T": T, "cve": r.cve, "vendor": r.vendorProject, "product": r["product"],
                              "dateAdded": r.dateAdded, "published": r.pub,
                              "epss_T": r.epss_T, "cvss3_max": r.cvss3_max, "in_U": bool(r.in_U)})
        summary[T] = info
    pd.DataFrame(thr_rows).to_csv(OUT / "threshold_table.csv", index=False)
    pd.DataFrame(k_rows).to_csv(OUT / "topk_table.csv", index=False)
    pd.DataFrame(gold_rows).to_csv(OUT / "gold_list.csv", index=False)
    (OUT / "summary.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False) + "\n")
    return summary


if __name__ == "__main__":
    s = run()
    print(json.dumps(s, indent=1, ensure_ascii=False))
    print(pd.read_csv(OUT / "threshold_table.csv").to_string(index=False))
    print(pd.read_csv(OUT / "topk_table.csv").to_string(index=False))
    sys.exit(0)
