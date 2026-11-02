"""M1 그림: 같은 작업량(상위 k건)에서 찾은 비율 곡선.

입력: results/m1/curve_<T>.csv (backtest.py 출력)
출력: figs/m1_coverage_curve.png
"""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from matplotlib import font_manager  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
IN = ROOT / "results" / "m1"
OUT = ROOT / "figs"

FONT = "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc"
TS = ["2025-06-01", "2025-12-01", "2026-03-31"]
# 참조 팔레트 1~3번(전체 쌍 검증된 범위) + 무작위는 중립 회색
C = {"epss": "#2a78d6", "cvss": "#eb6834", "random": "#8a8984"}
INK, INK2, GRID, SURF = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"


def main() -> None:
    font_manager.fontManager.addfont(FONT)
    plt.rcParams["font.family"] = font_manager.FontProperties(fname=FONT).get_name()
    OUT.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(8.0, 5.0), dpi=160, facecolor=SURF)
    ax.set_facecolor(SURF)
    grid = np.unique(np.logspace(1, 5.3, 80).astype(int))
    means = {}
    for key in ("epss", "cvss", "random"):
        ys = []
        for T in TS:
            d = pd.read_csv(IN / f"curve_{T}.csv")
            y = 100 * np.interp(grid, d.k, d[f"{key}_hits"]) / d.gold.iloc[0]
            ys.append(y)
            ax.plot(grid, y, color=C[key], lw=1, alpha=0.25)
        means[key] = np.mean(ys, axis=0)
        ax.plot(grid, means[key], color=C[key], lw=2)
    labels = {"epss": "EPSS 순", "cvss": "CVSS 순", "random": "무작위"}
    for key, xk in (("epss", 2500), ("cvss", 6000), ("random", 40000)):
        yk = float(np.interp(xk, grid, means[key]))
        ax.annotate(labels[key], (xk, yk), xytext=(6, 6 if key != "random" else -14),
                    textcoords="offset points", color=INK, fontsize=10)
    t = pd.read_csv(IN / "topk_table.csv")
    k1000 = t[t.k == 1000]
    ax.axvline(1000, color=INK2, lw=1, ls=":")
    ax.text(1000, 96, f" k=1,000\n EPSS {k1000.epss_cov_pct.mean():.1f}%, CVSS {k1000.cvss_cov_pct.mean():.1f}% (3시점 평균)",
            color=INK2, fontsize=8.5, va="top")
    ax.set_xscale("log")
    ax.set_ylim(0, 100)
    ax.set_xlim(10, grid.max())
    ax.set_xlabel("작업량 k (점수 상위 k건만 본다, 로그 축)", color=INK2)
    ax.set_ylabel("T 뒤 90일 KEV 추가(T 이전 공개분) 중 찾은 비율 (%)", color=INK2)
    ax.set_title("KEV 시점 분리 백테스트: 같은 작업량에서 찾은 비율\n"
                 "T = 2025-06-01, 2025-12-01, 2026-03-31. 굵은 선 = 평균, 옅은 선 = 시점별",
                 color=INK, fontsize=11, loc="left")
    ax.grid(True, which="major", color=GRID, lw=0.8)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=INK2)
    fig.text(0.01, 0.01, "정답 29, 23, 31건. CVSS는 오늘 값(v3 최대), EPSS는 T 당일 파일(제3자 미러). "
             "같은 창 KEV 추가의 47~65%는 T에 순위 대상이 아니라 이 곡선 밖이다.",
             fontsize=7.5, color=INK2)
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    fig.savefig(OUT / "m1_coverage_curve.png", facecolor=SURF)
    print(OUT / "m1_coverage_curve.png")


if __name__ == "__main__":
    main()
