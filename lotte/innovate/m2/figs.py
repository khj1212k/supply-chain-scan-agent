"""M2 깔때기 그림: v0.5.0 과 main 을 나란히, 가로 막대. 값은 results/m2/funnel.csv 그대로.

사용: .venv/bin/python m2/figs.py
출력: figs/m2_funnel.png
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager  # noqa: E402

INNO = Path(__file__).resolve().parents[1]
RES = INNO / "results" / "m2"
FONT = "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc"
SURFACE, INK, INK2, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#8a8984", "#e6e5e1"
BAR, BAR_LAST = "#2a78d6", "#1b4f8f"  # 한 색상 계열. 마지막(신호 큐)만 같은 계열의 진한 단계


def main() -> None:
    font_manager.fontManager.addfont(FONT)
    plt.rcParams["font.family"] = font_manager.FontProperties(fname=FONT).get_name()
    rows = list(csv.DictReader(open(RES / "funnel.csv")))
    summ = json.loads((RES / "summary.json").read_text())
    rows = [r for r in rows if not r["stage"].startswith("참고")]  # 참고 행은 그림 아래 문장으로
    labels = [r["stage"] for r in rows]
    panels = [("v0.5.0", "v0.5.0 (3c0d659, 2022-12)"), ("main", "main (c7cb6d5, 2026-10)")]
    num = [[float(r[p]) if r[p].replace(".", "", 1).isdigit() else None for r in rows] for p, _ in panels]
    xmax = max(v for col in num for v in col if v is not None)

    fig, axes = plt.subplots(1, 2, figsize=(12, 6.0), sharey=True, facecolor=SURFACE)
    y = list(range(len(labels)))[::-1]
    for ax, (p, title), vals in zip(axes, panels, num):
        ax.set_facecolor(SURFACE)
        for yi, v, r in zip(y, vals, rows):
            if v is None:
                if r[p] == "not yet":
                    txt = "아직 없음 (reach 결과 대기)"
                elif "/" in r[p]:
                    a_, b_ = [x.strip() for x in r[p].split("/")]
                    txt = f"호출 경로 있음(symbol) {a_}행 / 큐 Go {b_}행 (govulncheck, reach)"
                else:
                    txt = r[p]
                ax.text(xmax * 0.01, yi, txt, va="center", ha="left", fontsize=9, color=INK2)
                continue
            last = r["stage"] == "신호 큐"
            ax.barh(yi, v, height=0.62, color=BAR_LAST if last else BAR, edgecolor=SURFACE, linewidth=2)
            ax.text(v + xmax * 0.012, yi, f"{int(v):,}", va="center", ha="left", fontsize=10, color=INK)
        ax.set_title(title, loc="left", fontsize=12, color=INK, pad=8)
        ax.set_xlim(0, xmax * 1.15)
        ax.set_ylim(-0.8, len(labels) - 0.4)
        ax.xaxis.grid(True, color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.spines["bottom"].set_color(GRID)
        ax.tick_params(axis="both", colors=INK2, labelsize=9, length=0)
        q = summ[p]
        go = q["queue_by_eco"].get("Go", 0)
        ca = q["osv_call_analysis"]
        ax.text(0, -0.13, f"신호 큐 {q['queue']}행 중 Go {go}행. 큐 밖 {q['out_of_queue']}행, 표본 {q['sample']}행",
                fontsize=9, color=INK2, transform=ax.transAxes)
        ax.text(0, -0.19, f"참고: osv-scanner 내장 Go 호출 분석에서 큐 Go {ca['go_queue_rows']}행 중 called {ca['go_queue_called']}행",
                fontsize=9, color=INK2, transform=ax.transAxes)
    axes[0].set_yticks(y)
    axes[0].set_yticklabels(labels, fontsize=10, color=INK)
    fig.suptitle("Online Boutique 스캔 깔때기 (OSV-Scanner 2.7.0 오프라인. Go 표준 라이브러리 제외, Java(adservice, Maven) 미스캔)",
                 x=0.01, ha="left", fontsize=13, color=INK)
    fig.text(0.01, 0.01,
             "단위가 섞여 있다: 구성요소, 권고, 보고, 신호 큐는 행(서비스 x 패키지 버전 x 권고 또는 CVE), 고유 CVE, EPSS, KEV는 CVE 개수. 신호 큐는 프런트엔드만 공개 가정.\n"
             "OSV DB 2026-11-02, EPSS 2026-11-01, KEV 2026.10.30. 재현: bash m2/run.sh",
             fontsize=8, color=MUTED)
    fig.tight_layout(rect=(0, 0.08, 1, 0.94))
    out = INNO / "figs" / "m2_funnel.png"
    fig.savefig(out, dpi=150, facecolor=SURFACE)
    print("->", out)


if __name__ == "__main__":
    main()
