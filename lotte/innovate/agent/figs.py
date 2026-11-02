"""그림: 구조도(figs/arch.png), 조치안 결과(figs/agent_results.png).

사용: .venv/bin/python -m agent.figs [--results <run_id,...>]
색: 참조 팔레트(dataviz 스킬) 1~2번 + 중립 회색. LLM 칸만 파랑, 사람 칸은 주황, 나머지 코드는 회색.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

INNO = Path(__file__).resolve().parents[1]
FIGS = INNO / "figs"
FONT = "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc"
font_manager.fontManager.addfont(FONT)
plt.rcParams["font.family"] = font_manager.FontProperties(fname=FONT).get_name()
plt.rcParams["axes.unicode_minus"] = False

INK, INK2, MUTED, GRID, SURF = "#0b0b0b", "#52514e", "#8a8984", "#e4e3df", "#fcfcfb"
BLUE, ORANGE = "#2a78d6", "#eb6834"
FILL = {"code": "#efeeea", "llm": "#d6e6f8", "human": "#fbe0d5", "plan": SURF}
EDGE = {"code": MUTED, "llm": BLUE, "human": ORANGE, "plan": MUTED}


def box(ax, x, y, w, h, text, kind="code", dashed=False, size=8.5):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08",
                                fc=FILL[kind], ec=EDGE[kind], lw=1.4, ls="--" if dashed else "-"))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=size, color=INK, linespacing=1.3)


def arrow(ax, x0, y0, x1, y1, text=None, color=INK2, rad=0.0):
    ax.add_patch(FancyArrowPatch((x0, y0), (x1, y1), arrowstyle="-|>", mutation_scale=11, lw=1.1, color=color,
                                 connectionstyle=f"arc3,rad={rad}"))
    if text:
        ax.text((x0 + x1) / 2, (y0 + y1) / 2 + 0.12, text, ha="center", va="bottom", fontsize=7.5, color=INK2)


def arch() -> Path:
    fig, ax = plt.subplots(figsize=(12.5, 6.6), dpi=160, facecolor=SURF)
    ax.set_facecolor(SURF)
    ax.set_xlim(0, 12.5)
    ax.set_ylim(0, 6.6)
    ax.axis("off")
    ax.text(0.15, 6.35, "SW 공급망 스캐닝 프로토타입 구조 (Online Boutique v0.5.0, 오프라인 DB)", fontsize=12, color=INK, weight="bold")
    ax.text(0.15, 6.05, "파랑 = LLM(Claude Sonnet 5.5, 설정 한 줄로 교체)   주황 = 사람   회색 = 코드   점선 = 설계만, 이번에 안 돌림",
            fontsize=8.5, color=INK2)
    # 1행: 스캔 깔때기 (M2, 도달성)
    y1, h = 4.55, 0.95
    xs = [0.15, 2.15, 4.15, 6.15, 8.15, 10.35]
    labels = ["SBOM\nSyft 1.55", "취약점 스캔\nOSV-Scanner 2.7\n오프라인 DB", "정규화\npurl, CVE 별칭 조인",
              "신호 조인\nKEV, EPSS, CVSS, SSVC", "기한과 확인 큐\nBOD 26-04 표 16칸", "Go 도달성\ngovulncheck 1.9\n로컬 DB"]
    for i, (x, t) in enumerate(zip(xs, labels)):
        box(ax, x, y1, 1.8 if i < 5 else 2.0, h, t)
        if i:
            arrow(ax, xs[i - 1] + 1.8, y1 + h / 2, x, y1 + h / 2)
    # 영향도 판정 (설계만)
    box(ax, 8.15, 3.05, 4.2, 0.9, "영향도 판정 에이전트 + 근거 검사 + not_affected 사람 승인\n(기획안 5절 7~9번. 이번 실습에서 미구현)", "plan", dashed=True, size=8)
    arrow(ax, 9.05, y1, 9.05, 3.95, color=MUTED)
    # 2행: 조치안 루프 (agent/)
    y2 = 1.55
    box(ax, 0.15, y2, 1.8, h, "후보 생성 (코드)\nproxy.golang.org\n+ OSV fixed")
    box(ax, 2.35, y2, 2.0, h, "조치안 에이전트\n읽기 도구 6개\nsubmit_plan", "llm")
    box(ax, 4.75, y2, 1.7, h, "출력 가드레일\n후보 밖 버전 차단")
    box(ax, 6.85, y2, 2.0, h, "기계 판정\ngo get, tidy, build,\ntest, 재스캔")
    box(ax, 9.25, y2, 1.4, h, "PR 작성\nopen_fix_pr", "llm")
    box(ax, 11.0, y2, 1.35, h, "사람 승인\nneeds_approval\n-> 로컬 패치", "human")
    arrow(ax, 1.95, y2 + h / 2, 2.35, y2 + h / 2)
    arrow(ax, 4.35, y2 + h / 2, 4.75, y2 + h / 2)
    arrow(ax, 6.45, y2 + h / 2, 6.85, y2 + h / 2)
    arrow(ax, 8.85, y2 + h / 2, 9.25, y2 + h / 2, "통과")
    arrow(ax, 10.65, y2 + h / 2, 11.0, y2 + h / 2)
    arrow(ax, 7.85, y2, 3.35, y2, rad=-0.3)
    ax.text(5.6, y2 - 0.95, "실패: 판정 로그를 붙여 재생성 (최대 3회)", ha="center", va="center", fontsize=7.5, color=INK2)
    arrow(ax, 5.6, y2 + h, 3.6, y2 + h, rad=0.5)
    ax.text(4.6, y2 + h + 0.6, "트립: 실패 1회로 세고 사유를 붙임", ha="center", va="bottom", fontsize=7.5, color=INK2)
    arrow(ax, 9.05, y1, 1.05, y2 + h, color=MUTED, rad=0.12)
    ax.text(0.2, 3.35, "신호 큐의 (서비스, 모듈, 권고 묶음)\n-> 조치 사례", fontsize=7.5, color=INK2)
    ax.text(0.15, 0.1, "트레이스는 OpenAI로 내보내지 않고 로컬 JSONL에만 저장(set_trace_processors). "
            "LLM에 KEV, EPSS 값은 주지 않는다. 키는 LAB_ANTHROPIC_API_KEY 로만 받고 출력하지 않는다.", fontsize=7.5, color=INK2)
    FIGS.mkdir(parents=True, exist_ok=True)
    out = FIGS / "arch.png"
    fig.savefig(out, facecolor=SURF, bbox_inches="tight")
    plt.close(fig)
    return out


def results(run_ids: list[str]) -> Path:
    rows = []
    for rid in run_ids:
        with open(INNO / "results" / "agent" / "runs" / rid / "summary.csv") as f:
            rows += list(csv.DictReader(f))
    order = ["min_target", "min_target_retry", "min_all", "latest", "llm_single", "agent"]
    rows.sort(key=lambda r: (order.index(r["policy"]) if r["policy"] in order else 99, r["model"]))
    names = {"min_target": "최소 수정\n(1회)", "min_target_retry": "최소 수정\n+다음 후보(3회)", "min_all": "전부 고치는\n최소(1회)",
             "latest": "최신\n(1회)"}
    names["llm_single"] = "LLM 1회 호출\n(고정 흐름)"
    names["agent"] = "에이전트\n(도구 탐색)"
    labels = [names.get(r["policy"], r["policy"]) + ("\n" + r["model"].split(":")[-1].replace("claude-", "") if r["model"] != "none" else "\n(LLM 없음)") for r in rows]
    n = [int(r["cases"]) for r in rows]
    first = [int(r["first_attempt_pass"]) for r in rows]
    final = [int(r["final_pass"]) for r in rows]
    keep = [int(r["pass_keep_go_1_19"]) for r in rows]
    fig, ax = plt.subplots(figsize=(11.5, 5.0), dpi=160, facecolor=SURF)
    ax.set_facecolor(SURF)
    xs = range(len(rows))
    w = 0.26
    b1 = ax.bar([x - w for x in xs], first, w - 0.03, color="#9cc3ee", label="첫 시도 통과")
    b2 = ax.bar(list(xs), final, w - 0.03, color=BLUE, label="최종 통과 (최대 3회)")
    b3 = ax.bar([x + w for x in xs], keep, w - 0.03, color=ORANGE, label="최종 통과 + go 1.19 유지")
    for bars in (b1, b2, b3):
        for b in bars:
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.12, f"{int(b.get_height())}", ha="center",
                    va="bottom", fontsize=8, color=INK)
    ax.set_xticks(list(xs))
    ax.set_xticklabels([f"{lb}\nn={k}" for lb, k in zip(labels, n)], fontsize=8.5, color=INK)
    ax.set_ylim(0, max(n) + 1.5)
    ax.set_ylabel("사례 수 (기계 판정 통과)", color=INK2, fontsize=9)
    ax.set_title("조치안 정책별 기계 판정 통과 (Online Boutique v0.5.0 Go, 정답 사례 10건)", fontsize=11, color=INK, loc="left")
    ax.grid(True, axis="y", color=GRID, lw=0.8)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=INK2)
    ax.legend(frameon=False, fontsize=8.5, loc="upper left", ncol=3)
    costs = {r["policy"]: float(r["cost_usd_per_case"]) for r in rows if r["model"] != "none"}
    note = ("건당 LLM 비용(Sonnet 5.5 공식 단가): " + ", ".join(f"{names.get(k, k).splitlines()[0]} \\${v:.3f}" for k, v in costs.items())
            + ".  모든 정책이 실패한 4건은 otel 계열(C03, C04, C09, C10): 시도한 조합은 앱 코드 수정이 필요하거나 새 HIGH 권고를 끌어왔다.")
    fig.text(0.01, -0.07, note, fontsize=7.8, color=INK2, ha="left", va="top")
    out = FIGS / "agent_results.png"
    fig.savefig(out, facecolor=SURF, bbox_inches="tight")
    plt.close(fig)
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="")
    a = ap.parse_args()
    print(arch())
    if a.results:
        print(results(a.results.split(",")))
