"""NOTES.md 표를 결과 파일에서 다시 만든다 (LLM 없음).

사용: .venv/bin/python -m vexpilot.report   (lotte/innovate 에서)
읽는 것: results/vexpilot/results.jsonl (1회차), results/vexpilot/repeats/run2, run3 (같은 프롬프트 반복)
"""
from __future__ import annotations

import json

from vexpilot import cases as C
from vexpilot import run as RUN

BASE = C.INNO / "results" / "vexpilot"
RUNS = {"run1": BASE, "run2": BASE / "repeats" / "run2", "run3": BASE / "repeats" / "run3"}
SHORT = {"exploitable": "E", "not_affected": "NA", "in_triage": "IT"}


def load(d) -> list[dict]:
    p = d / "results.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()] if p.exists() else []


def main() -> None:
    allr = {k: load(v) for k, v in RUNS.items()}
    r1 = allr["run1"]
    print("## 1회차 사례별")
    print("| # | task_id | 라벨 (사유) | 검사 전 | 검사 후 | 검사 | 형식 재요청 | 도구 호출 | LLM 호출 | 입력 토큰 (캐시 읽음) | 출력 토큰 | 비용 | 시간 |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for i, r in enumerate(r1, 1):
        print(f"| {i} | {r['task_id']} | {r['label']} ({r['label_category']}) | {r['pre_status']} / {r['pre_justification']} "
              f"| {r['post_status']} | {'통과' if r['check_passed'] else '강등'} | {'예' if r['schema_retry'] else '아니오'} "
              f"| {r['tool_calls']} | {r['llm_calls']} | {r['input_tokens']:,} ({r['cached_input_tokens']:,}) "
              f"| {r['output_tokens']:,} | ${r['cost_usd']:.4f} | {r['wall_s']}초 |")
    print()
    print("## 요약 (회차별, 검사 후 기준. 기준선은 항상 exploitable)")
    print("| 회차 | 정책 | exploitable 찾음 (/3) | 놓침 | 잘못 지움 | in_triage | 맞힌 not_affected (/5) | 그중 사유 일치 | exploitable 오경보 (/5) | 검사 강등 | 입력 토큰 | 캐시 읽음 | 출력 토큰 | 비용 | 시간 합 |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for k, rows in allr.items():
        if not rows:
            print(f"| {k} | 미실행 | | | | | | | | | | | | | |")
            continue
        b, pre, post = RUN.summarize(rows)
        down = sum(not r["check_passed"] and r["pre_status"] != "in_triage" for r in rows)
        for name, s in (("기준선", b), ("검사 전", pre), ("검사 후", post)):
            if name == "기준선" and k != "run1":
                continue
            extra = (f"{down} | {s['input_tokens']:,} | {s['cached_input_tokens']:,} | {s['output_tokens']:,} | "
                     f"${s['cost_usd']:.4f} | {s['wall_s']}초") if name != "기준선" else "- | 0 | 0 | 0 | $0 | 0초"
            print(f"| {k} | {name} | {s['exploitable_found']} | {s['misses']} | {s['wrongly_cleared']} | {s['in_triage']} "
                  f"| {s['correct_not_affected']} | {s['correct_not_affected_same_justification']} "
                  f"| {s['false_alarm_exploitable']} | {extra} |")
    print()
    print("## 사례별 3회 판정 (검사 후. E=exploitable, NA=not_affected, IT=in_triage)")
    print("| task_id | 라벨 | run1 | run2 | run3 | 3회 같음 | 도구 호출 (run1/2/3) | 비용 (run1/2/3) |")
    print("|---|---|---|---|---|---|---|---|")
    byid = {k: {r["task_id"]: r for r in rows} for k, rows in allr.items()}
    for r in r1:
        t = r["task_id"]
        ps = [byid[k].get(t, {}).get("post_status") for k in RUNS]
        tc = "/".join(str(byid[k].get(t, {}).get("tool_calls", "-")) for k in RUNS)
        co = "/".join(f"${byid[k][t]['cost_usd']:.4f}" if t in byid[k] else "-" for k in RUNS)
        print(f"| {t} | {r['label']} | " + " | ".join(SHORT.get(p, '-') for p in ps)
              + f" | {'예' if len(set(ps)) == 1 else '아니오'} | {tc} | {co} |")
    print()
    tot_cost = sum(r["cost_usd"] or 0 for rows in allr.values() for r in rows)
    tot_nc = sum(r["cost_usd_if_no_cache"] or 0 for rows in allr.values() for r in rows)
    tot_mc = sum(r["cost_usd_model_config"] or 0 for rows in allr.values() for r in rows)
    tot_in = sum(r["input_tokens"] for rows in allr.values() for r in rows)
    tot_ca = sum(r["cached_input_tokens"] for rows in allr.values() for r in rows)
    tot_out = sum(r["output_tokens"] for rows in allr.values() for r in rows)
    retries = sum(r["schema_retry"] for rows in allr.values() for r in rows)
    outcomes = {}
    for rows in allr.values():
        for r in rows:
            outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
    print("## 3회 합계")
    print(f"- 과제 실행 {sum(len(v) for v in allr.values())}회, 결과 종류 {outcomes}, 형식 재요청 {retries}회")
    print(f"- 입력 토큰 {tot_in:,} (캐시 읽음 {tot_ca:,}), 출력 토큰 {tot_out:,}")
    print(f"- 비용 (쓰기 할증 포함 추정) ${tot_cost:.4f}, model_config.cost_usd 만 ${tot_mc:.4f}, 캐시 없다고 친 값 ${tot_nc:.4f}")


if __name__ == "__main__":
    main()
