"""결과 묶기: 실행이 가리키는 판정 기록을 저장소로 복사하고, 사례별 비교표를 만든다.

사용: .venv/bin/python -m agent.export --runs baselines_v1,sonnet_v1,opus_escalation_v1
출력: results/agent/verdicts/<키>.json, results/agent/case_table.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil

from agent import godata as g
from agent import judge as J

RES = g.INNO / "results" / "agent"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", required=True)
    a = ap.parse_args()
    cases = {c["case_id"]: c for c in json.loads((RES / "cases.json").read_text())["cases"]}
    vd = RES / "verdicts"
    vd.mkdir(parents=True, exist_ok=True)
    table = []
    for rid in a.runs.split(","):
        for ln in open(RES / "runs" / rid / "results.jsonl"):
            r = json.loads(ln)
            c = cases[r["case_id"]]
            reasons, versions = [], []
            for at in r["attempts"]:
                k = at.get("verdict_key")
                if k and (J.CACHE / f"{k}.json").exists():
                    shutil.copy2(J.CACHE / f"{k}.json", vd / f"{k}.json")
                p = at.get("plan") or {}
                bumps = "+".join(f"{b['module'].split('/')[-1]}@{b['version']}" for b in p.get("also_bump", []))
                versions.append((p.get("target_version") or "-") + (f" (+{bumps})" if bumps else ""))
                reasons.append(at.get("fail_reason") or at.get("outcome"))
            fv = None
            if r.get("final_verdict_key"):
                fv = json.loads((vd / f"{r['final_verdict_key']}.json").read_text())
            table.append({
                "run": rid, "case_id": r["case_id"], "service": c["service"], "module": c["module"],
                "current": c["candidates"]["current"], "target_ids": " ".join(c["target_group"]["ids"]),
                "min_target_fix": c["candidates"]["min_target_fix"], "policy": r["policy"], "model": r["model"],
                "final_pass": r["final_pass"], "n_attempts": r["n_attempts"],
                "attempt_versions": " | ".join(versions), "attempt_outcomes": " | ".join(map(str, reasons)),
                "go_after": fv["go_directive_after"] if fv else "", "remaining_groups": fv["remaining_groups_in_module"] if fv else "",
                "tokens": r["input_tokens"] + r["output_tokens"], "cost_usd": r["cost_usd"],
            })
    with open(RES / "case_table.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(table[0]))
        w.writeheader()
        w.writerows(table)
    print(len(table), "rows ->", RES / "case_table.csv", "|", len(list(vd.glob("*.json"))), "verdicts")


if __name__ == "__main__":
    main()
