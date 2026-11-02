"""8건 실행과 요약. 규칙: vexpilot/CASES_RULE.md

사용 (lotte/innovate 에서)
  nice -n 10 .venv/bin/python -m vexpilot.run                     # 8건, LAB_MODEL(기본 anthropic:claude-sonnet-5-5)
  nice -n 10 .venv/bin/python -m vexpilot.run --summarize-only    # results.jsonl 로 summary.csv 만 다시
  nice -n 10 .venv/bin/python -m vexpilot.run --out results/vexpilot/repeats/run2   # 같은 프롬프트로 반복
출력: results/vexpilot/{results.jsonl, summary.csv, meta.json, trace.jsonl(.gz)}
- 이미 results.jsonl 에 있는 task_id 는 건너뛴다(중단 뒤 이어 돌리기). 처음부터 하려면 --fresh
- 누적 비용이 --budget(기본 $3.00, 이 세션의 앞선 호출분을 --spent-before 로 넣는다)을 넘으면 멈춘다
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import gzip
import json
import shutil
import subprocess
from datetime import datetime, timezone

import os

os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")  # 비용표를 네트워크에서 받지 않는다

from agent import godata as g  # noqa: E402
from agent import model_config as mc  # noqa: E402
from vexpilot import cases as C  # noqa: E402

OUT = C.INNO / "results" / "vexpilot"


def _git(*a) -> str:
    return subprocess.run(["git", *a], capture_output=True, text=True, cwd=C.INNO).stdout.strip()


def summarize(rows: list[dict]) -> list[dict]:
    """놓침 = exploitable 라벨인데 exploitable 로 안 낸 건(in_triage, not_affected, 미실행 포함).
    잘못 지움 = exploitable 라벨인데 not_affected. 기준선 '항상 exploitable'."""
    def block(name: str, preds: list[tuple[dict, str]]) -> dict:
        pos = [(r, p) for r, p in preds if r["label"] == "exploitable"]
        neg = [(r, p) for r, p in preds if r["label"] == "not_exploitable"]
        tp = sum(p == "exploitable" for _, p in pos)
        return {
            "policy": name, "cases": len(preds), "label_exploitable": len(pos), "label_not_exploitable": len(neg),
            "exploitable_found": tp, "misses": len(pos) - tp,
            "wrongly_cleared": sum(p == "not_affected" for _, p in pos),
            "in_triage": sum(p == "in_triage" for _, p in preds),
            "in_triage_on_exploitable": sum(p == "in_triage" for _, p in pos),
            "correct_not_affected": sum(p == "not_affected" for _, p in neg),
            "correct_not_affected_same_justification": sum(
                p == "not_affected" and r.get(("post" if "post" in name else "pre") + "_justification") == r["label_category"]
                for r, p in neg) if "agent" in name else 0,
            "false_alarm_exploitable": sum(p == "exploitable" for _, p in neg),
            "input_tokens": sum(r.get("input_tokens", 0) for r, _ in preds) if "agent" in name else 0,
            "cached_input_tokens": sum(r.get("cached_input_tokens", 0) for r, _ in preds) if "agent" in name else 0,
            "output_tokens": sum(r.get("output_tokens", 0) for r, _ in preds) if "agent" in name else 0,
            "cost_usd": round(sum(r.get("cost_usd") or 0 for r, _ in preds), 4) if "agent" in name else 0.0,
            "wall_s": round(sum(r.get("wall_s", 0) for r, _ in preds), 1) if "agent" in name else 0.0,
        }
    return [block("baseline_always_exploitable", [(r, "exploitable") for r in rows]),
            block("agent_pre_check", [(r, r["pre_status"]) for r in rows]),
            block("agent_post_check", [(r, r["post_status"]) for r in rows])]


def write_summary(rows: list[dict]) -> list[dict]:
    s = summarize(rows)
    with open(OUT / "summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(s[0]))
        w.writeheader()
        w.writerows(s)
    with open(OUT / "per_task.csv", "w", newline="") as f:
        cols = ["task_id", "label", "label_category", "pre_status", "pre_justification", "post_status",
                "post_justification", "check_passed", "check_reason", "outcome", "schema_retry", "llm_calls",
                "tool_calls", "input_tokens", "cached_input_tokens", "output_tokens", "cost_usd", "llm_s", "wall_s"]
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    return s


def load_rows() -> list[dict]:
    p = OUT / "results.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()] if p.exists() else []


async def main_async(a) -> None:
    global OUT
    if a.out:
        OUT = C.INNO / a.out
    OUT.mkdir(parents=True, exist_ok=True)
    if a.summarize_only:
        for s in write_summary(load_rows()):
            print(s)
        return
    if a.fresh:
        for n in ("results.jsonl", "summary.csv", "per_task.csv", "trace.jsonl", "trace.jsonl.gz", "meta.json"):
            (OUT / n).unlink(missing_ok=True)
    from vexpilot.vex_agent import run_task
    from agent.tracing_local import use_local_tracing

    cs = C.select()
    assert [c["task_id"] for c in cs] == C.EXPECTED, "사례 목록이 CASES_RULE.md 와 다르다"
    if a.cases:
        cs = [c for c in cs if c["task_id"] in a.cases.split(",")]
    done = {r["task_id"] for r in load_rows()}
    spec = mc.parse(a.model)
    meta_p = OUT / "meta.json"
    meta = json.loads(meta_p.read_text()) if meta_p.exists() else {"runs": []}
    run = {"started_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), "repo_head": _git("rev-parse", "HEAD"),
           "dirty_vexpilot": _git("status", "--porcelain", "vexpilot")[:2000], "model": spec.label,
           "budget_usd": a.budget, "spent_before_usd": a.spent_before, "max_turns": a.max_turns,
           "time_limit_s": a.time_limit, "prompt_cache": not a.no_cache, "labels_sha256": C.LABELS_SHA256,
           "osv_snapshot": g.osv_snapshot(), "availability": mc.availability(),
           "snapshots": {c["task_id"]: (open(f"{c['snapshot']}/.clone_ok").read().strip()
                                        if os.path.exists(f"{c['snapshot']}/.clone_ok") else None) for c in cs}}
    meta["runs"].append(run)
    meta_p.write_text(json.dumps(meta, indent=1, ensure_ascii=False) + "\n")
    use_local_tracing(OUT / "trace.jsonl")
    spent = a.spent_before + sum(r.get("cost_usd") or 0 for r in load_rows())
    for c in cs:
        if c["task_id"] in done:
            print("skip (done)", c["task_id"])
            continue
        if spent >= a.budget:
            print(f"STOP budget: spent {spent:.4f} >= {a.budget}")
            run["stopped_for_budget"] = True
            break
        r = await run_task(c, spec, spent_before=spent, budget=a.budget, cache=not a.no_cache,
                           max_turns=a.max_turns, time_limit_s=a.time_limit)
        r["run_started_utc"] = run["started_utc"]
        spent += r["cost_usd"] or 0
        with open(OUT / "results.jsonl", "a") as f:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"{c['task_id']} label={c['label']} pre={r['pre_status']}/{r['pre_justification']} "
              f"post={r['post_status']} check={r['check_passed']} outcome={r['outcome']} tools={r['tool_calls']} "
              f"tok={r['total_tokens']} cost={r['cost_usd']} wall={r['wall_s']}s cum=${spent:.4f}"
              + (f" ERROR {r['error']}" if r.get("error") else ""), flush=True)
        if r["outcome"] == "budget":
            run["stopped_for_budget"] = True
            break
    run["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    run["cumulative_cost_usd"] = round(spent, 4)
    meta_p.write_text(json.dumps(meta, indent=1, ensure_ascii=False) + "\n")
    for s in write_summary(load_rows()):
        print(s)
    tp = OUT / "trace.jsonl"
    if tp.exists() and tp.stat().st_size > 2 * 1024 * 1024:
        with open(tp, "rb") as fi, gzip.open(OUT / "trace.jsonl.gz", "ab") as fo:
            shutil.copyfileobj(fi, fo)
        tp.unlink()
        print("trace gzipped ->", OUT / "trace.jsonl.gz")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=None, help="LAB_MODEL 형식. 없으면 환경 변수 LAB_MODEL, 그다음 기본값")
    ap.add_argument("--cases", default="")
    ap.add_argument("--budget", type=float, default=3.0)
    ap.add_argument("--spent-before", type=float, default=0.0)
    ap.add_argument("--max-turns", type=int, default=20)
    ap.add_argument("--time-limit", type=float, default=600)
    ap.add_argument("--no-cache", action="store_true")
    ap.add_argument("--fresh", action="store_true")
    ap.add_argument("--summarize-only", action="store_true")
    ap.add_argument("--out", default="", help="출력 폴더 (lotte/innovate 기준). 기본 results/vexpilot. 반복 실행용")
    asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    main()
