"""정답 사례에 정책별로 돌려 통과율, 시도, 토큰, 비용, 지연을 잰다. 규칙: agent/CASES_RULE.md

사용 (lotte/innovate 에서)
  .venv/bin/python -m agent.run_eval --policies min_target,min_target_retry,min_all,latest   # LLM 없음
  .venv/bin/python -m agent.run_eval --policies agent --auto-approve                           # LAB_MODEL (기본 Sonnet 5.5)
  .venv/bin/python -m agent.run_eval --policies agent --cases C07 --model anthropic:claude-opus-5-5 --auto-approve
출력: results/agent/runs/<run_id>/{results.jsonl, summary.csv, meta.json}, 트레이스 results/agent/runs/<run_id>/trace.jsonl
--auto-approve 를 주면 사람 승인 단계를 코드가 자동 승인하고 그 건수를 기록한다 (일괄 평가용). 안 주면 CLI에서 y/n.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import subprocess
import time
from datetime import datetime, timezone

os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

from agent import godata as g  # noqa: E402
from agent import judge as J  # noqa: E402
from agent import model_config as mc  # noqa: E402

CASES = g.INNO / "results" / "agent" / "cases.json"
RUNS = g.INNO / "results" / "agent" / "runs"
BASELINES = ("min_target", "min_target_retry", "min_all", "latest")


def baseline_plans(policy: str, c: dict) -> list[str]:
    cd = c["candidates"]
    if policy == "min_target":
        return [cd["min_target_fix"]]
    if policy == "min_target_retry":
        return cd["allowed_versions"][:3]
    if policy == "min_all":
        return [cd["min_all_fix"]] if cd["min_all_fix"] else []
    if policy == "latest":
        return [cd["latest_stable"]]
    raise ValueError(policy)


def run_baseline(policy: str, c: dict) -> dict:
    t0 = time.time()
    attempts, final = [], None
    for k, ver in enumerate(baseline_plans(policy, c), 1):
        v = J.judge(c["service"], c["module"], c["target_group"]["ids"], [(c["module"], ver)])
        attempts.append({"attempt": k, "plan": {"module": c["module"], "target_version": ver, "also_bump": []},
                         "outcome": "pass" if v["pass"] else "judge_fail", "verdict_key": v["key"],
                         "fail_reason": v["fail_reason"], "judge_wall_s": v["wall_s"], "judge_cached": v["cached"]})
        if v["pass"]:
            final = v
            break
    return {"case_id": c["case_id"], "policy": policy, "model": "none", "attempts": attempts,
            "applicable": bool(attempts), "final_pass": final is not None,
            "first_attempt_pass": bool(attempts) and attempts[0]["outcome"] == "pass", "n_attempts": len(attempts),
            "guardrail_trips": 0, "out_of_list_proposals": 0, "final_verdict_key": final["key"] if final else None,
            "llm_calls": 0, "input_tokens": 0, "output_tokens": 0, "cached_tokens": 0, "cost_usd": 0.0,
            "llm_s": 0.0, "judge_s": round(sum(a["judge_wall_s"] for a in attempts if not a["judge_cached"]), 1),
            "wall_s": round(time.time() - t0, 1), "approval": None}


def verdict_by_key(k: str | None) -> dict | None:
    if not k:
        return None
    p = J.CACHE / f"{k}.json"
    return json.loads(p.read_text()) if p.exists() else None


def summarize(rows: list[dict]) -> list[dict]:
    out = []
    keyf = lambda r: (r["policy"], r["model"])
    for pol in sorted({keyf(r) for r in rows}):
        rs = [r for r in rows if keyf(r) == pol and r.get("applicable", True)]
        n = len(rs)
        fv = [verdict_by_key(r["final_verdict_key"]) for r in rs]
        out.append({
            "policy": pol[0], "model": pol[1], "cases": n,
            "final_pass": sum(r["final_pass"] for r in rs),
            "first_attempt_pass": sum(r["first_attempt_pass"] for r in rs),
            "mean_attempts": round(sum(r["n_attempts"] for r in rs) / n, 2) if n else None,
            "guardrail_trips": sum(r["guardrail_trips"] for r in rs),
            "out_of_list_proposals": sum(r["out_of_list_proposals"] for r in rs),
            "pass_keep_go_1_19": sum(1 for v in fv if v and not v["raises_go_directive"]),
            "pass_module_clean": sum(1 for v in fv if v and v["remaining_groups_in_module"] == 0),
            "tokens_per_case": round(sum(r["input_tokens"] + r["output_tokens"] for r in rs) / n) if n else None,
            "cost_usd_total": round(sum(r["cost_usd"] or 0 for r in rs), 4),
            "cost_usd_per_case": round(sum(r["cost_usd"] or 0 for r in rs) / n, 4) if n else None,
            "llm_s_per_case": round(sum(r["llm_s"] for r in rs) / n, 1) if n else None,
            "judge_s_per_case": round(sum(r["judge_s"] for r in rs) / n, 1) if n else None,
            "auto_approved": sum(1 for r in rs if r.get("approval") and r["approval"]["auto"] and r["approval"]["approved"]),
        })
    return out


async def main_async(a) -> None:
    data = json.loads(CASES.read_text())
    cases = [c for c in data["cases"] if not a.cases or c["case_id"] in a.cases.split(",")]
    run_id = a.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    d = RUNS / run_id
    d.mkdir(parents=True, exist_ok=True)
    pols = a.policies.split(",")
    meta = {"run_id": run_id, "started_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "repo_commit": subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=g.INNO).stdout.strip(),
            "policies": pols, "cases": [c["case_id"] for c in cases], "auto_approve": a.auto_approve,
            "osv_snapshot": data["meta"]["osv_snapshot"], "availability": mc.availability()}
    rows = []
    out = d / "results.jsonl"
    spec = None
    if "agent" in pols:
        from agent.remediation import run_case
        from agent.tracing_local import use_local_tracing
        spec = mc.parse(a.model)
        meta["model"] = spec.label
        use_local_tracing(d / "trace.jsonl")
    (d / "meta.json").write_text(json.dumps(meta, indent=1, ensure_ascii=False) + "\n")
    for c in cases:
        for pol in pols:
            if pol in BASELINES:
                r = await asyncio.to_thread(run_baseline, pol, c)
            elif pol == "agent":
                try:
                    r = await run_case(c, spec, d / "patches", a.auto_approve)
                except Exception as e:  # 공급자 오류 등은 그 사례 '오류'로 남기고 계속
                    msg = str(e).replace(os.environ.get("LAB_ANTHROPIC_API_KEY", "@@none@@"), "[KEY]")[:500]
                    r = {"case_id": c["case_id"], "policy": "agent", "model": spec.label, "error": f"{type(e).__name__}: {msg}",
                         "attempts": [], "final_pass": False, "first_attempt_pass": False, "n_attempts": 0, "guardrail_trips": 0,
                         "out_of_list_proposals": 0, "final_verdict_key": None, "llm_calls": 0, "input_tokens": 0,
                         "output_tokens": 0, "cached_tokens": 0, "cost_usd": 0.0, "llm_s": 0.0, "judge_s": 0.0,
                         "wall_s": 0.0, "approval": None}
            else:
                raise SystemExit(f"unknown policy {pol}")
            rows.append(r)
            with open(out, "a") as f:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
            print(f"{c['case_id']} {pol:17s} pass={r['final_pass']} attempts={r['n_attempts']} "
                  f"tok={r['input_tokens'] + r['output_tokens']} cost={r['cost_usd']} wall={r['wall_s']}s"
                  + (f" ERROR {r['error']}" if r.get("error") else ""), flush=True)
    summ = summarize(rows)
    with open(d / "summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summ[0]))
        w.writeheader()
        w.writerows(summ)
    meta["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    (d / "meta.json").write_text(json.dumps(meta, indent=1, ensure_ascii=False) + "\n")
    for s in summ:
        print(s)
    print("->", d)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--policies", default="min_target,min_target_retry,min_all,latest")
    ap.add_argument("--cases", default="")
    ap.add_argument("--model", default=None, help="LAB_MODEL 형식. 없으면 환경 변수 LAB_MODEL, 그다음 기본값")
    ap.add_argument("--auto-approve", action="store_true")
    ap.add_argument("--run-id", default=None)
    asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    main()
