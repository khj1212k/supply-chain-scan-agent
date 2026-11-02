"""정답 사례 고르기 (agent/CASES_RULE.md 를 그대로 코드로). 출력: results/agent/cases.json

사용: .venv/bin/python -m agent.cases --scan-dir /home/user/work/agenttmp
  (scan_<서비스>.json 은 judge.scan_gomod 와 같은 osv-scanner 오프라인 스캔 결과)
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent import candidates, godata as g
from agent.judge import SERVICES, WORKTREE, scan_gomod

OUT = g.INNO / "results" / "agent" / "cases.json"
MAX_CASES = 10


def group_signals(ids: list[str]) -> dict:
    recs, _ = g.osv_index()
    cves = set(g.cves_of(ids))
    rel = {a for i in ids for a in recs[i].get("related", []) if a.startswith("CVE-")}
    kev = sorted((cves | rel) & g.kev())
    ep = max([g.epss().get(c, 0.0) for c in cves | rel] or [0.0])
    return {"cves": sorted(cves), "related_cves": sorted(rel - cves), "kev": kev, "epss_max": ep}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rescan", action="store_true", help="osv-scanner 를 다시 돌린다")
    a = ap.parse_args()
    pool = []
    for svc in SERVICES:
        scan = scan_gomod(WORKTREE / "src" / svc, tag=f"cases_{svc}", reuse=not a.rescan)
        for mod, info in sorted(scan["packages"].items()):
            if mod in ("stdlib", "toolchain"):
                continue
            ranked = []
            for grp in info["groups"]:
                s = group_signals(grp["ids"])
                ranked.append((bool(s["kev"]), s["epss_max"], grp["max_severity"] or 0.0, grp["ids"][0], grp, s))
            ranked.sort(key=lambda x: (-x[0], -x[1], -x[2], x[3]))
            if not ranked:
                continue
            kevf, ep, sev, _, grp, sig = ranked[0]
            pool.append({"service": svc, "module": mod, "version": info["version"], "target_group": grp,
                         "signals": sig, "sort": [kevf, ep, sev, grp["ids"][0]],
                         "n_groups_in_module": len(info["groups"])})
    pool.sort(key=lambda p: (-p["sort"][0], -p["sort"][1], -p["sort"][2], p["sort"][3]))
    picked, used_mod, per_svc = [], set(), {s: 0 for s in SERVICES}
    i = 0
    while i < len(pool) and len(picked) < MAX_CASES:
        head = pool[i]
        if head["module"] in used_mod:
            i += 1
            continue
        # 같은 정렬 값(같은 모듈 같은 묶음 값)인 후보 중 서비스 고르기 규칙 적용
        ties = [p for p in pool[i:] if p["module"] == head["module"] and p["sort"] == head["sort"]]
        ties.sort(key=lambda p: (per_svc[p["service"]], p["service"] != "frontend", p["service"]))
        p = ties[0]
        c = candidates.build(p["module"], p["version"], "1.19", p["target_group"]["ids"])
        if not c["candidates"]:
            p["skipped"] = "대상 묶음을 고치는 같은 메이저 안정 버전 없음"
            i += 1
            used_mod.add(p["module"])
            continue
        used_mod.add(p["module"])
        per_svc[p["service"]] += 1
        p["case_id"] = f"C{len(picked) + 1:02d}"
        p["candidates"] = c
        picked.append(p)
        i += 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    meta = {"rule": "agent/CASES_RULE.md", "worktree_commit": "3c0d6597809d1f40dccd24b757b7ca67d40cadf8",
            "osv_snapshot": g.osv_snapshot(), "pool_size": len(pool), "n_cases": len(picked)}
    OUT.write_text(json.dumps({"meta": meta, "cases": picked}, indent=1, ensure_ascii=False) + "\n")
    for p in picked:
        c = p["candidates"]
        print(p["case_id"], p["service"], p["module"], p["version"], p["target_group"]["ids"], p["signals"]["kev"],
              round(p["signals"]["epss_max"], 4), "min_target", c["min_target_fix"], "min_all", c["min_all_fix"],
              "latest", c["latest_stable"], "shown", len(c["candidates"]))
    print("pool", len(pool), "cases", len(picked), "->", OUT)


if __name__ == "__main__":
    main()
