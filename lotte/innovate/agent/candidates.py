"""후보 버전은 코드가 만든다 (LLM이 버전을 지어낼 자리를 없앤다. 기획안 2-2). 규칙은 agent/CASES_RULE.md.

후보 = proxy.golang.org @v/list 의 안정 버전 중 현재보다 높고, 같은 메이저이고,
       오프라인 OSV Go 덤프 기준 대상 권고 묶음이 그 버전에 영향을 주지 않는 것.
보여 주는 후보는 가장 낮은 것부터 8개 + 가장 높은 것 2개. 가드레일은 보여 준 후보만 허용한다.
"""
from __future__ import annotations

from agent import godata as g

SHOW_LOW, SHOW_HIGH = 8, 2


def build(module: str, current: str, base_go: str, target_ids: list[str]) -> dict:
    current = g.norm(current)
    before = g.affecting(module, current)
    tgt = set(target_ids)
    allv = [v for v in g.module_versions(module)
            if g.is_stable(v) and g.major_of(v) == g.major_of(current) and g.cmp(v, current) > 0]
    rows = []
    for v in allv:
        rem = g.affecting(module, v)
        rows.append({"version": v, "fixes_target": not (tgt & set(rem)),
                     "remaining_groups": len(g.groups(rem)) if rem else 0})
    fix_t = [r for r in rows if r["fixes_target"]]
    full = [r for r in rows if r["remaining_groups"] == 0]
    shown = fix_t[:SHOW_LOW] + [r for r in fix_t[-SHOW_HIGH:] if r not in fix_t[:SHOW_LOW]]
    cands = []
    for r in shown:
        gd = g.go_directive(module, r["version"])
        cands.append({"version": r["version"], "go_directive": gd,
                      "raises_go_directive": g.go_ver_key(gd) > g.go_ver_key(base_go),
                      "remaining_advisory_groups_in_module": r["remaining_groups"]})
    return {
        "module": module,
        "current": current,
        "base_go_directive": base_go,
        "target_ids": sorted(tgt),
        "advisory_groups_now": g.groups(before),
        "n_newer_stable_same_major": len(allv),
        "n_fix_target": len(fix_t),
        "min_target_fix": fix_t[0]["version"] if fix_t else None,
        "min_all_fix": full[0]["version"] if full else None,
        "latest_stable": allv[-1] if allv else None,
        "candidates": cands,
        "allowed_versions": [c["version"] for c in cands],
    }
