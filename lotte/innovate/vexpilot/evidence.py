"""제출 형식과 근거 검사 (코드). 기획안 5절 '근거 검사 (사유별)' 표를 작게. 규칙은 첫 LLM 실행 전에 고정했다.

검사 전(pre) = 모델이 낸 판정. 검사 후(post) = 아래 규칙으로 통과 못 하면 in_triage 로 강등.
- 상태와 사유 짝: exploitable<->vulnerable, not_affected<->code_not_present|code_not_reachable|requires_configuration|requires_environment
- exploitable: file_lines 1개 이상. 전부 스냅샷 안에 있는 파일, 존재하는 줄. 그중 1개 이상은 그 줄에 symbol 의 마지막 이름이 있어야 한다
- code_not_reachable: hit_count=0 이라고 적은 검색 기록 1개 이상. 0이라고 적은 기록은 전부 다시 돌려 0건이어야 한다
- code_not_present: 모듈 기록 또는 0건 검색 기록 1개 이상, 적은 기록은 전부 확인돼야 한다
    - 모듈 'absent': 루트 go.mod require 와 vendor/modules.txt 에 없음
    - 모듈 버전: 루트 go.mod(또는 vendor/modules.txt) 버전과 같고, 이 CVE 의 OSV 레코드 어느 것도 그 버전을 영향 범위로 보지 않음
- requires_configuration: configs 1개 이상, 전부 파일과 줄이 있고 그 줄에 value 문자열이 있음
- requires_environment: 이 실습에는 자산 표가 없어 검사할 수 없다 -> 항상 강등
- in_triage: 그대로
검사는 근거 형식까지만 본다. 그 줄이 주장을 뒷받침하는지는 사람 몫이다 (기획안 5절).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from agent import godata as g
from vexpilot import repo_tools as T

NOT_AFFECTED_JUST = ("code_not_present", "code_not_reachable", "requires_configuration", "requires_environment")


class FileLine(BaseModel):
    file: str = Field(description="path relative to the repository root, e.g. pkg/x/y.go or vendor/golang.org/x/crypto/ssh/client.go")
    line: int = Field(description="1-based line number")
    symbol: str = Field(description="vulnerable symbol or call that appears on that line, e.g. ssh.NewClientConn")


class SearchRecord(BaseModel):
    regex: str = Field(description="exact regex passed to search_code")
    path_glob: str = Field(description="exact path_glob passed to search_code")
    include_vendor: bool = Field(description="exact include_vendor passed to search_code")
    hit_count: int = Field(description="hit_count returned by search_code")


class ModuleRecord(BaseModel):
    module: str = Field(description="Go module path")
    version: str = Field(description="version in this repo's go.mod, or 'absent' if the module is not required")


class ConfigRecord(BaseModel):
    file: str
    line: int
    value: str = Field(description="text that appears on that line, e.g. a setting name and value")


class Verdict(BaseModel):
    status: Literal["exploitable", "not_affected", "in_triage"]
    justification: Literal["code_not_present", "code_not_reachable", "requires_configuration",
                           "requires_environment", "vulnerable", "none"]
    file_lines: list[FileLine] = Field(default_factory=list, description="evidence for exploitable")
    searches: list[SearchRecord] = Field(default_factory=list, description="absence evidence (hit_count 0) or context")
    modules: list[ModuleRecord] = Field(default_factory=list, description="evidence for code_not_present")
    configs: list[ConfigRecord] = Field(default_factory=list, description="evidence for requires_configuration")
    rationale_ko: str = Field(description="한국어 1~3문장")


def _last_name(symbol: str) -> str:
    s = re.sub(r"\(.*$", "", symbol.strip())
    return re.split(r"[.\s]", s)[-1] if s else ""


def _check_file_lines(root: Path, fls: list[FileLine]) -> dict:
    items = []
    for fl in fls:
        t = T.line_text(root, fl.file, fl.line)
        name = _last_name(fl.symbol)
        items.append({"file": fl.file, "line": fl.line, "symbol": fl.symbol, "line_exists": t is not None,
                      "symbol_on_line": bool(t is not None and name and name in t)})
    ok = bool(items) and all(i["line_exists"] for i in items) and any(i["symbol_on_line"] for i in items)
    return {"ok": ok, "items": items}


def _check_searches(root: Path, srs: list[SearchRecord], need_zero: bool = True) -> dict:
    items = []
    for s in srs:
        r = T.search(root, s.regex, s.path_glob, s.include_vendor)
        items.append({"regex": s.regex, "path_glob": s.path_glob, "include_vendor": s.include_vendor,
                      "claimed": s.hit_count, "rerun": r.get("hit_count"), "error": r.get("error")})
    zero = [i for i in items if i["claimed"] == 0]
    ok = bool(zero) and all(i["rerun"] == 0 and not i["error"] for i in zero)
    return {"ok": ok, "items": items, "n_zero_claims": len(zero)}


def _check_modules(root: Path, cve: str, mrs: list[ModuleRecord]) -> dict:
    eff = T.effective_versions(root)
    vend = T._vendor_modules(str(root))
    recs = T.records_for_cve(cve)
    items = []
    for m in mrs:
        cur = eff.get(m.module, {}).get("version") or vend.get(m.module)
        if m.version.strip().lower() == "absent":
            ok = cur is None
            items.append({"module": m.module, "claimed": "absent", "repo_version": cur, "ok": ok})
            continue
        same = cur is not None and g.norm(cur) == g.norm(m.version)
        affected = any(g._affects(r, m.module, cur) for r in recs) if cur else None
        items.append({"module": m.module, "claimed": m.version, "repo_version": cur, "version_matches": same,
                      "in_affected_range": affected, "ok": bool(same and affected is False)})
    return {"ok": bool(items) and all(i["ok"] for i in items), "items": items}


def _check_configs(root: Path, crs: list[ConfigRecord]) -> dict:
    items = []
    for c in crs:
        t = T.line_text(root, c.file, c.line)
        items.append({"file": c.file, "line": c.line, "value": c.value, "line_exists": t is not None,
                      "value_on_line": bool(t is not None and c.value.strip() and c.value.strip() in t)})
    return {"ok": bool(items) and all(i["line_exists"] and i["value_on_line"] for i in items), "items": items}


def check(v: Verdict, root: str | Path, cve: str) -> dict:
    """반환: {post_status, post_justification, passed, reason, details}"""
    root = Path(root)
    st, js = v.status, v.justification
    res = {"pre_status": st, "pre_justification": js}

    def out(passed: bool, reason: str, details: dict | None = None):
        return {**res, "post_status": st if passed else "in_triage", "post_justification": js if passed else "none",
                "passed": passed, "reason": reason, "details": details or {}}

    if st == "in_triage":
        return out(True, "in_triage stays in_triage")
    if st == "exploitable" and js != "vulnerable":
        return out(False, f"status/justification mismatch: exploitable with {js}")
    if st == "not_affected" and js not in NOT_AFFECTED_JUST:
        return out(False, f"status/justification mismatch: not_affected with {js}")
    if st == "exploitable":
        d = _check_file_lines(root, v.file_lines)
        return out(d["ok"], "file:line exists and symbol on line" if d["ok"] else "file:line evidence missing or unverifiable", d)
    if js == "code_not_reachable":
        d = _check_searches(root, v.searches)
        return out(d["ok"], "absence search reran with 0 hits" if d["ok"] else "no absence search record, or rerun found hits", d)
    if js == "code_not_present":
        dm = _check_modules(root, cve, v.modules) if v.modules else {"ok": None, "items": []}
        ds = _check_searches(root, [s for s in v.searches if s.hit_count == 0]) if any(s.hit_count == 0 for s in v.searches) else {"ok": None, "items": []}
        checks = [x["ok"] for x in (dm, ds) if x["ok"] is not None]
        ok = bool(checks) and all(checks)
        return out(ok, "module/absence records verified" if ok else "module or absence records missing or not verified",
                   {"modules": dm, "searches": ds})
    if js == "requires_configuration":
        d = _check_configs(root, v.configs)
        return out(d["ok"], "config file:line has value" if d["ok"] else "config evidence missing or unverifiable", d)
    if js == "requires_environment":
        return out(False, "requires_environment cannot be checked: no asset table in this harness")
    return out(False, "unknown case")
