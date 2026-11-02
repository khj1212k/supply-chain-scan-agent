"""기계 판정 (코드). 조치안을 서비스 사본에 적용하고 빌드, 테스트, 재스캔으로 통과 여부를 정한다.

규칙: agent/CASES_RULE.md '후보와 판정'. LLM은 이 결과를 고칠 수 없다.
같은 (서비스, 변경 목록)은 같은 결과라 캐시한다 (/home/user/work/agenttmp/judge_cache).
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from agent import godata as g

WORKTREE = Path("/home/user/work/ob_v0.5.0")
SERVICES = ["frontend", "checkoutservice", "productcatalogservice", "shippingservice"]
TMP = Path("/home/user/work/agenttmp")
CACHE = TMP / "judge_cache"
OSV_SCANNER = "/home/user/tools/bin/osv-scanner"
OSV_DB = "/home/user/work/osvdb"
BASE_GO = "1.19"
HIGH = 7.0  # 새 권고 중 max_severity 7.0 이상만 막는다. 등급 없는 권고와 7.0 미만은 통과한다


def _env() -> dict:
    e = {k: v for k, v in os.environ.items() if not k.startswith(("LAB_", "ANTHROPIC", "OPENAI"))}
    e.update({"GOPATH": "/home/user/tools/gopath", "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": "auto",
              "GOMAXPROCS": "2", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": OSV_DB,
              "PATH": "/usr/local/go/bin:" + e.get("PATH", "")})
    return e


def _run(cmd: list[str], cwd: Path, timeout: int = 600) -> dict:
    t0 = time.time()
    try:
        p = subprocess.run(["nice", "-n", "10"] + cmd, cwd=cwd, env=_env(), capture_output=True, text=True, timeout=timeout)
        rc, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as ex:
        rc, out, err = -9, ex.stdout or "", (ex.stderr or "") + f"\nTIMEOUT {timeout}s"
        out = out if isinstance(out, str) else out.decode("utf8", "ignore")
        err = err if isinstance(err, str) else err.decode("utf8", "ignore")
    tail = "\n".join((out + "\n" + err).strip().splitlines()[-40:])[-3000:]
    return {"cmd": " ".join(cmd), "rc": rc, "s": round(time.time() - t0, 1), "tail": tail, "stdout": out}


def scan_gomod(service_dir: Path, tag: str, reuse: bool = False) -> dict:
    """osv-scanner 오프라인으로 go.mod 하나를 스캔. DB를 못 읽으면 예외 (빈 결과를 '취약점 없음'으로 읽지 않는다)."""
    out = TMP / "scans" / f"{tag}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    if not (reuse and out.exists()):
        p = subprocess.run([OSV_SCANNER, "scan", "source", "--offline-vulnerabilities", "-L", str(Path(service_dir) / "go.mod"),
                            "--format", "json"], env=_env(), capture_output=True, text=True, timeout=600)
        if re.search(r"could not load db|no offline version", p.stderr):
            raise RuntimeError(f"osv-scanner DB 오류: {p.stderr[-500:]}")
        if p.returncode not in (0, 1):
            raise RuntimeError(f"osv-scanner rc={p.returncode}: {p.stderr[-500:]}")
        out.write_text(p.stdout)
    d = json.loads(out.read_text())
    pk = {}
    for r in d.get("results", []):
        for p in r.get("packages", []):
            grps = []
            for gr in p.get("groups", []):
                sev = gr.get("max_severity")
                grps.append({"ids": sorted(gr["ids"]), "max_severity": float(sev) if sev else None})
            pk[p["package"]["name"]] = {"version": p["package"]["version"], "groups": grps}
    return {"packages": pk, "path": str(out)}


def _requires(gomod: str) -> dict:
    return dict(re.findall(r"^\s*(?:require\s+)?([\w.\-/]+\.[\w.\-/]+)\s+(v\S+)", gomod, re.M))


def _go_line(gomod: str) -> str | None:
    m = re.search(r"^go\s+(\S+)", gomod, re.M)
    return m[1] if m else None


def plan_key(service: str, bumps: list[tuple[str, str]]) -> str:
    s = service + "|" + "|".join(f"{m}@{v}" for m, v in sorted(bumps))
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def judge(service: str, module: str, target_ids: list[str], bumps: list[tuple[str, str]]) -> dict:
    """bumps: [(모듈, 버전)]. 첫 항목이 대상 모듈."""
    key = plan_key(service, bumps)
    cp = CACHE / f"{key}.json"
    if cp.exists():
        v = json.loads(cp.read_text())
        v["cached"] = True
        return v
    src = WORKTREE / "src" / service
    work = TMP / "judge" / service / key
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(src, work)
    gomod0 = (work / "go.mod").read_text()
    pre = scan_gomod(src, tag=f"pre_{service}", reuse=True)
    t0 = time.time()
    steps, reason = [], None
    s = _run(["go", "get"] + [f"{m}@{v}" for m, v in bumps], work)
    steps.append(("go_get", s))
    if s["rc"] != 0:
        reason = "go_get"
    if not reason:
        s = _run(["go", "mod", "tidy"], work)
        steps.append(("tidy", s))
        reason = "tidy" if s["rc"] != 0 else None
    if not reason:
        s = _run(["go", "build", "./..."], work)
        steps.append(("build", s))
        reason = "build" if s["rc"] != 0 else None
    test_note = None
    if not reason:
        s = _run(["go", "test", "-count=1", "./..."], work, timeout=300)
        steps.append(("test", s))
        if s["rc"] != 0:
            reason = "test"
        test_note = "no test files only" if s["rc"] == 0 and "ok " not in s["stdout"] else None
    gv = _run(["go", "version"], work)
    gomod1 = (work / "go.mod").read_text()
    post, target_gone, new_high, remaining = None, None, [], None
    if not reason:
        post = scan_gomod(work, tag=f"post_{service}_{key}")
        after_ids = {i for gr in post["packages"].get(module, {}).get("groups", []) for i in gr["ids"]}
        target_gone = not (set(target_ids) & after_ids)
        pre_ids = {i for p in pre["packages"].values() for gr in p["groups"] for i in gr["ids"]}
        for name, p in post["packages"].items():
            if name == "stdlib":
                continue
            for gr in p["groups"]:
                if not (set(gr["ids"]) & pre_ids) and (gr["max_severity"] or 0) >= HIGH:
                    new_high.append({"module": name, "ids": gr["ids"], "max_severity": gr["max_severity"]})
        remaining = len(post["packages"].get(module, {}).get("groups", []))
        if not target_gone:
            reason = "target_remains"
        elif new_high:
            reason = "new_high"
    r0, r1 = _requires(gomod0), _requires(gomod1)
    changed = sorted(m for m in set(r0) | set(r1) if r0.get(m) != r1.get(m))
    go_after = _go_line(gomod1)
    verdict = {
        "service": service, "module": module, "bumps": bumps, "key": key, "cached": False,
        "pass": reason is None, "fail_reason": reason, "test_note": test_note,
        "target_gone": target_gone, "new_high": new_high,
        "remaining_groups_in_module": remaining,
        "groups_in_module_before": len(pre["packages"].get(module, {}).get("groups", [])),
        "go_directive_before": _go_line(gomod0), "go_directive_after": go_after,
        "raises_go_directive": g.go_ver_key(go_after) > g.go_ver_key(BASE_GO),
        "toolchain": gv["tail"].strip(),
        "resolved_version": r1.get(module), "modules_changed": len(changed),
        "steps": [{"step": n, "rc": s["rc"], "s": s["s"], "tail": s["tail"] if s["rc"] != 0 else ""} for n, s in steps],
        "wall_s": round(time.time() - t0, 1),
        "gomod_diff": "".join(difflib.unified_diff(gomod0.splitlines(True), gomod1.splitlines(True), "a/go.mod", "b/go.mod")),
        "post_scan": post["path"] if post else None,
    }
    CACHE.mkdir(parents=True, exist_ok=True)
    cp.write_text(json.dumps(verdict, indent=1, ensure_ascii=False))
    return verdict


def failure_log(v: dict) -> str:
    """다음 시도에 붙이는 판정 로그 (사람이 읽는 형태, 3000자 이내)."""
    if v["pass"]:
        return "PASS"
    lines = [f"FAIL reason={v['fail_reason']} bumps={v['bumps']}"]
    for s in v["steps"]:
        if s["rc"] != 0:
            lines.append(f"[{s['step']} rc={s['rc']}]\n{s['tail']}")
    if v["fail_reason"] == "target_remains":
        lines.append("target advisory group still present after rescan")
    if v["new_high"]:
        lines.append(f"new HIGH/CRITICAL advisories: {v['new_high'][:5]}")
    return "\n".join(lines)[-3000:]
