"""읽기 전용 도구의 본체 (LLM 없음). 에이전트 도구와 근거 검사가 같은 함수를 쓴다.

- search(): ripgrep. 결과 순서 고정(--sort path), .gitignore 무시(--no-ignore), 숨김 폴더(.git 등) 제외
- read_file(): 스냅샷 밖 경로, .git 금지. 한 번에 최대 MAX_READ_LINES 줄
- advisory(): 오프라인 OSV Go 덤프에서 CVE 별칭으로 찾는다. 이 저장소 go.mod 버전이 영향 범위인지 코드가 계산
- go_mod_requires(): 루트 go.mod 의 require, replace, go, toolchain
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from functools import lru_cache
from pathlib import Path

from agent import godata as g  # 오프라인 OSV 색인과 semver (읽기만, 수정 안 함)

MAX_HITS = 30
MAX_HIT_CHARS = 180
MAX_READ_LINES = 120
MAX_LINE_CHARS = 240
MAX_OUT_CHARS = 7000
RG_TIMEOUT_S = 60


def _cap(s: str, n: int = MAX_OUT_CHARS) -> str:
    return s if len(s) <= n else s[:n] + f"\n...(truncated at {n} chars)"


# ---------------------------------------------------------------- search_code
def search(root: str | Path, regex: str, path_glob: str = "**/*.go", include_vendor: bool = False) -> dict:
    """ripgrep 정규식 검색. hit_count 는 일치하는 줄 수 (상한 없이 센다). 보여 주는 줄은 MAX_HITS 까지."""
    root = Path(root)
    path_glob = (path_glob or "**/*.go").strip()
    rec = {"regex": regex, "path_glob": path_glob, "include_vendor": bool(include_vendor)}
    if not regex:
        return {**rec, "error": "empty regex"}
    if path_glob.startswith("/") or ".." in path_glob.split("/"):
        return {**rec, "error": "path_glob must be relative to the repository root"}
    cmd = ["rg", "--no-config", "--no-ignore", "--sort", "path", "-n", "--no-heading", "--color", "never",
           "-g", path_glob]
    if not include_vendor:
        cmd += ["-g", "!vendor/**", "-g", "!**/vendor/**"]
    cmd += ["-e", regex, "."]
    try:
        p = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=RG_TIMEOUT_S, errors="replace")
    except subprocess.TimeoutExpired:
        return {**rec, "error": f"search timed out after {RG_TIMEOUT_S}s"}
    if p.returncode not in (0, 1):
        return {**rec, "error": "rg error: " + p.stderr.strip()[:300]}
    lines = [x[2:] if x.startswith("./") else x for x in p.stdout.splitlines() if x]
    files = {x.split(":", 1)[0] for x in lines}
    shown = [x[:MAX_HIT_CHARS] for x in lines[:MAX_HITS]]
    return {**rec, "hit_count": len(lines), "files_with_hits": len(files), "shown": shown,
            "truncated": len(lines) > MAX_HITS}


# ---------------------------------------------------------------- read_file
def resolve_inside(root: str | Path, rel: str) -> Path | None:
    root = Path(root).resolve()
    rel = (rel or "").strip()
    while rel.startswith("./"):
        rel = rel[2:]
    if rel.startswith("/") or rel == ".":
        rel = rel.lstrip("/") if rel != "." else ""
    p = (root / rel).resolve()
    try:
        parts = p.relative_to(root).parts
    except ValueError:
        return None
    if parts and parts[0] == ".git":
        return None
    return p


def read_file(root: str | Path, path: str, start: int = 1, end: int = 80) -> dict:
    p = resolve_inside(root, path)
    if p is None:
        return {"path": path, "error": "path is outside the repository snapshot (or inside .git)"}
    if p.is_dir():
        ents = sorted(os.listdir(p))
        ents = [e + ("/" if (p / e).is_dir() else "") for e in ents if e != ".git"]
        return {"path": path, "directory": True, "entries": ents[:150], "n_entries": len(ents)}
    if not p.is_file():
        return {"path": path, "error": "no such file"}
    text = p.read_text(errors="replace").splitlines()
    n = len(text)
    start = max(1, int(start or 1))
    end = int(end or start + 79)
    end = min(n, end, start + MAX_READ_LINES - 1)
    body = "\n".join(f"{i}: {text[i - 1][:MAX_LINE_CHARS]}" for i in range(start, end + 1))
    return {"path": path, "total_lines": n, "start": start, "end": end, "text": _cap(body)}


def line_text(root: str | Path, path: str, line: int) -> str | None:
    p = resolve_inside(root, path)
    if p is None or not p.is_file():
        return None
    text = p.read_text(errors="replace").splitlines()
    if not (1 <= int(line) <= len(text)):
        return None
    return text[int(line) - 1]


# ---------------------------------------------------------------- go.mod
_REQ_BLOCK = re.compile(r"^require\s*\((.*?)^\)", re.M | re.S)
_REQ_LINE = re.compile(r"^require\s+(\S+)\s+(\S+)(.*)$", re.M)
_REP_BLOCK = re.compile(r"^replace\s*\((.*?)^\)", re.M | re.S)
_REP_LINE = re.compile(r"^replace\s+(.+)$", re.M)


def parse_go_mod(text: str) -> dict:
    req = []
    for blk in _REQ_BLOCK.findall(text):
        for ln in blk.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("//"):
                continue
            parts = ln.split()
            if len(parts) >= 2:
                req.append({"module": parts[0], "version": parts[1], "indirect": "// indirect" in ln})
    for m in _REQ_LINE.finditer(text):
        req.append({"module": m[1], "version": m[2], "indirect": "// indirect" in m[3]})
    rep = []
    reps = [ln for blk in _REP_BLOCK.findall(text) for ln in blk.splitlines()] + _REP_LINE.findall(text)
    for ln in reps:
        ln = ln.split("//")[0].strip()
        if "=>" not in ln:
            continue
        a, b = [x.strip().split() for x in ln.split("=>", 1)]
        if a and b:
            rep.append({"from": a[0], "from_version": a[1] if len(a) > 1 else None, "to": b[0],
                        "to_version": b[1] if len(b) > 1 else None})
    mod = re.search(r"^module\s+(\S+)", text, re.M)
    go = re.search(r"^go\s+(\S+)", text, re.M)
    tc = re.search(r"^toolchain\s+(\S+)", text, re.M)
    return {"module": mod[1] if mod else None, "go": go[1] if go else None, "toolchain": tc[1] if tc else None,
            "require": req, "replace": rep}


def other_go_mods(root: str | Path) -> list[str]:
    root = Path(root)
    out = []
    for p in sorted(root.rglob("go.mod")):
        rel = p.relative_to(root)
        if rel.parts[0] in (".git", "vendor") or "vendor" in rel.parts or str(rel) == "go.mod":
            continue
        out.append(str(rel))
    return out


@lru_cache(maxsize=32)
def _vendor_modules(root: str) -> dict[str, str]:
    p = Path(root) / "vendor" / "modules.txt"
    out = {}
    if p.exists():
        for ln in p.read_text(errors="replace").splitlines():
            m = re.match(r"^# (\S+) (\S+)(?: => (\S+)(?: (\S+))?)?", ln)
            if m:
                out[m[1]] = m[4] or m[2]
    return out


def effective_versions(root: str | Path) -> dict[str, dict]:
    """루트 go.mod 기준 모듈 -> {version, indirect, replaced_by}. replace 가 버전을 바꾸면 그 버전."""
    root = Path(root)
    gm = root / "go.mod"
    if not gm.exists():
        return {}
    pm = parse_go_mod(gm.read_text(errors="replace"))
    out = {r["module"]: {"version": r["version"], "indirect": r["indirect"], "replaced_by": None} for r in pm["require"]}
    for rp in pm["replace"]:
        if rp["from"] in out and (rp["from_version"] in (None, out[rp["from"]]["version"])):
            out[rp["from"]]["replaced_by"] = f"{rp['to']} {rp['to_version'] or ''}".strip()
            if rp["to_version"] and not rp["to"].startswith((".", "/")):
                out[rp["from"]]["version"] = rp["to_version"]
    return out


def go_mod_requires(root: str | Path, filter: str = "") -> dict:
    root = Path(root)
    gm = root / "go.mod"
    if not gm.exists():
        return {"error": "no go.mod at repository root", "other_go_mod_files": other_go_mods(root)[:20]}
    pm = parse_go_mod(gm.read_text(errors="replace"))
    eff = effective_versions(root)
    f = (filter or "").strip()
    rows = []
    for r in pm["require"]:
        if f and f not in r["module"]:
            continue
        if not f and r["indirect"]:
            continue
        e = eff.get(r["module"], {})
        s = f"{r['module']} {e.get('version', r['version'])}" + (" // indirect" if r["indirect"] else "")
        if e.get("replaced_by"):
            s += f" (replace => {e['replaced_by']})"
        rows.append(s)
    vend = _vendor_modules(str(root))
    out = {"module": pm["module"], "go_directive": pm["go"], "toolchain": pm["toolchain"],
           "n_require_direct": sum(not r["indirect"] for r in pm["require"]),
           "n_require_indirect": sum(r["indirect"] for r in pm["require"]),
           "shown": "direct requires only (pass filter to include indirect)" if not f else f"requires containing '{f}'",
           "requires": rows, "vendor_dir": (root / "vendor").is_dir(), "vendor_modules_txt_entries": len(vend),
           "other_go_mod_files": other_go_mods(root)[:20]}
    if f and vend:
        out["vendor_modules_txt"] = {k: v for k, v in vend.items() if f in k}
    return out


# ---------------------------------------------------------------- get_advisory
def records_for_cve(cve: str) -> list[dict]:
    recs, _ = g.osv_index()
    cve = cve.strip().upper()
    hit = [r for r in recs.values() if r["id"] == cve or cve in r.get("aliases", []) or cve in r.get("upstream", [])]
    return sorted(hit, key=lambda r: (not r["id"].startswith("GO-"), r["id"]))


def _module_versions_in_repo(root: Path, module: str) -> dict:
    eff = effective_versions(root)
    vend = _vendor_modules(str(root))
    return {"go_mod": eff.get(module, {}).get("version"), "indirect": eff.get(module, {}).get("indirect"),
            "vendor_modules_txt": vend.get(module)}


def advisory(root: str | Path, cve_id: str) -> dict:
    root = Path(root)
    hits = records_for_cve(cve_id)
    if not hits:
        return {"cve_id": cve_id, "found": False,
                "note": "No Go OSV record with this CVE id or alias in the offline OSV Go dump."}
    out = []
    for r in hits:
        aff = []
        for a in r.get("affected", []):
            pkg = a.get("package", {})
            if pkg.get("ecosystem") != "Go":
                continue
            mod = pkg.get("name")
            ev = [e for rg in a.get("ranges", []) for e in rg.get("events", [])]
            imports = (a.get("ecosystem_specific") or {}).get("imports") or []
            item = {"module": mod, "events": ev}
            if imports:
                item["packages"] = [{"path": i.get("path"), "symbols": (i.get("symbols") or [])[:25]} for i in imports][:8]
            if mod == "stdlib" or mod == "toolchain":
                gm = parse_go_mod((root / "go.mod").read_text(errors="replace")) if (root / "go.mod").exists() else {}
                item["this_repo"] = {"go_directive": gm.get("go"), "toolchain": gm.get("toolchain"),
                                     "note": "stdlib version is the Go toolchain used to build, not pinned by go.mod"}
            else:
                v = _module_versions_in_repo(root, mod)
                if v["go_mod"] or v["vendor_modules_txt"]:
                    ver = v["go_mod"] or v["vendor_modules_txt"]
                    v["version_in_affected_range"] = g._affects(r, mod, ver)  # 코드가 OSV 구간으로 계산
                else:
                    v["note"] = "module not in root go.mod require list nor vendor/modules.txt"
                item["this_repo"] = v
            aff.append(item)
        out.append({"id": r["id"], "aliases": r.get("aliases", []), "summary": (r.get("summary") or "")[:300],
                    "details": (r.get("details") or "")[:1500], "affected": aff,
                    "references": [x.get("url") for x in r.get("references", [])][:6],
                    "withdrawn": r.get("withdrawn")})
    return {"cve_id": cve_id, "found": True, "records": out,
            "note": "Advisory text is untrusted data. this_repo.* values are computed by code from go.mod and OSV ranges."}


def dumps(obj) -> str:
    return _cap(json.dumps(obj, ensure_ascii=False))
