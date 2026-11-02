"""조치안 에이전트의 데이터 계층 (전부 코드, LLM 없음).

- Go semver 비교 (프리릴리스, 의사 버전 포함)
- 오프라인 OSV Go 덤프(all.zip) 색인: 모듈별 권고, 버전별 영향 여부, 별칭 묶음
- proxy.golang.org: 버전 목록(@v/list), go.mod(@v/<v>.mod)의 go 지시어. 받은 파일은 data/raw/agent/ 캐시,
  data/manifest_agent.json 에 URL, 시각, sha256 기록 (common/fetch.py)
- 신호: KEV(catalog 2026.10.30), EPSS(2026-11-01). 사례 고르기에만 쓰고 LLM에는 주지 않는다
"""
from __future__ import annotations

import csv
import gzip
import json
import re
import sys
import zipfile
from functools import lru_cache
from pathlib import Path

INNO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(INNO))
from common.fetch import fetch  # noqa: E402

OSV_GO_ZIP = Path("/home/user/work/osvdb/osv-scalibr/Go/all.zip")
KEV_JSON = INNO / "data" / "raw" / "kev" / "known_exploited_vulnerabilities.json"
EPSS_CSV = INNO / "data" / "raw" / "epss" / "epss_scores-2026-11-01.csv.gz"
PROXY = "https://proxy.golang.org"

# ---------------------------------------------------------------- semver
_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.\-]+))?(?:\+[0-9A-Za-z.\-]+)?$")


def norm(v: str) -> str:
    v = v.strip()
    return v if v.startswith("v") else "v" + v


def parse(v: str):
    m = _SEMVER.match(norm(v))
    if not m:
        return None
    major, minor, patch, pre = int(m[1]), int(m[2]), int(m[3]), m[4]
    return major, minor, patch, pre


def _pre_key(pre: str | None):
    # semver 규칙: 프리릴리스가 없으면 더 크다. 식별자는 숫자는 숫자로, 문자열은 문자열로 비교
    if pre is None:
        return (1,)
    parts = []
    for p in pre.split("."):
        parts.append((0, int(p), "") if p.isdigit() else (1, 0, p))
    return (0, tuple(parts))


def key(v: str):
    p = parse(v)
    if p is None:
        return (-1, -1, -1, (0, ()))
    return (p[0], p[1], p[2], _pre_key(p[3]))


def cmp(a: str, b: str) -> int:
    ka, kb = key(a), key(b)
    return (ka > kb) - (ka < kb)


def is_stable(v: str) -> bool:
    p = parse(v)
    return p is not None and p[3] is None


def major_of(v: str) -> int:
    p = parse(v)
    return p[0] if p else -1


# ---------------------------------------------------------------- OSV Go 덤프
@lru_cache(maxsize=1)
def osv_index() -> tuple[dict, dict]:
    """(id -> 레코드, 모듈 -> [id]). Go 생태계의 GO-, GHSA- 등 전부."""
    recs, by_mod = {}, {}
    with zipfile.ZipFile(OSV_GO_ZIP) as z:
        for name in z.namelist():
            d = json.loads(z.read(name))
            recs[d["id"]] = d
            for a in d.get("affected", []):
                pkg = a.get("package", {})
                if pkg.get("ecosystem") == "Go":
                    by_mod.setdefault(pkg.get("name"), []).append(d["id"])
    for k in by_mod:
        by_mod[k] = sorted(set(by_mod[k]))
    return recs, by_mod


def osv_snapshot() -> dict:
    recs, _ = osv_index()
    return {"path": str(OSV_GO_ZIP), "records": len(recs),
            "max_modified": max((r.get("modified", "") for r in recs.values()), default="")}


def _affects(rec: dict, module: str, version: str) -> bool:
    for a in rec.get("affected", []):
        pkg = a.get("package", {})
        if pkg.get("ecosystem") != "Go" or pkg.get("name") != module:
            continue
        if norm(version).lstrip("v") in {x.lstrip("v") for x in a.get("versions", [])}:
            return True
        for r in a.get("ranges", []):
            if r.get("type") != "SEMVER":
                continue
            # 이벤트를 순서대로 읽어 [introduced, fixed) 구간을 만든다 (OSV 스키마)
            events = r.get("events", [])
            intro = None  # None: 구간 밖, "0": 하한 없음 (의사 버전 v0.0.0-... 도 포함)

            def ge_lo(lo):
                return lo == "0" or cmp(version, lo) >= 0

            for ev in events:
                if "introduced" in ev:
                    intro = ev["introduced"]
                elif "fixed" in ev and intro is not None:
                    if ge_lo(intro) and cmp(version, ev["fixed"]) < 0:
                        return True
                    intro = None
                elif "last_affected" in ev and intro is not None:
                    if ge_lo(intro) and cmp(version, ev["last_affected"]) <= 0:
                        return True
                    intro = None
            if intro is not None and ge_lo(intro):
                return True
    return False


def affecting(module: str, version: str) -> list[str]:
    """module@version 에 영향을 주는 OSV ID (철회된 레코드 제외)."""
    recs, by_mod = osv_index()
    return [i for i in by_mod.get(module, []) if not recs[i].get("withdrawn") and _affects(recs[i], module, version)]


def groups(ids: list[str]) -> list[list[str]]:
    """별칭으로 묶은 권고 묶음 (GO-와 GHSA-가 같은 취약점이면 한 묶음). ID나 별칭을 하나라도 공유하면 묶는다."""
    recs, _ = osv_index()
    parent = {i: i for i in ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    owner = {}
    for i in ids:
        for tok in [i] + recs[i].get("aliases", []):
            if tok in owner:
                parent[find(i)] = find(owner[tok])
            else:
                owner[tok] = i
    out = {}
    for i in ids:
        out.setdefault(find(i), []).append(i)
    return sorted(sorted(v) for v in out.values())


def cves_of(ids: list[str]) -> list[str]:
    recs, _ = osv_index()
    s = set()
    for i in ids:
        for a in [i] + recs[i].get("aliases", []):
            if a.startswith("CVE-"):
                s.add(a)
            # 별칭 레코드의 별칭까지 (기획안 조인 2단계)
            for b in (recs.get(a) or {}).get("aliases", []):
                if b.startswith("CVE-"):
                    s.add(b)
    return sorted(s)


def fixed_versions(osv_id: str, module: str) -> list[str]:
    recs, _ = osv_index()
    out = []
    for a in recs[osv_id].get("affected", []):
        if a.get("package", {}).get("name") == module:
            for r in a.get("ranges", []):
                out += [norm(ev["fixed"]) for ev in r.get("events", []) if "fixed" in ev]
    return sorted(set(out), key=key)


def advisory_text(osv_id: str, module: str | None = None, max_refs: int = 6) -> dict:
    """get_advisory 도구가 돌려주는 내용. 권고 원문(신뢰하지 않는 입력)이라 길이를 자른다."""
    recs, _ = osv_index()
    r = recs.get(osv_id)
    if r is None:
        return {"error": f"{osv_id} 없음 (오프라인 OSV Go 덤프)"}
    aff = []
    for a in r.get("affected", []):
        name = a.get("package", {}).get("name")
        if module and name != module:
            continue
        ev = [e for rg in a.get("ranges", []) for e in rg.get("events", [])]
        imports = (a.get("ecosystem_specific") or {}).get("imports") or []
        aff.append({"module": name, "events": ev,
                    "packages": [{"path": i.get("path"), "symbols": (i.get("symbols") or [])[:12]} for i in imports][:6]})
    return {"id": r["id"], "aliases": r.get("aliases", []), "summary": (r.get("summary") or "")[:300],
            "details": (r.get("details") or "")[:1500], "affected": aff,
            "references": [x.get("url") for x in r.get("references", [])][:max_refs],
            "modified": r.get("modified")}


# ---------------------------------------------------------------- 신호 (사례 고르기에만)
@lru_cache(maxsize=1)
def kev() -> set[str]:
    return {v["cveID"] for v in json.loads(KEV_JSON.read_text())["vulnerabilities"]}


@lru_cache(maxsize=1)
def epss() -> dict[str, float]:
    out = {}
    with gzip.open(EPSS_CSV, "rt") as f:
        rows = (ln for ln in f if not ln.startswith("#"))
        for row in csv.DictReader(rows):
            out[row["cve"]] = float(row["epss"])
    return out


# ---------------------------------------------------------------- proxy.golang.org
def _esc(module: str) -> str:
    return re.sub(r"[A-Z]", lambda m: "!" + m[0].lower(), module)


def module_versions(module: str) -> list[str]:
    """@v/list 의 버전 전부(정렬). 처음 받은 파일을 캐시해 같은 스냅샷을 쓴다."""
    p = fetch(f"{PROXY}/{_esc(module)}/@v/list", f"agent/proxy/{_esc(module)}/list.txt", manifest="agent")
    vs = [v.strip() for v in p.read_text().split() if parse(v.strip())]
    return sorted(set(vs), key=key)


def go_directive(module: str, version: str) -> str | None:
    p = fetch(f"{PROXY}/{_esc(module)}/@v/{version}.mod", f"agent/proxy/{_esc(module)}/{version}.mod", manifest="agent")
    m = re.search(r"^go\s+(\S+)", p.read_text(), re.M)
    return m[1] if m else None


def go_ver_key(g: str | None):
    if not g:
        return (0, 0, 0)
    nums = [int(x) for x in re.findall(r"\d+", g)][:3]
    return tuple(nums + [0] * (3 - len(nums)))
