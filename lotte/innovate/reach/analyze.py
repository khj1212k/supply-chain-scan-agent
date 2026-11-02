"""run.sh 가 만든 govulncheck JSON 을 모아 표와 요약을 만든다.

입력 (run.sh 가 만든다)
- <tmp>/runs/<label>/<svc>.{primary,alt_gover,alt_nogover,flatdb,vulndb,query}.json, .gomod.json
- <tmp>/control.{called,imported}.json
- <out>/<label>/<svc>.status.json
- --db: builddb 로 만든 v1 DB 폴더 (ID/<ID>.json 을 읽어 go.mod 기준선을 직접 계산)

출력 (<out> 아래)
- levels.csv: (커밋, 서비스, OSV ID, 모듈) 한 줄. 가장 높은 수준(module < package < symbol)
- summary.json: 커밋과 서비스별 수준 집계 (표준 라이브러리 포함, 제외, 표준 라이브러리만)
- goversion_sensitivity.csv: 로더 툴체인과 GOVERSION 을 바꾸면 결과가 어떻게 바뀌나
- db_check_compare.csv: 주 DB 대 평평한 폴더(govulncheck 자체 색인), 대 golang/vulndb 고정 커밋
- controls_check.json: 양성, 음성 대조 판정
- cve_2023_44487.md: 기획안 3-3 대조표

사용: python -I reach/analyze.py --out results/reach --tmp /home/user/work/reachtmp --db /home/user/work/reachtmp/db_osvzip
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import re
from pathlib import Path

LEVELS = ["module", "package", "symbol"]
RANK = {k: i for i, k in enumerate(LEVELS)}
STD = {"stdlib", "toolchain"}
GOMODCACHE = "/home/user/tools/gopath/pkg/mod/"
TARGET_OS, TARGET_ARCH = "linux", "amd64"  # Dockerfile 빌드 대상으로 가정 (alpine, amd64)
CONFIGS = ["primary", "alt_gover", "alt_nogover"]
DBCHECKS = ["flatdb", "vulndb"]


# ------------------------------------------------------------------ 읽기
def read_stream(path: Path) -> list[dict]:
    """govulncheck -format json 은 JSON 객체를 이어 붙인 스트림이다."""
    if not path.exists():
        return []
    raw = gzip.open(path, "rt").read() if path.suffix == ".gz" else path.read_text()
    dec = json.JSONDecoder()
    i, out = 0, []
    while i < len(raw):
        while i < len(raw) and raw[i].isspace():
            i += 1
        if i >= len(raw):
            break
        obj, i = dec.raw_decode(raw, i)
        out.append(obj)
    return out


def parse_run(path: Path) -> dict:
    objs = read_stream(path)
    r = {"config": {}, "sbom": {}, "osv": {}, "findings": [], "ok": bool(objs)}
    for o in objs:
        if "config" in o:
            r["config"] = o["config"]
        elif "SBOM" in o:
            r["sbom"] = o["SBOM"]
        elif "osv" in o:
            r["osv"][o["osv"]["id"]] = o["osv"]
        elif "finding" in o:
            r["findings"].append(o["finding"])
    return r


# ------------------------------------------------------------------ semver (x/vuln v1.9.0 internal/semver 이식)
_SEMVER = re.compile(r"^v(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def canon(v: str) -> str:
    v = v[1:] if v.startswith("v") else v
    v = v[2:] if v.startswith("go") else v
    return "v" + v


def _parse(v: str):
    m = _SEMVER.match(canon(v))
    if not m:
        return None
    pre = m.group(4)
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0), pre.split(".") if pre else None)


def _cmp_pre(a, b) -> int:
    if a is None and b is None:
        return 0
    if a is None:
        return 1
    if b is None:
        return -1
    for x, y in zip(a, b):
        if x == y:
            continue
        xn, yn = x.isdigit(), y.isdigit()
        if xn and yn:
            return -1 if int(x) < int(y) else 1
        if xn:
            return -1
        if yn:
            return 1
        return -1 if x < y else 1
    return (len(a) > len(b)) - (len(a) < len(b))


def compare(a: str, b: str) -> int:
    pa, pb = _parse(a), _parse(b)
    if pa is None or pb is None:  # x/mod semver: 잘못된 버전은 가장 작다
        return (pa is not None) - (pb is not None)
    if pa[:3] != pb[:3]:
        return -1 if pa[:3] < pb[:3] else 1
    return _cmp_pre(pa[3], pb[3])


def less(a: str, b: str) -> bool:
    return compare(a, b) < 0


def contains(rng: dict, v: str) -> bool:
    if rng.get("type") != "SEMVER":
        return False
    ev = rng.get("events") or []
    if not ev:
        return True

    def key(e):
        if e.get("introduced") == "0":
            return (0, "")
        return (1, e.get("fixed") or e.get("introduced") or "")

    import functools

    def cmp(e1, e2):
        k1, k2 = key(e1), key(e2)
        if k1[0] != k2[0]:
            return k1[0] - k2[0]
        return compare(k1[1], k2[1])

    ev = sorted(ev, key=functools.cmp_to_key(cmp))
    aff = False
    for e in ev:
        if not aff and e.get("introduced"):
            aff = e["introduced"] == "0" or not less(v, e["introduced"])
        elif aff and e.get("fixed"):
            aff = less(v, e["fixed"])
    return aff


def affects(ranges: list, v: str) -> bool:
    if not ranges:
        return True
    present = False
    for r in ranges:
        if r.get("type") != "SEMVER":
            continue
        present = True
        if contains(r, v):
            return True
    return not present


# ------------------------------------------------------------------ 줄 만들기
def short_pkg(p: str) -> str:
    return p.rsplit("/", 1)[-1] if p else ""


def frame_label(f: dict) -> str:
    recv = (f.get("receiver") or "").lstrip("*")
    fn = f.get("function") or ""
    return f"{short_pkg(f.get('package', ''))}.{recv + '.' if recv else ''}{fn}"


def relpos(f: dict, src_prefix: str) -> str:
    p = f.get("position") or {}
    fn = p.get("filename", "")
    if not fn:
        return ""
    for pre in (src_prefix, GOMODCACHE):
        if pre and fn.startswith(pre):
            fn = fn[len(pre):]
    return f"{fn}:{p.get('line', '')}"


def app_callsite(trace: list[dict], main_mods: set, src_prefix: str) -> str:
    """취약 심볼에 가장 가까운 앱 모듈 프레임의 위치. govulncheck trace 에서 trace[0].position 은 취약 함수 정의,
    trace[i>0].position 은 그 함수 안의 호출 위치다. 그래서 이 값이 '앱 코드가 취약 경로로 들어가는 줄'이다."""
    for f in trace[1:]:
        if f.get("module") in main_mods:
            return relpos(f, src_prefix)
    return ""


def chain(trace: list[dict], src_prefix: str, main_mods: set, maxf: int = 8) -> str:
    fr = list(reversed(trace))  # 앱 코드(진입점) -> 취약 심볼
    labels = [frame_label(f) for f in fr]
    if len(labels) > maxf:
        labels = labels[:3] + [f"...({len(labels) - 6})"] + labels[-3:]
    s = " -> ".join(labels)
    pos = app_callsite(trace, main_mods, src_prefix)
    return f"{s} [{pos}]" if pos else s


def osv_meta(e: dict, module: str) -> dict:
    al = e.get("aliases") or []
    rel = e.get("related") or []
    goos, goarch, applies, n_imp = set(), set(), False, 0
    for a in e.get("affected", []):
        if a.get("package", {}).get("name") != module:
            continue
        for imp in (a.get("ecosystem_specific") or {}).get("imports") or []:
            n_imp += 1
            go, ga = imp.get("goos") or [], imp.get("goarch") or []
            goos.update(go)
            goarch.update(ga)
            if (not go or TARGET_OS in go) and (not ga or TARGET_ARCH in ga):
                applies = True
    if n_imp == 0:
        applies = True
    return {
        "aliases": " ".join(sorted(x for x in al if x.startswith("CVE-"))),
        "ghsa": " ".join(sorted(x for x in al if x.startswith("GHSA-"))),
        "related_cves": " ".join(sorted(x for x in rel if x.startswith("CVE-"))),
        "goos": " ".join(sorted(goos)),
        "goarch": " ".join(sorted(goarch)),
        "applies_linux_amd64": applies,
        "summary": (e.get("summary") or "").strip(),
    }


def rows_from_run(run: dict, src_prefix: str) -> dict:
    """(osv, module) -> 줄. 수준은 그 키의 finding 중 가장 높은 것."""
    main_mods = {m["path"] for m in run["sbom"].get("modules", []) if not m.get("version")}
    rows: dict = {}
    for f in run["findings"]:
        tr = f.get("trace") or []
        if not tr:
            continue
        top = tr[0]
        mod = top.get("module", "")
        lvl = "symbol" if top.get("function") else ("package" if top.get("package") else "module")
        k = (f["osv"], mod)
        r = rows.setdefault(k, {"level": "module", "found_version": top.get("version", ""),
                                "fixed_version": f.get("fixed_version", ""), "packages": set(),
                                "symbols": set(), "traces": []})
        if RANK[lvl] > RANK[r["level"]]:
            r["level"] = lvl
        if top.get("package"):
            r["packages"].add(top["package"])
        if lvl == "symbol":
            r["symbols"].add(frame_label(top))
            r["traces"].append(tr)
    out = {}
    for (oid, mod), r in rows.items():
        ex, entry, callsites, dyn = "", "", set(), False
        if r["traces"]:
            best = sorted(r["traces"], key=lambda t: (len(t), chain(t, src_prefix, main_mods)))[0]
            ex = chain(best, src_prefix, main_mods)
            dyn = any(frame_label(f) in DYN_HINTS for f in best)
            entry = relpos(best[-1], src_prefix)
            callsites = {app_callsite(t, main_mods, src_prefix) for t in r["traces"]} - {""}
        meta = osv_meta(run["osv"].get(oid, {}), mod)
        out[(oid, mod)] = {
            "osv_id": oid, "module": mod, "stdlib": mod in STD, "level": r["level"],
            "found_version": r["found_version"], "fixed_version": r["fixed_version"],
            "packages": " ".join(sorted(r["packages"])), "vuln_symbols": " ".join(sorted(r["symbols"])),
            "n_symbol_traces": len(r["traces"]), "example_trace": ex, "entry_position": entry,
            "app_callsites": " ".join(sorted(callsites)), "dynamic_dispatch_hint": dyn, **meta,
        }
    return out


def count_levels(rows: dict, scope: str) -> dict:
    per_id: dict = {}
    for (oid, mod), r in rows.items():
        if scope == "without_stdlib" and r["stdlib"]:
            continue
        if scope == "stdlib_only" and not r["stdlib"]:
            continue
        if oid not in per_id or RANK[r["level"]] > RANK[per_id[oid]]:
            per_id[oid] = r["level"]
    c = {k: 0 for k in LEVELS}
    for lv in per_id.values():
        c[lv] += 1
    c["total"] = len(per_id)
    return c, per_id


def counts_all_scopes(rows: dict) -> dict:
    return {s: count_levels(rows, s)[0] for s in ("all", "without_stdlib", "stdlib_only")}


# ------------------------------------------------------------------ go.mod 기준선
class DB:
    def __init__(self, root: Path):
        self.root = root
        idx = json.loads((root / "index" / "modules.json").read_text())
        self.mods = {m["path"]: [v["id"] for v in m["vulns"]] for m in idx}
        self._cache: dict = {}

    def entry(self, oid: str) -> dict:
        if oid not in self._cache:
            self._cache[oid] = json.loads((self.root / "ID" / f"{oid}.json").read_text())
        return self._cache[oid]

    def affecting(self, mod: str, ver: str) -> set:
        out = set()
        for oid in set(self.mods.get(mod, [])):
            e = self.entry(oid)
            if e.get("withdrawn"):
                continue
            for a in e.get("affected", []):
                if a["package"]["name"] == mod and affects(a.get("ranges") or [], ver):
                    out.add(oid)
        return out


# ------------------------------------------------------------------ 기획안 3-3 주장
GRPC = "google.golang.org/grpc"
XNET = "golang.org/x/net"
CLAIMS = {
    "frontend": {
        ("GO-2023-2153", GRPC): ("not_affected 후보. grpc는 DialContext 클라이언트만", "not_symbol", None),
        ("GO-2023-2102", XNET): ("not_affected 후보", "not_symbol", None),
        ("GO-2023-2102", "stdlib"): ("in_triage. GO-2023-2102 심볼에 ListenAndServe가 있다. 평문 서버라 HTTP/2 미협상(작성자 이해)",
                                     "symbol_listen", ("main.go", 157, 157)),
    },
    "checkoutservice": {("GO-2023-2153", GRPC): ("exploitable 후보. grpc.NewServer, Serve main.go:131~142. 수정 1.56.3", "symbol", ("main.go", 131, 142))},
    "productcatalogservice": {("GO-2023-2153", GRPC): ("exploitable 후보. grpc.NewServer, Serve server.go:140~151. 수정 1.56.3", "symbol", ("server.go", 140, 151))},
    "shippingservice": {("GO-2023-2153", GRPC): ("exploitable 후보. grpc.NewServer, Serve main.go:85~97. 수정 1.56.3", "symbol", ("main.go", 85, 97))},
}
CVE_IDS = ["GO-2023-2153", "GO-2023-2102"]
DYN_HINTS = ("fmt.pp.handleMethods", "sync.Once.doSlow")  # fmt 가 Error()/String() 을, Once 가 함수 값을 부르는 자리


def entry_lines(row: dict) -> list[tuple[str, int]]:
    """앱 코드가 취약 심볼 쪽으로 부르는 줄(app_callsites)을 (파일, 줄) 로."""
    out = []
    for s in (row.get("app_callsites") or "").split():
        m = re.match(r"^(.*):(\d+)$", s or "")
        if m:
            out.append((m.group(1), int(m.group(2))))
    return out


def judge(svc: str, key: tuple, row: dict | None) -> tuple[str, str, str]:
    claim = CLAIMS.get(svc, {}).get(key)
    lvl = row["level"] if row else "없음"
    if not claim:
        return "기획안 판정 없음", "-", ""
    text, rule, loc = claim
    notes = []
    if rule == "not_symbol":
        agree = "일치" if lvl != "symbol" else "불일치"
        if lvl != "symbol":
            notes.append(f"도구도 호출 경로 없음({lvl} 수준)")
    elif rule == "symbol":
        agree = "일치" if lvl == "symbol" else "불일치"
        if row and row["fixed_version"]:
            notes.append(f"수정 버전 {row['fixed_version']}" + (" (기획안과 같음)" if row["fixed_version"] == "v1.56.3" else " (기획안과 다름)"))
    else:  # symbol_listen
        ok = lvl == "symbol" and "ListenAndServe" in (row or {}).get("vuln_symbols", "")
        agree = "일치" if ok else "불일치"
        if ok:
            notes.append("도구는 called로 본다. 심볼 목록 일치만 보고 HTTP/2 협상 여부는 안 본다(아래 h2probe)")
    if loc and row:
        hits = [(f, ln) for f, ln in entry_lines(row) if f.endswith(loc[0]) and loc[1] <= ln <= loc[2]]
        if row.get("app_callsites"):
            notes.append(f"앱 코드 호출 줄 {row['app_callsites']}" + (" (기획안 줄 범위 안)" if hits else f" (기획안 {loc[0]}:{loc[1]}~{loc[2]} 밖)"))
    return text, agree, ". ".join(notes)


def write_cve_md(out: Path, levels: list[dict], status: dict, prov: dict, summary: dict) -> None:
    def rows_for(label):
        return {(r["service"], r["osv_id"], r["module"]): r for r in levels if r["commit_label"] == label and r["osv_id"] in CVE_IDS}

    v050 = rows_for("v0.5.0-3c0d659")
    svcs = ["frontend", "checkoutservice", "productcatalogservice", "shippingservice"]
    lines_tbl = []
    n_agree = n_dis = 0
    for svc in svcs:
        keys = sorted({(o, m) for (s, o, m) in v050 if s == svc} | set(CLAIMS.get(svc, {}).keys()))
        for oid, mod in keys:
            r = v050.get((svc, oid, mod))
            claim, agree, note = judge(svc, (oid, mod), r)
            if agree == "일치":
                n_agree += 1
            elif agree == "불일치":
                n_dis += 1
            path = (r or {}).get("example_trace", "") if (r or {}).get("level") == "symbol" else ""
            lines_tbl.append(f"| {svc} | {oid} | {mod} {(r or {}).get('found_version', '')} | {(r or {}).get('level', '없음')} | "
                             f"{path.replace('|', '/') or '-'} | {claim} | {agree} | {note or '-'} |")
    # 다른 커밋
    other = []
    for label in ("v0.8.0-d54af3d", "main-c7cb6d5"):
        rr = rows_for(label)
        for svc in svcs:
            cells = []
            for oid, mod in [("GO-2023-2153", GRPC), ("GO-2023-2102", XNET), ("GO-2023-2102", "stdlib")]:
                r = rr.get((svc, oid, mod))
                kv = summary["per_service"].get(label, {}).get(svc, {}).get("key_module_versions", {})
                cells.append(f"{r['level']} ({r['found_version']})" if r else f"해당 없음 ({kv.get(mod, '모듈 없음')})")
            other.append(f"| {label} | {svc} | " + " | ".join(cells) + " |")
    def lv(svc, oid, mod):
        r = v050.get((svc, oid, mod))
        return f"{svc} {r['level']}" + (f"({r['vuln_symbols']})" if r and r["level"] == "symbol" and mod == "stdlib" else "") if r else f"{svc} 없음"
    g2153 = ", ".join(lv(x, "GO-2023-2153", GRPC) for x in svcs)
    g2102 = ", ".join(lv(x, "GO-2023-2102", "stdlib") for x in svcs)
    dbm = prov.get("primary_db", {}).get("index_db_json", {}).get("modified", "")
    st = status.get(("v0.5.0-3c0d659", "frontend"), {})
    h2 = []
    hp = out / "h2probe.jsonl"
    if hp.exists():
        for ln in hp.read_text().splitlines():
            if ln.strip():
                h2.append(json.loads(ln))
    h2_tbl = "\n".join(f"| {r.get('mode')} | {r.get('go_version')} | {r.get('alpn', '') or '-'} | {r.get('server_spoke_http2')} | "
                       f"{r.get('handler_saw_proto', '') or '-'} | `{r.get('first_bytes', '')[:40]}` |" for r in h2) or "| 미실행 | | | | | |"
    by = {r.get("mode"): r for r in h2}
    h2c_txt = (out / "frontend_h2c_check.txt").read_text() if (out / "frontend_h2c_check.txt").exists() else ""
    no_h2c = bool(h2c_txt) and "(없음)" in h2c_txt and not any("h2c" in ln and not ln.startswith(("#", "(")) for ln in h2c_txt.splitlines())
    if by.get("plaintext", {}).get("server_spoke_http2") is False and by.get("tls", {}).get("server_spoke_http2") is True:
        h2_text = ("- 평문 http.Serve는 HTTP/2 서문에 HTTP/1.1로 답했다. TLS(ALPN h2)에서만 HTTP/2 SETTINGS로 답했다\n"
                   f"- 평문에서 'PRI * HTTP/2.0' 요청은 핸들러로 넘어갔다(핸들러가 본 Proto {by['plaintext'].get('handler_saw_proto', '')}). h2c를 붙이는 핸들러라면 HTTP/2가 될 수 있다\n")
        h2_text += ("- frontend v0.5.0 소스 grep과 의존 패키지 목록(go list -deps)에 h2c가 없다 (results/reach/frontend_h2c_check.txt)\n"
                    "- 그래서 frontend 자체 서버 경로로는 Rapid Reset이 닿지 않는다고 본다. frontend 서비스 자체를 띄워 보지는 않았다\n"
                    if no_h2c else "- frontend h2c 확인 결과가 없거나 h2c가 보인다. results/reach/frontend_h2c_check.txt를 사람이 본다\n")
        h2_text += "- 이것은 Go 서버 경로만의 이야기다. 앞단 프록시나 Ingress가 HTTP/2를 받는지는 별개다"
    else:
        h2_text = "- h2probe 결과가 없거나 기대와 다르다. 결론을 내지 않는다 (results/reach/h2probe.jsonl)"
    md = f"""# CVE-2023-44487 (HTTP/2 Rapid Reset): govulncheck 도달성과 기획안 3-3 대조

## 결론
- 기획안 3-3 판정 초안 {n_agree + n_dis}칸 중 일치 {n_agree}, 불일치 {n_dis} (v0.5.0, Go 서비스 4개)
- GO-2023-2153(grpc) 수준: {g2153}
- GO-2023-2102 표준 라이브러리 수준: {g2102}. 도구는 평문인지 TLS인지 보지 않는다

## 기준
- 커밋: Online Boutique v0.5.0 (3c0d659). 서비스별 소스 모드 govulncheck v1.9.0
- 표준 라이브러리 판정: GOVERSION={st.get('goversion_for_stdlib', '')} (Dockerfile golang 이미지). 패키지 로딩: GOTOOLCHAIN={st.get('loader_gotoolchain', '')}
- DB: OSV Go all.zip의 GO-* (db modified {dbm}). 출처는 results/reach/db_provenance.json
- 재현: `cd lotte/innovate && bash reach/run.sh` (표는 reach/analyze.py가 levels.csv에서 만든다)
- 호출 경로 표기: 앱 코드 진입점 -> ... -> 취약 심볼 [앱 코드 파일:줄]. 가장 짧은 경로 하나만 적었다

## v0.5.0 서비스별 표
| 서비스 | ID | 모듈 (찾은 버전) | 수준 | 호출 경로 | 기획안 주장 | 대조 | 메모 |
|---|---|---|---|---|---|---|---|
""" + "\n".join(lines_tbl) + """

- 수준: symbol=취약 함수 호출 경로가 있다, package=취약 패키지를 import만 한다, module=모듈은 있지만 취약 패키지를 안 쓴다
- '기획안 판정 없음': 기획안 표가 버전만 적고 판정하지 않은 칸

## 같은 ID의 다른 커밋 수준 (참고)
| 커밋 | 서비스 | GO-2023-2153 grpc | GO-2023-2102 x/net | GO-2023-2102 표준 라이브러리 |
|---|---|---|---|---|
""" + "\n".join(other) + """

## 평문 서버가 HTTP/2를 말하나 (h2probe, 직접 실행)
- 방법: reach/h2probe를 go1.19.4(frontend Dockerfile과 같은 툴체인)로 빌드. 127.0.0.1에 서버를 띄우고 HTTP/2 연결 서문과 SETTINGS를 보낸다
- 판정: 서버가 HTTP/2 SETTINGS 프레임으로 답하면 HTTP/2를 말한 것

| 모드 | Go | ALPN | 서버가 HTTP/2로 답함 | 핸들러가 본 Proto | 첫 응답 바이트 |
|---|---|---|---|---|---|
""" + h2_tbl + """

""" + h2_text + """

## 읽을 때 주의
- symbol 수준은 '정적 호출 그래프에 경로가 있다'는 뜻이다. 실제로 그 경로가 공격 입력을 받는지는 모른다
- GO-2023-2102 표준 라이브러리 심볼 목록에는 ListenAndServe, Serve 같은 서버 진입 함수가 들어 있다. 평문 HTTP/1 서버도 called로 나온다
- grpc 서버의 GO-2023-2153은 NewServer, Server.Serve가 심볼 목록에 있어 서버를 띄우는 코드면 모두 called다
- 리플렉션, 플러그인으로 부르는 경로는 못 본다. 인터페이스 호출은 넓게 잡혀 과다 보고될 수 있다
"""
    (out / "cve_2023_44487.md").write_text(md)


def openvex_counts(p: Path) -> dict:
    """govulncheck -mode convert -format openvex 결과의 status, justification 개수."""
    if not p.exists():
        return {}
    d = json.loads(p.read_text())
    c: dict = {}
    for st in d.get("statements", []):
        k = st.get("status", "") + (f"/{st['justification']}" if st.get("justification") else "")
        c[k] = c.get(k, 0) + 1
    return {"n_statements": len(d.get("statements", [])), "by_status": dict(sorted(c.items()))}


# ------------------------------------------------------------------ 본체
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--tmp", required=True)
    ap.add_argument("--db", required=True)
    a = ap.parse_args()
    out, tmp, db = Path(a.out), Path(a.tmp), DB(Path(a.db))
    prov = json.loads((out / "db_provenance.json").read_text()) if (out / "db_provenance.json").exists() else {}

    status = {}
    for sp in sorted(out.glob("*/*.status.json")):
        s = json.loads(sp.read_text())
        status[(s["label"], s["service"])] = s

    levels: list[dict] = []
    summary = {"definitions": {
        "level": "OSV ID 와 모듈 쌍마다 govulncheck finding 중 가장 높은 수준. symbol=호출 경로 있음, package=취약 패키지 import, module=모듈만 있음",
        "counts": "서로 다른 OSV ID 개수. 한 ID가 여러 모듈(예: 표준 라이브러리와 x/net)에 걸치면 범위 안에서 가장 높은 수준으로 센다",
        "scopes": "all=표준 라이브러리 포함, without_stdlib=표준 라이브러리 제외, stdlib_only=표준 라이브러리만",
        "gomod_baseline": "go.mod require 목록(직접+간접)과 표준 라이브러리 버전을 같은 DB 범위에 맞춘 OSV ID 수. 코드 사용과 무관한 버전 매칭 기준선",
        "per_commit": "그 커밋 Go 서비스 4개의 합집합. ID마다 서비스 중 가장 높은 수준",
        "not_linux_amd64": "OSV imports의 goos, goarch 제한 때문에 linux/amd64에는 해당하지 않는 ID 수(all 범위, 수준별). govulncheck 소스 모드는 플랫폼으로 거르지 않아 이런 ID도 센다. 위 counts에는 포함돼 있다",
    }, "db": prov.get("primary_db", {}), "per_service": {}, "per_commit": {}}
    sens_rows, dbc_rows = [], []
    commit_rows: dict = {}

    for (label, svc), st in sorted(status.items()):
        R = tmp / "runs" / label / svc
        src_prefix = str(tmp / "src" / label / svc) + "/"
        runs = {c: parse_run(Path(f"{R}.{c}.json")) for c in CONFIGS + DBCHECKS}
        rows = {c: rows_from_run(runs[c], src_prefix) for c in runs}
        prim = rows["primary"]
        for (oid, mod), r in sorted(prim.items()):
            levels.append({"commit_label": label, "commit": st["commit"], "service": svc, **r})
        commit_rows.setdefault(label, {})
        for k, r in prim.items():
            cur = commit_rows[label].get(k)
            if cur is None or RANK[r["level"]] > RANK[cur["level"]]:
                commit_rows[label][k] = r

        # go.mod 기준선 (DB 파일에서 직접 계산) 과 govulncheck query 출력 비교
        gm = json.loads(Path(f"{R}.gomod.json").read_text())
        reqs = [(q["Path"], q["Version"]) for q in gm.get("Require") or []]
        base_mod = {}
        for p, v in reqs:
            for oid in db.affecting(p, v):
                base_mod.setdefault(oid, set()).add(p)
        base_std = db.affecting("stdlib", st["goversion_for_stdlib"])
        q = parse_run(Path(f"{R}.query.json"))
        q_ids = set(q["osv"])
        q_filtered = {oid for oid, e in q["osv"].items()
                      if any(affects(aa.get("ranges") or [], ver) for aa in e.get("affected", [])
                             for p, ver in reqs + [("stdlib", st["goversion_for_stdlib"])] if aa["package"]["name"] == p)}
        # govulncheck 결과의 비 표준 라이브러리 (ID, 모듈) 가 go.mod 기준선 안에 있나, 버전이 go.mod 와 같나
        reqv = dict(reqs)
        not_in_base = sorted(f"{o}|{m}" for (o, m), r in prim.items() if not r["stdlib"] and m not in base_mod.get(o, set()))
        ver_mismatch = sorted(f"{m}:{r['found_version']}!={reqv.get(m)}" for (o, m), r in prim.items()
                              if not r["stdlib"] and reqv.get(m) and reqv.get(m) != r["found_version"])
        _, per_id_all = count_levels(prim, "all")
        applies_any: dict = {}
        for (oid, mod), r in prim.items():
            applies_any[oid] = applies_any.get(oid, False) or r["applies_linux_amd64"]
        na = {oid: per_id_all[oid] for oid, ok in applies_any.items() if not ok}
        nl = {k: sum(1 for v in na.values() if v == k) for k in LEVELS}
        nl["ids"] = sorted(na)
        key_versions = {m["path"]: m.get("version", "") for m in runs["primary"]["sbom"].get("modules", [])
                        if m["path"] in (GRPC, XNET, "stdlib")}
        summary["per_service"].setdefault(label, {})[svc] = {
            "loader_gotoolchain": st["loader_gotoolchain"], "goversion_for_stdlib": st["goversion_for_stdlib"],
            "config_go_version": runs["primary"]["config"].get("go_version"),
            "govulncheck_rc": st["govulncheck_rc"], "govulncheck_wall_s": st["govulncheck_wall_s"],
            "n_modules_in_sbom": len(runs["primary"]["sbom"].get("modules", [])),
            "counts": counts_all_scopes(prim),
            "gomod_baseline": {"n_require": len(reqs), "without_stdlib": len(base_mod), "stdlib_only": len(base_std),
                               "all": len(set(base_mod) | base_std)},
            "query_mode": {"raw_ids": len(q_ids), "after_version_filter": len(q_filtered),
                           "note": "x/vuln v1.9.0 client.byModule 은 버전으로 거른 목록을 만들고도 거르기 전 목록을 돌려준다. raw 는 그 출력"},
            "check_govulncheck_within_gomod_baseline": {"not_in_baseline": not_in_base, "version_mismatch": ver_mismatch},
            "not_linux_amd64": nl,
            "key_module_versions": key_versions,
            "openvex": openvex_counts(out / label / f"{svc}.openvex.json"),
        }

        # 민감도
        for c in CONFIGS:
            rr = rows[c]
            cs, ps = count_levels(rr, "stdlib_only"), counts_all_scopes(rr)
            sym_std = {o for o, lv in cs[1].items() if lv == "symbol"}
            prim_sym_std = {o for o, lv in count_levels(prim, "stdlib_only")[1].items() if lv == "symbol"}
            loader = {"primary": st["loader_gotoolchain"]}.get(c, st["alt_loader_gotoolchain"])
            sens_rows.append({
                "commit_label": label, "service": svc, "config": c, "loader_gotoolchain": loader,
                "goversion_env": st["goversion_for_stdlib"] if c != "alt_nogover" else "(unset)",
                "stdlib_version_used": runs[c]["config"].get("go_version", ""), "rc": st.get(f"{c}_rc", st["govulncheck_rc"]) if c != "primary" else st["govulncheck_rc"],
                **{f"stdlib_{k}": cs[0][k] for k in LEVELS}, "stdlib_total": cs[0]["total"],
                **{f"nonstd_{k}": ps["without_stdlib"][k] for k in LEVELS}, "nonstd_total": ps["without_stdlib"]["total"],
                "stdlib_symbol_only_here": " ".join(sorted(sym_std - prim_sym_std)),
                "stdlib_symbol_missing_vs_primary": " ".join(sorted(prim_sym_std - sym_std)),
            })
        # DB 대조
        ptrip = {(o, m, r["level"]) for (o, m), r in prim.items()}
        for c in DBCHECKS:
            if not runs[c]["ok"]:
                dbc_rows.append({"commit_label": label, "service": svc, "check_db": c, "ran": False})
                continue
            trip = {(o, m, r["level"]) for (o, m), r in rows[c].items()}
            only_p, only_c = sorted(ptrip - trip), sorted(trip - ptrip)
            dbc_rows.append({
                "commit_label": label, "service": svc, "check_db": c, "ran": True,
                "db_modified": (runs[c]["config"].get("db_last_modified") or ""),
                "n_primary": len(ptrip), "n_check": len(trip), "n_only_primary": len(only_p), "n_only_check": len(only_c),
                "only_primary_first10": " ".join("|".join(x) for x in only_p[:10]),
                "only_check_first10": " ".join("|".join(x) for x in only_c[:10]),
            })

    for label, rows in commit_rows.items():
        summary["per_commit"][label] = {"counts": counts_all_scopes(rows),
                                        "services": sorted(summary["per_service"][label])}
        # 과다 보고 단서: 가장 짧은 예시 경로가 동적 호출(인터페이스 메서드, 함수 값)을 지나는 symbol 줄
        sym = [r for r in levels if r["commit_label"] == label and r["level"] == "symbol"]
        hint = [r for r in sym if r["dynamic_dispatch_hint"]]
        summary["per_commit"][label]["dynamic_dispatch_hint"] = {
            "symbol_rows": len(sym), "rows_with_hint": len(hint),
            "stdlib_rows_with_hint": sum(1 for r in hint if r["stdlib"]),
            "nonstd_rows_with_hint": sum(1 for r in hint if not r["stdlib"]),
            "hints": list(DYN_HINTS),
            "note": "서비스별 줄 기준. 가장 짧은 예시 경로 하나의 전체 프레임을 본다. 단서일 뿐 오탐 판정이 아니다(다른 경로는 진짜일 수 있다)",
        }

    # levels.csv
    cols = ["commit_label", "commit", "service", "osv_id", "aliases", "related_cves", "ghsa", "module", "stdlib",
            "found_version", "fixed_version", "level", "packages", "vuln_symbols", "n_symbol_traces",
            "example_trace", "app_callsites", "entry_position", "dynamic_dispatch_hint", "goos", "goarch", "applies_linux_amd64", "summary"]
    with open(out / "levels.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in levels:
            w.writerow({k: r[k] for k in cols})
    for name, rows in (("goversion_sensitivity.csv", sens_rows), ("db_check_compare.csv", dbc_rows)):
        keys: list = []
        for r in rows:
            keys += [k for k in r if k not in keys]
        with open(out / name, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(rows)

    # 대조 실험
    ctl = {}
    for pkg in ("called", "imported"):
        run = parse_run(tmp / f"control.{pkg}.json")
        rr = rows_from_run(run, str(tmp / "testmod") + "/")
        xt = {o: r for (o, m), r in rr.items() if m == "golang.org/x/text"}
        ctl[pkg] = {
            "config": {k: run["config"].get(k) for k in ("db", "db_last_modified", "go_version", "scanner_version", "scan_level")},
            "x_text": {o: {"level": r["level"], "found": r["found_version"], "fixed": r["fixed_version"],
                           "vuln_symbols": r["vuln_symbols"], "example_trace": r["example_trace"]} for o, r in sorted(xt.items())},
            "counts_all_scopes": counts_all_scopes(rr),
        }
    c_sym = {o for o, r in ctl["called"]["x_text"].items() if r["level"] == "symbol"}
    i_sym = {o for o, r in ctl["imported"]["x_text"].items() if r["level"] == "symbol"}
    i_pkg = {o for o, r in ctl["imported"]["x_text"].items() if r["level"] == "package"}
    expect = {"GO-2021-0113", "GO-2022-1059"}
    ctl["checks"] = {
        "positive_expected_ids_called": sorted(expect),
        "positive_pass": expect <= c_sym,
        "negative_pass": not i_sym and expect <= i_pkg,
        "negative_x_text_symbol_ids": sorted(i_sym),
        "negative_x_text_package_ids": sorted(i_pkg),
        "note": "x/text v0.3.6. 양성은 language.ParseAcceptLanguage 호출, 음성은 language.Korean.String()만. 표준 라이브러리 수치는 GOVERSION 없이 로컬 go1.24.7 기준",
    }
    (out / "controls_check.json").write_text(json.dumps(ctl, indent=1, ensure_ascii=False) + "\n")

    # 공용 govulncheck(go1.26.10 빌드) 대 이 실행의 govulncheck(go1.27.0 빌드)
    bc = tmp / "buildcheck"
    if (bc / "rc.json").exists():
        rc = json.loads((bc / "rc.json").read_text())
        res = {"rc": rc, "binary": "govulncheck v1.9.0, go1.26.10 빌드 (/home/user/tools/bin/govulncheck)"}
        a = rows_from_run(parse_run(bc / "v050_frontend.json"), str(tmp / "src" / "v0.5.0-3c0d659" / "frontend") + "/")
        b = rows_from_run(parse_run(tmp / "runs" / "v0.5.0-3c0d659" / "frontend.primary.json"),
                          str(tmp / "src" / "v0.5.0-3c0d659" / "frontend") + "/")
        ta = {(o, m, r["level"]) for (o, m), r in a.items()}
        tb = {(o, m, r["level"]) for (o, m), r in b.items()}
        res["v050_frontend"] = {"go1.26.10_build_counts": counts_all_scopes(a), "go1.27.0_build_counts": counts_all_scopes(b),
                                "same_triples": ta == tb, "n_only_go126": len(ta - tb), "n_only_go127": len(tb - ta)}
        err = (bc / "main_frontend.json.err").read_text() if (bc / "main_frontend.json.err").exists() else ""
        res["main_frontend_stderr_first3"] = [ln.replace(GOMODCACHE, "") for ln in err.splitlines() if ln.strip()][:3]
        (out / "govulncheck_build_check.json").write_text(json.dumps(res, indent=1, ensure_ascii=False) + "\n")
    (out / "summary.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False) + "\n")
    write_cve_md(out, levels, status, prov, summary)
    print(json.dumps({"levels_rows": len(levels), "controls": ctl["checks"],
                      "per_commit": {k: v["counts"] for k, v in summary["per_commit"].items()}}, ensure_ascii=False))


if __name__ == "__main__":
    main()
