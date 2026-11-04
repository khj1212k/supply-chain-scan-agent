"""M2 깔때기: 스캔 결과 정규화, CVE 조인, 신호, BOD 기한, 신호 큐, 표본, 깔때기, 경로 비교, 기획안 3-2 대조.

입력
- $M2TMP/<라벨>/{lock,lock_call,lock_resolve,sbom,lock_std_gomod,lock_std_override,std_probe}.json, sbom.cdx.json (m2/scan.sh)
- OSV 오프라인 DB zip (권고 레코드, 별칭의 별칭 조회): /home/user/work/osvdb/osv-scalibr/<생태계>/all.zip
  + Bitnami/all.zip (별칭 BIT-* 레코드. common.fetch 로 받고 data/manifest_m2.json 에 기록)
- 신호: data/raw/kev, data/raw/epss/epss_scores-2026-11-01.csv.gz, data/raw/derived/nvd_table.csv.gz

규칙 (기획안 부록 B scan() 과 같게)
- 보고 행 키: (서비스, 생태계, 이름, 버전, CVE). CVE 는 권고 별칭 -> 별칭 레코드의 별칭 순. 없으면 related 의 CVE 를 후보로 (KEV 우선)
- 둘 다 없으면 키 끝은 권고 ID 중 사전순 첫째, 조인 'none' (기한 계산 대상 아님)
- 기한: BOD 16칸 사전. SSVC 가 없으면 automatable no, technical total
- 신호 큐 (프런트엔드만 공개): 기한 3d, 3d+F, 14d 또는 KEV 또는 EPSS>=0.1
- 표본: 큐 밖에서 생태계별 5건, random.Random(20261102)

사용: .venv/bin/python m2/funnel.py
출력: results/m2/ (summary.json, funnel.csv, findings_<라벨>.csv, services.csv, path_compare*.csv, stdlib_variants.csv,
      compare_proposal.csv, log_issues.csv, data_asof.csv)
"""
from __future__ import annotations

import collections
import csv
import gzip
import json
import os
import random
import re
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

INNO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(INNO))
from common.fetch import fetch  # noqa: E402

TMP = Path(os.environ.get("M2TMP", "/home/user/work/m2tmp"))
OSVDB = Path(os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", "/home/user/work/osvdb")) / "osv-scalibr"
OUT = INNO / "results" / "m2"
RAW = INNO / "data" / "raw"
GCS = "https://osv-vulnerabilities.storage.googleapis.com"
LABELS = ["v0.5.0", "main", "v0.8.0"]
STEPS = ["lock", "lock_call", "lock_resolve", "sbom", "lock_std_gomod", "lock_std_override", "std_probe"]
COMMITS = {"v0.5.0": "3c0d6597809d1f40dccd24b757b7ca67d40cadf8",
           "main": "c7cb6d5bfd6ea3aed768634ebbcb98cb7a523712",
           "v0.8.0": "d54af3d2510995d33521ac543dd885b150213f95"}
PUBLIC = "frontend"  # v0.5.0 매니페스트의 LoadBalancer 는 frontend-external 하나 (기획안 3-2)
SEED = 20261102

# (KEV, 공개 노출, 자동화, 기술적 영향) -> 기한. CERT/CC 정리표 기준 (CISA 이미지 원본 미대조). 기획안 부록 B 그대로
BOD = {"NNNP": "upgrade", "YNNP": "14d", "NYNP": "60d", "NNYP": "60d", "NNNT": "upgrade", "YYNP": "14d", "YNYP": "14d", "NYYP": "14d",
       "YNNT": "14d", "NYNT": "14d", "NNYT": "60d", "YYYP": "3d", "YYNT": "3d+F", "YNYT": "3d+F", "NYYT": "3d", "YYYT": "3d+F"}
DUE_ORDER = ["3d+F", "3d", "14d", "60d", "upgrade"]
EXPOSURES = {"all_internal": lambda s: False, "frontend_only": lambda s: s == PUBLIC, "all_public": lambda s: True}

# 기획안 3-2 값 (사전 분석 3-2 표와 본문)
PROPOSAL = {
    "v0.5.0": {"services": 11, "components": 859, "reported": 609, "eco_npm": 262, "eco_Go": 164, "eco_PyPI": 119, "eco_Maven": 64,
               "package_versions": 74, "top5_share_pct": 35.5, "join_alias": 595, "join_related": 5, "join_none": 9,
               "unique_cves": 244, "ghsa_critical": 21, "kev_rows": 10, "signal_B_rows": 14, "crit_and_B": 1,
               "due_all_internal": "0, 0, 10, 323, 267", "due_frontend_only": "0, 3, 32, 318, 247", "due_all_public": "1, 23, 400, 176, 0",
               "queue": 38, "queue_Go": 36, "out_of_queue": 562, "out_package_versions": 73, "sample": 20, "mal": 0},
    "main": {"services": 12, "components": 903, "reported": 208, "eco_npm": 42, "eco_Go": 38, "eco_PyPI": 120, "eco_Maven": 8,
             "package_versions": 41, "top5_share_pct": 57.7, "join_alias": 199, "join_related": 0, "join_none": 9,
             "unique_cves": 115, "ghsa_critical": 10, "kev_rows": 1, "signal_B_rows": 1, "crit_and_B": 1,
             "due_all_internal": "0, 0, 1, 124, 74", "due_frontend_only": "0, 1, 9, 117, 72", "due_all_public": "1, 13, 146, 39, 0",
             "queue": 10, "queue_Go": 9, "out_of_queue": 189, "out_package_versions": 37, "sample": 20, "mal": 0},
}


# ---------- 입력 읽기 ----------
def service_of(path: str) -> str:
    parts = Path(path).parts
    if "src" in parts:
        return parts[parts.index("src") + 1]
    return parts[1] if path.startswith("/") else parts[0]  # Syft 위치 '/frontend/go.mod'


def norm_name(eco: str, name: str) -> str:
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def norm_ver(eco: str, v: str) -> str:
    return v[1:] if eco == "Go" and v.startswith("v") else v


def load_scan(p: Path) -> tuple[list[dict], dict]:
    """osv-scanner JSON -> 구성요소 행 목록, 권고 레코드 사전."""
    d = json.loads(p.read_text())
    rows, recs = [], {}
    for res in d.get("results", []):
        src = res["source"]["path"]
        for pk in res.get("packages", []):
            P = pk["package"]
            vids = []
            for v in pk.get("vulnerabilities", []) or []:
                vids.append(v["id"])
                recs[v["id"]] = v
            called = {}  # osv-scanner 내장 Go 호출 분석 (켜졌을 때만): 권고 ID -> called
            for g in pk.get("groups", []) or []:
                for i, a in (g.get("experimental_analysis") or {}).items():
                    called[i] = bool(a.get("called"))
            rows.append({"source": src, "service": service_of(src) if res["source"]["type"] != "sbom" else "",
                         "eco": P["ecosystem"], "name": P["name"], "version": P.get("version", ""),
                         "purl": P.get("purl", ""), "vulns": vids, "called": called})
    return rows, recs


def loaded_dbs(log: Path) -> set[str]:
    return set(re.findall(r"Loaded (.+?) local db from", log.read_text()))


class OSVIndex:
    """권고 ID -> 레코드. 생태계 zip 안 파일 이름이 '<ID>.json' 이라 이름으로 바로 찾는다."""

    def __init__(self, zips: dict[str, Path]):
        self.z = {e: zipfile.ZipFile(p) for e, p in zips.items() if p.exists()}
        self.names = {e: set(z.namelist()) for e, z in self.z.items()}
        self.cache: dict[str, dict | None] = {}

    def get(self, i: str) -> dict | None:
        if i not in self.cache:
            self.cache[i] = None
            for e, z in self.z.items():
                if f"{i}.json" in self.names[e]:
                    self.cache[i] = json.loads(z.read(f"{i}.json"))
                    break
        return self.cache[i]


# ---------- 신호 ----------
def load_signals() -> dict:
    kev_doc = json.loads((RAW / "kev" / "known_exploited_vulnerabilities.json").read_text())
    kev = {v["cveID"]: v for v in kev_doc["vulnerabilities"]}
    ep_path = RAW / "epss" / "epss_scores-2026-11-01.csv.gz"
    with gzip.open(ep_path, "rt") as f:
        head = f.readline().strip()
    ep = pd.read_csv(ep_path, skiprows=1)
    ep = dict(zip(ep["cve"], ep["epss"]))
    nvd = pd.read_csv(RAW / "derived" / "nvd_table.csv.gz", dtype=str, keep_default_na=False,
                      usecols=["cve", "cvss3_max", "cvss3_nvd", "ssvc_automatable", "ssvc_technical"]).set_index("cve")
    return {"kev": kev, "kev_meta": {"catalogVersion": kev_doc.get("catalogVersion"), "dateReleased": kev_doc.get("dateReleased"), "count": kev_doc.get("count")},
            "epss": ep, "epss_meta": head.lstrip("#"), "nvd": nvd}


# ---------- 핵심: 기획안 scan() 과 같은 정규화와 큐 ----------
def analyze(rows: list[dict], recs: dict, idx: OSVIndex, sig: dict | None = None, label: str = "") -> dict:
    comps = [(r["service"], r["eco"], r["name"], r["version"]) for r in rows]
    ids_of = collections.defaultdict(list)
    for r in rows:
        k = (r["service"], r["eco"], r["name"], r["version"])
        for i in r["vulns"]:
            if i not in ids_of[k]:
                ids_of[k].append(i)
    ids = sorted({i for v in ids_of.values() for i in v})
    det = {i: (recs.get(i) or idx.get(i) or {}) for i in ids}
    extra = sorted({a for i in ids for a in det[i].get("aliases", []) if a not in det and not a.startswith("CVE-")})
    missing_alias = []
    for a in extra:
        r = idx.get(a)
        det[a] = r or {}
        if r is None:
            missing_alias.append(a)

    F, how, cve_of, adv = {}, {}, {}, collections.defaultdict(set)
    seen = set()
    for c4 in comps:
        if c4 in seen:  # 같은 서비스에 같은 패키지 버전이 두 파일에서 나오면 한 번만 (cartservice src, tests)
            continue
        seen.add(c4)
        svc, e, n, v = c4
        for i in ids_of.get(c4, []):
            recs_i = [i] + det[i].get("aliases", [])
            one = [a for a in recs_i if a.startswith("CVE-")]
            two = [a for r in recs_i for a in (det.get(r) or {}).get("aliases", []) if a.startswith("CVE-")]
            rel = sorted({a for r in recs_i for a in (det.get(r) or {}).get("related", []) if a.startswith("CVE-")})
            if one or two:
                c = (one + two)[0]
                key, how_key = (svc, e, n, v, c), "alias"
                cve_of[key] = c
            else:
                key, how_key = (svc, e, n, v, sorted(recs_i)[0]), "related" if rel else "none"
                if rel:
                    kev = sig["kev"] if sig else {}
                    cve_of[key] = ([x for x in rel if x in kev] or rel)[0]
            how[key] = how_key
            adv[key].add(i)
            sev = (det[i].get("database_specific") or {}).get("severity")
            F[key] = F.get(key) or sev

    res = {"components": len(comps), "components_unique": len(set(comps)),
           "components_by_eco": dict(collections.Counter(c[1] for c in comps)),
           "components_excl_test_csproj": sum(1 for r in rows if not re.search(r"/tests?/[^/]*\.csproj$", r["source"])),
           "services": len({c[0] for c in comps}),
           "vulnerable_components": sum(1 for c in set(comps) if ids_of.get(c)),
           "package_versions_all": len({c[1:] for c in comps}),
           "vulnerable_package_versions": len({c[1:] for c in comps if ids_of.get(c)}),
           "advisory_findings": sum(len(v) for k, v in ids_of.items()),
           "advisory_ids": len(ids), "advisory_id_prefix": dict(collections.Counter(i.split("-")[0] for i in ids)),
           "alias_records_extra": len(extra), "alias_records_missing": missing_alias,
           "mal_ids": [i for i in ids if i.startswith("MAL-")],
           "reported": len(F), "reported_by_eco": dict(collections.Counter(k[1] for k in F)),
           "join": dict(collections.Counter(how.values()))}
    pk = collections.Counter(k[1:4] for k in F)
    res["package_versions"] = len(pk)
    res["top5_share_pct"] = round(sum(n for _, n in pk.most_common(5)) / len(F) * 100, 1) if F else 0.0
    res["top5"] = [["|".join(k), n] for k, n in pk.most_common(5)]
    rows_c = list(cve_of)
    cves = sorted(set(cve_of.values()))
    res["unique_cves"] = len(cves)
    res["_F"], res["_how"], res["_cve_of"], res["_adv"], res["_cves"] = F, how, cve_of, adv, cves
    if sig is None:
        return res

    kev, ep, nvd = sig["kev"], sig["epss"], sig["nvd"]

    def ssvc(c):
        if c in nvd.index:
            r = nvd.loc[c]
            return (r["ssvc_automatable"] or None), (r["ssvc_technical"] or None)
        return None, None

    sv = {c: ssvc(c) for c in cves}

    def due(k, public):
        c = cve_of[k]
        a, t = sv[c]
        return BOD["YN"[c not in kev] + "YN"[not public] + "YN"[(a or "no").lower() != "yes"] + ("P" if (t or "total").lower() == "partial" else "T")]

    sigB = {k for k in rows_c if cve_of[k] in kev or ep.get(cve_of[k], 0) >= .1}
    crit = {k for k in rows_c if F[k] == "CRITICAL"}
    res.update({"rows_with_cve": len(rows_c), "ghsa_critical": len(crit), "kev_rows": sum(cve_of[k] in kev for k in rows_c),
                "kev_cves": sorted({cve_of[k] for k in rows_c if cve_of[k] in kev}),
                "epss01_cves": sorted({c for c in cves if ep.get(c, 0) >= .1}),
                "signal_B_rows": len(sigB), "crit_and_B": len(sigB & crit),
                "ghsa_severity_missing": sum(not v for v in F.values()),
                "ssvc_missing_cves": sum(sv[c] == (None, None) for c in cves),
                "nvd_missing_cves": sum(c not in nvd.index for c in cves)})
    for name, f in EXPOSURES.items():
        cnt = collections.Counter(due(k, f(k[0])) for k in rows_c)
        res[f"due_{name}"] = {d: cnt.get(d, 0) for d in DUE_ORDER}
    q = [k for k in rows_c if due(k, k[0] == PUBLIC) in ("3d", "3d+F", "14d") or k in sigB]
    qs = set(q)
    out = [k for k in rows_c if k not in qs]
    rng = random.Random(SEED)
    sample = [x for e in sorted({k[1] for k in out}) for x in rng.sample(sorted(k for k in out if k[1] == e), min(5, sum(k[1] == e for k in out)))]
    allpub = [k for k in rows_c if due(k, True) in ("3d", "3d+F", "14d") or k in sigB]
    by = collections.defaultdict(set)
    for k in rows_c:
        by[cve_of[k]].add(due(k, k[0] == PUBLIC))
    res.update({"queue": len(q), "queue_by_eco": dict(collections.Counter(k[1] for k in q)),
                "queue_by_service": dict(collections.Counter(k[0] for k in q)),
                "queue_unique_cves": len({cve_of[k] for k in q}),
                "queue_share_of_rows_with_cve_pct": round(len(q) / len(rows_c) * 100, 1) if rows_c else 0.0,
                "out_of_queue": len(out), "out_by_due": dict(collections.Counter(due(k, k[0] == PUBLIC) for k in out)),
                "out_by_eco": dict(collections.Counter(k[1] for k in out)), "out_package_versions": len({k[1:4] for k in out}),
                "sample": len(sample), "sample_by_eco": dict(collections.Counter(k[1] for k in sample)),
                "all_public_queue": len(allpub), "all_public_queue_package_versions": len({k[1:4] for k in allpub}),
                "go_share_reported_pct": round(sum(k[1] == "Go" for k in F) / len(F) * 100, 1) if F else 0.0,
                "due_split_cves": sum(len(v) > 1 for v in by.values()),
                "kev_detail": [[k[0], k[2], k[3], cve_of[k], how[k]] for k in rows_c if cve_of[k] in kev],
                "no_cve": sorted({(k[1], k[2], k[4]) for k in F if how[k] == "none"}),
                "related_rows": [[k[0], k[2], k[3], k[4], cve_of[k]] for k in rows_c if how[k] == "related"]})
    # 행 표
    table, in_sample = [], set(sample)
    for k in F:
        c = cve_of.get(k, "")
        a, t = sv.get(c, (None, None)) if c else (None, None)
        nv = nvd.loc[c] if c and c in nvd.index else None
        row = {"label": label, "service": k[0], "ecosystem": k[1], "package": k[2], "version": k[3], "key_id": k[4],
               "advisories": " ".join(sorted(adv[k])), "join": how[k], "cve": c, "ghsa_severity": F[k] or "",
               "kev": int(c in kev) if c else "", "epss": ep.get(c, "") if c else "",
               "cvss3_max": nv["cvss3_max"] if nv is not None else "", "ssvc_automatable": a or "", "ssvc_technical": t or "",
               "ssvc_default_used": int((a, t) == (None, None)) if c else ""}
        for name, f in EXPOSURES.items():
            row[f"due_{name}"] = due(k, f(k[0])) if c else ""
        row["in_queue"] = int(k in qs)
        row["queue_reason"] = ("" if k not in qs else
                               "+".join(x for x, ok in (("due", due(k, k[0] == PUBLIC) in ("3d", "3d+F", "14d")),
                                                        ("KEV", c in kev), ("EPSS>=0.1", ep.get(c, 0) >= .1)) if ok))
        row["in_sample"] = int(k in in_sample)
        table.append(row)
    res["_table"] = table
    res["_sample"] = sample
    return res


# ---------- 경로 비교 ----------
def pkgset(rows: list[dict]) -> dict[tuple, set]:
    """(생태계, 정규화 이름, 정규화 버전) -> 권고 ID 집합. 버전 UNKNOWN 과 파일 항목은 뺀다."""
    out = collections.defaultdict(set)
    for r in rows:
        if r["version"] in ("", "UNKNOWN"):
            continue
        out[(r["eco"], norm_name(r["eco"], r["name"]), norm_ver(r["eco"], r["version"]))] |= set(r["vulns"])
    return out


def compare_paths(label: str, lock_rows, sbom_rows) -> tuple[list[dict], list[dict]]:
    A, B = pkgset(lock_rows), pkgset(sbom_rows)
    ecos = sorted({k[0] for k in A} | {k[0] for k in B})
    summary, diff = [], []
    for e in ecos:
        a = {k: v for k, v in A.items() if k[0] == e}
        b = {k: v for k, v in B.items() if k[0] == e}
        summary.append({"label": label, "ecosystem": e,
                        "lock_package_versions": len(a), "sbom_package_versions": len(b),
                        "both": len(a.keys() & b.keys()), "only_lock": len(a.keys() - b.keys()), "only_sbom": len(b.keys() - a.keys()),
                        "lock_vulnerable": sum(1 for v in a.values() if v), "sbom_vulnerable": sum(1 for v in b.values() if v),
                        "lock_advisory_ids": len(set().union(*a.values()) if a else set()),
                        "sbom_advisory_ids": len(set().union(*b.values()) if b else set()),
                        "same_ids_on_shared": sum(1 for k in a.keys() & b.keys() if a[k] == b[k])})
        for k in sorted(a.keys() ^ b.keys()):
            diff.append({"label": label, "ecosystem": e, "package": k[1], "version": k[2],
                         "side": "only_lock" if k in a else "only_sbom", "advisories": " ".join(sorted(a.get(k) or b.get(k) or []))})
        for k in sorted(a.keys() & b.keys()):
            if a[k] != b[k]:
                diff.append({"label": label, "ecosystem": e, "package": k[1], "version": k[2], "side": "ids_differ",
                             "advisories": "lock:" + " ".join(sorted(a[k])) + " | sbom:" + " ".join(sorted(b[k]))})
    return summary, diff


def syft_components(p: Path) -> tuple[collections.Counter, collections.Counter, int, int]:
    d = json.loads(p.read_text())
    per_svc, per_eco, files, unknown = collections.Counter(), collections.Counter(), 0, 0
    for c in d.get("components", []):
        if c.get("type") == "file":
            files += 1
            continue
        props = {x["name"]: x["value"] for x in c.get("properties", [])}
        loc = props.get("syft:location:0:path", "")
        per_svc[service_of(loc) if loc else "?"] += 1
        per_eco[props.get("syft:package:type", "?")] += 1
        unknown += c.get("version") in (None, "", "UNKNOWN")
    return per_svc, per_eco, files, unknown


def sbom_rows_with_service(sbom_cdx: Path, sbom_scan_rows: list[dict]) -> list[dict]:
    """SBOM 스캔에는 서비스가 없다. Syft SBOM 의 위치로 (생태계, 이름, 버전) -> 서비스를 붙인다."""
    eco_of = {"npm": "npm", "golang": "Go", "pypi": "PyPI", "maven": "Maven", "nuget": "NuGet", "github": "GitHub Actions"}
    d = json.loads(sbom_cdx.read_text())
    where = collections.defaultdict(set)
    for c in d.get("components", []):
        if c.get("type") == "file" or not c.get("purl"):
            continue
        props = {x["name"]: x["value"] for x in c.get("properties", [])}
        t = c["purl"].split(":", 1)[1].split("/", 1)[0]
        e = eco_of.get(t, t)
        name = c["name"] if e != "Maven" or not c.get("group") else f"{c['group']}:{c['name']}"
        where[(e, norm_name(e, name), norm_ver(e, c.get("version", "")))].add(service_of(props.get("syft:location:0:path", "/?/x")))
    out = []
    for r in sbom_scan_rows:
        k = (r["eco"], norm_name(r["eco"], r["name"]), norm_ver(r["eco"], r["version"]))
        for s in sorted(where.get(k, {"?"})):
            out.append(dict(r, service=s))
    return out


# ---------- 로그 점검 ----------
LOG_PATTERNS = {
    "db_load_error": r"could not load db|no offline version|unable to fetch OSV database|failed to load",
    "deps_dev_blocked": r"api\.deps\.dev",
    "resolution_failed": r"failed resolution",
    "extraction_error": r"Error during extraction",
    "no_purl_in_sbom": r"Neither CPE nor PURL found",
    "call_analysis": r"code analysis|govulncheck",
    "warn": r"\bWARN\b|warning",
    "error_other": r"\berror\b",
}


def scan_logs() -> list[dict]:
    out = []
    for lab in LABELS:
        for log in sorted((TMP / lab).glob("*.log")):
            txt = log.read_text(errors="replace").splitlines()
            for cat, pat in LOG_PATTERNS.items():
                hits = [l for l in txt if re.search(pat, l, re.I)]
                if cat == "error_other":
                    hits = [l for l in hits if not re.search("|".join(v for k, v in LOG_PATTERNS.items() if k != "error_other"), l, re.I)]
                if hits:
                    out.append({"label": lab, "step": log.stem, "category": cat, "lines": len(hits), "example": hits[0][:300]})
    return out


def write_csv(p: Path, rows: list[dict]) -> None:
    if not rows:
        p.write_text("")
        return
    keys = list(rows[0])
    for r in rows[1:]:
        keys += [k for k in r if k not in keys]
    with open(p, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def reach_column(res_by_label: dict, idx: "OSVIndex") -> tuple[dict, dict]:
    """reach/ 결과(다른 에이전트 담당)가 있으면 읽고, 없으면 'not yet'.

    - 맞추는 키: 커밋 해시(commit 열) + 서비스 + OSV ID + 모듈(= 보고 행의 패키지). 표준 라이브러리 행은 헤드라인 큐에 없어서 안 맞는다
    - 큐 Go 행마다 그 행 권고들의 수준 중 가장 높은 것 (symbol > package > module). levels.csv 에 없으면 none
    - 보조 연결: 권고 ID 로 못 찾으면 같은 커밋, 서비스, 모듈의 GO- 레코드 중 OSV aliases 나 related 에 그 행 CVE 가 있는 것.
      (예: x/net 의 CVE-2023-44487 행은 GHSA-qppj-fm5r-hxr3 로만 붙는데, Go DB 는 같은 수정을 GO-2023-2102 related 로 둔다)
      이렇게 붙은 행은 detail 의 via_related_cve 로 따로 센다
    - 값: 'symbol 행 수 / 큐 Go 행 수'. 자세한 분포는 summary.json go_reachable_detail
    """
    p = INNO / "results" / "reach" / "levels.csv"
    if not p.exists():
        return {lab: "not yet" for lab in res_by_label}, {}
    meta = {"file": str(p.relative_to(INNO)), "sha256": __import__("hashlib").sha256(p.read_bytes()).hexdigest()[:12],
            "mtime_utc": datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    try:
        df = pd.read_csv(p, dtype=str, keep_default_na=False)
    except Exception as e:  # 형식을 모를 때 지어내지 않는다
        return {lab: f"levels.csv 읽기 실패: {e}" for lab in res_by_label}, meta
    need = {"commit", "service", "osv_id", "module", "level"}
    if not need <= set(df.columns):
        return {lab: f"levels.csv 형식 미확인 (열: {', '.join(df.columns)})" for lab in res_by_label}, meta
    rank = {"symbol": 3, "package": 2, "module": 1}
    lv, by_mod = {}, collections.defaultdict(set)
    for r in df.itertuples():
        k = (r.commit, r.service, r.osv_id, r.module)
        lv[k] = max(lv.get(k, 0), rank.get(r.level, 0))
        by_mod[(r.commit, r.service, r.module)].add(r.osv_id)
    out, detail = {}, {}
    for lab, res in res_by_label.items():
        if not (df["commit"] == COMMITS[lab]).any():
            out[lab] = "levels.csv 에 이 커밋 없음"
            continue
        cnt = collections.Counter()
        for row in res["_table"]:
            if not (row["in_queue"] and row["ecosystem"] == "Go"):
                continue
            best = max((lv.get((COMMITS[lab], row["service"], a, row["package"]), 0) for a in row["advisories"].split()), default=0)
            via = "id"
            if best == 0 and row["cve"]:
                for gid in sorted(by_mod.get((COMMITS[lab], row["service"], row["package"]), ())):
                    rec = idx.get(gid) or {}
                    if row["cve"] in rec.get("aliases", []) + rec.get("related", []):
                        best = max(best, lv[(COMMITS[lab], row["service"], gid, row["package"])])
                        via = f"related_cve:{gid}"
                if best:
                    cnt["via_related_cve"] += 1
            name = {3: "symbol", 2: "package", 1: "module", 0: "none"}[best]
            row["reach_level"] = name if via == "id" or name == "none" else f"{name} ({via})"
            cnt[name] += 1
        q = sum(v for k, v in cnt.items() if k != "via_related_cve")
        out[lab] = f"{cnt['symbol']} / {q}"
        detail[lab] = dict(cnt, go_queue_rows=q)
    return out, {"source": meta, **detail}


def git_info() -> dict:
    def g(*a):
        try:
            return subprocess.run(["git", "-C", str(INNO), *a], capture_output=True, text=True, timeout=30).stdout.strip()
        except Exception:
            return ""
    nvd = "/home/user/work/nvd"
    nvd_head = subprocess.run(["git", "-C", nvd, "log", "-1", "--format=%H %cI"], capture_output=True, text=True).stdout.strip() if Path(nvd).exists() else ""
    if not nvd_head:  # 미러 복제가 지워졌으면 m1 재현 기록의 고정 커밋 (nvd_table.csv.gz 를 만든 커밋)
        rc = INNO / "results" / "m1" / "REPRO_CHECK.md"
        m = re.search(r"nvd-json-data-feeds `([0-9a-f]{40})`", rc.read_text()) if rc.exists() else None
        nvd_head = f"{m[1]} (results/m1/REPRO_CHECK.md 기록. 복제 없음)" if m else "미확인"
    # m2_dirty: 실행한 코드(m2/, common/)가 커밋본과 다른가. results/m2 는 scan.sh 가 먼저 로그를 다시 쓰므로 보지 않는다
    #   (예전 정의는 results/m2 까지 봐서 코드가 깨끗해도 항상 true였다. 2026-11-02 정정 06-6)
    return {"repo_head": g("rev-parse", "HEAD"), "m2_dirty": bool(g("status", "--porcelain", "--", "m2", "common")),
            "nvd_feed_commit": nvd_head}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    t0 = datetime.now(timezone.utc)
    # 별칭 레코드 BIT-* 를 위해 Bitnami 덤프를 받는다 (스캔 대상 생태계는 아니라 osv-scanner 캐시에는 넣지 않는다)
    bit = fetch(f"{GCS}/Bitnami/all.zip", "osv/Bitnami/all.zip", manifest="m2")
    zips = {e: OSVDB / e / "all.zip" for e in ["Go", "npm", "PyPI", "NuGet", "Maven", "GitHub Actions"]}
    zips["Bitnami"] = bit
    idx = OSVIndex(zips)

    # 0. 스캔 무결성: 패키지에 나온 생태계마다 'Loaded <생태계> local db' 가 로그에 있어야 한다
    integrity = []
    scans = {}
    for lab in LABELS:
        for step in STEPS:
            p = TMP / lab / f"{step}.json"
            rows, recs = load_scan(p)
            ecos = {r["eco"] for r in rows if r["version"] not in ("", "UNKNOWN")}
            dbs = loaded_dbs(TMP / lab / f"{step}.log")
            lost = sorted(ecos - dbs)
            integrity.append({"label": lab, "step": step, "packages": len(rows), "ecosystems": " ".join(sorted(ecos)),
                              "dbs_loaded": " ".join(sorted(dbs)), "ecosystems_without_db": " ".join(lost)})
            if lost:
                raise SystemExit(f"{lab} {step}: DB 없이 스캔된 생태계 {lost}. 다시 돌린다")
            scans[(lab, step)] = (rows, recs)
    write_csv(OUT / "scan_integrity.csv", integrity)

    # 1. 신호
    sig = load_signals()

    res, svc_rows, path_rows, path_diff, std_rows, findings = {}, [], [], [], [], []
    for lab in LABELS:
        lock_rows, lock_recs = scans[(lab, "lock")]
        r = analyze(lock_rows, lock_recs, idx, sig, lab)
        res[lab] = r
        findings += r["_table"]
        # 서비스별: Syft 구성요소, osv-scanner 패키지, 취약 패키지, 보고 행, 큐
        per_svc, per_eco, files, unknown = syft_components(TMP / lab / "sbom.cdx.json")
        r["syft_components"] = sum(per_svc.values())
        r["syft_by_type"] = dict(per_eco)
        r["syft_file_entries"] = files
        r["syft_unknown_version"] = unknown
        r["syft_services"] = len([s for s in per_svc if s != "?"])
        lock_by_svc = collections.Counter(x["service"] for x in lock_rows)
        vul_by_svc = collections.Counter(x["service"] for x in lock_rows if x["vulns"])
        rep_by_svc = collections.Counter(t["service"] for t in r["_table"])
        q_by_svc = collections.Counter(t["service"] for t in r["_table"] if t["in_queue"])
        eco_by_svc = collections.defaultdict(set)
        for x in lock_rows:
            eco_by_svc[x["service"]].add(x["eco"])
        for s in sorted(set(per_svc) | set(lock_by_svc)):
            svc_rows.append({"label": lab, "service": s, "ecosystems": " ".join(sorted(eco_by_svc.get(s, []))),
                             "syft_components": per_svc.get(s, 0), "osv_lock_packages": lock_by_svc.get(s, 0),
                             "osv_lock_vulnerable": vul_by_svc.get(s, 0), "reported_rows": rep_by_svc.get(s, 0),
                             "signal_queue_rows": q_by_svc.get(s, 0)})
        # 두 경로 비교
        sb_rows, sb_recs = scans[(lab, "sbom")]
        sm, df = compare_paths(lab, lock_rows, sb_rows)
        path_rows += sm
        path_diff += df
        rs = analyze(sbom_rows_with_service(TMP / lab / "sbom.cdx.json", sb_rows), sb_recs, idx, sig, lab)
        r["sbom_path"] = {k: rs[k] for k in ("components", "vulnerable_package_versions", "advisory_ids", "reported", "reported_by_eco",
                                              "unique_cves", "kev_rows", "queue", "queue_by_eco")}
        # deps.dev 해석 시도 변형과 같은지
        rr, rrec = scans[(lab, "lock_resolve")]
        same = sorted((x["source"], x["eco"], x["name"], x["version"], tuple(x["vulns"])) for x in rr) == \
            sorted((x["source"], x["eco"], x["name"], x["version"], tuple(x["vulns"])) for x in lock_rows)
        r["lock_resolve_identical"] = same
        # 호출 분석 켠 기본 실행: 권고 목록이 같은지, called 표시 (참고)
        cr, _ = scans[(lab, "lock_call")]
        r["lock_call_identical_vulns"] = sorted((x["source"], x["eco"], x["name"], x["version"], tuple(x["vulns"])) for x in cr) == \
            sorted((x["source"], x["eco"], x["name"], x["version"], tuple(x["vulns"])) for x in lock_rows)
        called = {(x["service"], x["eco"], x["name"], x["version"]): x["called"] for x in cr}
        go_q = go_called = go_rep = go_rep_called = go_unknown = 0
        for t in r["_table"]:
            if t["ecosystem"] != "Go":
                t["osv_call_analysis"] = ""
                continue
            flags = [called.get((t["service"], "Go", t["package"], t["version"]), {}).get(a) for a in t["advisories"].split()]
            flags = [f for f in flags if f is not None]
            t["osv_call_analysis"] = "called" if any(flags) else ("not_called" if flags else "no_result")
            go_rep += 1
            go_rep_called += t["osv_call_analysis"] == "called"
            go_unknown += t["osv_call_analysis"] == "no_result"
            if t["in_queue"]:
                go_q += 1
                go_called += t["osv_call_analysis"] == "called"
        r["osv_call_analysis"] = {"go_reported_rows": go_rep, "go_reported_called": go_rep_called, "go_no_result": go_unknown,
                                  "go_queue_rows": go_q, "go_queue_called": go_called,
                                  "go_groups_with_analysis": sum(len(x["called"]) for x in cr)}
        # 표준 라이브러리 변형
        # std_probe: 빈 모듈의 stdlib 결과를 Go 서비스마다 붙인다 (서비스 4개가 같은 golang 이미지인 것은 scan.sh 가 확인)
        pr, prec = scans[(lab, "std_probe")]
        probe = [x for x in pr if x["name"] == "stdlib"]
        go_svcs = sorted({x["service"] for x in lock_rows if x["eco"] == "Go"})
        composite = lock_rows + [dict(probe[0], service=sv, source=f"(std_probe) {sv}") for sv in go_svcs]
        scans[(lab, "lock+std_probe")] = (composite, {**lock_recs, **prec})
        for step, note in (("lock", "stdlib 제외 (osv-scanner 2.7.0 기본. 헤드라인)"),
                           ("lock_std_gomod", "stdlib 포함, ScanGoModVersion (go.mod toolchain 또는 go 지시어)"),
                           ("lock_std_override", "GoVersionOverride=Dockerfile 버전. 매칭 뒤 표시만 바뀜 (무효, 동작 확인용)"),
                           ("lock+std_probe", "stdlib 포함, Dockerfile golang 이미지 버전으로 매칭 (빈 모듈 탐침)")):
            v = r if step == "lock" else analyze(*scans[(lab, step)], idx, sig, lab)
            std = [x for x in scans[(lab, step)][0] if x["name"] == "stdlib"]
            std_rows.append({"label": lab, "variant": step, "note": note,
                             "stdlib_versions": " ".join(sorted({x["version"] for x in std})),
                             "stdlib_advisory_ids": len({i for x in std for i in x["vulns"]}),
                             "components": v["components"], "reported": v["reported"], "reported_Go": v["reported_by_eco"].get("Go", 0),
                             "unique_cves": v["unique_cves"], "kev_rows": v["kev_rows"], "kev_cves": " ".join(v["kev_cves"]),
                             "queue": v["queue"], "queue_Go": v["queue_by_eco"].get("Go", 0),
                             "out_of_queue": v["out_of_queue"], "sample": v["sample"]})

    # 2. Go 도달 열
    reach, reach_detail = reach_column(res, idx)

    # 3. 깔때기
    stages = [("구성요소", "서비스 x 패키지 버전 (osv-scanner 잠금 파일 항목)", "components"),
              ("취약 구성요소", "권고 1건 이상인 구성요소", "vulnerable_components"),
              ("권고 보고", "구성요소 x 권고 ID (도구 원 출력)", "advisory_findings"),
              ("보고 (CVE 정규화)", "구성요소 x CVE (같은 CVE 권고는 합침. 기획안 '보고')", "reported"),
              ("고유 CVE", "CVE (related 후보 포함)", "unique_cves"),
              ("EPSS>=0.1", "고유 CVE 중 EPSS 2026-11-01 >= 0.1", None),
              ("KEV", "고유 CVE 중 KEV 2026.10.30", None),
              ("신호 큐", "보고 행 (프런트엔드만 공개: 3d, 3d+F, 14d, KEV, EPSS>=0.1)", "queue"),
              ("Go 도달 확인", "신호 큐 Go 행 중 symbol 수준 / 큐 Go 행 (results/reach/levels.csv, 다른 작업)", None),
              ("참고: osv-scanner 내장 Go 호출 분석", "신호 큐 Go 행 중 called (lock_call, 기본값 실행)", None)]
    funnel = []
    for st, unit, key in stages:
        row = {"stage": st, "unit": unit}
        for lab in LABELS:
            if key:
                row[lab] = res[lab][key]
            elif st == "EPSS>=0.1":
                row[lab] = len(res[lab]["epss01_cves"])
            elif st == "KEV":
                row[lab] = len(res[lab]["kev_cves"])
            elif st.startswith("참고"):
                ca = res[lab]["osv_call_analysis"]
                row[lab] = f"{ca['go_queue_called']} / {ca['go_queue_rows']}"
            else:
                row[lab] = reach[lab]
        funnel.append(row)
    write_csv(OUT / "funnel.csv", funnel)

    # 4. 기획안 대조 (숫자만. 이유는 m2/NOTES.md)
    cmp_rows = []
    for lab in ("v0.5.0", "main"):
        r, p = res[lab], PROPOSAL[lab]
        mine = {"services": r["services"], "components": r["components"], "reported": r["reported"],
                "eco_npm": r["reported_by_eco"].get("npm", 0), "eco_Go": r["reported_by_eco"].get("Go", 0),
                "eco_PyPI": r["reported_by_eco"].get("PyPI", 0), "eco_Maven": r["reported_by_eco"].get("Maven", 0),
                "package_versions": r["package_versions"], "top5_share_pct": r["top5_share_pct"],
                "join_alias": r["join"].get("alias", 0), "join_related": r["join"].get("related", 0), "join_none": r["join"].get("none", 0),
                "unique_cves": r["unique_cves"], "ghsa_critical": r["ghsa_critical"], "kev_rows": r["kev_rows"],
                "signal_B_rows": r["signal_B_rows"], "crit_and_B": r["crit_and_B"],
                "due_all_internal": ", ".join(str(r["due_all_internal"][d]) for d in DUE_ORDER),
                "due_frontend_only": ", ".join(str(r["due_frontend_only"][d]) for d in DUE_ORDER),
                "due_all_public": ", ".join(str(r["due_all_public"][d]) for d in DUE_ORDER),
                "queue": r["queue"], "queue_Go": r["queue_by_eco"].get("Go", 0), "out_of_queue": r["out_of_queue"],
                "out_package_versions": r["out_package_versions"], "sample": r["sample"], "mal": len(r["mal_ids"])}
        for k, pv in p.items():
            mv = mine[k]
            delta = round(mv - pv, 1) if isinstance(pv, (int, float)) else ""
            cmp_rows.append({"label": lab, "item": k, "proposal": pv, "this_run": mv, "delta": delta})
    write_csv(OUT / "compare_proposal.csv", cmp_rows)

    # 5. 표, 로그, 기준 시점
    write_csv(OUT / "services.csv", svc_rows)
    write_csv(OUT / "path_compare.csv", path_rows)
    write_csv(OUT / "path_compare_diff.csv", path_diff)
    write_csv(OUT / "stdlib_variants.csv", std_rows)
    for lab in LABELS:
        write_csv(OUT / f"findings_{lab}.csv", [t for t in findings if t["label"] == lab])
    write_csv(OUT / "log_issues.csv", scan_logs())

    inv = pd.read_csv(OUT / "osv_db_inventory.csv")
    asof = [{"source": f"OSV {r.ecosystem} all.zip", "as_of": r.max_record_modified, "detail": f"records {r.records}, sha256 {r.sha256[:12]}, file {r.file_mtime_utc}"}
            for r in inv.itertuples()]
    with zipfile.ZipFile(bit) as z:
        mx = max(json.loads(z.read(n)).get("modified", "") for n in z.namelist())
        nrec = len(z.namelist())
    m2man = json.loads((INNO / "data" / "manifest_m2.json").read_text())
    asof.append({"source": "OSV Bitnami all.zip (별칭 조회만)", "as_of": mx, "detail": f"records {nrec}, fetched {m2man['osv/Bitnami/all.zip']['fetched_utc']}, sha256 {m2man['osv/Bitnami/all.zip']['sha256'][:12]}"})
    asof.append({"source": "KEV", "as_of": sig["kev_meta"]["dateReleased"], "detail": f"catalogVersion {sig['kev_meta']['catalogVersion']}, count {sig['kev_meta']['count']}"})
    asof.append({"source": "EPSS", "as_of": sig["epss_meta"], "detail": "epss_scores-2026-11-01.csv.gz"})
    gi = git_info()
    asof.append({"source": "NVD 표 (CVSS, SSVC)", "as_of": gi["nvd_feed_commit"], "detail": "fkie-cad/nvd-json-data-feeds 복제 HEAD, m1/nvd_table.py"})
    for lab in LABELS:
        asof.append({"source": f"Online Boutique {lab}", "as_of": COMMITS[lab], "detail": "git worktree HEAD"})
    write_csv(OUT / "data_asof.csv", asof)

    summary = {"generated_utc": t0.strftime("%Y-%m-%dT%H:%M:%SZ"), "git": gi,
               "reproduce": "cd lotte/innovate && bash m2/run.sh", "go_reachable": reach, "go_reachable_detail": reach_detail}
    for lab in LABELS:
        summary[lab] = {k: v for k, v in res[lab].items() if not k.startswith("_")}
        summary[lab]["commit"] = COMMITS[lab]
        summary[lab]["sample_rows"] = [[k[0], k[1], k[2], k[3], res[lab]["_cve_of"][k]] for k in res[lab]["_sample"]]
    (OUT / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1, default=list) + "\n")
    for lab in LABELS:
        s = summary[lab]
        print(lab, "서비스", s["services"], "구성요소", s["components"], "Syft", s["syft_components"], "보고", s["reported"], s["reported_by_eco"],
              "패키지버전", s["package_versions"], "상위5", s["top5_share_pct"], "조인", s["join"], "고유CVE", s["unique_cves"],
              "KEV행", s["kev_rows"], s["kev_cves"], "큐", s["queue"], s["queue_by_eco"], "큐밖", s["out_of_queue"], "표본", s["sample"],
              "MAL", s["mal_ids"], "별칭 레코드 없음", len(s["alias_records_missing"]), "resolve 동일", s["lock_resolve_identical"])
    print("Go 도달:", reach)


if __name__ == "__main__":
    main()
