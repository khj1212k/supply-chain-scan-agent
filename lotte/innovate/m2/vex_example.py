"""CycloneDX 1.6 VEX 예시 1건: CVE-2023-44487 (HTTP/2 Rapid Reset), Online Boutique v0.5.0, 상태 in_triage.

- 대상 구성요소: 이번 오프라인 스캔(results/m2/findings_v0.5.0.csv)에서 이 CVE 로 조인된 행 전부 (지어내지 않는다)
- purl: osv-scanner 잠금 파일 스캔 출력의 purl
- 점수: NVD 미러 레코드의 CVSS 벡터 (없으면 nvd_table 의 점수만). EPSS, KEV 는 properties 로
- 상태: 사람 승인과 도달성 확인 전이라 in_triage. justification 은 넣지 않는다 (not_affected 일 때만 쓰는 칸)
- 검증: (1) 쓴 enum 값을 1.6 스키마 정의와 대조 (2) jsonschema 로 전체 스키마 검증 (spdx, jsf 참조 포함)
  - 'format'(date-time 등) 검사는 rfc3339-validator 가 없으면 건너뛴다. 결과 파일에 그대로 적는다

사용: .venv/bin/python m2/vex_example.py
출력: results/m2/vex_CVE-2023-44487.cdx.json, results/m2/vex_validation.json
"""
from __future__ import annotations

import csv
import gzip
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

INNO = Path(__file__).resolve().parents[1]
OUT = INNO / "results" / "m2"
SCHEMA_DIR = INNO / "data" / "raw" / "cyclonedx" / "1.6"
TMP = Path(os.environ.get("M2TMP", "/home/user/work/m2tmp"))
NVD = Path("/home/user/work/nvd")
CVE = "CVE-2023-44487"
LABEL, COMMIT = "v0.5.0", "3c0d6597809d1f40dccd24b757b7ca67d40cadf8"
STATE = "in_triage"


def purls() -> dict:
    p = TMP / LABEL / "lock.json"
    d = json.loads(p.read_text()) if p.exists() else json.loads(gzip.open(OUT / "raw" / f"{LABEL}_lock.json.gz").read())
    out = {}
    for res in d["results"]:
        svc = Path(res["source"]["path"]).parts
        svc = svc[svc.index("src") + 1]
        for pk in res["packages"]:
            P = pk["package"]
            out[(svc, P["ecosystem"], P["name"], P["version"])] = P.get("purl", "")
    return out


def nvd_rating() -> list[dict]:
    f = NVD / "CVE-2023" / "CVE-2023-444xx" / f"{CVE}.json"
    if not f.exists():
        return []
    d = json.loads(f.read_text())
    out = []
    for m in d.get("metrics", {}).get("cvssMetricV31", []):
        if m.get("type") == "Primary":
            c = m["cvssData"]
            out.append({"source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{CVE}"},
                        "score": c["baseScore"], "severity": c["baseSeverity"].lower(), "method": "CVSSv31", "vector": c["vectorString"]})
    return out


def main() -> None:
    rows = [r for r in csv.DictReader(open(OUT / f"findings_{LABEL}.csv")) if r["cve"] == CVE]
    if not rows:
        raise SystemExit(f"{CVE} 행이 findings_{LABEL}.csv 에 없다")
    pu = purls()
    comps, affects, advisories = [], [], set()
    for r in sorted(rows, key=lambda r: (r["service"], r["package"])):
        purl = pu.get((r["service"], r["ecosystem"], r["package"], r["version"]), "")
        ref = f"{r['service']}:{purl or r['package'] + '@' + r['version']}"
        comps.append({"type": "library", "bom-ref": ref, "name": r["package"], "version": r["version"], "purl": purl,
                      "properties": [{"name": "lab:service", "value": r["service"]},
                                     {"name": "lab:bod_due_frontend_only", "value": r["due_frontend_only"]},
                                     {"name": "lab:osv_advisories", "value": r["advisories"]}]})
        affects.append({"ref": ref})
        advisories |= set(r["advisories"].split())
    epss, kev = rows[0]["epss"], rows[0]["kev"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    services = sorted({r["service"] for r in rows})
    vex = {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"applied-llm-lab/m2/{COMMIT}/{CVE}")),
        "version": 1,
        "metadata": {"timestamp": now,
                     "tools": {"components": [{"type": "application", "name": "osv-scanner", "version": "2.7.0"},
                                              {"type": "application", "name": "syft", "version": "1.55.0"}]},
                     "component": {"type": "application", "bom-ref": "online-boutique", "name": "online-boutique",
                                   "version": LABEL, "properties": [{"name": "lab:git_commit", "value": COMMIT}]}},
        "components": comps,
        "vulnerabilities": [{
            "bom-ref": f"vuln:{CVE}", "id": CVE,
            "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{CVE}"},
            "references": [{"id": a, "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{a}"}} for a in sorted(advisories)],
            "ratings": nvd_rating(),
            "analysis": {"state": STATE,
                         "detail": (f"오프라인 OSV-Scanner 잠금 파일 스캔에서 {len(rows)}행({', '.join(services)})이 이 CVE 로 조인됨. "
                                    "호출 도달성(govulncheck)과 HTTP/2 서버 노출 확인 전, 사람 승인 전이라 in_triage. "
                                    "not_affected 판정은 근거(호출 경로 없음, 평문 HTTP/1.1 등)를 확인한 뒤 사람이 바꾼다"),
                         "firstIssued": now, "lastUpdated": now},
            "affects": affects,
            "properties": [{"name": "lab:epss_2026-11-01", "value": str(epss)}, {"name": "lab:kev_2026.10.30", "value": str(kev)}],
        }],
    }
    (OUT / f"vex_{CVE}.cdx.json").write_text(json.dumps(vex, ensure_ascii=False, indent=1) + "\n")

    # 검증
    schema = json.loads((SCHEMA_DIR / "bom-1.6.schema.json").read_text())
    defs = schema["definitions"]
    enum_checks = {
        "analysis.state": STATE in defs["impactAnalysisState"]["enum"],
        "ratings.method": all(r["method"] in defs["scoreMethod"]["enum"] for r in vex["vulnerabilities"][0]["ratings"]),
        "ratings.severity": all(r["severity"] in defs["severity"]["enum"] for r in vex["vulnerabilities"][0]["ratings"]),
        "components.type": all(c["type"] in defs["component"]["properties"]["type"]["enum"] for c in comps),
    }
    full = {"ran": False}
    try:
        import jsonschema
        from importlib.metadata import version
        from referencing import Registry, Resource
        reg = Registry()
        for f in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
            s = json.loads((SCHEMA_DIR / f).read_text())
            reg = reg.with_resource(s["$id"], Resource.from_contents(s))
        fc = jsonschema.Draft7Validator.FORMAT_CHECKER
        v = jsonschema.Draft7Validator(schema, registry=reg, format_checker=fc)
        errs = sorted(v.iter_errors(vex), key=lambda e: list(e.path))
        try:
            import rfc3339_validator  # noqa: F401
            fmt = "date-time 검사함"
        except ImportError:
            fmt = "date-time 형식 검사는 건너뜀 (rfc3339-validator 없음)"
        full = {"ran": True, "jsonschema": version("jsonschema"), "valid": not errs, "errors": [f"{list(e.path)}: {e.message}" for e in errs[:20]],
                "format_note": fmt}
    except ImportError as e:
        full = {"ran": False, "reason": f"jsonschema 없음: {e}"}
    result = {"file": f"results/m2/vex_{CVE}.cdx.json", "components": len(comps), "services": services,
              "advisories": sorted(advisories), "enum_checks": enum_checks, "full_schema": full}
    (OUT / "vex_validation.json").write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n")
    print(json.dumps(result, ensure_ascii=False))
    if not all(enum_checks.values()) or (full.get("ran") and not full.get("valid")):
        raise SystemExit("VEX 검증 실패")


if __name__ == "__main__":
    main()
