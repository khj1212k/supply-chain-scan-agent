"""NVD 미러(fkie-cad/nvd-json-data-feeds)의 CVE 파일 41만 개를 표 하나로 줄인다.

출력: data/raw/derived/nvd_table.csv.gz
열: cve, published, status, cvss3_max, cvss3_nvd, cvss4_max, cvss2_max,
    ssvc_exploitation, ssvc_automatable, ssvc_technical

- cvss3_max: v3.1, v3.0 점수 중 최대 (Primary, Secondary 모두). 기획안 부록 B 와 같은 규칙
- cvss3_nvd: NVD 자체(Primary) v3 점수. 없으면 빈칸
- CVSS 는 미러 커밋(1b66e03) 기준 현재 값이다 (RESULTS 'CVSS는 현재 값'과 같은 정의)
사용: python m1/nvd_table.py /home/user/work/nvd
"""
from __future__ import annotations

import csv
import gzip
import json
import os
import sys
from multiprocessing import Pool
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "raw" / "derived" / "nvd_table.csv.gz"
COLS = ["cve", "published", "status", "cvss3_max", "cvss3_nvd", "cvss4_max", "cvss2_max",
        "ssvc_exploitation", "ssvc_automatable", "ssvc_technical"]


def _scores(ms: dict, keys) -> list[float]:
    return [m["cvssData"]["baseScore"] for k in keys for m in ms.get(k, []) if "cvssData" in m]


def parse(path: str) -> list:
    with open(path, "rb") as f:
        d = json.load(f)
    ms = d.get("metrics", {}) or {}
    v3 = _scores(ms, ("cvssMetricV31", "cvssMetricV30"))
    v3n = [m["cvssData"]["baseScore"] for k in ("cvssMetricV31", "cvssMetricV30")
           for m in ms.get(k, []) if m.get("type") == "Primary" and "cvssData" in m]
    v4 = _scores(ms, ("cvssMetricV40",))
    v2 = _scores(ms, ("cvssMetricV2",))
    ssvc = {}
    for s in ms.get("ssvcV203", []):
        for o in (s.get("ssvcData") or {}).get("options", []):
            ssvc.update({k.lower(): v for k, v in o.items()})
    return [d["id"], d.get("published", "")[:19], d.get("vulnStatus", ""),
            max(v3) if v3 else "", max(v3n) if v3n else "", max(v4) if v4 else "", max(v2) if v2 else "",
            ssvc.get("exploitation", ""), ssvc.get("automatable", ""), ssvc.get("technicalimpact", "")]


def main(nvd_dir: str) -> None:
    files = []
    for dp, _, fs in os.walk(nvd_dir):
        if "/.git" in dp:
            continue
        files += [os.path.join(dp, f) for f in fs if f.startswith("CVE-") and f.endswith(".json")]
    files.sort()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with Pool(4) as p, gzip.open(OUT, "wt", newline="") as g:
        w = csv.writer(g)
        w.writerow(COLS)
        n = 0
        for row in p.imap(parse, files, chunksize=500):
            w.writerow(row)
            n += 1
    print(f"{n} rows -> {OUT}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/home/user/work/nvd")
