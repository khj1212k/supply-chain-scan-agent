"""M2 입력 준비: OSV 오프라인 DB를 개인 캐시에 고정하고, 빠진 생태계와 CycloneDX 스키마를 받는다.

- OSV-Scanner 캐시 구조: <osvdb>/osv-scalibr/<생태계>/all.zip
- Go, npm, PyPI, NuGet: 2026-11-02에 받은 /home/user/work/osvdb 사본을 복사 (스냅샷 고정, data/manifest_m2.json)
  - 사본이 없으면 OSV 공식 GCS 덤프를 새로 받는다 (그때는 스냅샷 날짜가 달라진다)
- Maven, GitHub Actions: SBOM 경로에 나와서 필요. common.fetch 로 받고 data/manifest_m2.json 에 기록
- 결과: results/m2/osv_db_inventory.csv (생태계, 크기, sha256, 파일 시각, 레코드 수, 레코드 최대 modified)

사용: .venv/bin/python m2/prepare.py --osvdb /home/user/work/m2tmp/osvdb
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

INNO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(INNO))
from common.fetch import fetch, sha256  # noqa: E402

GCS = "https://osv-vulnerabilities.storage.googleapis.com"
SHARED = Path("/home/user/work/osvdb/osv-scalibr")
# 생태계 이름(OSV 표기) -> data/raw 아래 경로(공백 없이)
ECOS = {"Go": "Go", "npm": "npm", "PyPI": "PyPI", "NuGet": "NuGet", "Maven": "Maven", "GitHub Actions": "GitHub_Actions"}
FROM_SHARED = {"Go", "npm", "PyPI", "NuGet"}
CDX = "https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema"
SCHEMAS = ["bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"]


def zip_stats(p: Path) -> tuple[int, str]:
    n, mx = 0, ""
    with zipfile.ZipFile(p) as z:
        for name in z.namelist():
            d = json.loads(z.read(name))
            n += 1
            mx = max(mx, d.get("modified", ""))
    return n, mx


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--osvdb", required=True, help="OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY 로 쓸 개인 폴더")
    ap.add_argument("--out", default=str(INNO / "results" / "m2"))
    a = ap.parse_args()
    base = Path(a.osvdb) / "osv-scalibr"
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    rows = []
    for eco, slug in ECOS.items():
        dest = base / eco / "all.zip"
        raw = INNO / "data" / "raw" / "osv" / slug / "all.zip"
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            if eco in FROM_SHARED and (SHARED / eco / "all.zip").exists():
                shutil.copy2(SHARED / eco / "all.zip", dest)  # 시각 보존 복사
            else:
                p = fetch(f"{GCS}/{eco.replace(' ', '%20')}/all.zip", f"osv/{slug}/all.zip", manifest="m2")
                shutil.copy2(p, dest)
        h = sha256(dest)
        if (SHARED / eco / "all.zip").exists() and sha256(SHARED / eco / "all.zip") == h:
            src_note = "same bytes as /home/user/work/osvdb (lead download)"
        elif raw.exists() and sha256(raw) == h:
            src_note = "fetched by m2 (data/manifest_m2.json)"
        else:
            src_note = "unknown origin (private cache only)"
        n, mx = zip_stats(dest)
        rows.append({
            "ecosystem": eco,
            "path": str(dest),
            "bytes": dest.stat().st_size,
            "sha256": h,
            "file_mtime_utc": datetime.fromtimestamp(dest.stat().st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "records": n,
            "max_record_modified": mx,
            "source": src_note,
            "url": f"{GCS}/{eco.replace(' ', '%20')}/all.zip",
        })
        print(eco, rows[-1]["records"], rows[-1]["max_record_modified"], src_note)

    with open(out / "osv_db_inventory.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    for s in SCHEMAS:
        fetch(f"{CDX}/{s}", f"cyclonedx/1.6/{s}", manifest="m2")
    print("schemas ok")


if __name__ == "__main__":
    main()
