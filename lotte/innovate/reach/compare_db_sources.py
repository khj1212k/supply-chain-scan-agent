"""두 OSV 원본(OSV Go all.zip의 GO-*, golang/vulndb data/osv)을 govulncheck가 쓰는 필드로 비교한다.

비교 필드: affected[].package.name, ranges, ecosystem_specific.imports(path, symbols, goos, goarch), aliases, withdrawn.
사용: python -I compare_db_sources.py <zip_dir> <vulndb_dir> <out_json>
"""
import json
import sys
from pathlib import Path


def key_fields(d):
    aff = []
    for a in d.get("affected", []):
        imps = []
        for p in (a.get("ecosystem_specific") or {}).get("imports", []) or []:
            imps.append((p.get("path"), tuple(sorted(p.get("symbols") or [])),
                         tuple(p.get("goos") or []), tuple(p.get("goarch") or [])))
        aff.append((a["package"]["name"], json.dumps(a.get("ranges"), sort_keys=True), tuple(sorted(imps))))
    return {"affected": sorted(aff), "aliases": sorted(d.get("aliases") or []), "withdrawn": bool(d.get("withdrawn"))}


def main():
    zdir, vdir, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    z = {p.stem: json.loads(p.read_text()) for p in zdir.glob("GO-*.json")}
    v = {p.stem: json.loads(p.read_text()) for p in vdir.glob("GO-*.json")}
    both = sorted(set(z) & set(v))
    diff = {"affected": [], "aliases": [], "withdrawn": []}
    for i in both:
        a, b = key_fields(z[i]), key_fields(v[i])
        for k in diff:
            if a[k] != b[k]:
                diff[k].append(i)
    res = {
        "zip_go_entries": len(z),
        "vulndb_go_entries": len(v),
        "in_both": len(both),
        "only_zip": sorted(set(z) - set(v)),
        "only_vulndb": sorted(set(v) - set(z)),
        "diff_affected_count": len(diff["affected"]),
        "diff_affected_ids": diff["affected"],
        "diff_aliases_count": len(diff["aliases"]),
        "diff_aliases_ids_first20": diff["aliases"][:20],
        "diff_withdrawn_ids": diff["withdrawn"],
    }
    out.write_text(json.dumps(res, indent=1, ensure_ascii=False) + "\n")
    print({k: (len(v) if isinstance(v, list) else v) for k, v in res.items()})


if __name__ == "__main__":
    main()
