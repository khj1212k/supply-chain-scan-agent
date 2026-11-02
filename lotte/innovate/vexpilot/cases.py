"""사례 고르기 (규칙: vexpilot/CASES_RULE.md). LLM 없음.

사용: .venv/bin/python -m vexpilot.cases   (lotte/innovate 에서)
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

INNO = Path(__file__).resolve().parents[1]
LABELS = INNO / "data" / "raw" / "vexbench" / "vex_bench.jsonl"
LABELS_SHA256 = "06c58010defd28a3165598072b36fd56e986bc4c39c91f3c0095dc82b2800ddf"
REPOS = Path("/home/user/work/vexpilot/repos")

EXCLUDED_REPOS = {"kubernetes/kubernetes", "kubernetes/minikube", "rancher/rancher", "cilium/cilium", "moby/moby",
                  "istio/istio"}
TOTAL = 8

# CASES_RULE.md 에 적은 목록. 코드가 같은 목록을 만드는지 확인용
EXPECTED = [
    "caddyserver-caddy-8dc7667-CVE-2025-29785",
    "containers-podman-6a65597-CVE-2023-48795",
    "stretchr-testify-285adcc-CVE-2022-28948",
    "aquasecurity-trivy-37da98d-CVE-2024-32473",
    "aquasecurity-trivy-98e136e-CVE-2024-24791",
    "containers-podman-38ccfa2-CVE-2024-37298",
    "containers-podman-5ae6347-CVE-2025-47914",
    "containers-podman-6541fc4-CVE-2025-58181",
]

_LANG = re.compile(r"""['"]language['"]\s*:\s*['"]([^'"]+)['"]""")


def language(row: dict) -> str | None:
    m = row.get("metadata")
    s = m if isinstance(m, str) else json.dumps(m)
    mm = _LANG.search(s or "")
    return mm[1].lower() if mm else None


def repo_name(url: str) -> str:
    return "/".join(url.rstrip("/").removesuffix(".git").split("/")[-2:])


def load_rows() -> list[dict]:
    raw = LABELS.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    if sha != LABELS_SHA256:
        raise SystemExit(f"라벨 파일 sha256 불일치: {sha}")
    return [json.loads(x) for x in raw.decode().splitlines() if x.strip()]


def select() -> list[dict]:
    go = [r for r in load_rows() if language(r) == "go"]
    pool = [r for r in go if repo_name(r["repo_url"]) not in EXCLUDED_REPOS]
    pos = sorted((r for r in pool if r["ground_truth"] == "exploitable"), key=lambda r: r["task_id"])
    neg = sorted((r for r in pool if r["ground_truth"] == "not_exploitable"), key=lambda r: r["task_id"])
    picked = pos[:TOTAL] + neg[:max(0, TOTAL - len(pos))]
    out = []
    for r in picked:
        out.append({"task_id": r["task_id"], "repo": repo_name(r["repo_url"]), "repo_url": r["repo_url"],
                    "commit_sha": r["commit_sha"], "cve_id": r["cve_id"], "label": r["ground_truth"],
                    "label_category": r["ground_truth_category"], "snapshot": str(REPOS / r["task_id"])})
    return out


def counts() -> dict:
    go = [r for r in load_rows() if language(r) == "go"]
    pool = [r for r in go if repo_name(r["repo_url"]) not in EXCLUDED_REPOS]
    f = lambda rs, lab: sum(r["ground_truth"] == lab for r in rs)
    return {"go": len(go), "go_exploitable": f(go, "exploitable"), "go_not_exploitable": f(go, "not_exploitable"),
            "pool": len(pool), "pool_exploitable": f(pool, "exploitable"),
            "pool_not_exploitable": f(pool, "not_exploitable")}


def main() -> None:
    cs = select()
    print(json.dumps(counts(), ensure_ascii=False))
    for i, c in enumerate(cs, 1):
        ok = (Path(c["snapshot"]) / ".clone_ok").exists()
        print(f"{i} {c['task_id']} {c['label']} {c['label_category']} snapshot={'ok' if ok else 'missing'}")
    same = [c["task_id"] for c in cs] == EXPECTED
    print("CASES_RULE.md 목록과 같음:", same)
    if not same:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
