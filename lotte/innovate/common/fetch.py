"""다운로드, 캐시, manifest 기록.

- 받은 파일은 data/raw/ 아래에 둔다 (커밋 안 함).
- data/manifest.json 에 URL, 받은 시각(UTC), sha256, 크기를 남긴다 (커밋).
- 이미 받은 파일은 다시 받지 않는다. 재현할 때는 data/raw 를 지우고 다시 돈다.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
MANIFEST = ROOT / "data" / "manifest.json"


def _load_manifest() -> dict:
    if MANIFEST.exists():
        return json.loads(MANIFEST.read_text())
    return {}


def _save_manifest(m: dict) -> None:
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(m, indent=1, ensure_ascii=False, sort_keys=True) + "\n")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url: str, rel: str, retries: int = 4, timeout: int = 300) -> Path:
    """url 을 data/raw/rel 로 받는다. 있으면 그대로 쓴다."""
    dest = RAW / rel
    m = _load_manifest()
    if dest.exists() and rel in m:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    err = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "applied-llm-lab/innovate"})
            with urllib.request.urlopen(req, timeout=timeout) as r, open(tmp, "wb") as f:
                while True:
                    b = r.read(1 << 20)
                    if not b:
                        break
                    f.write(b)
            os.replace(tmp, dest)
            break
        except Exception as e:  # 네트워크 실패는 재시도
            err = e
            time.sleep(2 * (2 ** i))
    else:
        raise RuntimeError(f"fetch failed: {url}: {err}")
    m = _load_manifest()
    m[rel] = {
        "url": url,
        "fetched_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sha256": sha256(dest),
        "bytes": dest.stat().st_size,
    }
    _save_manifest(m)
    return dest
