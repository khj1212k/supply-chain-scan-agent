"""통과한 조치안을 Dockerfile 이미지와 같은 go1.19.4로 다시 빌드, 테스트한다 (go 지시어 '표시'를 실측으로 바꾸기).

- 판정(judge.py)이 남긴 작업 폴더(go.mod, go.sum 이 이미 바뀐 사본)를 복사해 쓴다
- go1.19.4 바이너리: proxy.golang.org 의 golang.org/toolchain@v0.0.1-go1.19.4.linux-amd64 (모듈 캐시)
- go 1.19 는 GOTOOLCHAIN 을 모른다. 바이너리를 직접 부른다. 모듈은 캐시만 쓴다(GOPROXY=off)
사용: .venv/bin/python -m agent.go119_check   출력: results/agent/go119_check.csv
"""
from __future__ import annotations

import csv
import json
import os
import shutil
import subprocess
from pathlib import Path

from agent import godata as g
from agent import judge as J

GO119 = Path("/home/user/tools/gopath/pkg/mod/golang.org/toolchain@v0.0.1-go1.19.4.linux-amd64/bin/go")
OUT = g.INNO / "results" / "agent" / "go119_check.csv"


def run(cmd, cwd):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("LAB_", "ANTHROPIC", "OPENAI"))}
    env.update({"GOPATH": "/home/user/tools/gopath", "GOFLAGS": "-mod=mod", "GOPROXY": "off", "GOMAXPROCS": "2",
                "GOTOOLCHAIN": "local", "GOROOT": str(GO119.parent.parent)})
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=600)
    return p.returncode, "\n".join((p.stdout + p.stderr).strip().splitlines()[-6:])[-600:]


def main() -> None:
    vd = g.INNO / "results" / "agent" / "verdicts"
    rows = []
    for p in sorted(vd.glob("*.json")):
        v = json.loads(p.read_text())
        if not v["pass"]:
            continue
        src = J.TMP / "judge" / v["service"] / v["key"]
        work = J.TMP / "go119" / v["key"]
        if work.exists():
            shutil.rmtree(work)
        shutil.copytree(src, work)
        ver = run([str(GO119), "version"], work)[1]
        b_rc, b_tail = run([str(GO119), "build", "./..."], work)
        t_rc, t_tail = (run([str(GO119), "test", "-count=1", "./..."], work) if b_rc == 0 else (None, ""))
        rows.append({"key": v["key"], "service": v["service"], "bumps": " ".join(f"{m}@{x}" for m, x in v["bumps"]),
                     "go_directive_after": v["go_directive_after"], "toolchain": ver, "build_rc": b_rc, "test_rc": t_rc,
                     "go1194_pass": b_rc == 0 and t_rc == 0, "tail": (b_tail if b_rc else t_tail).replace("\n", " | ")})
        print(v["key"], v["service"], rows[-1]["bumps"][-40:], "go", v["go_directive_after"], "build", b_rc, "test", t_rc)
    with open(OUT, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(len(rows), "->", OUT)


if __name__ == "__main__":
    main()
