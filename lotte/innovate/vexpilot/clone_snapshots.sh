#!/bin/bash
# 8개 사례의 저장소 스냅샷을 정확한 커밋으로 받는다 (git fetch --depth 1). codeload.github.com 은 막혀 있어 git 만 쓴다.
# 사용: cd lotte/innovate && bash vexpilot/clone_snapshots.sh
# 결과: /home/user/work/vexpilot/repos/<task_id>/ (+ .clone_ok 에 받은 시각 UTC)
set -u
cd "$(dirname "$0")/.." || exit 1
.venv/bin/python -c "from vexpilot import cases as C
for c in C.select(): print(c['task_id'], c['repo_url'], c['commit_sha'])" | while read -r t u c; do
  d=/home/user/work/vexpilot/repos/$t
  if [ -f "$d/.clone_ok" ]; then echo "skip $t"; continue; fi
  rm -rf "$d"; mkdir -p "$d"
  ( cd "$d" && git init -q && git remote add origin "$u" && nice -n 10 git fetch -q --depth 1 origin "$c" \
      && git -c advice.detachedHead=false checkout -q FETCH_HEAD ) \
    && [ "$(git -C "$d" rev-parse HEAD)" = "$c" ] && date -u +%FT%TZ > "$d/.clone_ok"
  echo "$t head=$(git -C "$d" rev-parse HEAD 2>/dev/null) ok=$([ -f "$d/.clone_ok" ] && echo yes || echo no) size=$(du -sh "$d" | cut -f1)"
done
