#!/usr/bin/env bash
# M2 전체를 한 번에: 스캔 -> 깔때기 -> VEX 예시 -> 그림
# 사용: cd lotte/innovate && bash m2/run.sh
# 미리 있어야 하는 것: /home/user/tools/bin/{syft,osv-scanner}, /home/user/work/osvdb (m2/prepare.py),
#   /home/user/work/ob_{v0.5.0,main,v0.8.0} 워크트리, data/raw/{kev,epss,derived/nvd_table.csv.gz} (m1)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
PY=.venv/bin/python
t0=$(date +%s)
bash m2/scan.sh
nice -n 10 $PY m2/funnel.py
$PY m2/vex_example.py
$PY m2/figs.py
echo "m2 done in $(( $(date +%s) - t0 ))s"
