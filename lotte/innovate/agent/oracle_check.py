"""존재 확인 (정책 비교 아님): 에이전트와 기준선이 모두 실패한 사례에 통과 조합이 있는지,
결과를 본 뒤 고른 조합 몇 개를 같은 기계 판정에 넣어 본다. 출력: results/agent/oracle_check.json
"""
from __future__ import annotations

import json

from agent import godata as g
from agent import judge as J

OTEL = ["go.opentelemetry.io/otel", "go.opentelemetry.io/otel/trace", "go.opentelemetry.io/otel/sdk",
        "go.opentelemetry.io/otel/exporters/otlp/otlptrace", "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"]
PLANS = {
    "C03": [[("go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp", "v0.44.0"),
             ("go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc", "v0.44.0")]
            + [(m, "v1.43.0") for m in OTEL] + [("golang.org/x/crypto", "v0.58.0")]],
    "C04": [[("go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc", "v0.46.0")]
            + [(m, "v1.43.0") for m in OTEL if m != "go.opentelemetry.io/otel/trace"] + [("golang.org/x/crypto", "v0.58.0")],
            # 2단계: 위 실패(google.golang.org/api v0.126.0 빌드 깨짐)를 보고 profiler, api 를 최신으로
            [("go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc", "v0.46.0")]
            + [(m, "v1.43.0") for m in OTEL if m != "go.opentelemetry.io/otel/trace"] + [("golang.org/x/crypto", "v0.58.0"),
               ("google.golang.org/api", "API_LATEST"), ("cloud.google.com/go/profiler", "PROF_LATEST")]],
}


def main() -> None:
    cases = {c["case_id"]: c for c in json.loads((g.INNO / "results/agent/cases.json").read_text())["cases"]}
    latest = {m: [v for v in g.module_versions(m) if g.is_stable(v)][-1] for m in ("google.golang.org/api", "cloud.google.com/go/profiler")}
    sub = {"API_LATEST": latest["google.golang.org/api"], "PROF_LATEST": latest["cloud.google.com/go/profiler"]}
    out = []
    for cid, plans in PLANS.items():
        plans = [[(m, sub.get(v, v)) for m, v in p] for p in plans]
        c = cases[cid]
        for bumps in plans:
            v = J.judge(c["service"], c["module"], c["target_group"]["ids"], bumps)
            out.append({"case_id": cid, "bumps": bumps, "pass": v["pass"], "fail_reason": v["fail_reason"], "key": v["key"],
                        "go_after": v["go_directive_after"], "new_high": v["new_high"],
                        "failed_step_tail": next((s["tail"][-600:] for s in v["steps"] if s["rc"] != 0), "")})
            print(cid, v["pass"], v["fail_reason"], v["go_directive_after"], len(v["new_high"]), out[-1]["failed_step_tail"][-300:].replace("\n", " | "))
    (g.INNO / "results/agent/oracle_check.json").write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
