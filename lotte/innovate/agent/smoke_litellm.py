"""배관 확인 1회: Agents SDK + LiteLLM + Claude. 도구 2번 호출, 구조화 출력, 사용량, 로컬 트레이스.

사용: .venv/bin/python -m agent.smoke_litellm   (lotte/innovate 에서)
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")  # 비용표를 네트워크에서 받지 않는다

from pydantic import BaseModel  # noqa: E402
from agents import Agent, ModelSettings, Runner, StopAtTools, function_tool  # noqa: E402

from agent import model_config as mc  # noqa: E402
from agent.tracing_local import use_local_tracing  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TRACE = ROOT / "results" / "agent" / "smoke_trace.jsonl"


@function_tool
def lookup_fix(module: str) -> str:
    """Return the minimum fixed version for a Go module (toy data)."""
    return {"golang.org/x/net": "v0.17.0", "google.golang.org/grpc": "v1.56.3"}.get(module, "unknown")


class Answer(BaseModel):
    net_fix: str
    grpc_fix: str
    note: str


@function_tool
def submit_answer(answer: Answer) -> str:
    """Submit the final answer. Call this exactly once at the end."""
    return answer.model_dump_json()


def main() -> int:
    spec = mc.parse(sys.argv[1] if len(sys.argv) > 1 else None)
    TRACE.unlink(missing_ok=True)
    use_local_tracing(TRACE)
    agent = Agent(
        name="smoke",
        instructions=("Call lookup_fix once for golang.org/x/net, then once for google.golang.org/grpc "
                      "(one call per turn), then call submit_answer."),
        tools=[lookup_fix, submit_answer],
        tool_use_behavior=StopAtTools(stop_at_tool_names=["submit_answer"]),
        model=mc.make_model(spec),
        model_settings=ModelSettings(include_usage=True, max_tokens=4000),
    )
    t0 = time.time()
    try:
        r = Runner.run_sync(agent, "What are the fixed versions?", max_turns=6)
    except Exception as e:
        msg = str(e).replace(os.environ.get("LAB_ANTHROPIC_API_KEY", "@@none@@"), "[KEY]")
        print("FAILED", type(e).__name__, msg[:800])
        return 1
    u = r.context_wrapper.usage
    print("final:", Answer.model_validate_json(r.final_output).model_dump())
    print("usage: requests", u.requests, "input", u.input_tokens, "output", u.output_tokens,
          "cached", getattr(u.input_tokens_details, "cached_tokens", None))
    print("cost_usd:", mc.cost_usd(spec.model_id, u.input_tokens, u.output_tokens))
    print("wall_s:", round(time.time() - t0, 2))
    tools = [i for i in r.new_items if i.type == "tool_call_item"]
    print("tool_calls:", len(tools))
    lines = TRACE.read_text().splitlines() if TRACE.exists() else []
    kinds = {}
    for ln in lines:
        d = json.loads(ln)
        k = d["event"] + ":" + str((d["data"].get("span_data") or {}).get("type", ""))
        kinds[k] = kinds.get(k, 0) + 1
    print("trace:", kinds)
    return 0


if __name__ == "__main__":
    sys.exit(main())
