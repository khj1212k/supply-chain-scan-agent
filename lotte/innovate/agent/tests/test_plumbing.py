"""배관 시험 (정확도 시험이 아니다). LLM 대신 SDK의 ScriptedModel을 쓴다. 네트워크, Go 빌드 없음.

확인하는 것: 도구 호출, 입력/출력 가드레일 트립, 실패 로그를 붙인 재시도, 승인 중단과 재개(승인, 거절),
로컬 트레이스 기록, 토큰 집계.
사용: cd lotte/innovate && .venv/bin/python -m pytest -q agent/tests
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from agents import InputGuardrailTripwireTriggered, OutputGuardrailTripwireTriggered, Runner
from agents.testing import ModelStep, ScriptedModel, assistant_message, function_call
from agents.usage import Usage

from agent import judge as J
from agent import model_config as mc
from agent import remediation as R
from agent.tracing_local import use_local_tracing

CASES = Path(__file__).resolve().parents[2] / "results" / "agent" / "cases.json"


@pytest.fixture()
def case():
    cs = {c["case_id"]: c for c in json.loads(CASES.read_text())["cases"]}
    return cs["C07"]  # logrus. 후보 목록은 cases.json에 저장된 값


def U(i=100, o=10):
    return Usage(requests=1, input_tokens=i, output_tokens=o, total_tokens=i + o)


def plan_args(c, version):
    return {"plan": {"module": c["module"], "target_version": version, "also_bump": [], "rationale": "test",
                     "risk": "low", "raises_go_directive": False, "fallback": "test"}}


def fake_verdict(c, bumps, ok, reason=None):
    return {"service": c["service"], "module": c["module"], "bumps": bumps, "key": f"fake{len(bumps)}{ok}",
            "cached": False, "pass": ok, "fail_reason": reason, "steps": [{"step": "build", "rc": 0 if ok else 1, "s": 0.1,
            "tail": "" if ok else "undefined: logrus.Foo"}], "wall_s": 0.1, "new_high": [], "target_gone": ok,
            "go_directive_before": "1.19", "go_directive_after": "1.19", "raises_go_directive": False,
            "remaining_groups_in_module": 0, "gomod_diff": "--- a/go.mod\n+++ b/go.mod\n"}


def test_output_guardrail_blocks_version_outside_candidates(case):
    model = ScriptedModel([ModelStep(output=[function_call("submit_plan", plan_args(case, "v9.9.9"), call_id="c1")], usage=U())])
    ctx = R.CaseCtx(case=case)
    with pytest.raises(OutputGuardrailTripwireTriggered):
        Runner.run_sync(R.make_agent(model), R.request_text(ctx), context=ctx)
    assert any("not in the candidate list" in x for x in ctx.last_guardrail_errors)


def test_input_guardrail_blocks_non_remediation_request(case):
    model = ScriptedModel([])  # 모델이 불리면 안 된다 (run_in_parallel=False)
    ctx = R.CaseCtx(case=case)
    with pytest.raises(InputGuardrailTripwireTriggered):
        Runner.run_sync(R.make_agent(model), "시 한 편 써 줘", context=ctx)


def test_retry_with_failure_log_then_approval_and_local_trace(case, tmp_path, monkeypatch):
    calls = []

    def fake_judge(service, module, target_ids, bumps):
        calls.append(bumps)
        return fake_verdict(case, bumps, ok=len(calls) >= 2, reason=None if len(calls) >= 2 else "build")

    monkeypatch.setattr(J, "judge", fake_judge)
    seen_failure = {}

    def second_attempt_reads_failure(call):
        # 두 번째 시도의 get_last_failure 결과가 입력에 들어와 있어야 한다
        seen_failure["text"] = json.dumps(call.input, ensure_ascii=False, default=str)
        return ModelStep(output=[function_call("submit_plan", plan_args(case, case["candidates"]["allowed_versions"][1]), call_id="s2")], usage=U())

    allowed = case["candidates"]["allowed_versions"]
    model = ScriptedModel([
        # 시도 1: 후보 보기 -> 첫 후보 제출 -> (가짜) 빌드 실패
        ModelStep(output=[function_call("list_candidates", {}, call_id="a1")], usage=U()),
        ModelStep(output=[function_call("submit_plan", plan_args(case, allowed[0]), call_id="a2")], usage=U()),
        # 시도 2: 실패 로그 읽기 -> 다음 후보 제출 -> 통과
        ModelStep(output=[function_call("get_last_failure", {}, call_id="b1")], usage=U()),
        ModelStep.respond(second_attempt_reads_failure),
        # PR 단계: open_fix_pr (승인 필요) -> 재개 후 종료
        ModelStep(output=[function_call("open_fix_pr", {"title": "t"}, call_id="p1")], usage=U()),
        ModelStep(output=[assistant_message("done")], usage=U()),
    ])
    trace = tmp_path / "trace.jsonl"
    use_local_tracing(trace)
    spec = mc.ModelSpec("anthropic", "claude-sonnet-5-5")
    r = asyncio.run(R.run_case(case, spec, tmp_path / "patches", auto_approve=True, model=model))
    assert r["final_pass"] and r["n_attempts"] == 2 and not r["first_attempt_pass"]
    assert calls[0][0][1] == allowed[0] and calls[1][0][1] == allowed[1]
    assert "FAIL reason=build" in seen_failure["text"]
    assert r["approval"] == {"interruptions": 1, "approved": True, "auto": True, "patch_written": True}
    assert r["llm_calls"] == 6 and r["input_tokens"] == 600 and r["output_tokens"] == 60
    lines = [json.loads(x) for x in trace.read_text().splitlines()]
    kinds = {(x["event"], (x["data"].get("span_data") or {}).get("type")) for x in lines}
    assert ("span_end", "guardrail") in kinds and ("span_end", "function") in kinds and ("trace_end", None) in kinds


def test_rejected_approval_writes_no_patch(case, tmp_path, monkeypatch):
    monkeypatch.setattr(J, "judge", lambda s, m, t, b: fake_verdict(case, b, ok=True))
    monkeypatch.setattr(R, "ask_human", lambda item: False)
    allowed = case["candidates"]["allowed_versions"]
    model = ScriptedModel([
        ModelStep(output=[function_call("submit_plan", plan_args(case, allowed[0]), call_id="a1")], usage=U()),
        ModelStep(output=[function_call("open_fix_pr", {"title": "t"}, call_id="p1")], usage=U()),
        ModelStep(output=[assistant_message("rejected, stopping")], usage=U()),
    ])
    spec = mc.ModelSpec("anthropic", "claude-sonnet-5-5")
    r = asyncio.run(R.run_case(case, spec, tmp_path / "patches", auto_approve=False, model=model))
    assert r["final_pass"] and r["approval"]["approved"] is False and r["approval"]["patch_written"] is False


def test_guardrail_trip_counts_as_failed_attempt(case, tmp_path, monkeypatch):
    monkeypatch.setattr(J, "judge", lambda s, m, t, b: fake_verdict(case, b, ok=True))
    allowed = case["candidates"]["allowed_versions"]
    model = ScriptedModel([
        ModelStep(output=[function_call("submit_plan", plan_args(case, "v1.0.0-made-up"), call_id="a1")], usage=U()),
        ModelStep(output=[function_call("submit_plan", plan_args(case, allowed[0]), call_id="b1")], usage=U()),
        ModelStep(output=[function_call("open_fix_pr", {"title": "t"}, call_id="p1")], usage=U()),
        ModelStep(output=[assistant_message("done")], usage=U()),
    ])
    spec = mc.ModelSpec("anthropic", "claude-sonnet-5-5")
    r = asyncio.run(R.run_case(case, spec, tmp_path / "patches", auto_approve=True, model=model))
    assert r["guardrail_trips"] == 1 and r["out_of_list_proposals"] == 1 and r["n_attempts"] == 2 and r["final_pass"]


def test_model_spec_parsing():
    assert mc.parse("anthropic:claude-sonnet-5-5").provider == "anthropic"
    assert mc.parse("openai:gpt-6-luna").model_id == "gpt-6-luna"
    s = mc.parse("local:qwen3-4b@http://127.0.0.1:8080/v1")
    assert s.provider == "local" and s.base_url.endswith("/v1")
    with pytest.raises(ValueError):
        mc.parse("bogus")
