"""모델 교체 구조: 설정 한 줄(LAB_MODEL)로 공급자와 모델을 바꾼다.

형식
- anthropic:<모델 ID>                 예) anthropic:claude-sonnet-5-5 (기본값)
- openai:<모델 ID>                    예) openai:gpt-6-luna
- local:<모델 이름>@<OpenAI 호환 URL>  예) local:qwen3-4b@http://127.0.0.1:8080/v1

키 규칙 (저장소 CLAUDE.md)
- Claude: 환경 변수 LAB_ANTHROPIC_API_KEY 만 읽고, 코드에서 api_key= 로 명시해서 넘긴다.
  ANTHROPIC_API_KEY 라는 이름은 읽지도 만들지도 않는다.
- OpenAI: 키를 코드가 갖지 않는다. 환경의 network secret 이 프록시에서 붙인다.
- 키 값은 어디에도 출력하지 않는다. availability()는 있음/없음만 보고한다.

연결 방식 (Agents SDK v0.24.0 docs/models/index.md 'Third-party adapters', 'Non-OpenAI models')
- anthropic: agents.extensions.models.litellm_model.LitellmModel(model="anthropic/<ID>", api_key=...)
- openai:    SDK 기본(Responses API), 모델 이름 문자열
- local:     OpenAIChatCompletionsModel + AsyncOpenAI(base_url=...)
"""
from __future__ import annotations

import os
import socket
from dataclasses import dataclass

DEFAULT_MODEL = "anthropic:claude-sonnet-5-5"

# 공식 단가 (USD / 100만 토큰). 출처: claude-api 스킬의 모델 표(2026-10-06 캐시, Anthropic 1차 API 단가),
# OpenAI 는 context/lotte/openai_stack.md 5절(S10~S12). 실행 전에 공식 가격 페이지로 다시 확인할 것.
PRICES = {
    "claude-sonnet-5-5": {"input": 2.00, "output": 10.00, "cache_read": 0.20},
    "claude-opus-5-5": {"input": 4.00, "output": 20.00, "cache_read": 0.20},
    "gpt-6-luna": {"input": 0.10, "output": 0.50, "cache_read": 0.01},
}


@dataclass(frozen=True)
class ModelSpec:
    provider: str  # anthropic | openai | local
    model_id: str
    base_url: str | None = None

    @property
    def label(self) -> str:
        return f"{self.provider}:{self.model_id}"


def parse(spec: str | None = None) -> ModelSpec:
    s = (spec or os.environ.get("LAB_MODEL") or DEFAULT_MODEL).strip()
    provider, _, rest = s.partition(":")
    if provider == "local":
        name, _, url = rest.partition("@")
        if not url:
            raise ValueError("local 형식: local:<이름>@<URL>")
        return ModelSpec("local", name, url)
    if provider not in ("anthropic", "openai") or not rest:
        raise ValueError(f"알 수 없는 LAB_MODEL: {s!r}")
    return ModelSpec(provider, rest)


def make_model(spec: ModelSpec):
    """Agent(model=...) 에 넣을 객체를 만든다."""
    if spec.provider == "anthropic":
        from agents.extensions.models.litellm_model import LitellmModel
        key = os.environ.get("LAB_ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("LAB_ANTHROPIC_API_KEY 없음: Claude 경로 미실행")
        return LitellmModel(model=f"anthropic/{spec.model_id}", api_key=key)
    if spec.provider == "openai":
        return spec.model_id  # SDK 기본 OpenAI 공급자. 키는 network secret
    from agents import AsyncOpenAI, OpenAIChatCompletionsModel
    client = AsyncOpenAI(base_url=spec.base_url, api_key="local-no-key")
    return OpenAIChatCompletionsModel(model=spec.model_id, openai_client=client)


def _tcp_ok(host: str, port: int = 443, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def availability() -> dict:
    """지금 쓸 수 있는 공급자. 비밀값은 출력하지 않고 있음/없음만."""
    import urllib.error
    import urllib.request
    out = {"anthropic_key_present": bool(os.environ.get("LAB_ANTHROPIC_API_KEY"))}
    # OpenAI: 프록시가 막으면 403(CONNECT 거부). 열려 있으면 키 없이도 401 등 OpenAI 응답이 온다
    try:
        urllib.request.urlopen(urllib.request.Request("https://api.openai.com/v1/models"), timeout=8)
        out["openai_reachable"] = "200"
    except urllib.error.HTTPError as e:
        out["openai_reachable"] = f"http {e.code}"
    except Exception as e:  # 프록시 CONNECT 거부 등
        out["openai_reachable"] = f"blocked ({type(e).__name__})"
    out["local_endpoint_8080"] = _tcp_ok("127.0.0.1", 8080, 1.0)
    return out


def cost_usd(model_id: str, input_tokens: int, output_tokens: int, cached_input_tokens: int = 0) -> float | None:
    p = PRICES.get(model_id)
    if not p:
        return None
    fresh = max(0, input_tokens - cached_input_tokens)
    return (fresh * p["input"] + cached_input_tokens * p["cache_read"] + output_tokens * p["output"]) / 1e6
