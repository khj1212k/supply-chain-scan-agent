"""트레이스를 OpenAI로 내보내지 않고 로컬 JSONL 파일에만 쓴다.

Agents SDK v0.24.0 docs/tracing.md 'Custom tracing processors':
set_trace_processors()는 기본 처리기(OpenAI 백엔드 내보내기)를 교체한다.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from agents.tracing import TracingProcessor, set_trace_processors


class LocalJsonlProcessor(TracingProcessor):
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _write(self, kind: str, obj) -> None:
        try:
            data = obj.export() if hasattr(obj, "export") else {}
        except Exception as e:  # 직렬화 실패는 기록만 하고 실행은 계속
            data = {"export_error": type(e).__name__}
        rec = {"t": time.time(), "event": kind, "data": data}
        with self._lock, open(self.path, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")

    def on_trace_start(self, trace):
        self._write("trace_start", trace)

    def on_trace_end(self, trace):
        self._write("trace_end", trace)

    def on_span_start(self, span):
        pass  # 끝날 때 한 번만 쓴다 (시작, 끝 시각이 다 들어 있다)

    def on_span_end(self, span):
        self._write("span_end", span)

    def shutdown(self):
        pass

    def force_flush(self):
        pass


def use_local_tracing(path: Path) -> LocalJsonlProcessor:
    p = LocalJsonlProcessor(path)
    set_trace_processors([p])
    return p
