"""Startup failure handling tests; no privileged BPF program is loaded."""

from __future__ import annotations

import asyncio
import importlib

import pytest


def test_bpf_initialization_failure_is_propagated_after_health_cleanup(monkeypatch):
    main = importlib.import_module("application.main")
    monkeypatch.setenv("REDIS_URL", "")
    monkeypatch.setenv("REDIS_HOST", "")

    class FakeApp:
        def __init__(self):
            self.router = self

        def add_get(self, *_args):
            pass

    class FakeRunner:
        def __init__(self, _app):
            self.cleaned = False

        async def setup(self):
            pass

        async def cleanup(self):
            self.cleaned = True

    class FakeSite:
        def __init__(self, _runner, _host, _port):
            self.stopped = False

        async def start(self):
            pass

        async def stop(self):
            self.stopped = True

    class FakeAttributor:
        def __init__(self, *_args, **_kwargs):
            pass

    class FakeDispatcher:
        def __init__(self, *_args, **_kwargs):
            self.closed = False

        async def close(self):
            self.closed = True

    class FailingBpfLoader:
        def __init__(self, _bpf_dir):
            pass

        def __enter__(self):
            raise RuntimeError("controlled BPF initialization failure")

        def __exit__(self, *_args):
            pass

    sites = []
    runner = FakeRunner(None)
    dispatcher = FakeDispatcher()
    monkeypatch.setattr(main.web, "Application", FakeApp)
    monkeypatch.setattr(main.web, "AppRunner", lambda _app: runner)
    monkeypatch.setattr(main.web, "TCPSite", lambda *args: sites.append(FakeSite(*args)) or sites[-1])
    monkeypatch.setattr(main, "CgroupPodAttributor", FakeAttributor)
    monkeypatch.setattr(main, "ApiDispatcher", lambda *_args: dispatcher)
    monkeypatch.setattr(main, "PhantomBpfLoader", FailingBpfLoader)

    with pytest.raises(RuntimeError, match="controlled BPF initialization failure"):
        asyncio.run(main.async_main())

    assert len(sites) == 2
    assert sites[1].stopped is True  # metrics site is stopped directly
    assert runner.cleaned is True
    assert dispatcher.closed is True
