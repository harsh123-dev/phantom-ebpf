"""Tests for event-scoped host-proc identity validation and handoff.

These tests exercise Python callback/processor logic with synthetic ring records;
they do not claim to verify a running kernel, BPF program, or Kubernetes API.
"""

from __future__ import annotations

import asyncio
import importlib
from types import SimpleNamespace
from uuid import UUID

from infrastructure.ebpf.event_parser import (
    EventType,
    ParsedEventHeader,
    ParsedExecEvent,
    PHANTOM_ABI_VERSION,
)


def test_proc_identity_requires_matching_tgid_and_event_cgroup(tmp_path, monkeypatch):
    main = importlib.import_module("application.main")
    proc_root = tmp_path / "host-proc"
    cgroup_root = tmp_path / "host-cgroup"
    cid = "a" * 64
    scope = cgroup_root / "kubepods.slice" / f"cri-containerd-{cid}.scope"
    scope.mkdir(parents=True)
    proc = proc_root / "4321"
    proc.mkdir(parents=True)
    (proc / "status").write_text("Name:\ttest\nTgid:\t4321\n", encoding="ascii")
    (proc / "cgroup").write_text(
        f"0::/{scope.relative_to(cgroup_root).as_posix()}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(main, "PROC_ROOT", str(proc_root))
    monkeypatch.setattr(main, "CGROUP_ROOT", str(cgroup_root))

    valid = main._read_container_id_sync(4321, 4321, scope.stat().st_ino)
    assert valid.container_id == cid
    assert valid.cgroup_inode_matches_event is True
    assert valid.reason == "validated_runtime_scope"

    wrong_cgroup = main._read_container_id_sync(4321, 4321, scope.stat().st_ino + 1)
    assert wrong_cgroup.container_id is None
    assert wrong_cgroup.cgroup_inode_matches_event is False
    assert wrong_cgroup.reason == "cgroup_id_mismatch"

    wrong_tgid = main._read_container_id_sync(4321, 9999, scope.stat().st_ino)
    assert wrong_tgid.container_id is None
    assert wrong_tgid.reason == "tgid_mismatch"


def _event(event_id: int, cgroup_id: int) -> ParsedExecEvent:
    header = ParsedEventHeader(
        abi_version=PHANTOM_ABI_VERSION,
        event_type=EventType.EXEC,
        total_size=0,
        event_id_hi=event_id,
        event_id_lo=event_id + 100,
        kernel_timestamp_ns=10_000 + event_id,
        cgroup_id=cgroup_id,
        pid_start_time_ns=500,
        pid=77,
        tgid=77,
        ppid=1,
        uid=1000,
        gid=1000,
        cpu=0,
        comm="sleep",
    )
    return ParsedExecEvent(header, 1, 0, 0, "/bin/sleep", "")


def test_callback_to_processor_handoff_is_event_scoped(monkeypatch):
    main = importlib.import_module("application.main")
    events = [_event(1, 1001), _event(2, 2002)]
    queue: asyncio.Queue = asyncio.Queue(maxsize=10)
    monkeypatch.setattr(main, "event_queue", queue)
    monkeypatch.setattr(main, "_CONTAINER_ID_CACHE", {})
    monkeypatch.setattr(main.ctypes, "string_at", lambda _data, _size: b"fixture")
    parsed = iter(events)
    monkeypatch.setattr(main, "parse_event", lambda _raw: next(parsed))
    cid = "b" * 64
    captures = iter([
        main.ProcessIdentityCapture(None, "/controller", False, 77, "cgroup_id_mismatch"),
        main.ProcessIdentityCapture(cid, "/target", True, 77, "validated_runtime_scope"),
    ])
    monkeypatch.setattr(main, "_read_container_id_sync", lambda *_args: next(captures))

    assert main.rb_callback(None, 1, 7) == 0
    assert main.rb_callback(None, 2, 7) == 0
    assert len(main._CONTAINER_ID_CACHE) == 2

    pod_uid = UUID("11111111-1111-4111-8111-111111111111")
    missing = SimpleNamespace(
        status=SimpleNamespace(value="missing"), pod_uid=None, namespace=None,
        container_name=None, image_digest=None, container_id=None,
    )
    resolved = SimpleNamespace(
        status=SimpleNamespace(value="resolved"), pod_uid=pod_uid,
        namespace="phantom-eval", pod_name="recommendationservice-abc",
        container_name="server", image_digest="sha256:" + "c" * 64,
        container_id="containerd://" + cid,
    )

    class Attributor:
        _node_name = "node-a"

        def __init__(self):
            self.calls = []

        async def attribute(self, cgroup_id, container_id, *, event_cgroup_validated):
            self.calls.append((cgroup_id, container_id, event_cgroup_validated))
            return missing if cgroup_id == 1001 else resolved

    class Dispatcher:
        def __init__(self):
            self.payloads = []

        async def dispatch_event(self, payload):
            self.payloads.append(payload)

    attributor = Attributor()
    dispatcher = Dispatcher()

    async def run_processor():
        task = asyncio.create_task(main.event_processor(attributor, dispatcher, "tenant"))
        await queue.join()
        task.cancel()
        await task

    asyncio.run(run_processor())

    assert attributor.calls == [
        (1001, None, False),
        (2002, cid, True),
    ]
    assert len(dispatcher.payloads) == 1
    assert dispatcher.payloads[0]["event_id"] == str(UUID(int=(2 << 64) | 102))
    assert dispatcher.payloads[0]["workload"]["container_id"] == "containerd://" + cid
    assert dispatcher.payloads[0]["workload"]["cgroup_id"] == 2002
    assert main._CONTAINER_ID_CACHE == {}


def test_short_lived_process_identity_capture_drops_gracefully(monkeypatch):
    """A short-lived process (e.g. /bin/true) whose /proc entry disappears before
    _read_container_id_sync runs must be counted with the correct per-reason label
    and must not raise an exception or leave stale entries in _CONTAINER_ID_CACHE.

    Regression test for the proc-race / identity-missing counter introduced
    alongside AGENT_IDENTITY_DROP_TOTAL.
    """
    import importlib
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import patch
    from prometheus_client import REGISTRY

    main = importlib.import_module("application.main")

    queue: asyncio.Queue = asyncio.Queue(maxsize=10)
    monkeypatch.setattr(main, "event_queue", queue)
    monkeypatch.setattr(main, "_CONTAINER_ID_CACHE", {})
    monkeypatch.setattr(main.ctypes, "string_at", lambda _data, _size: b"fixture")

    # Simulate an EXEC event for a short-lived process.
    short_lived_event = _event(42, 9001)
    monkeypatch.setattr(main, "parse_event", lambda _raw: short_lived_event)

    # Simulate /proc being gone by the time the callback reads it.
    proc_race_capture = main.ProcessIdentityCapture(
        None, None, False, None,
        "proc_or_cgroup_unavailable:FileNotFoundError",
    )
    monkeypatch.setattr(main, "_read_container_id_sync", lambda *_a: proc_race_capture)

    # Fire the ring-buffer callback.
    assert main.rb_callback(None, 1, 7) == 0
    assert len(main._CONTAINER_ID_CACHE) == 1  # stashed by callback

    # Attributor returns MISSING (the strict path for unvalidated cgroup).
    missing_identity = SimpleNamespace(
        status=SimpleNamespace(value="missing"),
        pod_uid=None, namespace=None, container_name=None,
        image_digest=None, container_id=None,
    )

    class _Attributor:
        _node_name = "node-x"
        async def attribute(self, cgroup_id, container_id, *, event_cgroup_validated):
            return missing_identity

    class _Dispatcher:
        async def dispatch_event(self, payload):
            pass  # should not be called

    # Snapshot the drop counter before processing.
    def _counter_value(metric_name, **labels):
        for metric in REGISTRY.collect():
            if metric.name == metric_name:
                for sample in metric.samples:
                    if all(sample.labels.get(k) == v for k, v in labels.items()):
                        return sample.value
        return 0.0

    before = _counter_value(
        "phantom_agent_identity_drop",
        event_type="exec",
        capture_reason="proc_exited_before_read",
        attribution_status="missing",
    )

    async def _run():
        task = asyncio.create_task(
            main.event_processor(_Attributor(), _Dispatcher(), "tenant")
        )
        await queue.join()
        task.cancel()
        await task

    asyncio.run(_run())

    after = _counter_value(
        "phantom_agent_identity_drop",
        event_type="exec",
        capture_reason="proc_exited_before_read",
        attribution_status="missing",
    )

    # The counter must have incremented by exactly 1.
    assert after - before == 1.0, (
        f"Expected identity drop counter to increment by 1; was {before} -> {after}"
    )

    # The cache entry must have been consumed by the processor.
    assert main._CONTAINER_ID_CACHE == {}
