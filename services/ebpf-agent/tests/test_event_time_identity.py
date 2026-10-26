"""Synthetic process-state race checks; no live BPF or container is mocked as proven."""

from types import SimpleNamespace
from pathlib import Path

from application.main import AGENT_EVENTS_TOTAL, _count_event, _event_time_executable_path
from infrastructure.ebpf.event_parser import EventType


def _event(event_type: EventType, path: str | None):
    return SimpleNamespace(
        header=SimpleNamespace(event_type=event_type), executable_path=path
    )


def test_non_exec_event_never_uses_later_process_executable() -> None:
    event = _event(EventType.PRIVILEGE, "/usr/local/bin/python3.11")
    assert _event_time_executable_path(event) == "unknown"


def test_kernel_exec_event_can_supply_absolute_path() -> None:
    assert _event_time_executable_path(_event(EventType.EXEC, "/usr/bin/python3")) == (
        "/usr/bin/python3"
    )


def test_missing_or_invalid_kernel_exec_path_remains_unknown() -> None:
    for path in (None, "", "python3", "/usr/bin/python\x00old"):
        assert _event_time_executable_path(_event(EventType.EXEC, path)) == "unknown"


def test_event_stage_counter_uses_parsed_kernel_event_type() -> None:
    metric = AGENT_EVENTS_TOTAL.labels(event_type="exec", stage="received")
    before = metric._value.get()
    _count_event(int(EventType.EXEC), "received")
    assert metric._value.get() == before + 1


def test_exec_collection_uses_post_exec_scheduler_tracepoint() -> None:
    source = (Path(__file__).parents[1] / "bpf" / "syscall_events.bpf.c").read_text()
    assert 'SEC("tracepoint/sched/sched_process_exec")' in source
    assert "int handle_sched_process_exec(void *ctx)" in source
    assert 'SEC("tracepoint/syscalls/sys_exit_execve")' not in source
    assert 'SEC("tracepoint/syscalls/sys_exit_execveat")' not in source
