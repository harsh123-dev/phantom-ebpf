"""
tests/ebpf-agent/conftest.py

Shared pytest fixtures for eBPF agent tests.

Provides:
- mock_event_stream: async generator fixture yielding a list of parsed events.
- sample_token_sequence: a small deterministic token sequence for Markov tests.
- mock_markov_model: a pre-trained MarkovModel on the sample sequence.
"""

from __future__ import annotations

import uuid

import pytest

from domain.markov.chain import MarkovModel, Token, tau, train
from infrastructure.ebpf.event_parser import (
    PHANTOM_ABI_VERSION,
    EventType,
    ParsedEvent,
    ParsedEventHeader,
    ParsedExecEvent,
    ParsedFileOpenEvent,
    ParsedLossEvent,
    ParsedNetworkEvent,
)

# ---------------------------------------------------------------------------
# Header factory
# ---------------------------------------------------------------------------

_NOW_NS: int = 1_700_000_000_000_000_000  # arbitrary monotonic time


def make_header(event_type: int, cpu: int = 0) -> ParsedEventHeader:
    """Build a minimal ParsedEventHeader for test events.

    Args:
        event_type: One of EventType enum integer values.
        cpu: CPU ID (default 0).

    Returns:
        A ParsedEventHeader.
    """
    return ParsedEventHeader(
        abi_version=PHANTOM_ABI_VERSION,
        event_type=event_type,
        total_size=0,
        event_id_hi=int(uuid.uuid4()) >> 64,
        event_id_lo=int(uuid.uuid4()) & 0xFFFFFFFFFFFFFFFF,
        kernel_timestamp_ns=_NOW_NS,
        cgroup_id=12345,
        pid_start_time_ns=_NOW_NS - 10_000_000_000,
        pid=1001,
        tgid=1001,
        ppid=1000,
        uid=0,
        gid=0,
        cpu=cpu,
        comm="python",
    )


# ---------------------------------------------------------------------------
# Event stream fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def mock_event_stream() -> list[ParsedEvent]:
    """A list of parsed events simulating a small eBPF event stream.

    Returns:
        A list containing exec, file_open, network, and loss events.
    """
    exec_evt = ParsedExecEvent(
        header=make_header(EventType.EXEC),
        parent_tgid=1000,
        argc=2,
        exec_flags=0,
        executable_path="/usr/bin/python3",
        argv_digest="",
    )
    file_open_evt = ParsedFileOpenEvent(
        header=make_header(EventType.FILE_OPEN),
        fd=3,
        open_flags=0,
        mode=0,
        syscall_result=3,
        path="/etc/ssl/certs/ca-certificates.crt",
    )
    net_evt = ParsedNetworkEvent(
        header=make_header(EventType.NET_CONNECT),
        direction=1,
        address_family=2,
        protocol=6,
        socket_type=1,
        local_port=54321,
        remote_port=443,
        local_address=bytes(16),
        remote_address=bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 8, 8, 8, 8]),
        syscall_result=0,
    )
    loss_evt = ParsedLossEvent(
        header=make_header(EventType.LOSS),
        dropped_since_last_report=3,
        ring_buffer_reserve_failures=1,
        user_space_submit_failures=0,
        loss_scope=1,
    )
    return [exec_evt, file_open_evt, net_evt, loss_evt]


# ---------------------------------------------------------------------------
# Markov fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def sample_token_sequence() -> list[Token]:
    """A deterministic token sequence for Markov chain tests.

    Returns:
        A list of Tokens representing a simple exec→read→connect pattern.
    """
    pattern: list[Token] = [
        tau("exec",        "exec",    "/usr/bin/python3",          "unprivileged"),
        tau("file_open",   "read",    "/etc/ssl/certs/ca.crt",     "unprivileged"),
        tau("net_connect", "connect", "8.8.8.8:443",               "unprivileged"),
        tau("file_open",   "read",    "/usr/lib/python3.11/abc.py","unprivileged"),
        tau("exec",        "exec",    "/usr/bin/python3",          "unprivileged"),
    ]
    # Repeat pattern to give the Markov chain enough data.
    return pattern * 40


@pytest.fixture()
def mock_markov_model(sample_token_sequence: list[Token]) -> MarkovModel:
    """A MarkovModel trained on sample_token_sequence.

    Args:
        sample_token_sequence: The sample sequence fixture.

    Returns:
        A trained MarkovModel.
    """
    sequences = [sample_token_sequence]
    return train(sequences, k_max=3)
