"""
tests/ebpf-agent/test_event_parser.py

Unit tests for the ring-buffer event parser (infrastructure/ebpf/event_parser.py).

Coverage:
- sizeof assertions for all C struct mirrors (the module-load assert catches drift).
- Header parsing from synthetic bytes.
- Correct dispatch to every event type.
- ABI version mismatch raises ParseError.
- Unknown event_type raises ParseError.
- Truncated buffers raise ParseError.
- NUL-terminated strings are stripped correctly.
- Network address bytes are preserved exactly.
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from infrastructure.ebpf.event_parser import (
    _EXPECTED_EXEC_SIZE,
    _EXPECTED_FILE_OPEN_SIZE,
    _EXPECTED_FILE_WRITE_SIZE,
    _EXPECTED_LOSS_SIZE,
    _EXPECTED_MODULE_SIZE,
    _EXPECTED_NAMESPACE_SIZE,
    _EXPECTED_NETWORK_SIZE,
    _EXPECTED_PRIVILEGE_SIZE,
    _HEADER_SIZE,
    PHANTOM_ABI_VERSION,
    PHANTOM_PATH_MAX,
    EventType,
    ParsedExecEvent,
    ParsedFileOpenEvent,
    ParsedFileWriteEvent,
    ParsedLossEvent,
    ParsedModuleLoadEvent,
    ParsedNamespaceEvent,
    ParsedNetworkEvent,
    ParsedPrivilegeEvent,
    ParseError,
    _CExecEvent,
    _CFileOpenEvent,
    _CFileWriteEvent,
    _CHeader,
    _CLossEvent,
    _CModuleLoadEvent,
    _CNamespaceEvent,
    _CNetworkEvent,
    _CPrivilegeEvent,
    parse_event,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_c_header(
    abi_version: int = PHANTOM_ABI_VERSION,
    event_type: int = EventType.EXEC,
    total_size: int = 0,
    cgroup_id: int = 9999,
    pid: int = 1234,
    tgid: int = 1234,
    ppid: int = 1000,
    uid: int = 0,
    gid: int = 0,
    cpu: int = 0,
    comm: bytes = b"test\x00" * 3 + b"\x00",
) -> _CHeader:
    """Build a _CHeader ctypes struct for testing.

    Args:
        abi_version: ABI version to embed.
        event_type: Event type discriminant.
        total_size: total_size field.
        cgroup_id: Cgroup ID.
        pid: Thread PID.
        tgid: Thread group ID.
        ppid: Parent PID.
        uid: User ID.
        gid: Group ID.
        cpu: CPU ID.
        comm: 16-byte comm string.

    Returns:
        A _CHeader instance.
    """
    h = _CHeader()
    h.abi_version         = abi_version
    h.event_type          = event_type
    h.total_size          = total_size
    h.event_id_hi         = 0xDEADBEEFCAFEBABE
    h.event_id_lo         = 0x0102030405060708
    h.kernel_timestamp_ns = 1_700_000_000_000_000_000
    h.cgroup_id           = cgroup_id
    h.pid_start_time_ns   = 1_699_000_000_000_000_000
    h.pid                 = pid
    h.tgid                = tgid
    h.ppid                = ppid
    h.uid                 = uid
    h.gid                 = gid
    h.cpu                 = cpu
    h.comm                = comm[:16]
    return h


def _header_bytes(**kwargs: Any) -> bytes:
    """Return the raw bytes for a _CHeader.

    Args:
        **kwargs: Overrides for _make_c_header().

    Returns:
        bytes of length _HEADER_SIZE.
    """
    return bytes(_make_c_header(**kwargs))


# ---------------------------------------------------------------------------
# sizeof assertion tests (guard against layout drift)
# ---------------------------------------------------------------------------


class TestSizeof:
    """Verify ctypes struct sizes match the expected ABI sizes."""

    def test_header_size(self) -> None:
        assert ctypes.sizeof(_CHeader) == _HEADER_SIZE

    def test_exec_event_size(self) -> None:
        assert ctypes.sizeof(_CExecEvent) == _EXPECTED_EXEC_SIZE

    def test_file_open_event_size(self) -> None:
        assert ctypes.sizeof(_CFileOpenEvent) == _EXPECTED_FILE_OPEN_SIZE

    def test_file_write_event_size(self) -> None:
        assert ctypes.sizeof(_CFileWriteEvent) == _EXPECTED_FILE_WRITE_SIZE

    def test_network_event_size(self) -> None:
        assert ctypes.sizeof(_CNetworkEvent) == _EXPECTED_NETWORK_SIZE

    def test_privilege_event_size(self) -> None:
        assert ctypes.sizeof(_CPrivilegeEvent) == _EXPECTED_PRIVILEGE_SIZE

    def test_namespace_event_size(self) -> None:
        assert ctypes.sizeof(_CNamespaceEvent) == _EXPECTED_NAMESPACE_SIZE

    def test_module_load_event_size(self) -> None:
        assert ctypes.sizeof(_CModuleLoadEvent) == _EXPECTED_MODULE_SIZE

    def test_loss_event_size(self) -> None:
        assert ctypes.sizeof(_CLossEvent) == _EXPECTED_LOSS_SIZE


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------


class TestHeaderParsing:
    """Tests for _parse_header() via parse_event()."""

    def _make_exec_bytes(self, **header_kwargs: Any) -> bytes:
        """Build synthetic bytes for a valid EXEC event."""
        c = _CExecEvent()
        c.header                   = _make_c_header(event_type=EventType.EXEC, **header_kwargs)
        c.parent_tgid              = 1000
        c.argc                     = 3
        c.exec_flags               = 0
        c.executable_path          = b"/usr/bin/python3\x00"
        c.argv_digest              = b"\x00"
        return bytes(c)

    def test_pid_parsed_correctly(self) -> None:
        raw = self._make_exec_bytes(pid=4242)
        evt = parse_event(raw)
        assert evt.header.pid == 4242

    def test_tgid_parsed_correctly(self) -> None:
        raw = self._make_exec_bytes(tgid=9898)
        evt = parse_event(raw)
        assert evt.header.tgid == 9898

    def test_cgroup_id_parsed(self) -> None:
        raw = self._make_exec_bytes(cgroup_id=55555)
        evt = parse_event(raw)
        assert evt.header.cgroup_id == 55555

    def test_comm_stripped(self) -> None:
        """NUL-padded comm is stripped to the meaningful string."""
        raw = self._make_exec_bytes(comm=b"nginx\x00" + b"\x00" * 10)
        evt = parse_event(raw)
        assert evt.header.comm == "nginx"


# ---------------------------------------------------------------------------
# Exec event
# ---------------------------------------------------------------------------


class TestExecEvent:
    """Tests for PHANTOM_EVT_EXEC parsing."""

    def test_exec_event_dispatch(self) -> None:
        """parse_event returns ParsedExecEvent for EXEC events."""
        c = _CExecEvent()
        c.header = _make_c_header(event_type=EventType.EXEC)
        c.parent_tgid     = 1000
        c.argc            = 2
        c.exec_flags      = 0
        c.executable_path = b"/usr/bin/ls\x00"
        c.argv_digest     = b"\x00"
        evt = parse_event(bytes(c))
        assert isinstance(evt, ParsedExecEvent)
        assert evt.executable_path == "/usr/bin/ls"
        assert evt.argc == 2

    def test_exec_path_nul_stripped(self) -> None:
        """Executable path has NUL bytes stripped."""
        c = _CExecEvent()
        c.header = _make_c_header(event_type=EventType.EXEC)
        c.executable_path = b"/bin/bash\x00" + b"\x00" * (PHANTOM_PATH_MAX - 10)
        evt = parse_event(bytes(c))
        assert isinstance(evt, ParsedExecEvent)
        assert evt.executable_path == "/bin/bash"


# ---------------------------------------------------------------------------
# File open event
# ---------------------------------------------------------------------------


class TestFileOpenEvent:
    """Tests for PHANTOM_EVT_FILE_OPEN parsing."""

    def test_file_open_dispatch(self) -> None:
        c = _CFileOpenEvent()
        c.header         = _make_c_header(event_type=EventType.FILE_OPEN)
        c.fd             = 5
        c.open_flags     = 0
        c.mode           = 0
        c.syscall_result = 5
        c.path           = b"/etc/passwd\x00"
        evt = parse_event(bytes(c))
        assert isinstance(evt, ParsedFileOpenEvent)
        assert evt.fd == 5
        assert evt.path == "/etc/passwd"

    def test_negative_fd_preserved(self) -> None:
        """Negative fd (failure) is preserved as a signed int."""
        c = _CFileOpenEvent()
        c.header         = _make_c_header(event_type=EventType.FILE_OPEN)
        c.fd             = -1
        c.syscall_result = 0xFFFFFFFF
        c.path           = b"\x00"
        evt = parse_event(bytes(c))
        assert isinstance(evt, ParsedFileOpenEvent)
        assert evt.fd == -1


# ---------------------------------------------------------------------------
# File write event
# ---------------------------------------------------------------------------


class TestFileWriteEvent:
    """Tests for PHANTOM_EVT_FILE_WRITE parsing."""

    def test_file_write_dispatch(self) -> None:
        c = _CFileWriteEvent()
        c.header            = _make_c_header(event_type=EventType.FILE_WRITE)
        c.fd                = 3
        c.requested_bytes   = 1024
        c.result_bytes      = 1024
        c.file_inode        = 123456789
        c.file_device_major = 8
        c.file_device_minor = 1
        c.path              = b"/tmp/output.log\x00"
        evt = parse_event(bytes(c))
        assert isinstance(evt, ParsedFileWriteEvent)
        assert evt.requested_bytes == 1024
        assert evt.file_inode == 123456789

    def test_negative_result_bytes_preserved(self) -> None:
        """Negative result_bytes (failure) is preserved as signed int."""
        c = _CFileWriteEvent()
        c.header         = _make_c_header(event_type=EventType.FILE_WRITE)
        c.result_bytes   = -11  # -EAGAIN
        evt = parse_event(bytes(c))
        assert isinstance(evt, ParsedFileWriteEvent)
        assert evt.result_bytes == -11


# ---------------------------------------------------------------------------
# Network event
# ---------------------------------------------------------------------------


class TestNetworkEvent:
    """Tests for PHANTOM_EVT_NET_CONNECT / NET_ACCEPT parsing."""

    def test_connect_dispatch(self) -> None:
        c = _CNetworkEvent()
        c.header         = _make_c_header(event_type=EventType.NET_CONNECT)
        c.direction      = 1      # CONNECT
        c.address_family = 2      # AF_INET
        c.protocol       = 6      # IPPROTO_TCP
        c.local_port     = 54321
        c.remote_port    = 443
        # IPv4-mapped IPv6: ::ffff:8.8.8.8
        remote = (ctypes.c_uint8 * 16)(
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 8, 8, 8, 8
        )
        ctypes.memmove(c.remote_address, remote, 16)
        evt = parse_event(bytes(c))
        assert isinstance(evt, ParsedNetworkEvent)
        assert evt.direction == 1
        assert evt.remote_port == 443
        # Verify remote address bytes.
        assert evt.remote_address[10] == 0xFF
        assert evt.remote_address[11] == 0xFF
        assert evt.remote_address[12] == 8
        assert evt.remote_address[15] == 8

    def test_accept_event_type(self) -> None:
        c = _CNetworkEvent()
        c.header    = _make_c_header(event_type=EventType.NET_ACCEPT)
        c.direction = 2
        evt = parse_event(bytes(c))
        assert isinstance(evt, ParsedNetworkEvent)
        assert evt.direction == 2


# ---------------------------------------------------------------------------
# Privilege event
# ---------------------------------------------------------------------------


class TestPrivilegeEvent:
    """Tests for PHANTOM_EVT_PRIVILEGE parsing."""

    def test_privilege_dispatch(self) -> None:
        c = _CPrivilegeEvent()
        c.header                     = _make_c_header(event_type=EventType.PRIVILEGE)
        c.previous_uid               = 1000
        c.new_uid                    = 0
        c.previous_gid               = 1000
        c.new_gid                    = 0
        c.capability_effective_before = 0
        c.capability_effective_after  = 0xFFFFFFFF
        c.transition_kind             = 1  # SETUID
        evt = parse_event(bytes(c))
        assert isinstance(evt, ParsedPrivilegeEvent)
        assert evt.previous_uid == 1000
        assert evt.new_uid == 0
        assert evt.capability_effective_after == 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Namespace event
# ---------------------------------------------------------------------------


class TestNamespaceEvent:
    """Tests for PHANTOM_EVT_NAMESPACE parsing."""

    def test_namespace_dispatch(self) -> None:
        c = _CNamespaceEvent()
        c.header                   = _make_c_header(event_type=EventType.NAMESPACE)
        c.namespace_type           = 0x40000000  # CLONE_NEWNET
        c.operation                = 1
        c.previous_namespace_inode = 4026531992
        c.target_namespace_inode   = 4026532000
        c.syscall_result           = 0
        evt = parse_event(bytes(c))
        assert isinstance(evt, ParsedNamespaceEvent)
        assert evt.previous_namespace_inode == 4026531992


# ---------------------------------------------------------------------------
# Module load event
# ---------------------------------------------------------------------------


class TestModuleLoadEvent:
    """Tests for PHANTOM_EVT_MODULE_LOAD parsing."""

    def test_module_dispatch(self) -> None:
        c = _CModuleLoadEvent()
        c.header          = _make_c_header(event_type=EventType.MODULE_LOAD)
        c.operation       = 1  # FINIT
        c.syscall_result  = 0
        c.module_name     = b"evil_kmod\x00"
        c.module_digest   = b"\x00"  # Always zeroed by BPF.
        evt = parse_event(bytes(c))
        assert isinstance(evt, ParsedModuleLoadEvent)
        assert evt.module_name == "evil_kmod"
        assert evt.module_digest == ""

    def test_module_digest_always_empty(self) -> None:
        """module_digest is always empty (zeroed in BPF per ABI spec)."""
        c = _CModuleLoadEvent()
        c.header        = _make_c_header(event_type=EventType.MODULE_LOAD)
        c.module_digest = b"\x00"
        evt = parse_event(bytes(c))
        assert isinstance(evt, ParsedModuleLoadEvent)
        assert evt.module_digest == ""


# ---------------------------------------------------------------------------
# Loss event
# ---------------------------------------------------------------------------


class TestLossEvent:
    """Tests for PHANTOM_EVT_LOSS parsing."""

    def test_loss_dispatch(self) -> None:
        c = _CLossEvent()
        c.header                       = _make_c_header(event_type=EventType.LOSS)
        c.dropped_since_last_report    = 42
        c.ring_buffer_reserve_failures = 3
        c.user_space_submit_failures   = 0
        c.loss_scope                   = 1  # CPU
        evt = parse_event(bytes(c))
        assert isinstance(evt, ParsedLossEvent)
        assert evt.dropped_since_last_report == 42
        assert evt.loss_scope == 1


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


class TestParseErrors:
    """Tests for ParseError conditions."""

    def test_abi_version_mismatch_raises(self) -> None:
        """Wrong ABI version raises ParseError."""
        c = _CExecEvent()
        c.header = _make_c_header(abi_version=999, event_type=EventType.EXEC)
        with pytest.raises(ParseError, match="ABI version"):
            parse_event(bytes(c))

    def test_unknown_event_type_raises(self) -> None:
        """Unknown event_type raises ParseError."""
        c = _CExecEvent()
        c.header = _make_c_header(event_type=99)
        with pytest.raises(ParseError, match="Unknown event_type"):
            parse_event(bytes(c))

    def test_truncated_header_raises(self) -> None:
        """Buffer shorter than header raises ParseError."""
        with pytest.raises(ParseError, match="too short"):
            parse_event(b"\x00" * 10)

    def test_truncated_exec_event_raises(self) -> None:
        """Buffer with valid header but truncated exec payload raises ParseError."""
        raw_header = _header_bytes(event_type=EventType.EXEC)
        # Only provide the header, not the full exec event.
        with pytest.raises(ParseError):
            parse_event(raw_header)
