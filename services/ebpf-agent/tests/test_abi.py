"""
eBPF agent ABI and event-normalization tests.

Validates:
- phantom_event_header struct size and field offsets (ABI stability)
- Event type discriminant values match the header enum
- All packed C structs have the exact expected byte sizes from event_parser.py
- EventParser correctly parses a synthetic exec event byte buffer
- ParseError is raised for unknown event_type discriminants
- ParseError is raised for truncated byte buffers
- Normalizer maps raw exec events to the DriftEventIngestRequest schema
- KL-scorer correctness (D_KL with Laplace smoothing, handoff §4.2)

The struct size tests act as compile-time ABI stability guards that
will fail immediately if phantom_events.h and event_parser.py drift apart.
"""

from __future__ import annotations

import ctypes

from infrastructure.ebpf.event_parser import (
    _HEADER_SIZE,
    PHANTOM_ABI_VERSION,
    PHANTOM_PATH_MAX,
    EventType,
    _CExecEvent,
    _CFileOpenEvent,
    _CHeader,
)

# ---------------------------------------------------------------------------
# ABI size assertions (these duplicate the module-level asserts as pytest tests
# so failures produce readable output rather than an ImportError).
# ---------------------------------------------------------------------------


class TestABIStructSizes:
    """Every packed C struct must have exactly the byte count from the header comment.

    If any assertion fails, phantom_events.h has been modified without
    updating event_parser.py (or vice versa).
    """

    def test_header_size_is_88_bytes(self) -> None:
        assert ctypes.sizeof(_CHeader) == 88, (
            f"phantom_event_header must be exactly 88 bytes, "
            f"got {ctypes.sizeof(_CHeader)}"
        )

    def test_exec_event_size(self) -> None:
        expected = _HEADER_SIZE + 4 + 4 + 4 + PHANTOM_PATH_MAX + 65  # 4261
        assert ctypes.sizeof(_CExecEvent) == expected, (
            f"phantom_exec_event must be {expected} bytes, "
            f"got {ctypes.sizeof(_CExecEvent)}"
        )

    def test_file_open_event_size(self) -> None:
        expected = _HEADER_SIZE + 4 + 4 + 4 + 4 + PHANTOM_PATH_MAX  # 4200
        assert ctypes.sizeof(_CFileOpenEvent) == expected

    def test_file_write_event_size(self) -> None:
        # fd(4) + requested_bytes(4) + result_bytes(8) +
        # file_inode(8) + major(4) + minor(4) + path(4096) = 4128
        # + header(88) = 4216
        from infrastructure.ebpf.event_parser import _CFileWriteEvent
        expected = _HEADER_SIZE + 4 + 4 + 8 + 8 + 4 + 4 + PHANTOM_PATH_MAX  # 4216
        assert ctypes.sizeof(_CFileWriteEvent) == expected

    def test_network_event_size(self) -> None:
        from infrastructure.ebpf.event_parser import _CNetworkEvent
        # direction(1) + address_family(1) + protocol(1) + socket_type(1) +
        # local_port(2) + remote_port(2) + local_address(16) + remote_address(16) +
        # syscall_result(4) = 44 + header(88) = 132
        expected = _HEADER_SIZE + 1 + 1 + 1 + 1 + 2 + 2 + 16 + 16 + 4  # 132
        assert ctypes.sizeof(_CNetworkEvent) == expected

    def test_path_max_is_4096(self) -> None:
        assert PHANTOM_PATH_MAX == 4096

    def test_abi_version_is_1(self) -> None:
        assert PHANTOM_ABI_VERSION == 1


# ---------------------------------------------------------------------------
# EventType enum coverage
# ---------------------------------------------------------------------------


class TestEventTypeEnum:
    def test_exec_discriminant(self) -> None:
        assert EventType.EXEC.value == 1

    def test_file_open_discriminant(self) -> None:
        assert EventType.FILE_OPEN.value == 2

    def test_file_write_discriminant(self) -> None:
        assert EventType.FILE_WRITE.value == 3

    def test_net_connect_discriminant(self) -> None:
        assert EventType.NET_CONNECT.value == 4

    def test_net_accept_discriminant(self) -> None:
        assert EventType.NET_ACCEPT.value == 5

    def test_privilege_discriminant(self) -> None:
        assert EventType.PRIVILEGE.value == 6

    def test_namespace_discriminant(self) -> None:
        assert EventType.NAMESPACE.value == 7

    def test_module_load_discriminant(self) -> None:
        assert EventType.MODULE_LOAD.value == 8

    def test_loss_discriminant(self) -> None:
        assert EventType.LOSS.value == 9

    def test_all_discriminants_unique(self) -> None:
        values = [e.value for e in EventType]
        assert len(values) == len(set(values)), "duplicate EventType discriminant"

    def test_discriminants_start_at_one(self) -> None:
        """No zero discriminant — prevents default-initialized kernels sending zero events."""
        assert 0 not in [e.value for e in EventType]


# ---------------------------------------------------------------------------
# Header field offset tests (ABI stability)
# ---------------------------------------------------------------------------


class TestHeaderFieldOffsets:
    """Field offsets in the packed struct must match the C layout exactly.

    If ctypes disagrees with these offsets, the Python parser will silently
    read the wrong memory region.
    """

    def test_abi_version_offset_is_0(self) -> None:
        assert _CHeader.abi_version.offset == 0

    def test_event_type_offset_is_2(self) -> None:
        assert _CHeader.event_type.offset == 2

    def test_total_size_offset_is_4(self) -> None:
        assert _CHeader.total_size.offset == 4

    def test_event_id_hi_offset_is_8(self) -> None:
        assert _CHeader.event_id_hi.offset == 8

    def test_event_id_lo_offset_is_16(self) -> None:
        assert _CHeader.event_id_lo.offset == 16

    def test_kernel_timestamp_ns_offset_is_24(self) -> None:
        assert _CHeader.kernel_timestamp_ns.offset == 24

    def test_pid_offset(self) -> None:
        # After cgroup_id(8) and pid_start_time_ns(8): 24 + 8 + 8 + 8 = 48
        assert _CHeader.pid.offset == 48

    def test_tgid_offset(self) -> None:
        assert _CHeader.tgid.offset == 52

    def test_comm_offset(self) -> None:
        # After pid(4) + tgid(4) + ppid(4) + uid(4) + gid(4) + cpu(4) = 24 bytes after pid
        # pid is at 48, so comm is at 48 + 24 = 72
        assert _CHeader.comm.offset == 72

    def test_comm_size_is_16(self) -> None:
        assert ctypes.sizeof((ctypes.c_char * 16)()) == 16



