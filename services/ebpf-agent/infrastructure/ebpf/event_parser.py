"""
services/ebpf-agent/infrastructure/ebpf/event_parser.py

Parses raw ring-buffer bytes from PHANTOM BPF programs into Python dataclasses.

Design:
- Every struct layout is declared as a ctypes.Structure subclass.
- The layout EXACTLY mirrors the C structs in include/phantom_events.h,
  including __attribute__((packed)) (enforced by ctypes with _pack_ = 1).
- Explicit sizeof assertions guard against any layout drift between the
  C header and the Python parser.
- The parser dispatches on the event_type field of the header to the
  correct struct, rejects unknown event_types, and emits a ParseError
  (never silently corrupts the event stream).

# VERIFY: All sizes below must be rechecked whenever phantom_events.h changes.
  Run `tests/ebpf-agent/test_event_parser.py` to validate sizeof alignment.

Struct field sizes (all packed, x86_64 and arm64 identical due to explicit
fixed-width fields):

    phantom_event_header:
      abi_version(2) + event_type(2) + total_size(4) +
      event_id_hi(8) + event_id_lo(8) +
      kernel_timestamp_ns(8) + cgroup_id(8) + pid_start_time_ns(8) +
      pid(4) + tgid(4) + ppid(4) + uid(4) + gid(4) + cpu(4) +
      comm(16) = 88 bytes

    phantom_exec_event:
      header(88) + parent_tgid(4) + argc(4) + exec_flags(4) +
      executable_path(4096) + argv_digest(65) = 4261 bytes

    phantom_file_open_event:
      header(88) + fd(4) + open_flags(4) + mode(4) + syscall_result(4) +
      path(4096) = 4200 bytes

    phantom_file_write_event:
      header(88) + fd(4) + requested_bytes(4) + result_bytes(8) +
      file_inode(8) + file_device_major(4) + file_device_minor(4) +
      path(4096) = 4216 bytes  (NB: result_bytes is s64 → needs 4-byte pad
      in natural layout, but packed removes it; see note below)

    phantom_network_event:
      header(88) + direction(1) + address_family(1) + protocol(1) +
      socket_type(1) + local_port(2) + remote_port(2) +
      local_address(16) + remote_address(16) + syscall_result(4) = 132 bytes

    phantom_privilege_event:
      header(88) + previous_uid(4) + new_uid(4) + previous_gid(4) +
      new_gid(4) + capability_effective_before(8) +
      capability_effective_after(8) + transition_kind(4) = 124 bytes

    phantom_namespace_event:
      header(88) + namespace_type(4) + operation(4) +
      previous_namespace_inode(8) + target_namespace_inode(8) +
      syscall_result(4) = 116 bytes  (NB: 4-byte pad before 8-byte fields
      in natural layout; packed removes it)

    phantom_module_load_event:
      header(88) + operation(4) + syscall_result(4) +
      module_name(64) + module_digest(65) = 225 bytes

    phantom_loss_event:
      header(88) + dropped_since_last_report(8) +
      ring_buffer_reserve_failures(8) + user_space_submit_failures(8) +
      loss_scope(4) = 116 bytes

# VERIFY: phantom_file_write_event — in the packed C struct fd is s32 (4 bytes)
  followed immediately by requested_bytes u32 (4 bytes), then result_bytes s64
  (8 bytes). Packed removes alignment padding so the total is exactly as above.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from enum import IntEnum

import structlog

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# ABI constants (must match phantom_events.h)
# ---------------------------------------------------------------------------

PHANTOM_ABI_VERSION: int = 1
PHANTOM_PATH_MAX: int = 4096

_HEADER_SIZE: int = 88
"""Expected size of phantom_event_header; asserted at module load."""


class EventType(IntEnum):
    """Discriminant values from enum phantom_event_type."""

    EXEC        = 1
    FILE_OPEN   = 2
    FILE_WRITE  = 3
    NET_CONNECT = 4
    NET_ACCEPT  = 5
    PRIVILEGE   = 6
    NAMESPACE   = 7
    MODULE_LOAD = 8
    LOSS        = 9


# ---------------------------------------------------------------------------
# ctypes structure definitions (packed to exactly mirror C __attribute__((packed)))
# ---------------------------------------------------------------------------

class _CHeader(ctypes.Structure):
    """C struct: phantom_event_header (packed, 88 bytes)."""

    _pack_ = 1
    _fields_ = [
        ("abi_version",         ctypes.c_uint16),
        ("event_type",          ctypes.c_uint16),
        ("total_size",          ctypes.c_uint32),
        ("event_id_hi",         ctypes.c_uint64),
        ("event_id_lo",         ctypes.c_uint64),
        ("kernel_timestamp_ns", ctypes.c_uint64),
        ("cgroup_id",           ctypes.c_uint64),
        ("pid_start_time_ns",   ctypes.c_uint64),
        ("pid",                 ctypes.c_uint32),
        ("tgid",                ctypes.c_uint32),
        ("ppid",                ctypes.c_uint32),
        ("uid",                 ctypes.c_uint32),
        ("gid",                 ctypes.c_uint32),
        ("cpu",                 ctypes.c_uint32),
        ("comm",                ctypes.c_char * 16),
    ]


assert ctypes.sizeof(_CHeader) == _HEADER_SIZE, (
    f"phantom_event_header size mismatch: "
    f"expected {_HEADER_SIZE}, got {ctypes.sizeof(_CHeader)}"
)


class _CExecEvent(ctypes.Structure):
    """C struct: phantom_exec_event (packed)."""

    _pack_ = 1
    _fields_ = [
        ("header",          _CHeader),
        ("parent_tgid",     ctypes.c_uint32),
        ("argc",            ctypes.c_uint32),
        ("exec_flags",      ctypes.c_uint32),
        ("executable_path", ctypes.c_char * PHANTOM_PATH_MAX),
        ("argv_digest",     ctypes.c_char * 65),
    ]


_EXPECTED_EXEC_SIZE = _HEADER_SIZE + 4 + 4 + 4 + PHANTOM_PATH_MAX + 65  # 4261
assert ctypes.sizeof(_CExecEvent) == _EXPECTED_EXEC_SIZE, (
    f"phantom_exec_event size mismatch: "
    f"expected {_EXPECTED_EXEC_SIZE}, got {ctypes.sizeof(_CExecEvent)}"
)


class _CFileOpenEvent(ctypes.Structure):
    """C struct: phantom_file_open_event (packed)."""

    _pack_ = 1
    _fields_ = [
        ("header",          _CHeader),
        ("fd",              ctypes.c_int32),
        ("open_flags",      ctypes.c_uint32),
        ("mode",            ctypes.c_uint32),
        ("syscall_result",  ctypes.c_uint32),
        ("path",            ctypes.c_char * PHANTOM_PATH_MAX),
    ]


_EXPECTED_FILE_OPEN_SIZE = _HEADER_SIZE + 4 + 4 + 4 + 4 + PHANTOM_PATH_MAX  # 4200
assert ctypes.sizeof(_CFileOpenEvent) == _EXPECTED_FILE_OPEN_SIZE, (
    f"phantom_file_open_event size mismatch: "
    f"expected {_EXPECTED_FILE_OPEN_SIZE}, got {ctypes.sizeof(_CFileOpenEvent)}"
)


class _CFileWriteEvent(ctypes.Structure):
    """C struct: phantom_file_write_event (packed)."""

    _pack_ = 1
    _fields_ = [
        ("header",             _CHeader),
        ("fd",                 ctypes.c_int32),
        ("requested_bytes",    ctypes.c_uint32),
        ("result_bytes",       ctypes.c_int64),
        ("file_inode",         ctypes.c_uint64),
        ("file_device_major",  ctypes.c_uint32),
        ("file_device_minor",  ctypes.c_uint32),
        ("path",               ctypes.c_char * PHANTOM_PATH_MAX),
    ]


_EXPECTED_FILE_WRITE_SIZE = _HEADER_SIZE + 4 + 4 + 8 + 8 + 4 + 4 + PHANTOM_PATH_MAX  # 4216
assert ctypes.sizeof(_CFileWriteEvent) == _EXPECTED_FILE_WRITE_SIZE, (
    f"phantom_file_write_event size mismatch: "
    f"expected {_EXPECTED_FILE_WRITE_SIZE}, got {ctypes.sizeof(_CFileWriteEvent)}"
)


class _CNetworkEvent(ctypes.Structure):
    """C struct: phantom_network_event (packed)."""

    _pack_ = 1
    _fields_ = [
        ("header",          _CHeader),
        ("direction",       ctypes.c_uint8),
        ("address_family",  ctypes.c_uint8),
        ("protocol",        ctypes.c_uint8),
        ("socket_type",     ctypes.c_uint8),
        ("local_port",      ctypes.c_uint16),
        ("remote_port",     ctypes.c_uint16),
        ("local_address",   ctypes.c_uint8 * 16),
        ("remote_address",  ctypes.c_uint8 * 16),
        ("syscall_result",  ctypes.c_int32),
    ]


_EXPECTED_NETWORK_SIZE = _HEADER_SIZE + 1 + 1 + 1 + 1 + 2 + 2 + 16 + 16 + 4  # 132
assert ctypes.sizeof(_CNetworkEvent) == _EXPECTED_NETWORK_SIZE, (
    f"phantom_network_event size mismatch: "
    f"expected {_EXPECTED_NETWORK_SIZE}, got {ctypes.sizeof(_CNetworkEvent)}"
)


class _CPrivilegeEvent(ctypes.Structure):
    """C struct: phantom_privilege_event (packed)."""

    _pack_ = 1
    _fields_ = [
        ("header",                      _CHeader),
        ("previous_uid",                ctypes.c_uint32),
        ("new_uid",                     ctypes.c_uint32),
        ("previous_gid",                ctypes.c_uint32),
        ("new_gid",                     ctypes.c_uint32),
        ("capability_effective_before", ctypes.c_uint64),
        ("capability_effective_after",  ctypes.c_uint64),
        ("transition_kind",             ctypes.c_uint32),
    ]


_EXPECTED_PRIVILEGE_SIZE = _HEADER_SIZE + 4 + 4 + 4 + 4 + 8 + 8 + 4  # 124
assert ctypes.sizeof(_CPrivilegeEvent) == _EXPECTED_PRIVILEGE_SIZE, (
    f"phantom_privilege_event size mismatch: "
    f"expected {_EXPECTED_PRIVILEGE_SIZE}, got {ctypes.sizeof(_CPrivilegeEvent)}"
)


class _CNamespaceEvent(ctypes.Structure):
    """C struct: phantom_namespace_event (packed)."""

    _pack_ = 1
    _fields_ = [
        ("header",                    _CHeader),
        ("namespace_type",            ctypes.c_uint32),
        ("operation",                 ctypes.c_uint32),
        ("previous_namespace_inode",  ctypes.c_uint64),
        ("target_namespace_inode",    ctypes.c_uint64),
        ("syscall_result",            ctypes.c_int32),
    ]


_EXPECTED_NAMESPACE_SIZE = _HEADER_SIZE + 4 + 4 + 8 + 8 + 4  # 116
assert ctypes.sizeof(_CNamespaceEvent) == _EXPECTED_NAMESPACE_SIZE, (
    f"phantom_namespace_event size mismatch: "
    f"expected {_EXPECTED_NAMESPACE_SIZE}, got {ctypes.sizeof(_CNamespaceEvent)}"
)


class _CModuleLoadEvent(ctypes.Structure):
    """C struct: phantom_module_load_event (packed)."""

    _pack_ = 1
    _fields_ = [
        ("header",          _CHeader),
        ("operation",       ctypes.c_uint32),
        ("syscall_result",  ctypes.c_int32),
        ("module_name",     ctypes.c_char * 64),
        ("module_digest",   ctypes.c_char * 65),
    ]


_EXPECTED_MODULE_SIZE = _HEADER_SIZE + 4 + 4 + 64 + 65  # 225
assert ctypes.sizeof(_CModuleLoadEvent) == _EXPECTED_MODULE_SIZE, (
    f"phantom_module_load_event size mismatch: "
    f"expected {_EXPECTED_MODULE_SIZE}, got {ctypes.sizeof(_CModuleLoadEvent)}"
)


class _CLossEvent(ctypes.Structure):
    """C struct: phantom_loss_event (packed)."""

    _pack_ = 1
    _fields_ = [
        ("header",                       _CHeader),
        ("dropped_since_last_report",    ctypes.c_uint64),
        ("ring_buffer_reserve_failures", ctypes.c_uint64),
        ("user_space_submit_failures",   ctypes.c_uint64),
        ("loss_scope",                   ctypes.c_uint32),
    ]


_EXPECTED_LOSS_SIZE = _HEADER_SIZE + 8 + 8 + 8 + 4  # 116
assert ctypes.sizeof(_CLossEvent) == _EXPECTED_LOSS_SIZE, (
    f"phantom_loss_event size mismatch: "
    f"expected {_EXPECTED_LOSS_SIZE}, got {ctypes.sizeof(_CLossEvent)}"
)

# ---------------------------------------------------------------------------
# Python domain dataclasses (pure Python, no ctypes dependency)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParsedEventHeader:
    """Python representation of phantom_event_header."""

    abi_version: int
    event_type: int
    total_size: int
    event_id_hi: int
    event_id_lo: int
    kernel_timestamp_ns: int
    cgroup_id: int
    pid_start_time_ns: int
    pid: int
    tgid: int
    ppid: int
    uid: int
    gid: int
    cpu: int
    comm: str


@dataclass(frozen=True)
class ParsedExecEvent:
    """Python representation of phantom_exec_event."""

    header: ParsedEventHeader
    parent_tgid: int
    argc: int
    exec_flags: int
    executable_path: str
    argv_digest: str


@dataclass(frozen=True)
class ParsedFileOpenEvent:
    """Python representation of phantom_file_open_event."""

    header: ParsedEventHeader
    fd: int
    open_flags: int
    mode: int
    syscall_result: int
    path: str


@dataclass(frozen=True)
class ParsedFileWriteEvent:
    """Python representation of phantom_file_write_event."""

    header: ParsedEventHeader
    fd: int
    requested_bytes: int
    result_bytes: int
    file_inode: int
    file_device_major: int
    file_device_minor: int
    path: str


@dataclass(frozen=True)
class ParsedNetworkEvent:
    """Python representation of phantom_network_event."""

    header: ParsedEventHeader
    direction: int
    address_family: int
    protocol: int
    socket_type: int
    local_port: int
    remote_port: int
    local_address: bytes   # 16 bytes
    remote_address: bytes  # 16 bytes
    syscall_result: int


@dataclass(frozen=True)
class ParsedPrivilegeEvent:
    """Python representation of phantom_privilege_event."""

    header: ParsedEventHeader
    previous_uid: int
    new_uid: int
    previous_gid: int
    new_gid: int
    capability_effective_before: int
    capability_effective_after: int
    transition_kind: int


@dataclass(frozen=True)
class ParsedNamespaceEvent:
    """Python representation of phantom_namespace_event."""

    header: ParsedEventHeader
    namespace_type: int
    operation: int
    previous_namespace_inode: int
    target_namespace_inode: int
    syscall_result: int


@dataclass(frozen=True)
class ParsedModuleLoadEvent:
    """Python representation of phantom_module_load_event."""

    header: ParsedEventHeader
    operation: int
    syscall_result: int
    module_name: str
    module_digest: str


@dataclass(frozen=True)
class ParsedLossEvent:
    """Python representation of phantom_loss_event."""

    header: ParsedEventHeader
    dropped_since_last_report: int
    ring_buffer_reserve_failures: int
    user_space_submit_failures: int
    loss_scope: int


ParsedEvent = (
    ParsedExecEvent
    | ParsedFileOpenEvent
    | ParsedFileWriteEvent
    | ParsedNetworkEvent
    | ParsedPrivilegeEvent
    | ParsedNamespaceEvent
    | ParsedModuleLoadEvent
    | ParsedLossEvent
)


class ParseError(Exception):
    """Raised when raw ring-buffer bytes cannot be parsed as a valid event."""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _parse_header(raw: bytes) -> ParsedEventHeader:
    """Parse raw bytes into a ParsedEventHeader.

    Args:
        raw: At least _HEADER_SIZE bytes from the ring buffer.

    Returns:
        ParsedEventHeader populated from the raw bytes.

    Raises:
        ParseError: If the buffer is too short.
    """
    if len(raw) < _HEADER_SIZE:
        raise ParseError(
            f"Buffer too short for header: need {_HEADER_SIZE}, got {len(raw)}"
        )
    c = _CHeader.from_buffer_copy(raw[:_HEADER_SIZE])
    return ParsedEventHeader(
        abi_version=c.abi_version,
        event_type=c.event_type,
        total_size=c.total_size,
        event_id_hi=c.event_id_hi,
        event_id_lo=c.event_id_lo,
        kernel_timestamp_ns=c.kernel_timestamp_ns,
        cgroup_id=c.cgroup_id,
        pid_start_time_ns=c.pid_start_time_ns,
        pid=c.pid,
        tgid=c.tgid,
        ppid=c.ppid,
        uid=c.uid,
        gid=c.gid,
        cpu=c.cpu,
        comm=c.comm.rstrip(b"\x00").decode("latin-1", errors="replace"),
    )


def parse_event(raw: bytes) -> ParsedEvent:
    """Parse raw ring-buffer bytes into a typed Python event dataclass.

    The event type is determined by reading the event_type field of the
    phantom_event_header. Unknown event types raise ParseError.

    Args:
        raw: Raw bytes as received from the ring buffer.

    Returns:
        A typed ParsedEvent dataclass.

    Raises:
        ParseError: If the bytes are malformed, too short, or have an
            unknown event type.
    """
    header = _parse_header(raw)

    if header.abi_version != PHANTOM_ABI_VERSION:
        raise ParseError(
            f"ABI version mismatch: expected {PHANTOM_ABI_VERSION}, "
            f"got {header.abi_version}"
        )

    ev_type = header.event_type

    try:
        if ev_type == EventType.EXEC:
            if len(raw) < _EXPECTED_EXEC_SIZE:
                raise ParseError(f"EXEC event too short: {len(raw)} < {_EXPECTED_EXEC_SIZE}")
            c = _CExecEvent.from_buffer_copy(raw[:_EXPECTED_EXEC_SIZE])
            return ParsedExecEvent(
                header=header,
                parent_tgid=c.parent_tgid,
                argc=c.argc,
                exec_flags=c.exec_flags,
                executable_path=c.executable_path.rstrip(b"\x00").decode("utf-8", errors="replace"),
                argv_digest=c.argv_digest.rstrip(b"\x00").decode("ascii", errors="replace"),
            )

        elif ev_type == EventType.FILE_OPEN:
            if len(raw) < _EXPECTED_FILE_OPEN_SIZE:
                raise ParseError("FILE_OPEN event too short")
            c = _CFileOpenEvent.from_buffer_copy(raw[:_EXPECTED_FILE_OPEN_SIZE])  # type: ignore[assignment]
            return ParsedFileOpenEvent(
                header=header,
                fd=c.fd,
                open_flags=c.open_flags,
                mode=c.mode,
                syscall_result=c.syscall_result,
                path=c.path.rstrip(b"\x00").decode("utf-8", errors="replace"),
            )

        elif ev_type == EventType.FILE_WRITE:
            if len(raw) < _EXPECTED_FILE_WRITE_SIZE:
                raise ParseError("FILE_WRITE event too short")
            c = _CFileWriteEvent.from_buffer_copy(raw[:_EXPECTED_FILE_WRITE_SIZE])  # type: ignore[assignment]
            return ParsedFileWriteEvent(
                header=header,
                fd=c.fd,
                requested_bytes=c.requested_bytes,
                result_bytes=c.result_bytes,
                file_inode=c.file_inode,
                file_device_major=c.file_device_major,
                file_device_minor=c.file_device_minor,
                path=c.path.rstrip(b"\x00").decode("utf-8", errors="replace"),
            )

        elif ev_type in (EventType.NET_CONNECT, EventType.NET_ACCEPT):
            if len(raw) < _EXPECTED_NETWORK_SIZE:
                raise ParseError("NETWORK event too short")
            c = _CNetworkEvent.from_buffer_copy(raw[:_EXPECTED_NETWORK_SIZE])  # type: ignore[assignment]
            return ParsedNetworkEvent(
                header=header,
                direction=c.direction,
                address_family=c.address_family,
                protocol=c.protocol,
                socket_type=c.socket_type,
                local_port=c.local_port,
                remote_port=c.remote_port,
                local_address=bytes(c.local_address),
                remote_address=bytes(c.remote_address),
                syscall_result=c.syscall_result,
            )

        elif ev_type == EventType.PRIVILEGE:
            if len(raw) < _EXPECTED_PRIVILEGE_SIZE:
                raise ParseError("PRIVILEGE event too short")
            c = _CPrivilegeEvent.from_buffer_copy(raw[:_EXPECTED_PRIVILEGE_SIZE])  # type: ignore[assignment]
            return ParsedPrivilegeEvent(
                header=header,
                previous_uid=c.previous_uid,
                new_uid=c.new_uid,
                previous_gid=c.previous_gid,
                new_gid=c.new_gid,
                capability_effective_before=c.capability_effective_before,
                capability_effective_after=c.capability_effective_after,
                transition_kind=c.transition_kind,
            )

        elif ev_type == EventType.NAMESPACE:
            if len(raw) < _EXPECTED_NAMESPACE_SIZE:
                raise ParseError("NAMESPACE event too short")
            c = _CNamespaceEvent.from_buffer_copy(raw[:_EXPECTED_NAMESPACE_SIZE])  # type: ignore[assignment]
            return ParsedNamespaceEvent(
                header=header,
                namespace_type=c.namespace_type,
                operation=c.operation,
                previous_namespace_inode=c.previous_namespace_inode,
                target_namespace_inode=c.target_namespace_inode,
                syscall_result=c.syscall_result,
            )

        elif ev_type == EventType.MODULE_LOAD:
            if len(raw) < _EXPECTED_MODULE_SIZE:
                raise ParseError("MODULE_LOAD event too short")
            c = _CModuleLoadEvent.from_buffer_copy(raw[:_EXPECTED_MODULE_SIZE])  # type: ignore[assignment]
            return ParsedModuleLoadEvent(
                header=header,
                operation=c.operation,
                syscall_result=c.syscall_result,
                module_name=c.module_name.rstrip(b"\x00").decode("utf-8", errors="replace"),
                module_digest=c.module_digest.rstrip(b"\x00").decode("ascii", errors="replace"),
            )

        elif ev_type == EventType.LOSS:
            if len(raw) < _EXPECTED_LOSS_SIZE:
                raise ParseError("LOSS event too short")
            c = _CLossEvent.from_buffer_copy(raw[:_EXPECTED_LOSS_SIZE])  # type: ignore[assignment]
            return ParsedLossEvent(
                header=header,
                dropped_since_last_report=c.dropped_since_last_report,
                ring_buffer_reserve_failures=c.ring_buffer_reserve_failures,
                user_space_submit_failures=c.user_space_submit_failures,
                loss_scope=c.loss_scope,
            )

        else:
            raise ParseError(f"Unknown event_type: {ev_type}")

    except ctypes.ArgumentError as exc:
        raise ParseError(f"ctypes parse failure for event_type={ev_type}: {exc}") from exc
