"""
services/ebpf-agent/infrastructure/ebpf/loader.py

libbpf-based BPF object loader using ctypes bindings.

Design:
- Uses ctypes to call libbpf C functions directly; no Python-bpf library
  is required beyond the system libbpf.so.
- Loads pre-compiled .bpf.o files (CO-RE) and attaches them to their
  declared tracepoints via BPF_PROG_TYPE_TRACEPOINT attach.
- Exposes a dict of ring buffer file descriptors for the polling thread.
- Exposes per-CPU reserve-failure counters for loss-event reporting.

Kernel requirement: 5.8 (BPF_MAP_TYPE_RINGBUF).

# VERIFY: libbpf.so path may differ across distributions.
  The loader searches LD_LIBRARY_PATH and /usr/lib, /usr/local/lib.
  Set LIBBPF_SO_PATH env var to override.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self

import structlog

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# libbpf ctypes interface
# ---------------------------------------------------------------------------

# Locate libbpf.so. Prefer an explicit path set via env var.
_LIBBPF_SO = os.environ.get("LIBBPF_SO_PATH") or ctypes.util.find_library("bpf")
if _LIBBPF_SO is None:
    _LIBBPF_SO = "libbpf.so.1"  # Final fallback; will raise OSError if absent.

_libbpf: ctypes.CDLL | None = None


def _get_libbpf() -> ctypes.CDLL:
    """Load and return the libbpf shared library singleton.

    Returns:
        The ctypes CDLL handle to libbpf.

    Raises:
        OSError: If libbpf.so cannot be found or loaded.
    """
    global _libbpf
    if _libbpf is None:
        _libbpf = ctypes.CDLL(_LIBBPF_SO, use_errno=True)
        _configure_libbpf_prototypes(_libbpf)
        log.info("ebpf_loader.libbpf_loaded", path=_LIBBPF_SO)
    return _libbpf


def _configure_libbpf_prototypes(lib: ctypes.CDLL) -> None:
    """Set ctypes argument and return types for the libbpf functions we use.

    Args:
        lib: The loaded libbpf CDLL.
    """
    c_void_p = ctypes.c_void_p
    c_int    = ctypes.c_int
    c_char_p = ctypes.c_char_p

    # bpf_object__open(const char *path) -> struct bpf_object *
    lib.bpf_object__open.restype  = c_void_p
    lib.bpf_object__open.argtypes = [c_char_p]

    # bpf_object__load(struct bpf_object *) -> int
    lib.bpf_object__load.restype  = c_int
    lib.bpf_object__load.argtypes = [c_void_p]

    # bpf_object__close(struct bpf_object *)
    lib.bpf_object__close.restype  = None
    lib.bpf_object__close.argtypes = [c_void_p]

    # bpf_object__find_map_by_name(struct bpf_object *, const char *) -> struct bpf_map *
    lib.bpf_object__find_map_by_name.restype  = c_void_p
    lib.bpf_object__find_map_by_name.argtypes = [c_void_p, c_char_p]

    # bpf_map__fd(const struct bpf_map *) -> int
    lib.bpf_map__fd.restype  = c_int
    lib.bpf_map__fd.argtypes = [c_void_p]

    # bpf_object__next_program(struct bpf_object *, struct bpf_program *) -> struct bpf_program *
    lib.bpf_object__next_program.restype  = c_void_p
    lib.bpf_object__next_program.argtypes = [c_void_p, c_void_p]

    # bpf_program__attach(struct bpf_program *) -> struct bpf_link *
    lib.bpf_program__attach.restype  = c_void_p
    lib.bpf_program__attach.argtypes = [c_void_p]

    # bpf_link__destroy(struct bpf_link *)
    lib.bpf_link__destroy.restype  = None
    lib.bpf_link__destroy.argtypes = [c_void_p]

    # bpf_program__name(const struct bpf_program *) -> const char *
    lib.bpf_program__name.restype  = c_char_p
    lib.bpf_program__name.argtypes = [c_void_p]

    # ring_buffer__new(int map_fd, ring_buffer_sample_fn fn, void *ctx, opts) -> ring_buffer *
    lib.ring_buffer__new.restype  = c_void_p
    lib.ring_buffer__new.argtypes = [c_int, c_void_p, c_void_p, c_void_p]

    # ring_buffer__poll(ring_buffer *, int timeout_ms) -> int
    lib.ring_buffer__poll.restype  = c_int
    lib.ring_buffer__poll.argtypes = [c_void_p, c_int]

    # ring_buffer__free(ring_buffer *)
    lib.ring_buffer__free.restype  = None
    lib.ring_buffer__free.argtypes = [c_void_p]

    # ring_buffer__add(ring_buffer *, int map_fd, ring_buffer_sample_fn fn, void *ctx) -> int
    lib.ring_buffer__add.restype = c_int
    lib.ring_buffer__add.argtypes = [c_void_p, c_int, c_void_p, c_void_p]

# Callback signature: int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size)
RING_BUFFER_SAMPLE_FN = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)


# ---------------------------------------------------------------------------
# Ring-buffer map names (must match SEC(".maps") names in .bpf.c files)
# ---------------------------------------------------------------------------

RINGBUF_MAP_NAMES = [
    "rb_exec",
    "rb_file_open",
    "rb_file_write",
    "rb_network",
    "rb_privilege",
    "rb_namespace",
    "rb_module",
    "rb_loss",
]


@dataclass
class BpfObjectHandle:
    """Manages the lifetime of a loaded BPF object.

    Attributes:
        obj_ptr: ctypes void pointer to the underlying bpf_object.
        links: List of ctypes void pointers to attached bpf_links.
        map_fds: Mapping of map name → file descriptor integer.
        bpf_file: Path to the .bpf.o file that was loaded.
    """

    obj_ptr: ctypes.c_void_p
    links: list[ctypes.c_void_p] = field(default_factory=list)
    map_fds: dict[str, int] = field(default_factory=dict)
    bpf_file: str = ""

    def close(self) -> None:
        """Detach all links and close the BPF object.

        Idempotent — safe to call multiple times.
        """
        lib = _get_libbpf()
        for link in self.links:
            if link:
                lib.bpf_link__destroy(link)
        self.links.clear()
        if self.obj_ptr:
            lib.bpf_object__close(self.obj_ptr)
            self.obj_ptr = None  # type: ignore[assignment]
        log.info("ebpf_loader.bpf_object_closed", bpf_file=self.bpf_file)


class PhantomBpfLoader:
    """Loads and attaches all PHANTOM CO-RE BPF programs from compiled objects.

    Each .bpf.o file corresponds to one event category. The loader opens each
    object, loads it into the kernel, attaches all programs, and collects the
    ring-buffer file descriptors for the event polling loop.

    Args:
        bpf_dir: Directory containing compiled .bpf.o files.
        ringbuf_size_bytes: Ring-buffer size per map in bytes (must be power of 2).
    """

    # Ordered list of .bpf.o files to load.
    BPF_OBJECTS: tuple[str, ...] = (
        "syscall_events.bpf.o",
        "file_events.bpf.o",
        "network_events.bpf.o",
        "process_events.bpf.o",
    )

    def __init__(
        self,
        bpf_dir: str | Path,
        ringbuf_size_bytes: int = 512 * 1024,
    ) -> None:
        """Initialise the loader.

        Args:
            bpf_dir: Directory containing compiled .bpf.o files.
            ringbuf_size_bytes: Ring-buffer size in bytes; must be power of 2.
        """
        self._bpf_dir = Path(bpf_dir)
        self._ringbuf_size = ringbuf_size_bytes
        self._handles: list[BpfObjectHandle] = []
        self._ringbuf_fds: dict[str, int] = {}

    @property
    def ringbuf_fds(self) -> dict[str, int]:
        """Return the dict of ring-buffer map name → file descriptor.

        Returns:
            Dict mapping ring-buffer map name to its file descriptor.
        """
        return dict(self._ringbuf_fds)

    def load_all(self) -> None:
        """Load and attach all PHANTOM BPF objects.

        Raises:
            OSError: If libbpf cannot be loaded.
            RuntimeError: If any BPF object fails to open or load.
        """
        lib = _get_libbpf()
        for obj_name in self.BPF_OBJECTS:
            obj_path = self._bpf_dir / obj_name
            if not obj_path.exists():
                log.warning(
                    "ebpf_loader.bpf_object_not_found",
                    path=str(obj_path),
                )
                continue
            handle = self._load_one(lib, obj_path)
            self._handles.append(handle)

        log.info(
            "ebpf_loader.all_objects_loaded",
            count=len(self._handles),
            ringbuf_fds=list(self._ringbuf_fds.keys()),
        )

    def _load_one(self, lib: ctypes.CDLL, obj_path: Path) -> BpfObjectHandle:
        """Load and attach one BPF object.

        Args:
            lib: The libbpf CDLL handle.
            obj_path: Absolute path to the .bpf.o file.

        Returns:
            A BpfObjectHandle for the loaded object.

        Raises:
            RuntimeError: If the object fails to open or load.
        """
        path_bytes = str(obj_path).encode()
        obj_ptr = lib.bpf_object__open(path_bytes)
        if not obj_ptr:
            raise RuntimeError(
                f"bpf_object__open({obj_path}) failed: "
                f"errno={ctypes.get_errno()}"
            )

        rc = lib.bpf_object__load(obj_ptr)
        if rc != 0:
            lib.bpf_object__close(obj_ptr)
            raise RuntimeError(
                f"bpf_object__load({obj_path}) failed: rc={rc}, "
                f"errno={ctypes.get_errno()}"
            )

        handle = BpfObjectHandle(obj_ptr=obj_ptr, bpf_file=str(obj_path))

        # Collect ring-buffer map file descriptors.
        for map_name in RINGBUF_MAP_NAMES:
            map_ptr = lib.bpf_object__find_map_by_name(obj_ptr, map_name.encode())
            if map_ptr:
                fd = lib.bpf_map__fd(map_ptr)
                if fd >= 0:
                    handle.map_fds[map_name] = fd
                    self._ringbuf_fds[map_name] = fd

        # Attach all programs.
        prog_ptr = lib.bpf_object__next_program(obj_ptr, None)
        while prog_ptr:
            name_bytes = lib.bpf_program__name(prog_ptr)
            name = name_bytes.decode() if name_bytes else "<unknown>"
            link_ptr = lib.bpf_program__attach(prog_ptr)
            if link_ptr:
                handle.links.append(link_ptr)
                log.info("ebpf_loader.program_attached", program=name)
            else:
                log.warning(
                    "ebpf_loader.program_attach_failed",
                    program=name,
                    errno=ctypes.get_errno(),
                )
            prog_ptr = lib.bpf_object__next_program(obj_ptr, prog_ptr)

        log.info(
            "ebpf_loader.bpf_object_loaded",
            path=str(obj_path),
            programs=len(handle.links),
            maps=len(handle.map_fds),
        )
        return handle

    def close_all(self) -> None:
        """Detach all programs and close all BPF objects.

        Idempotent — safe to call multiple times.
        """
        for handle in self._handles:
            handle.close()
        self._handles.clear()
        self._ringbuf_fds.clear()

    def __enter__(self) -> Self:
        """Context manager: load all objects on entry.

        Returns:
            self
        """
        self.load_all()
        return self

    def __exit__(self, *args: object) -> None:
        """Context manager: close all objects on exit."""
        self.close_all()


class RingBufferManager:
    """Manages the lifecycle of a libbpf ring_buffer and polls it."""

    def __init__(self, callback: RING_BUFFER_SAMPLE_FN):
        self._callback = callback
        self._rb_ptr = None
        self._lib = _get_libbpf()

    def add_map(self, map_fd: int) -> None:
        """Add a map to the ring buffer manager."""
        if not self._rb_ptr:
            # Create a new ring buffer manager with the first map
            # libbpf ring_buffer__new(int map_fd, ring_buffer_sample_fn fn, void *ctx, const struct ring_buffer_opts *opts)
            self._rb_ptr = self._lib.ring_buffer__new(map_fd, self._callback, None, None)
            if not self._rb_ptr:
                raise RuntimeError(f"ring_buffer__new failed for fd {map_fd}, errno={ctypes.get_errno()}")
        else:
            # Add additional map
            rc = self._lib.ring_buffer__add(self._rb_ptr, map_fd, self._callback, None)
            if rc < 0:
                raise RuntimeError(f"ring_buffer__add failed for fd {map_fd}, rc={rc}")

    def poll(self, timeout_ms: int = 100) -> int:
        """Poll the ring buffer for events.

        Returns the number of events processed or negative error.
        """
        if not self._rb_ptr:
            return 0
        return self._lib.ring_buffer__poll(self._rb_ptr, timeout_ms)

    def close(self) -> None:
        """Free the ring buffer manager."""
        if self._rb_ptr:
            self._lib.ring_buffer__free(self._rb_ptr)
            self._rb_ptr = None
