"""Regression tests for ring-buffer maps duplicated across BPF objects."""

from __future__ import annotations

from pathlib import Path

from infrastructure.ebpf import loader as loader_module
from infrastructure.ebpf.loader import PhantomBpfLoader, RINGBUF_MAPS_BY_OBJECT


class _FakeMap:
    def __init__(self, object_name: str, map_name: str, fd: int) -> None:
        self.object_name = object_name
        self.map_name = map_name
        self.fd = fd


class _FakeLib:
    def __init__(self) -> None:
        self.next_fd = 100
        self.closed: list[object] = []

    def bpf_object__open(self, path: bytes) -> object:
        return Path(path.decode()).name

    def bpf_object__load(self, _obj: object) -> int:
        return 0

    def bpf_object__find_map_by_name(self, obj: object, name: bytes) -> _FakeMap:
        self.next_fd += 1
        return _FakeMap(str(obj), name.decode(), self.next_fd)

    @staticmethod
    def bpf_map__fd(map_pointer: _FakeMap) -> int:
        return map_pointer.fd

    @staticmethod
    def bpf_object__next_program(_obj: object, _previous: object) -> None:
        return None

    def bpf_object__close(self, obj: object) -> None:
        self.closed.append(obj)


def test_loader_polls_each_object_producer_map_only(monkeypatch, tmp_path: Path) -> None:
    """EXEC and process producers must both be polled without unused maps."""
    for name in (
        "syscall_events.bpf.o",
        "file_events.bpf.o",
        "network_events.bpf.o",
        "process_events.bpf.o",
    ):
        (tmp_path / name).touch()
    fake_lib = _FakeLib()
    monkeypatch.setattr(loader_module, "_get_libbpf", lambda: fake_lib)

    loader = PhantomBpfLoader(tmp_path)
    loader.load_all()

    maps = loader.ringbuf_fds
    assert len(maps) == sum(
        len(RINGBUF_MAPS_BY_OBJECT[name])
        for name in ("syscall_events.bpf.o", "process_events.bpf.o")
    )
    assert maps == (
        ("syscall_events.bpf.o:rb_exec", 101),
        ("process_events.bpf.o:rb_privilege", 102),
        ("process_events.bpf.o:rb_namespace", 103),
        ("process_events.bpf.o:rb_module", 104),
    )
    assert all("rb_loss" not in name for name, _fd in maps)
    assert len(loader._handles) == 2

    loader.close_all()
    assert len(fake_lib.closed) == 2


def test_context_entry_failure_closes_previously_loaded_objects(monkeypatch, tmp_path: Path) -> None:
    class FailingLib(_FakeLib):
        def bpf_object__load(self, obj: object) -> int:
            if obj == "process_events.bpf.o":
                return -13
            return 0

    for name in ("syscall_events.bpf.o", "process_events.bpf.o"):
        (tmp_path / name).touch()
    fake_lib = FailingLib()
    monkeypatch.setattr(loader_module, "_get_libbpf", lambda: fake_lib)
    loader = PhantomBpfLoader(tmp_path)

    try:
        loader.__enter__()
    except RuntimeError as exc:
        assert "bpf_object__load" in str(exc)
    else:
        raise AssertionError("expected the second object load to fail")

    # Failed object's handle is closed by _load_one; the first successful
    # object's link/object is closed by __enter__ rollback.
    assert fake_lib.closed == ["process_events.bpf.o", "syscall_events.bpf.o"]
    assert loader._handles == []
    assert loader.ringbuf_fds == ()
