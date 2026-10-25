"""
services/ebpf-agent/application/main.py

PHANTOM eBPF agent daemon.

Fixed root causes (2026-08-31):
  1. cgroup_read_failed race: container_id is now read synchronously inside
     rb_callback (C thread, process still alive) and stored in a per-event
     side-channel dict keyed by (pid, tgid, start_time_ns). The async processor
     consumes and deletes the entry. No more /proc/<pid>/cgroup disappearing.
  2. executable_path empty for non-EXEC events: resolved from
     /host/proc/<pid>/exe symlink (falls back to comm string).
  3. Redis URL defaulting to localhost: agent now reads REDIS_URL env var
     (injected by the DaemonSet from phantom-config).
  4. /proc vs /host/proc: the DaemonSet mounts the host /proc at /host/proc;
     all /proc reads now use PROC_ROOT = /host/proc.
"""

import asyncio
import ctypes
import hashlib
import itertools
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from dataclasses import asdict
from typing import Any

import structlog
from aiohttp import web
from redis.asyncio import Redis
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from infrastructure.api.dispatcher import ApiDispatcher
from infrastructure.ebpf.event_parser import (
    EventType,
    ParseError,
    ParsedEvent,
    parse_event,
)
from infrastructure.ebpf.loader import (
    RING_BUFFER_SAMPLE_FN,
    PhantomBpfLoader,
    RingBufferManager,
)
from infrastructure.k8s.attributor import CgroupPodAttributor
from domain.event_lag import event_delivery_lag_seconds

log = structlog.get_logger(__name__)

# The DaemonSet mounts the host /proc at /host/proc (not /proc).
PROC_ROOT: str = "/host/proc"

# Per-event container-ID side channel:  key=(pid,tgid,start_time_ns) → container_id_str|None
# Written in rb_callback (synchronous, process still alive).
# Consumed and deleted in async event_processor.
_CONTAINER_ID_CACHE: dict[tuple[int, int, int], str | None] = {}

# Asyncio queue between the C ring-buffer callback and the Python processor.
event_queue: asyncio.Queue[ParsedEvent] = asyncio.Queue(maxsize=50000)

# Measures kernel event timestamp to userspace ring-buffer callback entry.
# bpf_ktime_get_ns() and time.monotonic_ns() share the node CLOCK_MONOTONIC
# domain when the pod has no time-namespace offset (the k3s lab default).
EVENT_DELIVERY_LAG_SECONDS = Histogram(
    "phantom_event_delivery_lag_seconds",
    "Time from kernel event timestamp to eBPF agent ring-buffer callback entry.",
    buckets=(0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0),
)
EVENT_DELIVERY_LAG_INVALID_TOTAL = Counter(
    "phantom_event_delivery_lag_invalid_total",
    "Events excluded from delivery-lag measurement due to invalid timestamps.",
    labelnames=("reason",),
)


def _observe_event_delivery_lag(
    kernel_timestamp_ns: int, callback_monotonic_ns: int | None = None
) -> float | None:
    """Observe kernel-to-callback lag if timestamps are valid in the shared monotonic domain.

    ``kernel_timestamp_ns`` is emitted by ``bpf_ktime_get_ns``. The callback
    timestamp is captured from ``time.monotonic_ns`` at callback entry. Zero
    kernel timestamps and negative deltas are rejected and counted; no zero
    sample is fabricated. The metric describes ring-buffer delivery only,
    not API ingestion, detection latency, or end-to-end latency.
    """
    received_ns = callback_monotonic_ns if callback_monotonic_ns is not None else time.monotonic_ns()
    lag_seconds, invalid_reason = event_delivery_lag_seconds(kernel_timestamp_ns, received_ns)
    if invalid_reason is not None:
        EVENT_DELIVERY_LAG_INVALID_TOTAL.labels(reason=invalid_reason).inc()
        return None
    assert lag_seconds is not None
    EVENT_DELIVERY_LAG_SECONDS.observe(lag_seconds)
    return lag_seconds

# Namespaces the agent should forward events for.
# Read from WATCH_NAMESPACES (comma-separated).  Empty → forward everything.
_WATCH_NAMESPACES: frozenset[str] = frozenset(
    ns.strip()
    for ns in os.environ.get("WATCH_NAMESPACES", "phantom-eval").split(",")
    if ns.strip()
)


# ---------------------------------------------------------------------------
# /proc helpers — called while the process is still alive (in rb_callback)
# ---------------------------------------------------------------------------

def _read_container_id_sync(pid: int) -> str | None:
    """Extract the 64-hex container ID from /host/proc/<pid>/cgroup.

    Called synchronously inside rb_callback while the source process is
    guaranteed to still exist (the ring buffer holds a reference to the
    pid start_time, and the kernel won't reuse the PID until the ring
    buffer entry is consumed).

    Supports cgroup v1, v2, containerd, and CRI-O path formats by matching
    the first 64-character lowercase hex string in the cgroup file.
    """
    cgroup_path = f"{PROC_ROOT}/{pid}/cgroup"
    try:
        with open(cgroup_path) as f:
            for line in f:
                m = re.search(r"[0-9a-f]{64}", line)
                if m:
                    return m.group(0)
    except OSError:
        pass
    return None


def _read_executable_path_sync(pid: int, comm: str) -> str:
    """Resolve the executable path from /host/proc/<pid>/exe.

    Used for non-EXEC events where the BPF struct does not carry the path.
    Falls back to the comm string (always present, max 15 chars) if the
    symlink cannot be read.
    """
    exe_link = f"{PROC_ROOT}/{pid}/exe"
    try:
        return os.readlink(exe_link)
    except OSError:
        return comm or "unknown"


# ---------------------------------------------------------------------------
# Ring-buffer callback (runs on the C poll thread, NOT in asyncio)
# ---------------------------------------------------------------------------

def rb_callback(ctx: Any, data: Any, size: int) -> int:  # noqa: ANN401
    """Called by libbpf for every ring-buffer event.

    Reads container-ID and executable path while the process is still alive,
    stashes results in _CONTAINER_ID_CACHE, then enqueues the parsed event
    for async processing.
    """
    callback_monotonic_ns = time.monotonic_ns()
    try:
        raw_bytes = ctypes.string_at(data, size)
        event = parse_event(raw_bytes)

        # Skip ring-buffer loss bookkeeping events.
        if event.header.event_type == EventType.LOSS:
            return 0

        _observe_event_delivery_lag(
            event.header.kernel_timestamp_ns,
            callback_monotonic_ns=callback_monotonic_ns,
        )

        # --- Read /proc synchronously NOW while the process is alive ---
        pid = event.header.pid
        tgid = event.header.tgid
        start_ns = event.header.pid_start_time_ns
        key = (pid, tgid, start_ns)

        container_id = _read_container_id_sync(pid)
        _CONTAINER_ID_CACHE[key] = container_id

        try:
            event_queue.put_nowait(event)
        except asyncio.QueueFull:
            log.warning("event_queue_full", pid=pid)
            _CONTAINER_ID_CACHE.pop(key, None)

    except ParseError as exc:
        log.warning("event_parse_error", error=str(exc))
    except Exception as exc:  # noqa: BLE001
        log.exception("rb_callback_error", error=str(exc))

    return 0


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

async def health_handler(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


async def metrics_handler(request: web.Request) -> web.Response:
    return web.Response(body=generate_latest(), headers={"Content-Type": CONTENT_TYPE_LATEST})


# ---------------------------------------------------------------------------
# Async event processor
# ---------------------------------------------------------------------------

# Maps kernel EventType → DriftEventIngestRequest event_type string
_EVENT_TYPE_MAP: dict[EventType, str] = {
    EventType.EXEC: "exec",
    EventType.FILE_OPEN: "file_open",
    EventType.FILE_WRITE: "file_write",
    EventType.NET_CONNECT: "network_connect",
    EventType.NET_ACCEPT: "network_accept",
    EventType.PRIVILEGE: "privilege_transition",
    EventType.NAMESPACE: "namespace_change",
    EventType.MODULE_LOAD: "module_load",
}

_AGENT_SEQUENCE = itertools.count(1)


async def event_processor(
    attributor: CgroupPodAttributor,
    dispatcher: ApiDispatcher,
    tenant_id: str,
) -> None:
    while True:
        try:
            event: ParsedEvent = await event_queue.get()

            pid = event.header.pid
            tgid = event.header.tgid
            start_ns = event.header.pid_start_time_ns
            cache_key = (pid, tgid, start_ns)

            # Retrieve and clear the container-ID cached by rb_callback.
            container_id = _CONTAINER_ID_CACHE.pop(cache_key, None)

            # Attribute workload identity.
            identity = await attributor.attribute(event.header.cgroup_id, container_id)

            if (
                identity.status.value != "resolved"
                or not identity.pod_uid
                or not identity.namespace
                or not identity.container_name
                or not identity.image_digest
                or not container_id
            ):
                log.warning(
                    "event_processor.identity_insufficient",
                    event_id=f"{event.header.event_id_hi:016x}{event.header.event_id_lo:016x}",
                    status=identity.status.value,
                    has_image_digest=bool(identity.image_digest),
                )
                event_queue.task_done()
                continue

            # Resolve executable_path for every event type.
            exec_path: str = getattr(event, "executable_path", "") or ""
            if not exec_path:
                # For non-EXEC events read the exe symlink (process may still exist).
                exec_path = _read_executable_path_sync(pid, event.header.comm)

            # Ensure min_length=1 satisfied.
            if not exec_path:
                exec_path = event.header.comm or "unknown"

            event_type_enum = EventType(event.header.event_type)
            event_type_str = _EVENT_TYPE_MAP.get(event_type_enum, "exec")

            # Observed string for the violation: use path for file events,
            # exec path for exec events, comm for everything else.
            raw_serialized = json.dumps(
                asdict(event), sort_keys=True, separators=(",", ":"),
                default=lambda value: value.hex() if isinstance(value, bytes) else str(value),
            ).encode()
            raw_event_digest = "sha256:" + hashlib.sha256(raw_serialized).hexdigest()

            payload: dict[str, Any] = {
                "schema_version": "v1",
                "event_id": str(uuid.uuid4()),
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "node_name": attributor._node_name or "unknown",
                "event_type": event_type_str,
                "process": {
                    "pid": event.header.pid,
                    "tgid": event.header.tgid,
                    "ppid": event.header.ppid,
                    "start_time_ns": event.header.pid_start_time_ns,
                    "comm": event.header.comm or "unknown",
                    "executable_path": exec_path,
                    "executable_hash": None,
                    "uid": event.header.uid,
                    "gid": event.header.gid,
                },
                "workload": {
                    "cluster_name": os.environ.get("PHANTOM_CLUSTER_NAME", "unknown"),
                    "namespace": identity.namespace or "unknown",
                    "pod_name": identity.pod_name or "unknown",
                    "pod_uid": str(identity.pod_uid),
                    "container_name": identity.container_name or "unknown",
                    "container_id": (
                        f"containerd://{container_id}" if container_id else "unknown"
                    ),
                    "image_digest": identity.image_digest,
                    "cgroup_id": event.header.cgroup_id,
                    "service_account": None,
                },
                "identity_status": identity.status.value,
                "violations": [],
                "evidence": {
                    "kernel_timestamp_ns": event.header.kernel_timestamp_ns,
                    "cpu": event.header.cpu,
                    "architecture": "x86_64",
                    "event_loss_observed": False,
                    "raw_event_digest": raw_event_digest,
                    "resource_path": getattr(event, "path", None),
                },
                "agent_sequence": next(_AGENT_SEQUENCE),
                "tenant_id": tenant_id,
            }

            # Namespace filter: skip events from KNOWN non-monitored namespaces.
            # IMPORTANT: When cgroup→pod attribution fails (MISSING/AMBIGUOUS), the
            # namespace is None → "unknown". We must NOT filter those events out,
            # because we cannot confirm they are outside the watched set — they may
            # simply be events from watched pods whose cgroup mapping is still warming up.
            # We only filter when attribution is RESOLVED and the namespace is explicitly
            # outside the watch list.
            event_ns: str = identity.namespace or "unknown"
            if (
                _WATCH_NAMESPACES
                and event_ns != "unknown"
                and event_ns not in _WATCH_NAMESPACES
            ):
                log.debug(
                    "event_processor.namespace_filtered",
                    namespace=event_ns,
                    pid=pid,
                )
                event_queue.task_done()
                continue


            await dispatcher.dispatch_event(payload)
            event_queue.task_done()

        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            log.exception("event_processor_error", error=str(exc))
            try:
                event_queue.task_done()
            except ValueError:
                pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def async_main() -> None:
    log.info("phantom_ebpf_agent.starting")

    node_name = os.environ.get("NODE_NAME", "unknown-node")
    gateway_url = os.environ.get("GATEWAY_URL", os.environ.get("PHANTOM_GATEWAY_URL", "http://phantom-api-gateway:8080"))
    token = os.environ.get("PHANTOM_AGENT_TOKEN", "")
    # REDIS_URL injected by the DaemonSet via phantom-config ConfigMap.
    redis_url = os.environ.get("REDIS_URL", "")
    if not redis_url:
        redis_host = os.environ.get("REDIS_HOST", "")
        redis_port = os.environ.get("REDIS_PORT", "6379")
        if redis_host:
            redis_url = f"redis://{redis_host}:{redis_port}"
        else:
            log.warning("phantom_ebpf_agent.no_redis_url_set_attribution_cache_disabled")
            redis_url = None  # type: ignore[assignment]

    tenant_id = "00000000-0000-0000-0000-000000000001"

    redis_client = Redis.from_url(redis_url, decode_responses=True) if redis_url else None
    attributor = CgroupPodAttributor(redis_client, node_name=node_name)  # type: ignore[arg-type]
    dispatcher = ApiDispatcher(gateway_url, token)

    # Health server
    app = web.Application()
    app.router.add_get("/healthz", health_handler)
    app.router.add_get("/metrics", metrics_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", 8080)
    await site.start()
    log.info("health_server.listening", port=8080)
    metrics_site = web.TCPSite(runner, "0.0.0.0", 9101)
    await metrics_site.start()
    log.info("metrics_server.listening", port=9101)

    bpf_dir = "/agent/bpf"
    c_callback = RING_BUFFER_SAMPLE_FN(rb_callback)

    try:
        with PhantomBpfLoader(bpf_dir) as loader:
            rb_manager = RingBufferManager(c_callback)
            for map_name, map_fd in loader.ringbuf_fds.items():
                log.info("binding_ring_buffer", map_name=map_name, map_fd=map_fd)
                rb_manager.add_map(map_fd)

            processor_task = asyncio.create_task(
                event_processor(attributor, dispatcher, tenant_id)
            )

            while True:
                rb_manager.poll(timeout_ms=50)
                await asyncio.sleep(0.01)

    except Exception as exc:  # noqa: BLE001
        log.exception("bpf_loader_error", error=str(exc))
    finally:
        await metrics_site.stop()
        await runner.cleanup()
        await dispatcher.close()
        if redis_client:
            await redis_client.aclose()


def main() -> None:
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
