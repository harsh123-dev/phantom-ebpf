"""
services/ebpf-agent/application/main.py

PHANTOM eBPF agent daemon.

Fixed root causes (2026-08-31):
  1. Host-proc cgroup evidence is read synchronously in rb_callback and stored
     by the ring record's event ID plus process/cgroup identity. The event's
     TGID and cgroup ID are checked before any workload attribution is allowed.
  2. Non-EXEC events do not carry an event-time executable path. A later
     /proc/<pid>/exe read can refer to a different exec state of the same PID;
     those events keep executable_path unknown rather than inventing a binding.
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
import stat
import time
import uuid
from datetime import datetime, timezone
from dataclasses import asdict, dataclass
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
CGROUP_ROOT: str = os.environ.get("PHANTOM_CGROUP_ROOT", "/sys/fs/cgroup")
_IDENTITY_DIAGNOSTICS: bool = os.environ.get(
    "PHANTOM_IDENTITY_DIAGNOSTICS", "false"
).lower() in {"1", "true", "yes"}

@dataclass(frozen=True)
class ProcessIdentityCapture:
    """Event-time host-proc evidence; it is not an executable/SBOM identity."""

    container_id: str | None
    cgroup_path: str | None
    cgroup_inode_matches_event: bool
    proc_tgid: int | None
    reason: str


# Key the synchronous /proc result to the actual ring record, not just the
# process. Multiple events for one process can be queued before the asyncio
# consumer runs, and a process can exec again without changing its PID/start.
_IdentityCacheKey = tuple[int, int, int, int, int, int]
_CONTAINER_ID_CACHE: dict[_IdentityCacheKey, ProcessIdentityCapture] = {}

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
AGENT_EVENTS_TOTAL = Counter(
    "phantom_agent_events_total",
    "Kernel records received and agent processing stages by event type.",
    labelnames=("event_type", "stage"),
)
AGENT_IDENTITY_DROP_TOTAL = Counter(
    "phantom_agent_identity_drop_total",
    "Events dropped at the identity gate, broken down by root cause. "
    "capture_reason reflects the /proc read outcome (proc_exited_before_read "
    "for a timing race with a short-lived process); attribution_status reflects "
    "the attributor verdict when capture itself succeeded.",
    labelnames=("event_type", "capture_reason", "attribution_status"),
)


def _count_event(event_type: int, stage: str) -> None:
    """Count actual parsed records; labels are a fixed enum and stage set."""
    AGENT_EVENTS_TOTAL.labels(
        event_type=EventType(event_type).name.lower(), stage=stage
    ).inc()


def _normalize_capture_reason(reason: str) -> str:
    """Map a raw ProcessIdentityCapture reason to a fixed-cardinality Prometheus label.

    Only FileNotFoundError (indicating /host/proc/<pid> or /status is absent
    because the process has already terminated) maps to proc_exited_before_read.
    Any other OS or filesystem exception maps to proc_or_cgroup_unavailable to
    avoid overstating the exit race. All other reason strings are fixed enumeration
    values defined in _read_container_id_sync and are forwarded unchanged.
    """
    if reason == "proc_or_cgroup_unavailable:FileNotFoundError":
        return "proc_exited_before_read"
    if reason.startswith("proc_or_cgroup_unavailable:"):
        return "proc_or_cgroup_unavailable"
    return reason


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
# /proc helpers — called immediately in rb_callback to narrow exit/PID races
# ---------------------------------------------------------------------------

def _read_container_id_sync(pid: int, tgid: int, event_cgroup_id: int) -> ProcessIdentityCapture:
    """Capture and validate host-proc cgroup identity for one BPF event.

    Only unified cgroup-v2 paths are accepted. The proc TGID must match the
    BPF header and the exact cgroup directory's inode must equal the event's
    ``bpf_get_current_cgroup_id()`` value. Failure at any step is abstention.
    This validates a workload/container join; it does not authenticate an
    executable, image, or SBOM component.
    """
    if pid <= 0 or tgid <= 0 or event_cgroup_id <= 0:
        return ProcessIdentityCapture(None, None, False, None, "invalid_event_identity")
    proc_dir = os.path.join(PROC_ROOT, str(pid))
    try:
        with open(os.path.join(proc_dir, "status"), encoding="ascii") as f:
            status = f.read()
        match_tgid = re.search(r"^Tgid:\s*(\d+)\s*$", status, re.MULTILINE)
        proc_tgid = int(match_tgid.group(1)) if match_tgid else None
        if proc_tgid != tgid:
            return ProcessIdentityCapture(None, None, False, proc_tgid, "tgid_mismatch")

        with open(os.path.join(proc_dir, "cgroup"), encoding="utf-8") as f:
            entries = [line.rstrip("\n").split(":", 2) for line in f]
        unified = next((parts[2] for parts in entries
                        if len(parts) == 3 and parts[0] == "0" and parts[1] == ""), None)
        if not unified or not unified.startswith("/"):
            return ProcessIdentityCapture(None, unified, False, proc_tgid, "no_unified_cgroup_path")

        root = os.path.realpath(CGROUP_ROOT)
        candidate = os.path.realpath(os.path.join(root, unified.lstrip("/")))
        if os.path.commonpath((root, candidate)) != root:
            return ProcessIdentityCapture(None, unified, False, proc_tgid, "cgroup_path_outside_root")
        cgroup_stat = os.stat(candidate, follow_symlinks=False)
        if not stat.S_ISDIR(cgroup_stat.st_mode):
            return ProcessIdentityCapture(None, unified, False, proc_tgid, "cgroup_not_directory")
        inode_matches = cgroup_stat.st_ino == event_cgroup_id
        if not inode_matches:
            return ProcessIdentityCapture(None, unified, False, proc_tgid, "cgroup_id_mismatch")

        # Runtime IDs are accepted only from a recognized terminal scope name,
        # never from an arbitrary 64-hex token elsewhere in the proc file.
        component = os.path.basename(candidate)
        runtime_match = re.fullmatch(
            r"(?:cri-containerd|docker|crio)-([0-9a-f]{64})\.scope", component
        )
        container_id = runtime_match.group(1) if runtime_match else None
        reason = "validated_runtime_scope" if container_id else "validated_cgroup_without_runtime_scope"
        return ProcessIdentityCapture(container_id, unified, True, proc_tgid, reason)
    except (OSError, ValueError) as exc:
        return ProcessIdentityCapture(
            None, None, False, None, f"proc_or_cgroup_unavailable:{type(exc).__name__}"
        )


def _event_time_executable_path(event: ParsedEvent) -> str:
    """Use only an absolute executable path captured by the EXEC kernel event.

    A non-EXEC event's later /proc exe symlink can reflect a subsequent exec
    by the same PID. It is unsuitable for component attribution even when the
    PID start time still matches, because exec does not change that start time.
    """
    if event.header.event_type != EventType.EXEC:
        return "unknown"
    path = getattr(event, "executable_path", None)
    if not isinstance(path, str) or not path.startswith("/") or "\x00" in path:
        return "unknown"
    return path


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
        _count_event(event.header.event_type, "received")

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
        key = (event.header.event_id_hi, event.header.event_id_lo,
               pid, tgid, start_ns, event.header.cgroup_id)

        capture = _read_container_id_sync(pid, tgid, event.header.cgroup_id)
        _CONTAINER_ID_CACHE[key] = capture
        if _IDENTITY_DIAGNOSTICS and event.header.event_type == EventType.EXEC:
            log.debug(
                "event_identity.capture",
                event_id=f"{event.header.event_id_hi:016x}{event.header.event_id_lo:016x}",
                pid=pid,
                tgid=tgid,
                pid_start_time_ns=start_ns,
                cgroup_id=event.header.cgroup_id,
                extracted_container_id=capture.container_id,
                cgroup_path=capture.cgroup_path,
                cgroup_inode_matches_event=capture.cgroup_inode_matches_event,
                identity_capture_reason=capture.reason,
            )

        try:
            event_queue.put_nowait(event)
            _count_event(event.header.event_type, "queued")
        except asyncio.QueueFull:
            log.warning("event_queue_full", pid=pid)
            _count_event(event.header.event_type, "queue_full")
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
            cache_key = (
                event.header.event_id_hi,
                event.header.event_id_lo,
                pid,
                tgid,
                start_ns,
                event.header.cgroup_id,
            )

            # Retrieve and clear only this ring record's event-time evidence.
            capture = _CONTAINER_ID_CACHE.pop(cache_key, None)
            container_id = (
                capture.container_id
                if capture is not None and capture.cgroup_inode_matches_event
                else None
            )

            # Attribute workload identity.
            identity = await attributor.attribute(
                event.header.cgroup_id,
                container_id,
                event_cgroup_validated=bool(
                    capture is not None and capture.cgroup_inode_matches_event
                ),
            )

            if (
                identity.status.value != "resolved"
                or not identity.pod_uid
                or not identity.namespace
                or not identity.container_name
                or not identity.image_digest
                or not (identity.container_id or container_id)
            ):
                # --- Identity gate: strict drop policy ---
                # Events are dropped here when workload identity cannot be
                # fully resolved. This is an intentional security boundary:
                # no event is attributed without a validated cgroup inode,
                # a matching TGID, a running container_id from Kubernetes,
                # a pod UID, a namespace, and an image digest.
                #
                # When a short-lived process (e.g. /bin/true) exits before
                # the ring-buffer callback reads /proc, the /proc entry is
                # gone and capture fails with proc_or_cgroup_unavailable.
                # There is no safe fallback: attributing on cgroup ID alone
                # (without the inode cross-check) risks misattribution to a
                # different workload reusing the same PID or cgroup slot.
                # The event is therefore dropped and counted below.
                #
                # NOTE: the namespace filter at the bottom of this function
                # applies to events that PASS this gate with a resolved but
                # unrecognised namespace. It does not apply here.
                _count_event(event.header.event_type, "identity_missing")
                _capture_reason = _normalize_capture_reason(
                    capture.reason if capture is not None else "missing_capture"
                )
                AGENT_IDENTITY_DROP_TOTAL.labels(
                    event_type=EventType(event.header.event_type).name.lower(),
                    capture_reason=_capture_reason,
                    attribution_status=identity.status.value,
                ).inc()
                event_exec_path = (
                    _event_time_executable_path(event)
                    if event.header.event_type == EventType.EXEC
                    else None
                )
                if _IDENTITY_DIAGNOSTICS and event.header.event_type == EventType.EXEC:
                    log.debug(
                        "event_processor.identity_insufficient",
                        event_id=f"{event.header.event_id_hi:016x}{event.header.event_id_lo:016x}",
                        status=identity.status.value,
                        has_image_digest=bool(identity.image_digest),
                        event_type=int(event.header.event_type),
                        pid=pid,
                        tgid=tgid,
                        pid_start_time_ns=start_ns,
                        comm=event.header.comm,
                        executable_path=event_exec_path,
                        cgroup_id=event.header.cgroup_id,
                        extracted_container_id=container_id,
                        cgroup_path=capture.cgroup_path if capture else None,
                        process_cgroup_inode_matches_event=bool(
                            capture and capture.cgroup_inode_matches_event
                        ),
                        has_container_id=bool(identity.container_id or container_id),
                        workload_namespace=identity.namespace,
                        workload_pod=identity.pod_name,
                        workload_uid=str(identity.pod_uid) if identity.pod_uid else None,
                        container_name=identity.container_name,
                        image_digest=identity.image_digest,
                        identity_capture_reason=capture.reason if capture else "missing_capture",
                    )
                event_queue.task_done()
                continue

            if _IDENTITY_DIAGNOSTICS and event.header.event_type == EventType.EXEC:
                log.debug(
                    "event_identity.workload_resolved",
                    event_id=f"{event.header.event_id_hi:016x}{event.header.event_id_lo:016x}",
                    pid=pid,
                    tgid=tgid,
                    pid_start_time_ns=start_ns,
                    cgroup_id=event.header.cgroup_id,
                    extracted_container_id=container_id,
                    cgroup_inode_matches_event=(
                        capture.cgroup_inode_matches_event if capture else False
                    ),
                    workload_namespace=identity.namespace,
                    workload_pod=identity.pod_name,
                    workload_uid=str(identity.pod_uid),
                    image_digest=identity.image_digest,
                    identity_status=identity.status.value,
                )

            exec_path = _event_time_executable_path(event)

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
                # Preserve the kernel record identity across the gateway and
                # API boundary instead of assigning an unrelated UUID here.
                "event_id": str(uuid.UUID(
                    int=(event.header.event_id_hi << 64) | event.header.event_id_lo
                )),
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
                    "executable_hash_status": "unavailable",
                    "uid": event.header.uid,
                    "gid": event.header.gid,
                },
                "workload": {
                    "cluster_name": os.environ.get("PHANTOM_CLUSTER_NAME", "unknown"),
                    "namespace": identity.namespace or "unknown",
                    "pod_name": identity.pod_name or "unknown",
                    "pod_uid": str(identity.pod_uid),
                    "container_name": identity.container_name or "unknown",
                    "container_id": identity.container_id or (
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
                _count_event(event.header.event_type, "namespace_filtered")
                log.debug(
                    "event_processor.namespace_filtered",
                    namespace=event_ns,
                    pid=pid,
                )
                event_queue.task_done()
                continue


            await dispatcher.dispatch_event(payload)
            _count_event(event.header.event_type, "dispatched")
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

    rb_manager: RingBufferManager | None = None
    processor_task: asyncio.Task[None] | None = None
    try:
        with PhantomBpfLoader(bpf_dir) as loader:
            rb_manager = RingBufferManager(c_callback)
            for map_name, map_fd in loader.ringbuf_fds:
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
        # BPF collection is required for agent readiness. Do not turn a loader
        # failure into a clean process exit after closing the health endpoint:
        # let the runtime record a non-zero failure and preserve its traceback.
        raise
    finally:
        # Cancel the processor task and free the ring buffer before closing the
        # web server so that in-flight events are not silently dropped.
        if processor_task is not None and not processor_task.done():
            processor_task.cancel()
            try:
                await processor_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if rb_manager is not None:
            try:
                rb_manager.close()
            except Exception as cleanup_exc:  # noqa: BLE001
                log.exception(
                    "phantom_ebpf_agent.cleanup_failed",
                    resource="ring_buffer_manager",
                    error=str(cleanup_exc),
                )
        for resource_name, cleanup in (
            ("metrics_site", metrics_site.stop),
            ("web_runner", runner.cleanup),
            ("api_dispatcher", dispatcher.close),
        ):
            try:
                await cleanup()
            except Exception as cleanup_exc:  # noqa: BLE001
                log.exception(
                    "phantom_ebpf_agent.cleanup_failed",
                    resource=resource_name,
                    error=str(cleanup_exc),
                )
        if redis_client:
            try:
                await redis_client.aclose()
            except Exception as cleanup_exc:  # noqa: BLE001
                log.exception(
                    "phantom_ebpf_agent.cleanup_failed",
                    resource="redis_client",
                    error=str(cleanup_exc),
                )


def main() -> None:
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
