import asyncio
import os
import uuid
import json
import ctypes
import structlog
import re
from datetime import datetime, timezone
from aiohttp import web
from redis.asyncio import Redis

from infrastructure.ebpf.loader import PhantomBpfLoader, RingBufferManager, RING_BUFFER_SAMPLE_FN
from infrastructure.ebpf.event_parser import parse_event, ParsedEvent, ParseError, EventType
from infrastructure.k8s.attributor import CgroupPodAttributor, AttributionStatus
from infrastructure.api.dispatcher import ApiDispatcher

log = structlog.get_logger(__name__)

# Global queues and managers
event_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)

def get_container_id_from_cgroup(pid: int) -> str | None:
    try:
        with open(f"/proc/{pid}/cgroup", "r") as f:
            lines = f.readlines()
        for line in lines:
            # Match any 64-character hexadecimal string
            match = re.search(r'([0-9a-f]{64})', line)
            if match:
                return match.group(1)
    except Exception as exc:
        log.debug("cgroup_read_failed", pid=pid, error=str(exc))
    return None

def rb_callback(ctx, data, size):
    try:
        raw_bytes = ctypes.string_at(data, size)
        parsed_event = parse_event(raw_bytes)
        
        # Fast path: skip LOSS events
        if parsed_event.header.event_type == EventType.LOSS:
            return 0
            
        # Put into asyncio queue for processing
        try:
            event_queue.put_nowait(parsed_event)
        except asyncio.QueueFull:
            log.warning("event_queue_full", dropped_event=parsed_event.header.event_type)
            
    except ParseError as exc:
        log.warning("event_parse_error", error=str(exc))
    except Exception as exc:
        log.exception("rb_callback_error", error=str(exc))
        
    return 0

async def health_handler(request):
    return web.json_response({"status": "ok"})

async def event_processor(attributor: CgroupPodAttributor, dispatcher: ApiDispatcher, tenant_id: str):
    while True:
        try:
            event: ParsedEvent = await event_queue.get()
            
            # Extract basic container ID by reading /proc/<pid>/cgroup
            container_id = get_container_id_from_cgroup(event.header.pid)
            
            # Attribute identity
            identity = await attributor.attribute(event.header.cgroup_id, container_id)
            
            # Map event type ENUM to API schema string
            event_type_enum = EventType(event.header.event_type)
            event_type_map = {
                EventType.EXEC: "exec",
                EventType.FILE_OPEN: "file_open",
                EventType.FILE_WRITE: "file_write",
                EventType.NET_CONNECT: "network_connect",
                EventType.NET_ACCEPT: "network_accept",
                EventType.PRIVILEGE: "privilege_transition",
                EventType.NAMESPACE: "namespace_change",
                EventType.MODULE_LOAD: "module_load",
            }
            event_type_str = event_type_map.get(event_type_enum, "exec")
            
            # Format payload to match DriftEventIngestRequest strictly
            payload = {
                "schema_version": "v1",
                "event_id": str(uuid.uuid4()),
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "node_name": attributor._node_name,
                "event_type": event_type_str,
                "process": {
                    "pid": event.header.pid,
                    "tgid": event.header.tgid,
                    "ppid": event.header.ppid,
                    "start_time_ns": event.header.pid_start_time_ns,
                    "comm": event.header.comm,
                    "executable_path": getattr(event, "executable_path", ""),
                    "uid": event.header.uid,
                    "gid": event.header.gid
                },
                "workload": {
                    "cluster_name": "phantom-eks",
                    "namespace": identity.namespace or "unknown",
                    "pod_name": identity.pod_name or "unknown",
                    "pod_uid": str(identity.pod_uid) if identity.pod_uid else str(uuid.UUID(int=0)),
                    "container_name": identity.container_name or "unknown",
                    "container_id": f"containerd://{container_id}" if container_id else "unknown",
                    "image_digest": identity.image_digest or "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "cgroup_id": event.header.cgroup_id,
                    "service_account": "default"
                },
                "identity_status": identity.status.value,
                "violations": [{
                    "violation_type": "unexpected_process_relation",
                    "observed": getattr(event, "executable_path", "unknown"),
                    "severity": "high",
                    "confidence": 0.99
                }],
                "evidence": {
                    "kernel_timestamp_ns": event.header.kernel_timestamp_ns,
                    "cpu": event.header.cpu,
                    "architecture": "x86_64",
                    "event_loss_observed": False,
                    "raw_event_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                },
                "agent_sequence": 1,
                "tenant_id": tenant_id
            }

            # Map specific fields for different event types
            if event_type_str == "file_open":
                payload["evidence"]["path"] = getattr(event, "path", "")
            elif event_type_str == "file_write":
                payload["evidence"]["path"] = getattr(event, "path", "")
            elif event_type_str == "exec":
                payload["evidence"]["executable_path"] = getattr(event, "executable_path", "")
            
            # Send to gateway
            await dispatcher.dispatch_event(payload)
            event_queue.task_done()
            
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.exception("event_processor_error", error=str(exc))

async def async_main():
    log.info("phantom_ebpf_agent.starting")
    
    # 1. Setup Environment
    node_name = os.environ.get("NODE_NAME", "unknown-node")
    gateway_url = os.environ.get("GATEWAY_URL", "http://phantom-api-gateway:8080")
    token = os.environ.get("PHANTOM_AGENT_TOKEN", "dev-bypass-token-for-local-testing")
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    # For local dev bypass, we use a fixed tenant_id
    tenant_id = "00000000-0000-0000-0000-000000000001"
    
    redis_client = Redis.from_url(redis_url, decode_responses=True)
    attributor = CgroupPodAttributor(redis_client, node_name=node_name)
    dispatcher = ApiDispatcher(gateway_url, token)
    
    # 2. Start Health Server
    app = web.Application()
    app.router.add_get('/healthz', health_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 8080)
    await site.start()
    log.info("health_server.listening", port=8080)
    
    # 3. Load BPF Programs and start RingBuffer manager
    bpf_dir = "/agent/bpf"
    c_callback = RING_BUFFER_SAMPLE_FN(rb_callback)
    
    try:
        with PhantomBpfLoader(bpf_dir) as loader:
            rb_manager = RingBufferManager(c_callback)
            for map_name, map_fd in loader.ringbuf_fds.items():
                log.info("binding_ring_buffer", map_name=map_name, map_fd=map_fd)
                rb_manager.add_map(map_fd)
            
            # 4. Start asyncio event processor worker
            processor_task = asyncio.create_task(event_processor(attributor, dispatcher, tenant_id))
            
            # 5. Polling loop
            while True:
                # ring_buffer__poll blocks C code, so we use a small timeout and yield to asyncio
                rb_manager.poll(timeout_ms=50)
                await asyncio.sleep(0.01)
                
    except Exception as exc:
        log.exception("bpf_loader_error", error=str(exc))
    finally:
        await runner.cleanup()
        await dispatcher.close()
        await redis_client.aclose()

def main():
    asyncio.run(async_main())

if __name__ == "__main__":
    main()
