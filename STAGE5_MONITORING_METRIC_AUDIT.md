# PHANTOM Stage 5B/C: Monitoring and Metric Audit

**Result:** exporter-port discrepancy is confirmed from source; event-lag metric is **missing**. Live scraping and workload metrics remain **UNKNOWN** because no cluster exists in the available environment. No fixes are applied in this stage.

## Issue classifications

| Issue | Classification | Basis |
|---|---|---|
| Causal exporter routing | **BLOCKER** | Exporter starts on 9090, while Service/scrape route only to health port 8080. |
| Generic `phantom` NetworkPolicy set | **WARNING / UNKNOWN** | If installed, its default-deny policy blocks monitoring ingress to causal engine; whether it is installed is unknown. The documented k3s deploy script does not apply this policy file. |
| cAdvisor replacement | **WARNING** | Static relabel string uses `$${1}`; `promtool` runtime/parser validation unavailable. |
| `phantom_event_collection_latency_seconds` | **BLOCKER** | No metric registration/exporter found; query cannot produce valid telemetry. |
| Nullable evaluator path | **BLOCKER** | `None` values from the prior runner correction are compared numerically and can raise `TypeError`. |
| Actual Prometheus targets, freshness, and resource values | **UNKNOWN** | No k3s, Prometheus, or cluster context is available. |
| Proposed metric instrumentation | **UNKNOWN / NOT IMPLEMENTED** | Design only; clock-domain and controlled event validation remain outstanding. |

## Causal engine exporter path

| Hop | Current source/config | Finding |
|---|---|---|
| Exporter creation | `services/causal-engine/app/interface/worker.py:233-237` calls `prometheus_client.start_http_server(9090)`. Causal engine pins `prometheus-client==0.20.0`. That version aliases `start_http_server` to `start_wsgi_server`; its default bind address is `0.0.0.0` in the [pinned upstream source](https://github.com/prometheus/client_python/blob/v0.20.0/prometheus_client/exposition.py). | Exporter listens on container port 9090 on all interfaces. No runtime confirmation is possible here. |
| Health server | `worker.py:62,246-255` binds the health app to `_HEALTH_PORT` (default 8081); `infra/k8s/k3s-lab/03-phantom-services.yaml:118-119` overrides `HEALTH_PORT=8080`. `_build_health_app()` exposes health/readiness routes, not `/metrics`. | The manifest's port 8080 is the health server. A stale worker comment mentions 8081, but the manifest override is explicit. |
| Pod port declaration | `03-phantom-services.yaml:99-106` declares only named container port `health:8080`. | Port 9090 is not declared. This alone does not prevent a process from listening, but leaves the named service target absent. |
| Service | `03-phantom-services.yaml:136-148` exposes only Service port 8080 targeting `health`. | There is no Service route to the actual exporter. |
| Prometheus target | `infra/k8s/k3s-lab/05-monitoring.yaml:19-23` scrapes `phantom-causal-engine.phantom.svc.cluster.local:8080`, using default path `/metrics`. | Target reaches the health server on port 8080, which has no `/metrics`; it does not reach the exporter at 9090. The scrape is statically misrouted. |

**Cause:** the application exporter is on 9090; the Deployment's health server is 8080; the Kubernetes Service and Prometheus scrape target both expose/use only 8080. The smallest topology correction is to declare a named `metrics` container port 9090, add a Service port 9090 targeting it, and change the causal-engine scrape target to Service port 9090. Keep health probes on 8080. No code or live manifest has been changed.

The k3s lab `deploy-all.sh` applies `06-network-policies.yaml`, which selects `phantom-eval` egress and does not select pods in `phantom`. The separate `infra/k8s/policies/network-policies.yaml` contains a default-deny policy in `phantom` and `allow-causal-engine` only permits gateway ingress; if that separate policy set is installed, Prometheus in namespace `monitoring` is not allowed to reach port 9090. Whether that policy set exists in a target cluster is **UNKNOWN**. Add a narrowly scoped monitoring-to-causal-engine ingress rule only if that policy set is part of the chosen deployment.

## Other monitoring-path issue

`05-monitoring.yaml:44-47` sets the cAdvisor node proxy path replacement to `/api/v1/nodes/$${1}/proxy/metrics/cadvisor`. Prometheus relabel replacements use capture references such as `${1}`; the doubled dollar is not the documented node-name interpolation. This is a likely reason cAdvisor targets would be malformed. Proposed correction: use `${1}`. Prometheus 2.45 config could not be validated because `promtool` is absent; target health and samples remain **UNKNOWN**. The scenario runner's CPU and memory queries depend on cAdvisor, so these values are not trustworthy until the target is healthy and returns fresh samples.

## Event-lag metric

Repository-wide search found no `phantom_event_collection_latency_seconds` registration or exporter. `services/ebpf-agent/application/main.py:331-338` serves only `/healthz` on port 8080 and has no metrics route/server. The DaemonSet in `infra/k8s/k3s-lab/04-ebpf-agent.yaml` has no metrics Service and Prometheus has no agent scrape job. The causal engine exports other metrics (for example `phantom_redis_stream_lag` and `phantom_redis_stream_messages_total`) but no event collection latency metric. The `research/evaluation/scenarios/scenario_runner.py:641,686` query for `phantom_event_collection_latency_seconds{quantile="0.95"}` is therefore a nonexistent metric query, not a differently named existing series.

The agent does carry `kernel_timestamp_ns` in the event ABI. `services/ebpf-agent/include/phantom_helpers.h:78` sets it with `bpf_ktime_get_ns()` and `phantom_events.h:11,57` documents it as monotonic nanoseconds. `application/main.py:223` separately stamps `observed_at` with wall-clock UTC before dispatch. These clock values must not be subtracted from one another. Linux documents `bpf_ktime_get_ns()` as monotonic time corresponding to `CLOCK_MONOTONIC`; Python documents `time.monotonic_ns()` as a monotonic clock with an unspecified epoch, so only same-clock differences are meaningful ([Linux BPF helper documentation](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.7.pdf), [Python 3.11 time documentation](https://docs.python.org/3.11/library/time.html)).

### Proposed instrumentation design (not implemented)

1. Define the metric precisely as **kernel-event-to-agent-ring-buffer-callback delivery lag**, not generic ingestion or detection latency. In `rb_callback`, take `time.monotonic_ns()` immediately after receiving the event and subtract `event.header.kernel_timestamp_ns`.
2. Both timestamps are nanoseconds from the node's monotonic clock domain; the agent pod must share that node clock without a time-namespace offset. Confirm this runtime assumption before trusting samples. Do not convert `observed_at` wall-clock timestamps into this calculation.
3. If the kernel timestamp is zero, the callback timestamp is earlier than the kernel timestamp, or clock-domain compatibility cannot be established, do not observe a sample; increment a bounded invalid-timestamp counter and leave the metric absent. Never substitute zero.
4. Record valid differences in seconds in a Prometheus `Histogram`, e.g. `phantom_event_delivery_lag_seconds`, without high-cardinality labels. Export the agent registry from a restricted ClusterIP Service on a dedicated metrics port. Compute p95 with `histogram_quantile(0.95, sum by (le) (rate(phantom_event_delivery_lag_seconds_bucket[5m]))) * 1000`; result units are milliseconds and the time window is five minutes. Empty query results remain `None`.
5. Add separate metrics if later needed: queue-to-dispatch processing duration or end-to-end event ingestion must be measured at their actual boundaries. Do not call these kernel-to-agent delivery lag.
6. Unit validation should use a fake monotonic clock and synthetic ABI fixture with a known timestamp delta, plus zero/future timestamp cases. A later approved non-attack smoke test should verify the agent target is up and fresh histogram buckets increase for a harmless event. This proves only that metric path and semantics work, not attack detection or overhead performance.

**Latency distinctions:** PHANTOM `mttd_s` in `ScenarioRunner` is the elapsed time from runner-recorded injection timestamp to first PHANTOM detection (`scenario_runner.py` around lines 490-510). It is detection latency. The proposed histogram is kernel event to agent callback delivery lag. Full end-to-end latency would require a correlated event identifier and timestamps through API acceptance/observation and, if relevant, PHANTOM detection. These are different measures.

## Optional-value analysis defect

The prior Stage 2 change correctly represents unavailable runner measurements as `None` in `scenario_runner.py:654-693`. `research/evaluation/metrics/evaluator.py:352-376` still compares each field to `0.0` and then passes all snapshots into numeric aggregations. With missing Prometheus series, `None > 0.0` can raise `TypeError`; even absent a crash, using “any positive value” as the measurement test confuses a measured zero with absent data. The proposed patch makes aggregation skip missing fields and calculates a metric only when its required phase observations exist. It does not create metric observations.

## Proposed correction and validation

The proposed diff adds causal exporter port 9090 to the Pod/Service, scrapes the Service on 9090, fixes the cAdvisor relabel replacement, and makes evaluator aggregation safe for missing values. It does **not** add a fabricated event-lag query; instrumentation design above must be separately implemented and tested. After the code/deployment changes are reviewed, validate YAML and Prometheus config offline, run focused tests, then (only after cluster identity and deployment approval) verify `/targets`, fresh series timestamps, and query results. Until then, resource overhead and latency remain **UNKNOWN/unmeasured**.
