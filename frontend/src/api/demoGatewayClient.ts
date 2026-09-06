/**
 * demoGatewayClient.ts — Offline/demo implementation of PhantomGatewayClient.
 *
 * Returns demo data derived from real EC2 eBPF evaluation runs.
 * Activated when VITE_USE_MOCK_DATA=true or the real API is unreachable.
 * All methods return Promises to match the real client interface exactly.
 */

import type {
  AttributionJobResponse,
  AttributionRequest,
  AttributionResultResponse,
  BdgEdgeResponse,
  BdgNodeResponse,
  BehavioralContractDetailResponse,
  BehavioralContractRecord,
  ContractListParams,
  DriftEventDetailResponse,
  IncidentArchiveResponse,
  IncidentCreateRequest,
  IncidentDetailResponse,
  IncidentListParams,
  IncidentReport,
  IncidentUpdateRequest,
  PaginatedResponse,
  PcepsScoreRequest,
  PcepsScoreResponse,
  SbomDetailResponse,
  SbomListParams,
  SbomRecord,
  SbomVerificationRequest,
  SbomVerificationResponse,
  SubgraphQueryRequest,
  SubgraphResponse,
  UUID,
  VerificationJobResponse,
} from "../types/phantom";

import {
  DEMO_CONTRACT_DETAILS,
  DEMO_CONTRACTS,
  DEMO_INCIDENTS,
  DEMO_SBOM_DETAILS,
  DEMO_SBOMS,
  DEMO_SUBGRAPH,
  makePage,
} from "./demoData";

const delay = (ms = 200 + Math.random() * 300) => new Promise((r) => setTimeout(r, ms));

export class DemoGatewayClient {
  // SBOM ----------------------------------------------------------------
  async getSbom(sbomId: UUID): Promise<SbomDetailResponse> {
    await delay();
    const detail = DEMO_SBOM_DETAILS[sbomId];
    if (!detail) throw new Error(`Demo: SBOM ${sbomId} not found`);
    return detail;
  }

  async listSboms(params: SbomListParams): Promise<PaginatedResponse<SbomRecord>> {
    await delay();
    return makePage(DEMO_SBOMS, params.limit ?? 20, params.cursor);
  }

  async submitSbomVerification(_sbomId: UUID, _req: SbomVerificationRequest): Promise<VerificationJobResponse> {
    await delay();
    return {
      verification_job_id: crypto.randomUUID(),
      sbom_id: _sbomId,
      status: "queued",
      submitted_at: new Date().toISOString(),
    };
  }

  async getSbomVerification(sbomId: UUID): Promise<SbomVerificationResponse> {
    await delay();
    return {
      verification_job_id: crypto.randomUUID(),
      sbom_id: sbomId,
      status: "verified",
      signing_identity: "phantom-ci@phantom-eval.iam.gserviceaccount.com",
      issuer: "https://token.actions.githubusercontent.com",
      rekor_entry_uuid: crypto.randomUUID(),
      verified_at: new Date(Date.now() - 3600_000).toISOString(),
      failure_reason: null,
    };
  }

  // Contracts -----------------------------------------------------------
  async getContract(contractId: UUID): Promise<BehavioralContractDetailResponse> {
    await delay();
    const detail = DEMO_CONTRACT_DETAILS[contractId];
    if (!detail) throw new Error(`Demo: Contract ${contractId} not found`);
    return detail;
  }

  async listContracts(params: ContractListParams): Promise<PaginatedResponse<BehavioralContractRecord>> {
    await delay();
    let items = [...DEMO_CONTRACTS];
    if (params.activation_status) {
      items = items.filter((c) => c.activation_status === params.activation_status);
    }
    return makePage(items, params.limit ?? 20, params.cursor);
  }

  // BDG -----------------------------------------------------------------
  async getBdgNode(nodeId: UUID): Promise<BdgNodeResponse> {
    await delay();
    const node = DEMO_SUBGRAPH.nodes.find((n) => n.node_id === nodeId);
    if (!node) throw new Error(`Demo: BDG node ${nodeId} not found`);
    return { node, snapshot_id: DEMO_SUBGRAPH.snapshot_id };
  }

  async getBdgEdge(edgeId: UUID): Promise<BdgEdgeResponse> {
    await delay();
    const edge = DEMO_SUBGRAPH.edges.find((e) => e.edge_id === edgeId);
    if (!edge) throw new Error(`Demo: BDG edge ${edgeId} not found`);
    return { edge, snapshot_id: DEMO_SUBGRAPH.snapshot_id };
  }

  async querySubgraph(_req: SubgraphQueryRequest): Promise<SubgraphResponse> {
    await delay(500);
    return DEMO_SUBGRAPH;
  }

  // Attribution ---------------------------------------------------------
  async submitAttribution(_req: AttributionRequest): Promise<AttributionJobResponse> {
    await delay();
    return {
      attribution_id: crypto.randomUUID(),
      status: "queued",
      snapshot_id: "snap-demo-001",
      submitted_at: new Date().toISOString(),
    };
  }

  async getAttribution(attributionId: UUID): Promise<AttributionResultResponse> {
    await delay();
    return {
      attribution_id: attributionId,
      status: "completed",
      snapshot_id: "snap-demo-001",
      drift_event_id: "50000000-0000-0000-0000-000000000001",
      estimand: "ATE(runtime_sbom_drift | unexpected_purl)",
      identified: true,
      identification_method: "backdoor.linear_regression",
      average_treatment_effect: 0.93,
      effect_ci_lower: 0.87,
      effect_ci_upper: 0.98,
      counterfactual_drift_probability: 0.07,
      attribution_confidence: {
        score: 0.93,
        data_coverage: 0.95,
        identity_resolution_confidence: 0.91,
        contract_verification_confidence: 1.0,
        graph_temporal_consistency: 0.94,
        refutation_stability: 0.92,
        loss_penalty: 0.0,
        explanation: ["High purl deviation confidence", "All refutation tests passed"],
      },
      refutation_results: [
        { method: "random_common_cause", passed: true, effect_estimate: 0.91, notes: "" },
        { method: "placebo_treatment_refuter", passed: true, effect_estimate: 0.03, notes: "" },
      ],
      failure_reason: null,
      completed_at: new Date().toISOString(),
    };
  }

  // PCEPS ---------------------------------------------------------------
  async submitPcepsScore(_req: PcepsScoreRequest): Promise<PcepsScoreResponse> {
    await delay();
    return {
      score_id: crypto.randomUUID(),
      drift_event_id: _req.drift_event_id,
      attribution_id: _req.attribution_id,
      model_version: _req.model_version,
      score: 0.92,
      severity: "critical",
      feature_completeness: 0.97,
      imputed_features: [],
      scored_at: new Date().toISOString(),
    };
  }

  // Incidents -----------------------------------------------------------
  async createIncident(_req: IncidentCreateRequest): Promise<IncidentReport> {
    await delay();
    return {
      incident_id: crypto.randomUUID(),
      revision: 1,
      status: "open",
      title: _req.title,
      summary: _req.summary,
      classification: _req.classification,
      evidence_hash: "sha256:" + "0".repeat(64),
      created_by: "phantom-system",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
  }

  async getIncident(incidentId: UUID): Promise<IncidentDetailResponse> {
    await delay();
    const report = DEMO_INCIDENTS.find((i) => i.incident_id === incidentId) ?? DEMO_INCIDENTS[0];
    return {
      report,
      drift_event_ids: report.drift_event_ids ?? [],
      attribution_ids: [],
      score_ids: report.score_ids ?? [],
      snapshot_id: "snap-demo-001",
      tags: ["supply-chain", "phantom-eval"],
      resolution_notes: null,
      archived_at: null,
    };
  }

  async listIncidents(params: IncidentListParams): Promise<PaginatedResponse<IncidentReport>> {
    await delay();
    let items = [...DEMO_INCIDENTS];
    if (params.status) items = items.filter((i) => i.status === params.status);
    if (params.classification) items = items.filter((i) => i.classification === params.classification);
    return makePage(items, params.limit ?? 10, params.cursor);
  }

  async updateIncident(incidentId: UUID, req: IncidentUpdateRequest): Promise<IncidentReport> {
    await delay();
    const existing = DEMO_INCIDENTS.find((i) => i.incident_id === incidentId) ?? DEMO_INCIDENTS[0];
    return {
      ...existing,
      ...(req.title ? { title: req.title } : {}),
      ...(req.status ? { status: req.status } : {}),
      ...(req.classification ? { classification: req.classification } : {}),
      revision: existing.revision + 1,
      updated_at: new Date().toISOString(),
    };
  }

  async archiveIncident(incidentId: UUID): Promise<IncidentArchiveResponse> {
    await delay();
    return {
      incident_id: incidentId,
      status: "archived",
      archived_at: new Date().toISOString(),
      revision: 2,
    };
  }

  // Drift events --------------------------------------------------------
  async getDriftEvent(driftEventId: UUID): Promise<DriftEventDetailResponse> {
    await delay();
    return {
      schema_version: "v1",
      drift_event_id: driftEventId,
      event_id: crypto.randomUUID(),
      observed_at: new Date(Date.now() - 3600_000).toISOString(),
      node_name: "ip-172-31-5-170.ap-south-1.compute.internal",
      event_type: "exec",
      process: {
        pid: 226384,
        tgid: 226384,
        ppid: 1,
        uid: 0,
        gid: 0,
        comm: "python3",
        executable_path: "/usr/local/bin/python3",
        start_time_ns: Date.now() * 1_000_000,
      },
      workload: {
        cluster_name: "phantom-eval",
        namespace: "phantom-eval",
        pod_name: "emailservice-7c8d9f4b5-xk2p9",
        pod_uid: crypto.randomUUID(),
        container_name: "server",
        container_id: "containerd://abcdef1234567890",
        image_digest: "sha256:b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
        cgroup_id: 226384,
        service_account: null,
      },
      identity_status: "ambiguous",
      sbom_binding: {
        sbom_id: "10000000-0000-0000-0000-000000000002",
        purl: "pkg:pypi/internal-metrics@1.0.0",
        binding_confidence: 0.92,
        binding_status: "resolved",
      },
      violations: [
        {
          violation_type: "unexpected_purl",
          expected: null,
          observed: "pkg:pypi/internal-metrics@1.0.0",
          severity: "critical",
          confidence: 0.92,
        },
      ],
      evidence: {
        kernel_timestamp_ns: Date.now() * 1_000_000,
        cpu: 0,
        architecture: "x86_64",
        event_loss_observed: false,
        correlation_id: null,
        raw_event_digest: "sha256:" + "e".repeat(64),
      },
      agent_sequence: 1,
      tenant_id: "00000000-0000-0000-0000-000000000001",
    };
  }
}
