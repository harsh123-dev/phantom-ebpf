import { useState } from "react";
import { usePhantomClient } from "../../hooks/usePhantomClient";
import { useAttributionPoller } from "../../hooks/useAttributionPoller";
import type { AttributionRequest, CovariateSpec, EstimatorType, UUID } from "../../types/phantom";

interface AttributionRequestModalProps {
  driftEventId: UUID;
  snapshotId: UUID;
  onClose: () => void;
  onSuccess: (attributionId: UUID) => void;
}

export const AttributionRequestModal = ({
  driftEventId,
  snapshotId,
  onClose,
  onSuccess,
}: AttributionRequestModalProps): JSX.Element => {
  const client = usePhantomClient();
  
  const [treatmentVariable, setTreatmentVariable] = useState<string>("");
  const [treatmentValue, setTreatmentValue] = useState<0 | 1>(1);
  const [estimator, setEstimator] = useState<EstimatorType>("backdoor.linear_regression");
  const [covariates, setCovariates] = useState<CovariateSpec[]>([]);
  const [counterfactualValue, setCounterfactualValue] = useState<0 | 1>(0);
  
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [jobId, setJobId] = useState<UUID | null>(null);

  const poller = useAttributionPoller(jobId);

  const addCovariate = () => {
    setCovariates([...covariates, { variable: "", source: "workload", observed_value: "" }]);
  };

  const removeCovariate = (index: number) => {
    setCovariates(covariates.filter((_, i) => i !== index));
  };

  const updateCovariate = (index: number, field: keyof CovariateSpec, value: string) => {
    const newCovariates = [...covariates];
    newCovariates[index] = { ...newCovariates[index], [field]: value } as CovariateSpec;
    setCovariates(newCovariates);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!/^[a-zA-Z0-9_]+$/.test(treatmentVariable)) {
      setError("Treatment variable must contain only letters, numbers, and underscores.");
      return;
    }
    setError(null);
    setSubmitting(true);
    
    try {
      const request: AttributionRequest = {
        schema_version: "v1",
        snapshot_id: snapshotId,
        drift_event_id: driftEventId,
        treatment: {
          variable: treatmentVariable,
          observed_value: treatmentValue,
          source_node_ids: [], // Would normally be selected via UI
        },
        outcome: {
          variable: "runtime_sbom_drift",
          observed_value: 1,
          target_node_ids: [],
        },
        covariates: covariates.map(c => ({
          ...c,
          // coerce empty strings to null, or keep string
          observed_value: c.observed_value === "" ? null : c.observed_value,
        })),
        estimator: estimator,
        counterfactual_treatment_value: counterfactualValue,
        // Assume default tenant for UI purposes, could be fetched from auth context
        tenant_id: "00000000-0000-0000-0000-000000000000",
      };

      const response = await client.submitAttribution(request);
      setJobId(response.attribution_id);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to submit attribution request.");
      setSubmitting(false);
    }
  };

  if (jobId) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
        <div className="w-full max-w-lg rounded-lg bg-white p-6 shadow-xl text-black">
          <h2 className="mb-4 text-xl font-bold">Attribution Analysis Running</h2>
          
          {poller.status === "idle" || poller.status === "queued" || poller.status === "running" ? (
            <div className="flex flex-col items-center justify-center py-8">
              <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin mb-4"></div>
              <p className="text-gray-600 font-medium">Estimating causal effect...</p>
              <p className="text-sm text-gray-400 mt-2">Status: {poller.status}</p>
            </div>
          ) : poller.status === "failed" || poller.error ? (
            <div className="bg-red-50 p-4 rounded text-red-700 mb-6">
              <p className="font-bold">Analysis Failed</p>
              <p>{poller.error || poller.result?.failure_reason || "Unknown error occurred."}</p>
            </div>
          ) : (
            <div className="bg-green-50 p-4 rounded text-green-800 mb-6 border border-green-200">
              <p className="font-bold mb-2">Analysis Complete</p>
              {poller.result?.identified ? (
                <p>Causal effect estimated successfully.</p>
              ) : (
                <p>Not identifiable: {poller.result?.failure_reason}</p>
              )}
            </div>
          )}

          <div className="flex justify-end gap-3 mt-4">
            <button
              type="button"
              onClick={() => {
                onSuccess(jobId);
                onClose();
              }}
              className="rounded bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-700"
            >
              {poller.status === "completed" || poller.status === "not_identifiable" ? "View Results" : "Close & Run in Background"}
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-2xl rounded-lg bg-white shadow-xl flex flex-col max-h-[90vh]">
        <div className="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
          <h2 className="text-xl font-bold text-gray-900">Analyze Causality</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-2xl font-semibold">&times;</button>
        </div>

        <div className="p-6 overflow-y-auto flex-1">
          {error && (
            <div className="mb-4 bg-red-50 p-3 rounded text-red-700 text-sm border border-red-200">
              {error}
            </div>
          )}

          <form id="attribution-form" onSubmit={handleSubmit} className="space-y-6 text-gray-900">
            <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Treatment Variable Name</label>
                <input
                  type="text"
                  required
                  value={treatmentVariable}
                  onChange={(e) => setTreatmentVariable(e.target.value)}
                  placeholder="e.g. unexpected_network"
                  className="w-full rounded border border-gray-300 p-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Observed Treatment Value</label>
                <div className="flex gap-4 mt-2">
                  <label className="flex items-center">
                    <input type="radio" checked={treatmentValue === 1} onChange={() => setTreatmentValue(1)} className="mr-2" />
                    1 (True)
                  </label>
                  <label className="flex items-center">
                    <input type="radio" checked={treatmentValue === 0} onChange={() => setTreatmentValue(0)} className="mr-2" />
                    0 (False)
                  </label>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Outcome</label>
                <input
                  type="text"
                  readOnly
                  value="runtime_sbom_drift"
                  className="w-full rounded border border-gray-200 bg-gray-50 p-2 text-sm text-gray-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Estimator</label>
                <select
                  value={estimator}
                  onChange={(e) => setEstimator(e.target.value as EstimatorType)}
                  className="w-full rounded border border-gray-300 p-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  <option value="backdoor.linear_regression">Linear Regression</option>
                  <option value="backdoor.propensity_score_matching">Propensity Score Matching</option>
                  <option value="backdoor.generalized_linear_model">Generalized Linear Model</option>
                </select>
              </div>
            </div>

            <div>
              <div className="flex justify-between items-center mb-2">
                <label className="block text-sm font-medium text-gray-700">Covariates</label>
                <button
                  type="button"
                  onClick={addCovariate}
                  className="text-xs font-medium text-blue-600 hover:text-blue-800"
                >
                  + Add Covariate
                </button>
              </div>
              
              {covariates.length === 0 ? (
                <p className="text-sm text-gray-500 italic py-2">No covariates added.</p>
              ) : (
                <div className="space-y-3">
                  {covariates.map((cov, index) => (
                    <div key={index} className="flex items-start gap-2 bg-gray-50 p-2 rounded border border-gray-200">
                      <input
                        type="text"
                        required
                        value={cov.variable}
                        onChange={(e) => updateCovariate(index, "variable", e.target.value)}
                        placeholder="Variable name"
                        className="flex-1 min-w-0 rounded border border-gray-300 p-1.5 text-sm"
                      />
                      <select
                        value={cov.source}
                        onChange={(e) => updateCovariate(index, "source", e.target.value)}
                        className="w-32 flex-shrink-0 rounded border border-gray-300 p-1.5 text-sm"
                      >
                        <option value="workload">Workload</option>
                        <option value="container">Container</option>
                        <option value="process">Process</option>
                        <option value="purl">Purl</option>
                        <option value="network">Network</option>
                        <option value="cluster">Cluster</option>
                        <option value="temporal">Temporal</option>
                      </select>
                      <input
                        type="text"
                        value={cov.observed_value as string}
                        onChange={(e) => updateCovariate(index, "observed_value", e.target.value)}
                        placeholder="Value (optional)"
                        className="w-32 flex-shrink-0 rounded border border-gray-300 p-1.5 text-sm"
                      />
                      <button
                        type="button"
                        onClick={() => removeCovariate(index)}
                        className="text-gray-400 hover:text-red-600 p-1.5"
                      >
                        &times;
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="border-t border-gray-200 pt-6">
              <label className="block text-sm font-medium text-gray-700 mb-1">Counterfactual Treatment Value</label>
              <div className="flex gap-4 mt-2 text-sm">
                <label className="flex items-center">
                  <input type="radio" checked={counterfactualValue === 1} onChange={() => setCounterfactualValue(1)} className="mr-2" />
                  1 (True)
                </label>
                <label className="flex items-center">
                  <input type="radio" checked={counterfactualValue === 0} onChange={() => setCounterfactualValue(0)} className="mr-2" />
                  0 (False)
                </label>
              </div>
              <p className="text-xs text-gray-500 mt-2">What would happen if the treatment variable had this value instead?</p>
            </div>
          </form>
        </div>

        <div className="px-6 py-4 border-t border-gray-200 bg-gray-50 flex justify-end gap-3 rounded-b-lg">
          <button
            type="button"
            onClick={onClose}
            disabled={submitting}
            className="rounded bg-white border border-gray-300 px-4 py-2 font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="submit"
            form="attribution-form"
            disabled={submitting}
            className="rounded bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-700 disabled:opacity-50"
          >
            {submitting ? "Submitting..." : "Run Analysis"}
          </button>
        </div>
      </div>
    </div>
  );
};
