import type { IncidentDetailResponse, UUID } from "../../../types/phantom";
import { useAttributionPoller } from "../../../hooks/useAttributionPoller";
import { ScoreGauge } from "../../../components/ui/ScoreGauge";
import { StatusIndicator } from "../../../components/ui/StatusIndicator";

interface CausalAttributionTabProps {
  incident: IncidentDetailResponse;
}

const AttributionResultCard = ({ attributionId }: { attributionId: UUID }) => {
  const { status, result, error } = useAttributionPoller(attributionId);

  if (status === "idle" || status === "queued" || status === "running") {
    return (
      <div className="bg-white rounded shadow-sm border border-gray-200 p-6 flex items-center gap-4">
        <div className="w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
        <div>
          <h4 className="font-bold text-gray-900">Analysis in Progress</h4>
          <p className="text-gray-500 text-sm">Estimating causal effect for attribution {attributionId.substring(0, 8)}...</p>
        </div>
      </div>
    );
  }

  if (status === "failed" || error || !result) {
    return (
      <div className="bg-red-50 p-4 rounded shadow-sm border border-red-200 text-red-700">
        <div className="font-bold">Analysis Failed ({attributionId.substring(0, 8)}...)</div>
        <div className="text-sm">{error || result?.failure_reason || "Unknown error"}</div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded shadow-sm border border-gray-200 overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-200 flex justify-between items-center bg-gray-50">
        <div>
          <h4 className="font-bold text-gray-900">Attribution Result</h4>
          <p className="text-xs text-gray-500 font-mono" title={attributionId}>{attributionId.substring(0, 8)}...</p>
        </div>
        <StatusIndicator status={status} variant="badge" />
      </div>

      <div className="p-6 text-black">
        {!result.identified ? (
          <div className="bg-yellow-50 border-l-4 border-yellow-400 p-4 text-yellow-800">
            <h5 className="font-bold mb-1">Not Identifiable</h5>
            <p className="text-sm">{result.failure_reason || "The causal effect could not be identified with the given data."}</p>
          </div>
        ) : (
          <div className="space-y-8">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div>
                <h5 className="font-semibold text-gray-800 mb-4">Effect Estimate</h5>
                <div className="bg-gray-50 rounded p-4 border border-gray-200">
                  <div className="text-sm text-gray-500 mb-1">Average Treatment Effect (ATE)</div>
                  <div className="text-3xl font-bold text-gray-900">
                    {result.average_treatment_effect !== null ? result.average_treatment_effect.toFixed(4) : "N/A"}
                  </div>
                  {result.effect_ci_lower !== null && result.effect_ci_upper !== null && (
                    <div className="text-xs text-gray-500 mt-2">
                      95% CI: [{result.effect_ci_lower.toFixed(4)}, {result.effect_ci_upper.toFixed(4)}]
                    </div>
                  )}
                </div>
              </div>

              <div className="flex justify-center items-center">
                {result.counterfactual_drift_probability !== null && (
                  <ScoreGauge
                    score={result.counterfactual_drift_probability * 100}
                    label="Counterfactual Drift Prob"
                  />
                )}
              </div>
            </div>

            {result.attribution_confidence && (
              <div>
                <h5 className="font-semibold text-gray-800 mb-4 border-b border-gray-200 pb-2">Confidence Metrics</h5>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-4">
                  {[
                    { label: "Data Coverage", val: result.attribution_confidence.data_coverage },
                    { label: "Identity Resolution", val: result.attribution_confidence.identity_resolution_confidence },
                    { label: "Contract Verification", val: result.attribution_confidence.contract_verification_confidence },
                    { label: "Graph Temporal Consistency", val: result.attribution_confidence.graph_temporal_consistency },
                    { label: "Refutation Stability", val: result.attribution_confidence.refutation_stability },
                    { label: "Loss Penalty", val: result.attribution_confidence.loss_penalty, invert: true },
                  ].map((metric) => (
                    <div key={metric.label}>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="font-medium text-gray-700">{metric.label}</span>
                        <span className="text-gray-500">{(metric.val * 100).toFixed(1)}%</span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-1.5">
                        <div
                          className={`h-1.5 rounded-full ${
                            metric.invert
                              ? metric.val > 0.5 ? 'bg-red-500' : 'bg-green-500'
                              : metric.val > 0.8 ? 'bg-green-500' : metric.val > 0.5 ? 'bg-yellow-500' : 'bg-red-500'
                          }`}
                          style={{ width: `${Math.max(0, Math.min(100, metric.val * 100))}%` }}
                        ></div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {result.refutation_results && result.refutation_results.length > 0 && (
              <div>
                <h5 className="font-semibold text-gray-800 mb-4 border-b border-gray-200 pb-2">Refutation Results</h5>
                <div className="overflow-x-auto rounded border border-gray-200">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-4 py-2 text-left text-xs font-semibold text-gray-600 uppercase">Method</th>
                        <th className="px-4 py-2 text-left text-xs font-semibold text-gray-600 uppercase">Passed</th>
                        <th className="px-4 py-2 text-left text-xs font-semibold text-gray-600 uppercase">Effect Estimate</th>
                        <th className="px-4 py-2 text-left text-xs font-semibold text-gray-600 uppercase">Notes</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-200 bg-white">
                      {result.refutation_results.map((ref: any, idx: number) => (
                        <tr key={idx}>
                          <td className="px-4 py-2 text-sm text-gray-900 font-medium">{ref.method}</td>
                          <td className="px-4 py-2 text-sm">
                            {ref.passed ? <span className="text-green-600 font-bold">✓ Yes</span> : <span className="text-red-600 font-bold">✗ No</span>}
                          </td>
                          <td className="px-4 py-2 text-sm text-gray-700">
                            {ref.effect_estimate !== null ? ref.effect_estimate.toFixed(4) : "N/A"}
                          </td>
                          <td className="px-4 py-2 text-sm text-gray-500">{ref.notes}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export const CausalAttributionTab = ({ incident }: CausalAttributionTabProps): JSX.Element => {
  if (incident.attribution_ids.length === 0) {
    return (
      <div className="text-center py-12 bg-gray-50 rounded border border-gray-200">
        <p className="text-gray-500">No causal attribution analyses have been run for this incident.</p>
        <p className="text-sm text-gray-400 mt-2">Go to the Behavioral Evidence tab to start an analysis.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {incident.attribution_ids.map((id: UUID) => (
        <AttributionResultCard key={id} attributionId={id} />
      ))}
    </div>
  );
};
