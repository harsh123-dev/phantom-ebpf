import { ScoreGauge } from "../../components/ui/ScoreGauge";
import { SeverityBadge } from "../../components/ui/SeverityBadge";
import { TimeAgo } from "../../components/ui/TimeAgo";
import type { PcepsScoreResponse } from "../../types/phantom";

interface PCEPSScorePanelProps {
  scoreData: PcepsScoreResponse;
}

export const PCEPSScorePanel = ({ scoreData }: PCEPSScorePanelProps): JSX.Element => {
  return (
    <div className="bg-white rounded-lg shadow border border-gray-200 p-6 flex flex-col gap-6">
      <div className="flex justify-between items-start">
        <h3 className="text-lg font-bold text-gray-900">PCEPS Score</h3>
        <SeverityBadge severity={scoreData.severity} />
      </div>

      <div className="flex flex-col sm:flex-row items-center gap-8 justify-center py-4 border-b border-gray-100">
        <ScoreGauge score={scoreData.score} label="Causal Probability" />
      </div>

      <div className="flex flex-col gap-3">
        <div className="flex justify-between text-sm">
          <span className="font-medium text-gray-700">Feature Completeness</span>
          <span className="font-semibold text-gray-900">{(scoreData.feature_completeness * 100).toFixed(0)}%</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2">
          <div
            className={`h-2 rounded-full ${scoreData.feature_completeness >= 0.8 ? 'bg-green-500' : 'bg-yellow-500'}`}
            style={{ width: `${Math.max(0, Math.min(100, scoreData.feature_completeness * 100))}%` }}
          ></div>
        </div>

        {scoreData.imputed_features && scoreData.imputed_features.length > 0 && (
          <div className="mt-2 bg-yellow-50 border-l-4 border-yellow-400 p-3">
            <div className="flex">
              <div className="flex-shrink-0">
                <span className="text-yellow-600 text-lg">⚠</span>
              </div>
              <div className="ml-3">
                <p className="text-sm text-yellow-700">
                  <strong>{scoreData.imputed_features.length} features</strong> were estimated due to missing telemetry:{" "}
                  {scoreData.imputed_features.join(", ")}
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="flex justify-between items-center text-xs text-gray-500 mt-2">
        <span>Model: <span className="font-medium text-gray-700 bg-gray-100 px-2 py-1 rounded">{scoreData.model_version}</span></span>
        <span>Scored <TimeAgo timestamp={scoreData.scored_at} /></span>
      </div>
    </div>
  );
};
