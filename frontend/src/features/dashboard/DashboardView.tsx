import { ContractCoverage } from "./components/ContractCoverage";
import { LiveDriftFeed } from "./components/LiveDriftFeed";
import { PcepsScoreDistribution } from "./components/PcepsScoreDistribution";
import { RecentIncidents } from "./components/RecentIncidents";

export const DashboardView = (): JSX.Element => (
  <main className="min-h-screen bg-gray-50 p-4 text-gray-900 md:p-6">
    <div className="mx-auto grid max-w-7xl gap-4">
      <LiveDriftFeed />
      <div className="grid gap-4 lg:grid-cols-2">
        <PcepsScoreDistribution />
        <ContractCoverage />
      </div>
      <RecentIncidents />
    </div>
  </main>
);
