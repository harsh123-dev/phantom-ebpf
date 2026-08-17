import { Routes, Route, Navigate } from 'react-router-dom';
import { DashboardView } from '../features/dashboard/DashboardView';
import { SBOMExplorerView } from '../features/sbom/SBOMExplorerView';
import { ContractExplorerView } from '../features/contracts/ContractExplorerView';
import { BDGVisualizerView } from '../features/graph/BDGVisualizerView';
import { IncidentListView } from '../features/incidents/IncidentListView';
import { IncidentDetailView } from '../features/incidents/IncidentDetailView';

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<DashboardView />} />
      <Route path="/sbom" element={<SBOMExplorerView />} />
      <Route path="/contracts" element={<ContractExplorerView />} />
      <Route path="/graph" element={<BDGVisualizerView />} />
      <Route path="/incidents" element={<IncidentListView />} />
      <Route path="/incidents/:id" element={<IncidentDetailView />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
