/**
 * @vitest-environment happy-dom
 */
import React from 'react';
import { describe, it, expect as vitestExpect, vi, beforeEach } from 'vitest';
import '@testing-library/jest-dom/vitest';
import * as matchers from '@testing-library/jest-dom/matchers';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

vitestExpect.extend(matchers);
const expect = vitestExpect;
import { MemoryRouter } from 'react-router-dom';
import { IncidentOverviewTab } from '../src/features/incidents/components/IncidentOverviewTab';
import { CausalAttributionTab } from '../src/features/incidents/components/CausalAttributionTab';
import { PCEPSScorePanel } from '../src/features/pceps/PCEPSScorePanel';
import { usePhantomClient } from '../src/hooks/usePhantomClient';
import { useAttributionPoller } from '../src/hooks/useAttributionPoller';

// Mock the hooks
vi.mock('../src/hooks/usePhantomClient');
vi.mock('../src/hooks/useAttributionPoller');

const mockIncidentDetail = {
  report: {
    incident_id: 'inc-123',
    revision: 5,
    title: 'Test Incident',
    summary: 'Test summary',
    status: 'open',
    classification: 'suspicious',
    evidence_hash: 'abc',
    created_by: 'user',
    created_at: '2026-07-25T00:00:00Z',
    updated_at: '2026-07-25T00:00:00Z'
  },
  drift_event_ids: [],
  attribution_ids: ['attr-123'],
  score_ids: [],
  snapshot_id: 'snap-1',
  tags: [],
  resolution_notes: null,
  archived_at: null
};

describe('Incident Detail Components', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Optimistic Locking', () => {
    it('shows optimistic lock conflict error message when API returns 409', async () => {
      const mockUpdate = vi.fn().mockRejectedValue({ status: 409, message: 'Conflict: revision mismatch' });
      vi.mocked(usePhantomClient).mockReturnValue({
        updateIncident: mockUpdate
      } as any);

      render(
        <MemoryRouter>
          <IncidentOverviewTab incident={mockIncidentDetail as any} onUpdate={vi.fn()} />
        </MemoryRouter>
      );

      fireEvent.click(screen.getByText('Edit Overview'));
      fireEvent.click(screen.getByText('Save Changes'));

      await waitFor(() => {
        expect(screen.getByText(/This incident was updated by someone else/i)).toBeInTheDocument();
      });
    });

    it('PATCH saves correctly with expected_revision', async () => {
      const mockUpdate = vi.fn().mockResolvedValue({
        ...mockIncidentDetail.report,
        title: 'New Title',
        revision: 6
      });
      vi.mocked(usePhantomClient).mockReturnValue({
        updateIncident: mockUpdate
      } as any);

      render(
        <MemoryRouter>
          <IncidentOverviewTab incident={mockIncidentDetail as any} onUpdate={vi.fn()} />
        </MemoryRouter>
      );

      fireEvent.click(screen.getByText('Edit Overview'));
      
      const titleInput = screen.getByRole('textbox', { name: /title/i });
      fireEvent.change(titleInput, { target: { value: 'New Title' } });
      
      fireEvent.click(screen.getByText('Save Changes'));

      await waitFor(() => {
        expect(mockUpdate).toHaveBeenCalledWith('inc-123', expect.objectContaining({
          expected_revision: 5,
          title: 'New Title'
        }));
      });
    });
  });

  describe('Causal Attribution Tab', () => {
    it('shows "not_identifiable" banner correctly', () => {
      vi.mocked(useAttributionPoller).mockReturnValue({
        status: 'not_identifiable',
        result: {
          identified: false,
          failure_reason: 'Hidden confounder detected',
          attribution_id: 'attr-123',
          status: 'not_identifiable'
        } as any,
        error: null
      });

      render(
        <MemoryRouter>
          <CausalAttributionTab incident={mockIncidentDetail as any} />
        </MemoryRouter>
      );

      expect(screen.getByText('Not Identifiable')).toBeInTheDocument();
      expect(screen.getByText(/Hidden confounder detected/i)).toBeInTheDocument();
    });
  });

  describe('PCEPS Score Panel', () => {
    it('shows imputed features warning', () => {
      const scoreData = {
        score_id: 'score-1',
        drift_event_id: 'event-1',
        attribution_id: 'attr-1',
        model_version: 'v1.0',
        score: 90,
        severity: 'critical' as const,
        feature_completeness: 0.7,
        imputed_features: ['network_bytes_out', 'syscall_count'],
        scored_at: '2026-07-25T00:00:00Z'
      };

      render(
        <MemoryRouter>
          <PCEPSScorePanel scoreData={scoreData} />
        </MemoryRouter>
      );

      expect(screen.getByText(/were estimated due to missing telemetry/i)).toBeInTheDocument();
      expect(screen.getByText(/network_bytes_out, syscall_count/i)).toBeInTheDocument();
    });
  });
});
