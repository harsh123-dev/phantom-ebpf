import { useEffect, useState } from "react";
import { getErrorMessage } from "../api/apiError";
import type { AttributionResultResponse, AttributionStatus, UUID } from "../types/phantom";
import { usePhantomClient } from "./usePhantomClient";

const POLL_INTERVAL_MS = 2_000;
const MAX_POLLS = 30;
const TERMINAL_STATUSES: AttributionStatus[] = ["completed", "not_identifiable", "failed"];

export interface AttributionPollerResult {
  status: AttributionStatus | "idle";
  result: AttributionResultResponse | null;
  error: string | null;
}

export const useAttributionPoller = (attributionId: UUID | null): AttributionPollerResult => {
  const client = usePhantomClient();
  const [status, setStatus] = useState<AttributionStatus | "idle">("idle");
  const [result, setResult] = useState<AttributionResultResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (attributionId === null) {
      setStatus("idle");
      setResult(null);
      setError(null);
      return undefined;
    }
    let active = true;
    let pollCount = 0;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const poll = async (): Promise<void> => {
      try {
        const nextResult = await client.getAttribution(attributionId);
        if (!active) return;
        setResult(nextResult);
        setStatus(nextResult.status);
        if (TERMINAL_STATUSES.includes(nextResult.status)) return;
        pollCount += 1;
        if (pollCount >= MAX_POLLS) {
          setError("Attribution analysis timed out after one minute.");
          return;
        }
        timer = globalThis.setTimeout(() => void poll(), POLL_INTERVAL_MS);
      } catch (reason: unknown) {
        if (active) setError(getErrorMessage(reason));
      }
    };
    void poll();
    return () => {
      active = false;
      if (timer !== null) globalThis.clearTimeout(timer);
    };
  }, [attributionId, client]);

  return { status, result, error };
};
