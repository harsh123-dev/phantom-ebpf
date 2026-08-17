import { useEffect, useState } from "react";
import { getErrorMessage } from "../../../api/apiError";
import { StatusIndicator } from "../../../components/ui/StatusIndicator";
import type { PhantomGatewayClient } from "../../../api/gatewayClient";
import type { SbomDetailResponse, SbomVerificationResponse } from "../../../types/phantom";
import { FailedBanner } from "./FailedBanner";
import { VerifiedBanner } from "./VerifiedBanner";

interface SBOMVerifyPanelProps {
  client: PhantomGatewayClient;
  detail: SbomDetailResponse;
  initialVerification: SbomVerificationResponse | null;
}

const terminalStatuses = ["verified", "failed"] as const;

export const SBOMVerifyPanel = ({
  client,
  detail,
  initialVerification,
}: SBOMVerifyPanelProps): JSX.Element => {
  const [verification, setVerification] = useState<SbomVerificationResponse | null>(initialVerification);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const status = verification?.status ?? detail.record.verification_status;

  useEffect(() => {
    setVerification(initialVerification);
    setRunning(false);
    setError(null);
  }, [initialVerification, detail.record.sbom_id]);

  useEffect(() => {
    if (!running || terminalStatuses.includes(status as "verified" | "failed")) return;
    const timer = globalThis.setInterval(() => {
      void client.getSbomVerification(detail.record.sbom_id).then((result) => {
        setVerification(result);
        if (terminalStatuses.includes(result.status as "verified" | "failed")) setRunning(false);
      }).catch((reason: unknown) => {
        setError(getErrorMessage(reason));
        setRunning(false);
      });
    }, 2_000);
    return () => globalThis.clearInterval(timer);
  }, [client, detail.record.sbom_id, running, status]);

  const verifyNow = async (): Promise<void> => {
    setRunning(true);
    setError(null);
    try {
      // # VERIFY: expected_identity and expected_issuer should be sourced from tenant policy when exposed to the frontend.
      const job = await client.submitSbomVerification(detail.record.sbom_id, {
        expected_identity: "",
        expected_issuer: "",
        rekor_required: true,
      });
      setVerification({
        verification_job_id: job.verification_job_id,
        sbom_id: job.sbom_id,
        status: job.status,
        signing_identity: null,
        issuer: null,
        rekor_entry_uuid: null,
        verified_at: null,
        failure_reason: null,
      });
    } catch (reason: unknown) {
      setError(getErrorMessage(reason));
      setRunning(false);
    }
  };

  return (
    <section className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-gray-900">Verification</h3>
        <StatusIndicator status={status} variant="badge" />
      </div>
      {status === "verified" ? <VerifiedBanner verification={verification} /> : null}
      {status === "failed" ? <FailedBanner reason={verification?.failure_reason ?? detail.verification_error ?? "Verification failed"} /> : null}
      {status === "pending" || status === "queued" || status === "running" ? (
        <div className="rounded border border-yellow-200 bg-yellow-50 p-4 text-sm text-yellow-900">
          <div className="mb-3">{running || status === "running" || status === "queued" ? "Verification is running." : "Verification is pending."}</div>
          <button type="button" disabled={running || status === "running" || status === "queued"} onClick={() => { void verifyNow(); }} className="rounded bg-yellow-600 px-3 py-2 text-sm font-medium text-white hover:bg-yellow-700 disabled:cursor-not-allowed disabled:opacity-60">
            {running ? "Verifying..." : "Verify Now"}
          </button>
        </div>
      ) : null}
      {error ? <div className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">{error}</div> : null}
    </section>
  );
};
