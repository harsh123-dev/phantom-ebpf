import type { SbomVerificationResponse } from "../../../types/phantom";

interface VerifiedBannerProps {
  verification: SbomVerificationResponse | null;
}

export const VerifiedBanner = ({ verification }: VerifiedBannerProps): JSX.Element => (
  <div className="rounded border border-green-200 bg-green-50 p-4 text-sm text-green-800">
    <div className="font-semibold">Signature verified</div>
    <div className="mt-2">Identity: {verification?.signing_identity ?? "unknown"}</div>
    <div>Issuer: {verification?.issuer ?? "unknown"}</div>
    {verification?.rekor_entry_uuid ? (
      <a href={`https://search.sigstore.dev/?uuid=${encodeURIComponent(verification.rekor_entry_uuid)}`} className="mt-2 inline-flex items-center gap-1 font-medium text-green-900" target="_blank" rel="noreferrer">
        Rekor {verification.rekor_entry_uuid.slice(0, 8)}...
        <svg viewBox="0 0 16 16" aria-hidden="true" className="h-3.5 w-3.5">
          <path d="M6 3h7v7h-2V6.4l-6.3 6.3-1.4-1.4L9.6 5H6V3Z" className="fill-current" />
        </svg>
      </a>
    ) : null}
  </div>
);
