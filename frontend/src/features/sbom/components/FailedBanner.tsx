interface FailedBannerProps {
  reason: string;
}

export const FailedBanner = ({ reason }: FailedBannerProps): JSX.Element => (
  <div className="rounded border border-red-200 bg-red-50 p-4 text-sm text-red-800">
    <div className="font-semibold">Verification failed</div>
    <div className="mt-1">{reason}</div>
  </div>
);
