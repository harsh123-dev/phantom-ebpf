import { useEffect, useState } from "react";
import type { ISOTimestamp } from "../../types/phantom";

interface TimeAgoProps {
  timestamp: ISOTimestamp;
}

const formatTimeAgo = (timestamp: ISOTimestamp, nowMs: number): string => {
  const thenMs = Date.parse(timestamp);
  if (!Number.isFinite(thenMs)) return "unknown time";
  const seconds = Math.max(0, Math.floor((nowMs - thenMs) / 1_000));
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.floor(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
};

export const TimeAgo = ({ timestamp }: TimeAgoProps): JSX.Element => {
  const [nowMs, setNowMs] = useState(() => Date.now());
  useEffect(() => {
    const timer = globalThis.setInterval(() => setNowMs(Date.now()), 30_000);
    return () => globalThis.clearInterval(timer);
  }, []);
  return <time dateTime={timestamp}>{formatTimeAgo(timestamp, nowMs)}</time>;
};
