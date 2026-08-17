import type { IncidentClassification, Severity } from "../../types/phantom";

export const truncateUuid = (value: string): string => `${value.slice(0, 8)}...`;

export const copyText = async (value: string): Promise<void> => {
  if (!navigator.clipboard) return;
  await navigator.clipboard.writeText(value);
};

export const classificationSeverity = (classification: IncidentClassification): Severity => {
  if (classification === "confirmed") return "critical";
  if (classification === "suspicious") return "high";
  if (classification === "benign") return "low";
  return "informational";
};

export const severityRank: Record<Severity, number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};
