import type { BehavioralConstraints, NetworkDestination } from "../../types/phantom";

export const shortDigest = (digest: string): string => digest.length > 19 ? `${digest.slice(0, 16)}...` : digest;

export const limitedList = (items: string[], limit: number): { shown: string[]; remaining: number } => ({
  shown: items.slice(0, limit),
  remaining: Math.max(0, items.length - limit),
});

export const portRange = (destination: NetworkDestination): string =>
  destination.port_min === destination.port_max
    ? String(destination.port_min)
    : `${destination.port_min}-${destination.port_max}`;

export const hasConstraints = (constraints: BehavioralConstraints): boolean =>
  constraints.allowed_executables.length > 0 ||
  constraints.allowed_network_destinations.length > 0 ||
  constraints.allowed_syscall_classes.length > 0 ||
  constraints.allowed_purls.length > 0;
