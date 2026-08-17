import type { JsonObject, JsonValue, SHA256Digest } from "../../types/phantom";

export interface CycloneDxComponent {
  name: string;
  version: string;
  purl: string;
  type: string;
}

export const copyText = async (value: string): Promise<void> => {
  if (!navigator.clipboard) return;
  await navigator.clipboard.writeText(value);
};

export const shortDigestTail = (digest: SHA256Digest): string => digest.slice(-16);

const isObject = (value: JsonValue | undefined): value is JsonObject =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const getString = (source: JsonObject, key: string): string => {
  const value = source[key];
  return typeof value === "string" ? value : "";
};

export const extractCycloneDxComponents = (document: JsonObject): CycloneDxComponent[] => {
  const rawComponents = document.components;
  if (!Array.isArray(rawComponents)) return [];
  return rawComponents.filter(isObject).map((component) => ({
    name: getString(component, "name"),
    version: getString(component, "version"),
    purl: getString(component, "purl"),
    type: getString(component, "type"),
  }));
};

export const filterComponents = (
  components: CycloneDxComponent[],
  query: string,
): CycloneDxComponent[] => {
  const normalized = query.trim().toLowerCase();
  if (normalized.length === 0) return components;
  return components.filter((component) =>
    component.name.toLowerCase().includes(normalized) || component.purl.toLowerCase().startsWith(normalized),
  );
};
