import { useMemo, useState } from "react";
import { DataTable, type Column } from "../../../components/ui/DataTable";
import type { JsonObject } from "../../../types/phantom";
import { extractCycloneDxComponents, filterComponents, type CycloneDxComponent } from "../sbomUtils";

interface ComponentTableProps {
  document: JsonObject;
  onSelectPurl: (purl: string) => void;
}

export const ComponentTable = ({ document, onSelectPurl }: ComponentTableProps): JSX.Element => {
  const [query, setQuery] = useState("");
  const components = useMemo(() => extractCycloneDxComponents(document), [document]);
  const filtered = useMemo(() => filterComponents(components, query), [components, query]);
  const columns = useMemo<Column<CycloneDxComponent>[]>(() => [
    { key: "name", header: "Name" },
    { key: "version", header: "Version" },
    {
      key: "purl",
      header: "PURL",
      render: (value) => typeof value === "string" ? (
        <button type="button" onClick={() => onSelectPurl(value)} className="max-w-md truncate font-mono text-xs text-blue-700 hover:text-blue-900">
          {value}
        </button>
      ) : null,
    },
    { key: "type", header: "Type" },
  ], [onSelectPurl]);
  return (
    <section className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-sm font-semibold text-gray-900">Component Tree</h3>
        <input
          aria-label="Search components"
          value={query}
          onChange={(event) => setQuery(event.currentTarget.value)}
          placeholder="name or purl"
          className="min-h-10 w-64 rounded border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none"
        />
      </div>
      <DataTable columns={columns} rows={filtered} loading={false} emptyMessage="No components match this search" />
    </section>
  );
};
