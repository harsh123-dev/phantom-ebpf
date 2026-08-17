import type { ReactNode } from "react";

export interface Column<T> {
  key: keyof T;
  header: string;
  render?: (value: T[keyof T], row: T) => ReactNode;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  loading: boolean;
  emptyMessage: string;
}

export const DataTable = <T extends object>({
  columns,
  rows,
  loading,
  emptyMessage,
}: DataTableProps<T>): JSX.Element => (
  <div className="overflow-hidden rounded border border-gray-200 bg-white">
    <table className="min-w-full divide-y divide-gray-200">
      <thead className="bg-gray-50">
        <tr>
          {columns.map((column) => (
            <th key={`${String(column.key)}-${column.header}`} scope="col" className="px-4 py-3 text-left text-xs font-semibold uppercase text-gray-600">
              {column.header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody className="divide-y divide-gray-100 bg-white">
        {loading && rows.length === 0
          ? [0, 1, 2].map((row) => (
            <tr key={row}>
              {columns.map((column) => (
                <td key={`${String(column.key)}-${column.header}`} className="px-4 py-4">
                  <div className="h-4 w-24 animate-pulse rounded bg-gray-200" />
                </td>
              ))}
            </tr>
          ))
          : null}
        {!loading && rows.length === 0 ? (
          <tr>
            <td colSpan={columns.length} className="px-4 py-8 text-center text-sm text-gray-500">
              {emptyMessage}
            </td>
          </tr>
        ) : null}
        {rows.map((row, index) => (
          <tr key={index} className="hover:bg-gray-50">
            {columns.map((column) => {
              const value = row[column.key];
              return (
                <td key={`${String(column.key)}-${column.header}`} className="px-4 py-3 text-sm text-gray-700">
                  {column.render ? column.render(value, row) : String(value)}
                </td>
              );
            })}
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);
