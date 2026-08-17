interface StatProps {
  label: string;
  value: string;
}

export const Stat = ({ label, value }: StatProps): JSX.Element => (
  <div className="rounded border border-gray-100 p-3">
    <div className="text-xs uppercase text-gray-500">{label}</div>
    <div className="mt-1 truncate text-sm font-semibold text-gray-900">{value}</div>
  </div>
);
