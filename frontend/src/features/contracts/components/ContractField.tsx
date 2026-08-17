interface ContractFieldProps {
  label: string;
  value: string | JSX.Element;
  mono?: boolean;
}

export const ContractField = ({
  label,
  value,
  mono = false,
}: ContractFieldProps): JSX.Element => (
  <div className="min-w-0 rounded border border-gray-100 p-3">
    <div className="text-xs uppercase text-gray-500">{label}</div>
    <div className={`mt-1 truncate text-sm text-gray-900 ${mono ? "font-mono" : "font-medium"}`}>{value}</div>
  </div>
);
