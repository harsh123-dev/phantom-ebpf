import type { Severity } from "../../../types/phantom";

export interface SeverityBarDatum {
  severity: Severity;
  count: number;
}

interface SeverityBarChartProps {
  data: SeverityBarDatum[];
}

const barColors: Record<Severity, string> = {
  informational: "fill-gray-400",
  low: "fill-blue-500",
  medium: "fill-yellow-500",
  high: "fill-orange-500",
  critical: "fill-red-500",
};

export const severityBarHeight = (count: number, maxCount: number, maxHeight: number): number => {
  if (count <= 0 || maxCount <= 0) return 0;
  return Math.max(6, Math.round((count / maxCount) * maxHeight));
};

export const SeverityBarChart = ({ data }: SeverityBarChartProps): JSX.Element => {
  const width = 520;
  const height = 220;
  const chartHeight = 150;
  const maxCount = Math.max(...data.map((item) => item.count), 0);
  if (maxCount === 0) {
    return <div className="flex h-56 items-center justify-center text-sm text-gray-500">No scored incidents in the last 24 hours</div>;
  }
  return (
    <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="PCEPS score distribution" className="h-64 w-full">
      <line x1="40" y1="170" x2="500" y2="170" className="stroke-gray-200" />
      <line x1="40" y1="20" x2="40" y2="170" className="stroke-gray-200" />
      {data.map((item, index) => {
        const barWidth = 56;
        const gap = 34;
        const x = 68 + index * (barWidth + gap);
        const barHeight = severityBarHeight(item.count, maxCount, chartHeight);
        const y = 170 - barHeight;
        return (
          <g key={item.severity}>
            <title>{`${item.severity}: ${item.count}`}</title>
            <rect x={x} y={y} width={barWidth} height={barHeight} rx="3" className={`${barColors[item.severity]} transition-all duration-700`} data-count={item.count} data-height={barHeight} />
            <text x={x + barWidth / 2} y={y - 8} textAnchor="middle" className="fill-gray-700 text-xs font-semibold">
              {item.count}
            </text>
            <text x={x + barWidth / 2} y="195" textAnchor="middle" className="fill-gray-600 text-xs">
              {item.severity}
            </text>
          </g>
        );
      })}
    </svg>
  );
};
