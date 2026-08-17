interface ScoreGaugeProps {
  score: number;
  label: string;
}

const clampScore = (score: number): number => Math.min(100, Math.max(0, score));

const gaugeColor = (score: number): string => {
  if (score <= 25) return "stroke-green-500";
  if (score <= 50) return "stroke-yellow-500";
  if (score <= 75) return "stroke-orange-500";
  return "stroke-red-500";
};

export const ScoreGauge = ({ score, label }: ScoreGaugeProps): JSX.Element => {
  const value = clampScore(score);
  const radius = 42;
  const circumference = Math.PI * radius;
  const offset = circumference - (value / 100) * circumference;
  return (
    <div className="flex flex-col items-center gap-2">
      <svg viewBox="0 0 120 70" role="img" aria-label={`${label}: ${value}`} className="h-24 w-32">
        <path d="M18 60a42 42 0 0 1 84 0" fill="none" className="stroke-gray-200" strokeWidth="10" strokeLinecap="round" />
        <path
          d="M18 60a42 42 0 0 1 84 0"
          fill="none"
          className={`${gaugeColor(value)} transition-all duration-700 ease-out`}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
        <text x="60" y="54" textAnchor="middle" className="fill-gray-900 text-xl font-semibold">
          {value}
        </text>
      </svg>
      <span className="text-sm font-medium text-gray-700">{label}</span>
    </div>
  );
};
