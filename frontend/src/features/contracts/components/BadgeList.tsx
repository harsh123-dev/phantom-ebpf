interface BadgeListProps {
  title: string;
  items: string[];
  remaining: number;
}

export const BadgeList = ({ title, items, remaining }: BadgeListProps): JSX.Element => (
  <div>
    <h4 className="mb-2 text-xs font-semibold uppercase text-gray-500">{title}</h4>
    <div className="flex flex-wrap gap-2">
      {items.map((item) => <span key={item} className="rounded bg-gray-100 px-2 py-1 text-xs text-gray-700">{item}</span>)}
      {remaining > 0 ? <span className="rounded bg-gray-200 px-2 py-1 text-xs text-gray-700">{remaining} more</span> : null}
      {items.length === 0 ? <span className="text-sm text-gray-500">None declared</span> : null}
    </div>
  </div>
);
