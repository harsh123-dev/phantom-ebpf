import type { BehavioralConstraints } from "../../../types/phantom";
import { limitedList, portRange } from "../contractUtils";
import { BadgeList } from "./BadgeList";

interface ConstraintSectionProps {
  constraints: BehavioralConstraints;
}

export const ConstraintSection = ({ constraints }: ConstraintSectionProps): JSX.Element => {
  const executables = limitedList(constraints.allowed_executables, 20);
  const purls = limitedList(constraints.allowed_purls, 50);
  return (
    <details className="rounded border border-gray-200 p-4" open>
      <summary className="cursor-pointer text-sm font-semibold text-gray-900">Constraints</summary>
      <div className="mt-4 space-y-5">
        <BadgeList title="Allowed Executables" items={executables.shown} remaining={executables.remaining} />
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase text-gray-500">Network Destinations</h4>
          <div className="overflow-hidden rounded border border-gray-200">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-3 py-2 text-left text-xs uppercase text-gray-600">Protocol</th>
                  <th className="px-3 py-2 text-left text-xs uppercase text-gray-600">CIDR</th>
                  <th className="px-3 py-2 text-left text-xs uppercase text-gray-600">Ports</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {constraints.allowed_network_destinations.map((destination) => (
                  <tr key={`${destination.protocol}-${destination.cidr}-${destination.port_min}-${destination.port_max}`}>
                    <td className="px-3 py-2 text-sm text-gray-700">{destination.protocol}</td>
                    <td className="px-3 py-2 font-mono text-xs text-gray-700">{destination.cidr}</td>
                    <td className="px-3 py-2 text-sm text-gray-700">{portRange(destination)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <BadgeList title="Syscall Classes" items={constraints.allowed_syscall_classes} remaining={0} />
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase text-gray-500">Allowed PURLs</h4>
          <div className="max-h-56 overflow-y-auto rounded border border-gray-200 p-3">
            {purls.shown.map((purl) => <div key={purl} className="font-mono text-xs text-gray-700">{purl}</div>)}
            {purls.remaining > 0 ? <div className="mt-2 text-xs text-gray-500">{purls.remaining} more</div> : null}
          </div>
        </div>
      </div>
    </details>
  );
};
