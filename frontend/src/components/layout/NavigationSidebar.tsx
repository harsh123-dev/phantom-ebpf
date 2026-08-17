import { NavLink } from "react-router-dom";

const navClass = ({ isActive }: { isActive: boolean }): string =>
  `block rounded px-3 py-2 text-sm font-medium ${isActive ? "bg-gray-800 text-white" : "text-gray-400 hover:bg-gray-800 hover:text-white"}`;

export function NavigationSidebar() {
  return (
    <div className="flex flex-col h-full py-4 px-3">
      <div className="mb-8 px-3">
        <div className="text-lg font-bold tracking-widest text-white">PHANTOM</div>
      </div>
      <nav className="flex flex-col gap-2">
        <NavLink to="/" className={navClass} end>
          Dashboard
        </NavLink>
        <NavLink to="/sbom" className={navClass}>
          SBOM Explorer
        </NavLink>
        <NavLink to="/contracts" className={navClass}>
          Contract Explorer
        </NavLink>
        <NavLink to="/graph" className={navClass}>
          Dependency Graph
        </NavLink>
        <NavLink to="/incidents" className={navClass}>
          Incidents
        </NavLink>
      </nav>
    </div>
  );
}
