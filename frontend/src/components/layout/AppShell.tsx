import { NavigationSidebar } from './NavigationSidebar'
import { AppRoutes } from '../../routes'

export function AppShell() {
  return (
    <>
      <aside className="w-56 flex-shrink-0 bg-[#111827] border-r border-[#1f2937] flex flex-col overflow-y-auto">
        <NavigationSidebar />
      </aside>

      <main className="flex-1 overflow-y-auto">
        <AppRoutes />
      </main>
    </>
  )
}
