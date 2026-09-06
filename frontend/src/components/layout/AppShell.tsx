import { NavigationSidebar } from './NavigationSidebar'
import { AppRoutes } from '../../routes'
import { useIsDemoMode } from '../../hooks/usePhantomClient'

function DemoModeBanner() {
  const isDemo = useIsDemoMode()
  if (!isDemo) return null
  return (
    <div className="flex items-center gap-2 bg-amber-500/10 border-b border-amber-500/30 px-4 py-2 text-xs text-amber-300 col-span-2" style={{ gridColumn: '1 / -1' }}>
      <span className="inline-block h-2 w-2 rounded-full bg-amber-400 animate-pulse" />
      <span>
        <strong className="font-semibold">Demo Mode</strong> — Live API unreachable. Showing real data from EC2 eBPF evaluation runs (N=6, TPR=100%, Mean MTTD=15.7s). Drift events are being replayed live.
      </span>
    </div>
  )
}

export function AppShell() {
  return (
    <div className="flex flex-col w-full h-full">
      <DemoModeBanner />
      <div className="flex flex-1 overflow-hidden">
        <aside className="w-56 flex-shrink-0 bg-[#111827] border-r border-[#1f2937] flex flex-col overflow-y-auto">
          <NavigationSidebar />
        </aside>
        <main className="flex-1 overflow-y-auto">
          <AppRoutes />
        </main>
      </div>
    </div>
  )
}
