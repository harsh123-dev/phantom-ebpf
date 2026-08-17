import { BrowserRouter } from 'react-router-dom'
import { AppShell } from './components/layout/AppShell'

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen overflow-hidden bg-[#0a0e1a]">
        <AppShell />
      </div>
    </BrowserRouter>
  )
}
