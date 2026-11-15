import { useState } from 'react'
import Overview from './pages/Overview'
import AuditTrail from './pages/AuditTrail'
import { SessionChip, SignInPanel } from './SignIn'
import { useSession } from './useSession'
import ModelCard from './pages/ModelCard'
import Explain from './pages/Explain'

const TABS = {
  overview: { label: 'Overview', component: Overview },
  audit: { label: 'Audit Trail', component: AuditTrail },
  card: { label: 'Model Card', component: ModelCard },
  explain: { label: 'Explain', component: Explain },
}

export default function App() {
  const [active, setActive] = useState('overview')
  const session = useSession()
  const ActiveComponent = TABS[active].component

  return (
    <div className="app">
      <header className="brand">
        <div className="brand-mark" aria-hidden="true">M</div>
        <div>
          <h1>MLShield</h1>
          <p>Every model release is scanned, scored and recorded. All values come live from the backend.</p>
        </div>
      </header>

      {session && <SessionChip session={session} />}

      <nav aria-label="Sections">
        {Object.entries(TABS).map(([key, tab]) => (
          <button
            key={key}
            className={key === active ? 'tab active' : 'tab'}
            onClick={() => setActive(key)}
            aria-current={key === active ? 'page' : undefined}
            data-testid={`tab-${key}`}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {/* Every data route needs a role, so nothing is fetched until someone is signed in. */}
      <main key={`${active}-${session ? session.token.slice(-12) : 'out'}`}>
        {session ? <ActiveComponent onNavigate={setActive} /> : <SignInPanel />}
      </main>
    </div>
  )
}
