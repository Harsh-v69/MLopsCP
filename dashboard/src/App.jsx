import { useState } from 'react'
import Overview from './pages/Overview'
import AuditTrail from './pages/AuditTrail'
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

      <main key={active}>
        <ActiveComponent onNavigate={setActive} />
      </main>
    </div>
  )
}
