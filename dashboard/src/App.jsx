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
      <header>
        <h1>MLShield</h1>
        <p className="muted">Transparency layer — live backend data, no mocks</p>
      </header>

      <nav>
        {Object.entries(TABS).map(([key, tab]) => (
          <button
            key={key}
            className={key === active ? 'tab active' : 'tab'}
            onClick={() => setActive(key)}
            data-testid={`tab-${key}`}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <main>
        <ActiveComponent />
      </main>
    </div>
  )
}
