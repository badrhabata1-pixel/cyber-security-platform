import { Link } from 'react-router-dom'
import { useAuth } from '../AuthContext.jsx'
import { manifestsForRole } from '../shell/manifests.js'

export default function Home() {
  const { user } = useAuth()
  const items = manifestsForRole(user.role)

  return (
    <>
      <h1 className="page-title">Welcome back</h1>
      <p className="muted">Signed in as {user.email}. Pick a module to get started.</p>
      <div className="card-grid">
        {items.map((m) => (
          <Link key={m.path} to={m.path} className="card module-card">
            <h3>{m.title}</h3>
            <span className="muted">{m.component ? 'Open' : 'Coming soon'}</span>
          </Link>
        ))}
        {items.length === 0 && <p className="muted">No modules available for your role.</p>}
      </div>
    </>
  )
}
