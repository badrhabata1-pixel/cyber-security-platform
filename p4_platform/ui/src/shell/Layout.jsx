import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../AuthContext.jsx'
import { manifestsForRole } from './manifests.js'

export default function Layout() {
  const { user, logout } = useAuth()
  const items = manifestsForRole(user.role)

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark" />
          CyberShield
        </div>
        <nav>
          <NavLink to="/" end className="nav-link">
            Overview
          </NavLink>
          {items.map((m) => (
            <NavLink key={m.path} to={m.path} className="nav-link">
              {m.title}
            </NavLink>
          ))}
        </nav>
        <div className="user-box">
          <div className="user-email" title={user.email}>
            {user.email}
          </div>
          <span className={`badge badge-${user.role}`}>{user.role}</span>
          <button className="btn btn-ghost" onClick={logout}>
            Sign out
          </button>
        </div>
      </aside>
      <main className="content">
        <Outlet />
      </main>
    </div>
  )
}
