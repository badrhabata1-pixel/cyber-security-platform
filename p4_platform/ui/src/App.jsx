import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './AuthContext.jsx'
import Layout from './shell/Layout.jsx'
import { manifestsForRole } from './shell/manifests.js'
import Login from './pages/Login.jsx'
import Home from './pages/Home.jsx'
import Placeholder from './pages/Placeholder.jsx'

export default function App() {
  const { isAuthenticated, loading, user } = useAuth()

  if (loading) return <div className="splash">Loading…</div>

  if (!isAuthenticated) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }

  return (
    <Routes>
      <Route path="/login" element={<Navigate to="/" replace />} />
      <Route element={<Layout />}>
        <Route index element={<Home />} />
        {manifestsForRole(user.role).map((m) => {
          const Component = m.component
          return (
            <Route
              key={m.path}
              path={m.path}
              element={Component ? <Component /> : <Placeholder title={m.title} />}
            />
          )
        })}
        <Route path="*" element={<Placeholder title="Page not found" notFound />} />
      </Route>
    </Routes>
  )
}
