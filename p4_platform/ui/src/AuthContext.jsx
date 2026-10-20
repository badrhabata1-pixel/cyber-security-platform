import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { api, ApiError, TOKEN_KEY } from './api.js'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY))
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(Boolean(localStorage.getItem(TOKEN_KEY)))

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY)
    setToken(null)
    setUser(null)
  }, [])

  const login = useCallback(async (email, password) => {
    const data = await api('/auth/login', { method: 'POST', body: { email, password }, token: '' })
    localStorage.setItem(TOKEN_KEY, data.access_token)
    setToken(data.access_token)
    setUser(data.user)
    return data.user
  }, [])

  // Restore the session from a stored token.
  useEffect(() => {
    if (!token || user) {
      setLoading(false)
      return
    }
    let cancelled = false
    api('/auth/me', { token })
      .then((u) => !cancelled && setUser(u))
      .catch((e) => {
        if (!cancelled && e instanceof ApiError && e.status === 401) logout()
      })
      .finally(() => !cancelled && setLoading(false))
    return () => {
      cancelled = true
    }
  }, [token, user, logout])

  const value = useMemo(
    () => ({ token, user, loading, isAuthenticated: Boolean(token && user), login, logout }),
    [token, user, loading, login, logout],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
