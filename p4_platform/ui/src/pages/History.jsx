import { useCallback, useEffect, useState } from 'react'
import { api } from '../api.js'

const fmt = (iso) => new Date(iso).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')

export default function History() {
  const [filters, setFilters] = useState({ module: '', from_date: '', to_date: '' })
  const [rows, setRows] = useState([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      setRows(await api('/history', { params: filters }))
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [filters])

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const set = (k) => (e) => setFilters((f) => ({ ...f, [k]: e.target.value }))
  const modules = [...new Set(rows.map((r) => r.module))]

  return (
    <>
      <h1 className="page-title">Audit History</h1>
      <p className="muted">Actions recorded across platform modules. All times are UTC.</p>

      <form
        className="filters"
        onSubmit={(e) => {
          e.preventDefault()
          load()
        }}
      >
        <label>
          Module
          <input list="modules" value={filters.module} onChange={set('module')} placeholder="All" />
          <datalist id="modules">
            {modules.map((m) => (
              <option key={m} value={m} />
            ))}
          </datalist>
        </label>
        <label>
          From
          <input type="date" value={filters.from_date} onChange={set('from_date')} />
        </label>
        <label>
          To
          <input type="date" value={filters.to_date} onChange={set('to_date')} />
        </label>
        <button className="btn btn-primary" disabled={loading}>
          {loading ? 'Loading…' : 'Apply'}
        </button>
      </form>

      {error && <div className="alert">{error}</div>}

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>User</th>
              <th>Module</th>
              <th>Action</th>
              <th>Ref</th>
              <th>Summary</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td className="nowrap">{fmt(r.ts)}</td>
                <td>{r.user}</td>
                <td>
                  <span className="tag">{r.module}</span>
                </td>
                <td>{r.action}</td>
                <td className="mono">{r.ref_id ?? '—'}</td>
                <td>{r.summary}</td>
              </tr>
            ))}
            {!loading && rows.length === 0 && (
              <tr>
                <td colSpan="6" className="empty">
                  No history entries found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  )
}
