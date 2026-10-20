export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export const TOKEN_KEY = 'platform_token'

export class ApiError extends Error {
  constructor(status, message) {
    super(message)
    this.status = status
  }
}

export async function api(path, { method = 'GET', body, token, params } = {}) {
  const url = new URL(API_URL + path)
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, v)
    })
  }
  const headers = {}
  if (body) headers['Content-Type'] = 'application/json'
  const t = token ?? localStorage.getItem(TOKEN_KEY)
  if (t) headers.Authorization = `Bearer ${t}`

  let res
  try {
    res = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined })
  } catch {
    throw new ApiError(0, 'Cannot reach the server')
  }
  const data = await res.json().catch(() => null)
  if (!res.ok) {
    const detail = typeof data?.detail === 'string' ? data.detail : res.statusText
    throw new ApiError(res.status, detail)
  }
  return data
}
