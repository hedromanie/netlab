import type { ModuleInfo, RunResult } from './types'

// In dev Vite proxies /api → backend. Override with VITE_API_URL if needed.
const API_BASE = import.meta.env.VITE_API_URL || ''

export async function fetchModules(): Promise<ModuleInfo[]> {
  const res = await fetch(`${API_BASE}/api/modules`)
  if (!res.ok) throw new Error(`Failed to load modules: ${res.status}`)
  return res.json()
}

export async function runModule(
  module: string,
  parameters: Record<string, string | number>,
  rateLimitPps?: number
): Promise<RunResult> {
  const body: Record<string, unknown> = { module, parameters }
  if (rateLimitPps !== undefined) body.rate_limit_pps = rateLimitPps

  const res = await fetch(`${API_BASE}/api/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

  const data = await res.json()
  if (!res.ok) {
    throw new Error(data.detail || `Request failed: ${res.status}`)
  }
  return data
}
