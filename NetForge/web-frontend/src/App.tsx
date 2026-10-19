import { useCallback, useEffect, useMemo, useState } from 'react'
import { fetchModules, runModule } from './api'
import type { ModuleInfo, RunResult } from './types'
import './index.css'

const CATEGORY_ORDER = ['recon', 'l2', 'l3_l4', 'misc']
const CATEGORY_LABELS: Record<string, string> = {
  recon: 'Reconnaissance',
  l2: 'Layer 2',
  l3_l4: 'Layer 3 / 4',
  misc: 'Other',
}

function App() {
  const [modules, setModules] = useState<ModuleInfo[]>([])
  const [selected, setSelected] = useState<ModuleInfo | null>(null)
  const [params, setParams] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<RunResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchModules()
      .then((data) => {
        setModules(data)
        if (data.length > 0) selectModule(data[0])
      })
      .catch((err) => setError(String(err.message || err)))
      .finally(() => setLoading(false))
  }, [])

  const selectModule = useCallback((mod: ModuleInfo) => {
    setSelected(mod)
    setResult(null)
    setError(null)
    const initial: Record<string, string> = {}
    for (const p of mod.parameters) {
      if (p.default !== null && p.default !== undefined) {
        initial[p.name] = String(p.default)
      } else {
        initial[p.name] = ''
      }
    }
    setParams(initial)
  }, [])

  const grouped = useMemo(() => {
    const map: Record<string, ModuleInfo[]> = {}
    for (const m of modules) {
      const cat = m.category || 'misc'
      if (!map[cat]) map[cat] = []
      map[cat].push(m)
    }
    return CATEGORY_ORDER
      .filter((c) => map[c]?.length)
      .map((c) => ({ category: c, label: CATEGORY_LABELS[c] || c, items: map[c] }))
  }, [modules])

  const handleParamChange = (name: string, value: string) => {
    setParams((prev) => ({ ...prev, [name]: value }))
  }

  const handleRun = async () => {
    if (!selected) return
    setRunning(true)
    setError(null)
    setResult(null)

    const payload: Record<string, string | number> = {}
    for (const p of selected.parameters) {
      const raw = params[p.name]
      if (raw === '' || raw === undefined) {
        if (p.required) {
          setError(`Parameter "${p.label}" is required`)
          setRunning(false)
          return
        }
        continue
      }
      if (p.type === 'int' || p.type === 'float') {
        payload[p.name] = p.type === 'int' ? parseInt(raw, 10) : parseFloat(raw)
      } else {
        payload[p.name] = raw
      }
    }

    try {
      const res = await runModule(selected.name, payload)
      setResult(res)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setRunning(false)
    }
  }

  if (loading) {
    return (
      <div className="empty-state">
        <h2>Loading modules…</h2>
      </div>
    )
  }

  if (error && modules.length === 0) {
    return (
      <div className="empty-state">
        <h2>Cannot reach API</h2>
        <p>{error}</p>
        <p style={{ marginTop: 12, fontSize: '0.85rem' }}>
          Start backend: <code>uvicorn netlab.web:app --reload --port 8000</code>
        </p>
      </div>
    )
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h1>NetForge</h1>
          <p>Network Attack Lab</p>
        </div>
        <nav className="module-list">
          {grouped.map((g) => (
            <div key={g.category} className="category">
              <div className="category-title">{g.label}</div>
              {g.items.map((m) => (
                <button
                  key={m.name}
                  type="button"
                  className={`module-item ${selected?.name === m.name ? 'active' : ''}`}
                  onClick={() => selectModule(m)}
                >
                  <div className="name">{m.name}</div>
                  <div className="desc">{m.description}</div>
                </button>
              ))}
            </div>
          ))}
        </nav>
      </aside>

      <main className="main">
        {selected ? (
          <>
            <div className="main-header">
              <h2>{selected.name}</h2>
              <div className="meta">
                {selected.category} · {selected.description}
              </div>
            </div>

            <div className={`content ${running ? 'loading' : ''}`}>
              <div className="form-card">
                <h3>Parameters</h3>
                {selected.parameters.length === 0 && (
                  <p className="result-empty">No parameters required</p>
                )}
                {selected.parameters.map((p) => (
                  <div key={p.name} className="field">
                    <label>
                      {p.label}
                      {p.required && <span className="req">*</span>}
                    </label>
                    <input
                      type={p.type === 'int' || p.type === 'float' ? 'number' : 'text'}
                      value={params[p.name] ?? ''}
                      onChange={(e) => handleParamChange(p.name, e.target.value)}
                      placeholder={p.default != null ? String(p.default) : ''}
                    />
                    {p.description && <div className="hint">{p.description}</div>}
                  </div>
                ))}
                <div className="actions">
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={handleRun}
                    disabled={running}
                  >
                    {running ? 'Running…' : 'Run Attack'}
                  </button>
                </div>
                {error && <div className="error-box">{error}</div>}
              </div>

              <div className="result-card">
                <h3>Result</h3>
                {!result && !running && (
                  <p className="result-empty">Run an attack to see results</p>
                )}
                {running && <p className="result-empty">Executing…</p>}
                {result && (
                  <>
                    <div className={`result-status ${result.status}`}>
                      Status: {result.status}
                    </div>
                    <div className="stat-grid">
                      <div className="stat">
                        <div className="label">Packets</div>
                        <div className="value">{result.packets_sent.toLocaleString()}</div>
                      </div>
                      <div className="stat">
                        <div className="label">Bytes</div>
                        <div className="value">{result.bytes_sent.toLocaleString()}</div>
                      </div>
                    </div>
                    {result.log_file && (
                      <div className="log-path">Log: {result.log_file}</div>
                    )}
                  </>
                )}
              </div>
            </div>
          </>
        ) : (
          <div className="empty-state">
            <h2>Select a module</h2>
            <p>Choose an attack from the sidebar to configure and run it.</p>
          </div>
        )}
      </main>
    </div>
  )
}

export default App
