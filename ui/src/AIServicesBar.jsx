import React, { useState, useEffect } from 'react'

const API = import.meta.env.VITE_API_URL ?? ''
const POLL_INTERVAL = 10_000 // refresh every 10 seconds

function categoryColor(cat) {
  switch (cat) {
    case 'llm':       return 'var(--orange)'
    case 'runtime':   return 'var(--blue)'
    case 'training':  return 'var(--yellow)'
    case 'vector-db': return 'var(--green)'
    case 'ui':        return '#c084fc'
    case 'inference': return 'var(--orange)'
    default:          return 'var(--text-dim)'
  }
}

function categoryLabel(cat) {
  switch (cat) {
    case 'llm':       return 'LLM'
    case 'runtime':   return 'Runtime'
    case 'training':  return 'Training'
    case 'vector-db': return 'Vector DB'
    case 'ui':        return 'UI'
    case 'inference': return 'Inference'
    default:          return 'AI'
  }
}

export const AIServicesBar = React.memo(function AIServicesBar() {
  const [services, setServices] = useState([])
  const [error, setError] = useState(false)

  useEffect(() => {
    let active = true

    async function fetchServices() {
      try {
        const res = await fetch(`${API}/api/services`)
        if (!res.ok) throw new Error(res.statusText)
        const data = await res.json()
        if (active) {
          setServices(data ?? [])
          setError(false)
        }
      } catch {
        if (active) setError(true)
      }
    }

    fetchServices()
    const id = setInterval(fetchServices, POLL_INTERVAL)
    return () => { active = false; clearInterval(id) }
  }, [])

  const processes = services.filter(s => s.type === 'process')
  const svcPorts  = services.filter(s => s.type === 'service')

  if (error) {
    return (
      <div className="ai-services-bar">
        <span className="asb-label">AI Services</span>
        <span className="asb-empty">Unable to fetch services</span>
      </div>
    )
  }

  if (services.length === 0) {
    return (
      <div className="ai-services-bar">
        <span className="asb-label">AI Services</span>
        <span className="asb-empty">No AI processes or services detected</span>
      </div>
    )
  }

  const processTitle = (p) =>
    [p.cmdline ? `Process — ${p.cmdline}` : `Process — ${p.name}`, p.pid ? `PID ${p.pid}` : null]
      .filter(Boolean)
      .join(' · ')

  const serviceTitle = (s) =>
    `Listening port — ${s.name} on localhost:${s.port} (TCP)`

  return (
    <div className="ai-services-bar">
      <span className="asb-label" title="Running AI-related processes (from /proc) and known listening ports on localhost">
        AI Services
      </span>

      <div className="asb-items">
        {processes.length > 0 && (
          <div className="asb-section" aria-label="Running processes">
            <span className="asb-section-label">Processes</span>
            {processes.map(p => (
              <div
                key={p.name}
                className="asb-chip"
                title={processTitle(p)}
              >
                <span
                  className="asb-kind-badge"
                  title="Detected from running process name (comm)"
                >
                  proc
                </span>
                <span
                  className="asb-dot"
                  style={{ background: categoryColor(p.category) }}
                />
                <span className="asb-name">{p.name}</span>
                <span
                  className="asb-cat-badge"
                  style={{
                    color: categoryColor(p.category),
                    borderColor: categoryColor(p.category),
                  }}
                >
                  {categoryLabel(p.category)}
                </span>
                <span className="asb-status asb-status-running">●</span>
              </div>
            ))}
          </div>
        )}

        {svcPorts.length > 0 && processes.length > 0 && (
          <span className="asb-divider" aria-hidden="true" />
        )}

        {svcPorts.length > 0 && (
          <div className="asb-section" aria-label="Listening ports">
            <span className="asb-section-label">Listening ports</span>
            {svcPorts.map(s => (
              <div
                key={`${s.name}:${s.port}`}
                className="asb-chip asb-chip-service"
                title={serviceTitle(s)}
              >
                <span
                  className="asb-dot"
                  style={{ background: categoryColor(s.category) }}
                />
                <span className="asb-name">{s.name}</span>
                <span className="asb-port">:{s.port}</span>
                <span
                  className="asb-cat-badge"
                  style={{
                    color: categoryColor(s.category),
                    borderColor: categoryColor(s.category),
                  }}
                >
                  {categoryLabel(s.category)}
                </span>
                <span className="asb-status asb-status-listening">●</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
})
