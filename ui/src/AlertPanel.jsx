import React from 'react'

function sevClass(sev) {
  switch ((sev ?? '').toLowerCase()) {
    case 'critical': return 'sev-critical'
    case 'high':     return 'sev-high'
    case 'medium':   return 'sev-medium'
    case 'low':      return 'sev-low'
    default:         return 'sev-info'
  }
}

function fmtTime(ts) {
  if (!ts) return ''
  const d = new Date(ts)
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function AlertPanel({ alerts, selectedAlert, onSelect }) {
  return (
    <div className="alert-panel">
      <div className="panel-header">
        Alerts ({alerts.length})
      </div>
      <div className="alert-list">
        {alerts.length === 0 ? (
          <div className="empty-state">No alerts yet.<br/>Waiting for tainted activity…</div>
        ) : (
          alerts.map(a => (
            <div
              key={a.id}
              className={`alert-item ${selectedAlert?.id === a.id ? 'selected' : ''}`}
              onClick={() => onSelect(a)}
            >
              <div className="alert-title" title={a.title}>{a.title}</div>
              <div className="alert-meta">
                <span className={`severity-badge ${sevClass(a.severity)}`}>{a.severity}</span>
                <span className="alert-time">{fmtTime(a.at)}</span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
