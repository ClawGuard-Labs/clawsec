import React, { useState, useMemo } from 'react'

const SEV_RANK  = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const ALL_SEVS  = ['critical', 'high', 'medium', 'low', 'info']
const SEV_SHORT = { critical: 'Crit', high: 'High', medium: 'Med', low: 'Low', info: 'Info' }

const TIME_OPTS = [
  { label: 'All', value: 'all' },
  { label: '1 h', value: '1h'  },
  { label: '3 h', value: '3h'  },
  { label: '12 h', value: '12h' },
]

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
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function sortedAlerts(alerts) {
  return [...alerts].sort((a, b) => {
    const sd = (b.risk_score ?? 0) - (a.risk_score ?? 0)
    if (sd !== 0) return sd
    const rd = (SEV_RANK[(b.severity ?? '').toLowerCase()] ?? 0) -
               (SEV_RANK[(a.severity ?? '').toLowerCase()] ?? 0)
    if (rd !== 0) return rd
    return new Date(b.at) - new Date(a.at)
  })
}

export const AlertPanel = React.memo(function AlertPanel({ alerts, selectedAlert, onSelect }) {
  const [activeSevs, setActiveSevs] = useState(() => new Set(ALL_SEVS))
  const [minScore,   setMinScore]   = useState(0)
  const [timeRange,  setTimeRange]  = useState('all')

  function toggleSev(sev) {
    setActiveSevs(prev => {
      const next = new Set(prev)
      if (next.has(sev)) {
        if (next.size > 1) next.delete(sev)   // keep at least one active
      } else {
        next.add(sev)
      }
      return next
    })
  }

  const filtered = useMemo(() => {
    const maxAge = { '1h': 3_600_000, '3h': 10_800_000, '12h': 43_200_000, 'all': Infinity }[timeRange]
    // eslint-disable-next-line react-hooks/purity -- time boundary for filter; recomputed whenever any dep changes.
    const cutoff = maxAge === Infinity ? -Infinity : Date.now() - maxAge
    return sortedAlerts(alerts).filter(a => {
      if (!activeSevs.has((a.severity ?? 'info').toLowerCase())) return false
      if ((a.risk_score ?? 0) < minScore) return false
      if (cutoff !== -Infinity && new Date(a.at).getTime() < cutoff) return false
      return true
    })
  }, [alerts, activeSevs, minScore, timeRange])

  const showCount = filtered.length !== alerts.length
    ? `${filtered.length}/${alerts.length}`
    : `${alerts.length}`

  return (
    <div className="alert-panel">
      <div className="panel-header">Alerts ({showCount})</div>

      {/* ── Filter bar ───────────────────────────────────────────────── */}
      <div className="alert-filters">

        {/* Severity toggles */}
        <div className="af-row">
          {ALL_SEVS.map(sev => (
            <button
              key={sev}
              className={`af-sev-btn ${sevClass(sev)}${activeSevs.has(sev) ? '' : ' af-dim'}`}
              onClick={() => toggleSev(sev)}
              title={sev}
            >
              {SEV_SHORT[sev]}
            </button>
          ))}
        </div>

        {/* Score slider */}
        <div className="af-row af-score-row">
          <span className="af-label">Score ≥</span>
          <input
            type="range"
            className="af-slider"
            min={0} max={100} step={5}
            value={minScore}
            style={{ '--pct': `${minScore}%` }}
            onChange={e => setMinScore(+e.target.value)}
          />
          <span className="af-score-val">{minScore === 0 ? 'Any' : minScore}</span>
        </div>

        {/* Time window */}
        <div className="af-row">
          {TIME_OPTS.map(opt => (
            <button
              key={opt.value}
              className={`af-time-btn${timeRange === opt.value ? ' af-time-active' : ''}`}
              onClick={() => setTimeRange(opt.value)}
            >
              {opt.label}
            </button>
          ))}
        </div>

      </div>

      {/* ── Alert list ───────────────────────────────────────────────── */}
      <div className="alert-list">
        {filtered.length === 0 ? (
          <div className="empty-state">No alerts match filters.</div>
        ) : (
          filtered.map(a => (
            <div
              key={a.id}
              className={`alert-item${selectedAlert?.id === a.id ? ' selected' : ''}`}
              onClick={() => onSelect(a)}
            >
              <div className="alert-title" title={a.title}>{a.title}</div>
              <div className="alert-meta">
                <span className={`severity-badge ${sevClass(a.severity)}`}>{a.severity}</span>
                {(a.risk_score ?? 0) > 0 && (
                  <span className="risk-score-badge">score {a.risk_score}</span>
                )}
                <span className="alert-time">{fmtTime(a.at)}</span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
})
