import React, { useCallback } from 'react'

// ── Risk helpers ──────────────────────────────────────────────────────────────

function riskClass(score) {
  if (score >= 70) return 'risk-high'
  if (score >= 40) return 'risk-med'
  if (score > 0)   return 'risk-low'
  return ''
}

function riskColor(score) {
  if (score >= 70) return 'var(--red)'
  if (score >= 40) return 'var(--yellow)'
  if (score > 0)   return 'var(--green)'
  return 'var(--text-dim)'
}

// ── Mini SVG graph thumbnail ──────────────────────────────────────────────────
// Renders a small node diagram: network ◆ → process ● → … → file ▬

function MiniGraph({ session }) {
  const nets  = Math.min(session.networks.length, 2)
  const procs = Math.min(session.processes.length, 5)
  const files = Math.min(session.files.length, 2)

  const items = []
  const y = 22
  let x = 14

  for (let i = 0; i < nets; i++)  { items.push({ kind: 'net',  x }); x += 30 }
  for (let i = 0; i < procs; i++) { items.push({ kind: 'proc', x, tainted: session.processes[i]?.is_tainted }); x += 30 }
  for (let i = 0; i < files; i++) { items.push({ kind: 'file', x }); x += 30 }

  const svgW = Math.max(x + 6, 60)
  const edgeColor = session.isTainted ? '#882020' : '#30363d'

  return (
    <svg
      width="100%" height="44"
      viewBox={`0 0 ${svgW} 44`}
      preserveAspectRatio="xMidYMid meet"
      style={{ display: 'block' }}
    >
      {items.slice(0, -1).map((_, i) => (
        <line key={`e${i}`}
          x1={items[i].x + 10} y1={y}
          x2={items[i + 1].x - 10} y2={y}
          stroke={edgeColor} strokeWidth="1.2"
        />
      ))}
      {items.map((item, i) => {
        if (item.kind === 'proc') return (
          <circle key={i} cx={item.x} cy={y} r="9"
            fill={item.tainted ? '#2a0808' : '#0d2040'}
            stroke={item.tainted ? '#e05252' : '#58a6ff'}
            strokeWidth="1.5"
          />
        )
        if (item.kind === 'file') return (
          <rect key={i} x={item.x - 10} y={y - 6} width="20" height="12" rx="1"
            fill="#1a1f00" stroke="#b8953a" strokeWidth="1.5"
          />
        )
        if (item.kind === 'net') return (
          <polygon key={i}
            points={`${item.x},${y - 9} ${item.x + 9},${y} ${item.x},${y + 9} ${item.x - 9},${y}`}
            fill="#220f00" stroke="#f0883e" strokeWidth="1.5"
          />
        )
        return null
      })}
    </svg>
  )
}

// ── SessionCard ───────────────────────────────────────────────────────────────

const SessionCard = React.memo(function SessionCard({ session, isHighlighted, onSelect }) {
  const cls = [
    'session-card',
    session.isTainted  ? 'sc-tainted' : '',
    session.hasAlerts  ? 'sc-alerted' : '',
    isHighlighted      ? 'sc-highlighted' : '',
  ].filter(Boolean).join(' ')

  const handleClick = useCallback(() => onSelect(session.id), [onSelect, session.id])

  return (
    <div className={cls} onClick={handleClick}>
      <div className="sc-header">
        <span className="sc-session-id">{session.id}</span>
        {session.maxRiskScore > 0 && (
          <span className={`sc-risk-badge ${riskClass(session.maxRiskScore)}`}>
            score {session.maxRiskScore}
          </span>
        )}
      </div>

      <div className="sc-root-name" style={{ color: riskColor(session.maxRiskScore) }}>
        {session.rootProc?.label ?? session.id}
      </div>

      <MiniGraph session={session} />

      <div className="sc-chips">
        {session.processes.slice(0, 5).map(p => (
          <span
            key={p.id}
            className={`sc-chip${p.is_tainted ? ' sc-chip-tainted' : ''}`}
          >
            {p.label}{p.meta?.pid ? ` (${p.meta.pid})` : ''}
          </span>
        ))}
        {session.processes.length > 5 && (
          <span className="sc-chip sc-chip-more">+{session.processes.length - 5} more</span>
        )}
      </div>

      {session.tags.length > 0 && (
        <div className="sc-tags">
          {session.tags.slice(0, 3).map(t => (
            <span key={t} className="sc-tag">{t}</span>
          ))}
          {session.tags.length > 3 && (
            <span className="sc-tag sc-tag-more">+{session.tags.length - 3}</span>
          )}
        </div>
      )}

      <div className="sc-footer">
        <span className="sc-counts">
          {session.processes.length} proc
          {session.files.length > 0    ? ` · ${session.files.length} file`   : ''}
          {session.networks.length > 0 ? ` · ${session.networks.length} net` : ''}
        </span>
        <span className="sc-drill-hint">explore →</span>
      </div>

      <div className="sc-hover-overlay">Click to explore →</div>
    </div>
  )
})

// ── SessionGrid ───────────────────────────────────────────────────────────────

export const SessionGrid = React.memo(function SessionGrid({ sessions, highlightedSessionId, onSessionSelect }) {
  return (
    <div className="session-grid-area">
      <div className="session-grid-toolbar">
        <span className="sg-count">
          {sessions.length} session{sessions.length !== 1 ? 's' : ''}
        </span>
        <span className="sg-hint">Click a card to explore its process tree</span>
      </div>

      {sessions.length === 0 ? (
        <div className="session-grid-empty">
          <div className="empty-state">
            No sessions yet.<br />Waiting for tainted or alerted activity…
          </div>
        </div>
      ) : (
        <div className="session-grid-scroll">
          <div className="session-grid">
            {sessions.map(sess => (
              <SessionCard
                key={sess.id}
                session={sess}
                isHighlighted={sess.id === highlightedSessionId}
                onSelect={onSessionSelect}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  )
})
