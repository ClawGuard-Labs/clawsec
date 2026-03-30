import React, { useMemo, useCallback } from 'react'

// ── Session builder ───────────────────────────────────────────────────────────
// Groups flat node/alert maps into per-session summary objects.

function buildSessions(nodes, alerts) {
  const map = {}

  for (const node of Object.values(nodes)) {
    const sid = node.session_id
    if (!sid) continue

    if (!map[sid]) {
      map[sid] = {
        id: sid,
        processes: [],
        files: [],
        networks: [],
        maxRiskScore: 0,
        isTainted: false,
        hasAlerts: false,
        tags: [],
        _tagSet: new Set(),
        firstSeen: node.first_seen,
      }
    }
    const s = map[sid]

    if (node.type === 'process')      s.processes.push(node)
    else if (node.type === 'file')    s.files.push(node)
    else if (node.type === 'network') s.networks.push(node)

    if (node.risk_score > s.maxRiskScore) s.maxRiskScore = node.risk_score
    if (node.is_tainted) s.isTainted = true
    if (new Date(node.first_seen) < new Date(s.firstSeen)) s.firstSeen = node.first_seen

    for (const tag of node.tags ?? []) {
      if (!s._tagSet.has(tag)) { s._tagSet.add(tag); s.tags.push(tag) }
    }
  }

  // Propagate alert risk scores and mark sessions
  for (const alert of alerts) {
    const s = alert.session_id ? map[alert.session_id] : null
    if (!s) continue
    s.hasAlerts = true
    if ((alert.risk_score ?? 0) > s.maxRiskScore) s.maxRiskScore = alert.risk_score
  }

  return Object.values(map)
    .map(s => {
      // Root process = the one whose ppid is not a pid within the same session
      const sessionPids = new Set(s.processes.map(p => p.meta?.pid))
      s.rootProc = s.processes.find(p => !sessionPids.has(p.meta?.ppid)) ?? s.processes[0]
      delete s._tagSet
      return s
    })
    .sort((a, b) => {
      const d = b.maxRiskScore - a.maxRiskScore
      return d !== 0 ? d : new Date(a.firstSeen) - new Date(b.firstSeen)
    })
}

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

export const SessionGrid = React.memo(function SessionGrid({ nodes, alerts, highlightedSessionId, onSessionSelect }) {
  const sessions = useMemo(
    () => buildSessions(nodes, alerts),
    [nodes, alerts]
  )

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
