import React from 'react'

function Row({ label, value }) {
  if (value === undefined || value === null || value === '') return null
  return (
    <div className="inspector-section">
      <div className="inspector-label">{label}</div>
      <div className="inspector-value">{String(value)}</div>
    </div>
  )
}

function fmtTime(ts) {
  if (!ts) return ''
  return new Date(ts).toLocaleString()
}

export const Inspector = React.memo(function Inspector({ node, alert }) {
  if (alert && !node) {
    return (
      <div className="inspector-panel">
        <div className="panel-header">Alert Detail</div>
        <div className="inspector-body">
          <div className="inspector-section">
            <div className="inspector-label">Title</div>
            <div className="inspector-value">{alert.title}</div>
          </div>
          <Row label="Severity"  value={alert.severity} />
          <Row label="Session"   value={alert.session_id} />
          <Row label="Time"      value={fmtTime(alert.at)} />
          {alert.detail && (
            <div className="inspector-section">
              <div className="inspector-label">Detail</div>
              <div className="inspector-value" style={{ whiteSpace: 'pre-wrap' }}>{alert.detail}</div>
            </div>
          )}
          {alert.node_ids?.length > 0 && (
            <div className="inspector-section">
              <div className="inspector-label">Linked Nodes</div>
              <div className="tag-list">
                {alert.node_ids.map(id => <span key={id} className="tag">{id}</span>)}
              </div>
            </div>
          )}
        </div>
      </div>
    )
  }

  if (node) {
    const typeIcon = { process: '⬤', file: '▬', network: '◆' }[node.type] ?? '?'
    const typeClass = `node-type-${node.type}`
    return (
      <div className="inspector-panel">
        <div className="panel-header">
          <span className={typeClass}>{typeIcon} </span>
          {node.type?.toUpperCase()}
        </div>
        <div className="inspector-body">
          {node.is_tainted && <div className="inspector-section"><span className="tainted-badge">TAINTED</span></div>}
          <Row label="ID"       value={node.id} />
          <Row label="Label"    value={node.label} />
          {node.meta?.count > 1 && <Row label="Occurrences" value={node.meta.count} />}
          <Row label="Session"  value={node.session_id} />
          <Row label="Risk Score" value={node.risk_score > 0 ? node.risk_score : undefined} />
          <Row label="First Seen" value={fmtTime(node.first_seen)} />
          <Row label="Last Seen"  value={fmtTime(node.last_seen)} />

          {node.meta && Object.keys(node.meta).length > 0 && (
            <div className="inspector-section">
              <div className="inspector-label">Process Info</div>
              {Object.entries(node.meta).map(([k, v]) => (
                <div key={k} style={{ display: 'flex', gap: 6, marginBottom: 3 }}>
                  <span style={{ color: 'var(--text-dim)', minWidth: 80 }}>{k}</span>
                  <span style={{ wordBreak: 'break-all' }}>{String(v)}</span>
                </div>
              ))}
            </div>
          )}

          {node.tags?.length > 0 && (
            <div className="inspector-section">
              <div className="inspector-label">Tags</div>
              <div className="tag-list">
                {node.tags.map(t => <span key={t} className="tag">{t}</span>)}
              </div>
            </div>
          )}
        </div>
      </div>
    )
  }

  return (
    <div className="inspector-panel">
      <div className="panel-header">Inspector</div>
      <div className="inspector-body">
        <div className="empty-state">Click a node or alert to inspect it.</div>
      </div>
    </div>
  )
})
