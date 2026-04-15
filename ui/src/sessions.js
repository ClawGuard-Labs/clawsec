// Session builder — groups flat node/alert maps into per-session summary objects.
// Extracted from SessionGrid.jsx so the component file only exports components
// (required for React Fast Refresh).

function pickRootProcess(processes) {
  if (!processes.length) return null
  const sessionPids = new Set(processes.map(p => p.meta?.pid))
  return processes.find(p => !sessionPids.has(p.meta?.ppid)) ?? processes[0]
}

export function buildSessions(nodes, alerts) {
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
      s.rootProc = pickRootProcess(s.processes)
      delete s._tagSet
      return s
    })
    .sort((a, b) => {
      const d = b.maxRiskScore - a.maxRiskScore
      return d !== 0 ? d : new Date(a.firstSeen) - new Date(b.firstSeen)
    })
}
