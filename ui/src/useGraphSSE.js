import { useEffect, useRef, useState } from 'react'

const API = import.meta.env.VITE_API_URL ?? ''
const MAX_ALERTS = 500

/**
 * useGraphSSE subscribes to /api/graph/events and maintains a live
 * in-memory graph state.
 *
 * Incoming SSE diffs are accumulated in a buffer and flushed to React
 * state once per animation frame, preventing render storms under high
 * event throughput.
 *
 * Returns { nodes, edges, alerts, status }
 *   status: 'connecting' | 'connected' | 'error'
 */
export function useGraphSSE() {
  const [nodes, setNodes]   = useState({})   // id → node
  const [edges, setEdges]   = useState({})   // id → edge
  const [alerts, setAlerts] = useState([])   // ordered list
  const [status, setStatus] = useState('connecting')

  const esRef = useRef(null)

  useEffect(() => {
    let es

    // Diff accumulator — merged across many SSE events, flushed once per rAF.
    const buf = { nodes: [], updatedNodes: [], removedNodeIds: [], edges: [], removedEdgeIds: [], alerts: [] }
    let rafId = null

    function flushBuffer() {
      rafId = null

      const hasNodes = buf.nodes.length || buf.updatedNodes.length || buf.removedNodeIds.length
      const hasEdges = buf.edges.length || buf.removedEdgeIds.length
      const hasAlerts = buf.alerts.length

      if (hasNodes) {
        const addedNodes     = buf.nodes.splice(0)
        const updatedNodes   = buf.updatedNodes.splice(0)
        const removedNodeIds = buf.removedNodeIds.splice(0)
        setNodes(prev => {
          const next = { ...prev }
          for (const n of addedNodes)     next[n.id] = n
          for (const n of updatedNodes)   next[n.id] = n
          for (const id of removedNodeIds) delete next[id]
          return next
        })
      }

      if (hasEdges) {
        const addedEdges     = buf.edges.splice(0)
        const removedEdgeIds = buf.removedEdgeIds.splice(0)
        setEdges(prev => {
          const next = { ...prev }
          for (const e of addedEdges)      next[e.id] = e
          for (const id of removedEdgeIds) delete next[id]
          return next
        })
      }

      if (hasAlerts) {
        const newAlerts = buf.alerts.splice(0)
        setAlerts(prev => [...newAlerts, ...prev].slice(0, MAX_ALERTS))
      }
    }

    function scheduleMerge() {
      if (rafId === null) {
        rafId = requestAnimationFrame(flushBuffer)
      }
    }

    function drainBuffer() {
      if (rafId !== null) { cancelAnimationFrame(rafId); rafId = null }
      buf.nodes.length = 0
      buf.updatedNodes.length = 0
      buf.removedNodeIds.length = 0
      buf.edges.length = 0
      buf.removedEdgeIds.length = 0
      buf.alerts.length = 0
    }

    function connect() {
      drainBuffer()
      es = new EventSource(`${API}/api/graph/events`)
      esRef.current = es

      es.addEventListener('init', (e) => {
        const snap = JSON.parse(e.data)
        const nm = {}
        const em = {}
        ;(snap.nodes ?? []).forEach(n => { nm[n.id] = n })
        ;(snap.edges ?? []).forEach(e => { em[e.id] = e })
        setNodes(nm)
        setEdges(em)
        setAlerts((snap.alerts ?? []).slice(0, MAX_ALERTS))
        setStatus('connected')
      })

      es.addEventListener('diff', (e) => {
        const diff = JSON.parse(e.data)

        if (diff.added_nodes)     buf.nodes.push(...diff.added_nodes)
        if (diff.updated_nodes)   buf.updatedNodes.push(...diff.updated_nodes)
        if (diff.removed_node_ids) buf.removedNodeIds.push(...diff.removed_node_ids)
        if (diff.added_edges)     buf.edges.push(...diff.added_edges)
        if (diff.removed_edge_ids) buf.removedEdgeIds.push(...diff.removed_edge_ids)
        if (diff.alerts)          buf.alerts.push(...diff.alerts)

        scheduleMerge()
      })

      es.onerror = () => {
        setStatus('error')
        es.close()
        setTimeout(connect, 3000)
      }
    }

    connect()
    return () => {
      if (rafId !== null) cancelAnimationFrame(rafId)
      if (esRef.current) esRef.current.close()
    }
  }, [])

  return { nodes, edges, alerts, status }
}
