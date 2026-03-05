import { useEffect, useRef, useState } from 'react'

const API = import.meta.env.VITE_API_URL ?? ''

/**
 * useGraphSSE subscribes to /api/graph/events and maintains a live
 * in-memory graph state.
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

    function connect() {
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
        setAlerts(snap.alerts ?? [])
        setStatus('connected')
      })

      es.addEventListener('diff', (e) => {
        const diff = JSON.parse(e.data)

        if (diff.added_nodes?.length || diff.updated_nodes?.length) {
          setNodes(prev => {
            const next = { ...prev }
            ;(diff.added_nodes ?? []).forEach(n => { next[n.id] = n })
            ;(diff.updated_nodes ?? []).forEach(n => { next[n.id] = n })
            return next
          })
        }
        if (diff.added_edges?.length) {
          setEdges(prev => {
            const next = { ...prev }
            diff.added_edges.forEach(e => { next[e.id] = e })
            return next
          })
        }
        if (diff.alerts?.length) {
          setAlerts(prev => [...diff.alerts, ...prev]) // newest first
        }
      })

      es.onerror = () => {
        setStatus('error')
        es.close()
        // Reconnect after 3 s
        setTimeout(connect, 3000)
      }
    }

    connect()
    return () => {
      if (esRef.current) esRef.current.close()
    }
  }, [])

  return { nodes, edges, alerts, status }
}
