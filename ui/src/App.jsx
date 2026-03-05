import { useState } from 'react'
import './App.css'
import { useGraphSSE }  from './useGraphSSE'
import { AlertPanel }   from './AlertPanel'
import { GraphView }    from './GraphView'
import { Inspector }    from './Inspector'

export default function App() {
  const { nodes, edges, alerts, status } = useGraphSSE()
  const [selectedNode,  setSelectedNode]  = useState(null)
  const [selectedAlert, setSelectedAlert] = useState(null)

  function handleAlertSelect(alert) {
    setSelectedAlert(alert)
    setSelectedNode(null)
  }

  function handleNodeSelect(nodeData) {
    setSelectedNode(nodeData)
    setSelectedAlert(null)
  }

  return (
    <div className="app">
      <div className="topbar">
        <span className="topbar-title">AI Agent Monitor — Provenance Graph</span>
        <span className="status-pill">
          <span className={`dot ${status}`} />
          {status === 'connected'
            ? `live · ${Object.keys(nodes).length} nodes · ${alerts.length} alerts`
            : status}
        </span>
      </div>

      <div className="main-area">
        <AlertPanel
          alerts={alerts}
          selectedAlert={selectedAlert}
          onSelect={handleAlertSelect}
        />

        <GraphView
          nodes={nodes}
          edges={edges}
          onNodeSelect={handleNodeSelect}
        />

        <Inspector
          node={selectedNode}
          alert={selectedAlert}
        />
      </div>
    </div>
  )
}
