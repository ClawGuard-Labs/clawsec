//go:build linux

package graphapi

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type AIServiceInfo struct {
	Type     string `json:"type"`              // "process" or "service"
	Name     string `json:"name"`              // process comm or service name
	Category string `json:"category"`          // "llm", "agent", "training", "vector-db", "inference", "ui"
	PID      uint32 `json:"pid,omitempty"`     // for processes
	Port     uint16 `json:"port,omitempty"`    // for services
	Status   string `json:"status"`            // "running", "listening"
	Cmdline  string `json:"cmdline,omitempty"` // full command line (truncated)
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var results []AIServiceInfo
	results = append(results, s.scanAIProcesses()...)
	results = append(results, s.probeAIServicePorts()...)
	writeJSON(w, results)
}

func (s *Server) scanAIProcesses() []AIServiceInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	type commInfo struct {
		comm    string
		pid     uint32
		cmdline string
		count   int
	}
	seen := map[string]*commInfo{}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%s/comm", entry.Name()))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(commBytes))

		if !s.cfg.IsAIProcessComm(comm) {
			continue
		}

		if info, exists := seen[comm]; exists {
			info.count++
			continue
		}

		cmdline := readCmdline(entry.Name())

		seen[comm] = &commInfo{
			comm:    comm,
			pid:     uint32(pid),
			cmdline: cmdline,
			count:   1,
		}
	}

	results := make([]AIServiceInfo, 0, len(seen))
	for _, info := range seen {
		name := info.comm
		if info.count > 1 {
			name = fmt.Sprintf("%s (%d instances)", info.comm, info.count)
		}
		results = append(results, AIServiceInfo{
			Type:     "process",
			Name:     name,
			Category: s.cfg.CategorizeProcess(info.comm),
			PID:      info.pid,
			Status:   "running",
			Cmdline:  info.cmdline,
		})
	}
	return results
}

func (s *Server) probeAIServicePorts() []AIServiceInfo {
	var results []AIServiceInfo
	for port, name := range s.cfg.ServicePorts() {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			continue
		}
		conn.Close()
		results = append(results, AIServiceInfo{
			Type:     "service",
			Name:     name,
			Category: s.cfg.CategorizeService(name),
			Port:     port,
			Status:   "listening",
		})
	}
	return results
}

func readCmdline(pidStr string) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%s/cmdline", pidStr))
	if err != nil || len(data) == 0 {
		return ""
	}
	s := strings.ReplaceAll(string(data), "\x00", " ")
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
