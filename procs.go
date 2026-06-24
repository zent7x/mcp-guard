package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type ProcInfo struct {
	PID     int
	CPU     float64
	Mem     string
	Command string
}

type ConnInfo struct {
	Local   string
	Remote  string
	State   string
	Process string
}

func procList(filter string) ([]ProcInfo, error) {
	// ps -axo pid,%cpu,rss,comm
	out, err := exec.Command("ps", "-axo", "pid,%cpu,rss,comm").Output()
	if err != nil {
		return nil, fmt.Errorf("ps failed: %w", err)
	}

	var procs []ProcInfo
	lines := bytes.Split(out, []byte("\n"))
	for i, line := range lines {
		if i == 0 {
			continue // header
		}
		fields := strings.Fields(string(line))
		if len(fields) < 4 {
			continue
		}

		cmd := fields[3]
		if filter != "" && !strings.Contains(strings.ToLower(cmd), strings.ToLower(filter)) {
			continue
		}

		pid, _ := strconv.Atoi(fields[0])
		cpu, _ := strconv.ParseFloat(fields[1], 64)
		rssKB, _ := strconv.Atoi(fields[2])
		mem := formatMem(rssKB)

		procs = append(procs, ProcInfo{
			PID:     pid,
			CPU:     cpu,
			Mem:     mem,
			Command: cmd,
		})
	}

	return procs, nil
}

func netConnections() ([]ConnInfo, error) {
	// netstat -an on macOS
	out, err := exec.Command("netstat", "-anp", "tcp").Output()
	if err != nil {
		// try without -p flag (macOS compatibility)
		out, err = exec.Command("netstat", "-an").Output()
		if err != nil {
			return nil, fmt.Errorf("netstat failed: %w", err)
		}
	}

	var conns []ConnInfo
	lines := bytes.Split(out, []byte("\n"))
	for _, line := range lines {
		s := string(line)
		if !strings.HasPrefix(s, "tcp") {
			continue
		}
		fields := strings.Fields(s)
		if len(fields) < 5 {
			continue
		}

		local := fields[3]
		remote := fields[4]
		state := ""
		process := ""

		if len(fields) >= 6 {
			state = fields[5]
		}
		if len(fields) >= 9 {
			process = fields[8]
		}

		if remote == "*.*" || remote == "0.0.0.0:*" || remote == ":::*" {
			remote = "(listening)"
		}

		conns = append(conns, ConnInfo{
			Local:   local,
			Remote:  remote,
			State:   state,
			Process: process,
		})
	}

	return conns, nil
}

func formatMem(kb int) string {
	if kb >= 1024*1024 {
		return fmt.Sprintf("%.1fGB", float64(kb)/1024/1024)
	}
	if kb >= 1024 {
		return fmt.Sprintf("%.1fMB", float64(kb)/1024)
	}
	return fmt.Sprintf("%dKB", kb)
}
