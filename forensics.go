package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ── types ─────────────────────────────────────────────────────────────────────

type PersistenceEntry struct {
	Type      string
	Name      string
	Path      string
	Command   string
	RunAtLoad bool
	Modified  time.Time
	Risk      string // low | medium | high
	Reason    string
}

// ── entry point ───────────────────────────────────────────────────────────────

func persistenceScan() ([]PersistenceEntry, error) {
	switch runtime.GOOS {
	case "darwin":
		return scanDarwinPersistence()
	case "linux":
		return scanLinuxPersistence()
	default:
		return nil, fmt.Errorf("persistence_scan not supported on %s", runtime.GOOS)
	}
}

// ── macOS ─────────────────────────────────────────────────────────────────────

func scanDarwinPersistence() ([]PersistenceEntry, error) {
	var entries []PersistenceEntry

	u, err := user.Current()
	if err != nil {
		return nil, err
	}

	launchDirs := []struct {
		path  string
		ptype string
		// skip Apple-signed system daemons by default to reduce noise
		skipSystem bool
	}{
		{filepath.Join(u.HomeDir, "Library/LaunchAgents"), "LaunchAgent/user", false},
		{"/Library/LaunchAgents", "LaunchAgent/system", false},
		{"/Library/LaunchDaemons", "LaunchDaemon/system", false},
		{"/System/Library/LaunchAgents", "LaunchAgent/Apple", true},
		{"/System/Library/LaunchDaemons", "LaunchDaemon/Apple", true},
	}

	for _, d := range launchDirs {
		plists, _ := filepath.Glob(filepath.Join(d.path, "*.plist"))
		for _, plist := range plists {
			e, err := parseDarwinPlist(plist, d.ptype)
			if err != nil {
				continue
			}
			// Skip low-noise Apple items unless they look suspicious
			if d.skipSystem && e.Risk == "low" {
				continue
			}
			entries = append(entries, e)
		}
	}

	// Crontab
	cron, _ := parseCrontabEntries()
	entries = append(entries, cron...)

	// Shell profiles — look for sourced scripts and inline downloads
	profiles := []string{
		filepath.Join(u.HomeDir, ".zshrc"),
		filepath.Join(u.HomeDir, ".zprofile"),
		filepath.Join(u.HomeDir, ".bashrc"),
		filepath.Join(u.HomeDir, ".bash_profile"),
		filepath.Join(u.HomeDir, ".profile"),
	}
	for _, p := range profiles {
		pe, _ := scanShellProfile(p)
		entries = append(entries, pe...)
	}

	return entries, nil
}

func parseDarwinPlist(path, ptype string) (PersistenceEntry, error) {
	// plutil -convert json writes JSON to stdout, preserving original file
	out, err := exec.Command("plutil", "-convert", "json", "-o", "-", path).Output()
	if err != nil {
		return PersistenceEntry{}, err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(out, &data); err != nil {
		return PersistenceEntry{}, err
	}

	e := PersistenceEntry{Type: ptype, Path: path}

	if label, ok := data["Label"].(string); ok {
		e.Name = label
	}

	// Program or ProgramArguments
	if prog, ok := data["Program"].(string); ok {
		e.Command = prog
	} else if args, ok := data["ProgramArguments"].([]interface{}); ok {
		var parts []string
		for _, a := range args {
			if s, ok := a.(string); ok {
				parts = append(parts, s)
			}
		}
		e.Command = strings.Join(parts, " ")
	}

	if ral, ok := data["RunAtLoad"].(bool); ok {
		e.RunAtLoad = ral
	}

	if info, err := os.Stat(path); err == nil {
		e.Modified = info.ModTime()
	}

	e.Risk, e.Reason = assessPlistRisk(e)
	return e, nil
}

func assessPlistRisk(e PersistenceEntry) (string, string) {
	cmd := strings.ToLower(e.Command)

	// Definite red flags
	if (strings.Contains(cmd, "curl") || strings.Contains(cmd, "wget")) &&
		(strings.Contains(cmd, "sh") || strings.Contains(cmd, "bash")) {
		return "high", "downloads and executes remote content"
	}
	if strings.Contains(cmd, "base64") && (strings.Contains(cmd, "sh") || strings.Contains(cmd, "eval")) {
		return "high", "base64-encoded payload piped to shell"
	}
	if strings.Contains(cmd, "/tmp/") || strings.Contains(cmd, "/var/tmp/") {
		return "high", "executes binary from temp directory"
	}
	if strings.Contains(cmd, "python") && strings.Contains(cmd, " -c ") {
		return "medium", "inline python code execution"
	}
	if strings.Contains(cmd, "bash -c") || strings.Contains(cmd, "sh -c") {
		return "medium", "inline shell command"
	}

	// Apple-signed paths are noise
	if strings.HasPrefix(e.Path, "/System/Library/") {
		return "low", "Apple system component"
	}

	// Anything modified in the last 7 days outside of Apple dirs is notable
	if time.Since(e.Modified) < 7*24*time.Hour && !strings.HasPrefix(e.Path, "/System/") {
		return "medium", fmt.Sprintf("modified %s ago", formatDuration(time.Since(e.Modified)))
	}

	return "low", ""
}

// ── Linux ─────────────────────────────────────────────────────────────────────

func scanLinuxPersistence() ([]PersistenceEntry, error) {
	var entries []PersistenceEntry

	u, _ := user.Current()

	// systemd user units
	userUnitDir := filepath.Join(u.HomeDir, ".config/systemd/user")
	systemdEntries, _ := scanSystemdUnits(userUnitDir, "systemd/user")
	entries = append(entries, systemdEntries...)

	// systemd system units (skip standard /lib paths to reduce noise)
	for _, dir := range []string{"/etc/systemd/system"} {
		se, _ := scanSystemdUnits(dir, "systemd/system")
		entries = append(entries, se...)
	}

	cron, _ := parseCrontabEntries()
	entries = append(entries, cron...)

	// /etc/cron.d
	cronD, _ := filepath.Glob("/etc/cron.d/*")
	for _, f := range cronD {
		ce, _ := parseCronFile(f, "cron.d")
		entries = append(entries, ce...)
	}

	// rc.local
	if _, err := os.Stat("/etc/rc.local"); err == nil {
		entries = append(entries, PersistenceEntry{
			Type:   "rc.local",
			Name:   "rc.local",
			Path:   "/etc/rc.local",
			Risk:   "medium",
			Reason: "runs at boot as root",
		})
	}

	// Shell profiles
	for _, p := range []string{
		filepath.Join(u.HomeDir, ".bashrc"),
		filepath.Join(u.HomeDir, ".bash_profile"),
		filepath.Join(u.HomeDir, ".profile"),
		"/etc/profile",
		"/etc/bash.bashrc",
	} {
		pe, _ := scanShellProfile(p)
		entries = append(entries, pe...)
	}

	return entries, nil
}

func scanSystemdUnits(dir, ptype string) ([]PersistenceEntry, error) {
	var entries []PersistenceEntry

	files, err := filepath.Glob(filepath.Join(dir, "*.service"))
	if err != nil || len(files) == 0 {
		return nil, err
	}

	for _, f := range files {
		e := PersistenceEntry{
			Type: ptype,
			Name: filepath.Base(f),
			Path: f,
		}

		if info, err := os.Stat(f); err == nil {
			e.Modified = info.ModTime()
		}

		// Parse ExecStart from .service file
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}

		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "ExecStart=") {
				e.Command = strings.TrimPrefix(line, "ExecStart=")
				break
			}
		}

		e.Risk, e.Reason = assessCommandRisk(e.Command)
		entries = append(entries, e)
	}
	return entries, nil
}

// ── shared ────────────────────────────────────────────────────────────────────

func parseCrontabEntries() ([]PersistenceEntry, error) {
	out, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		return nil, nil
	}
	return parseCronOutput(string(out), "crontab")
}

func parseCronFile(path, ptype string) ([]PersistenceEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCronOutput(string(data), ptype+":"+filepath.Base(path))
}

func parseCronOutput(content, ptype string) ([]PersistenceEntry, error) {
	var entries []PersistenceEntry

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// cron format: min hour dom month dow command
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		cmd := strings.Join(fields[5:], " ")
		schedule := strings.Join(fields[:5], " ")
		risk, reason := assessCommandRisk(cmd)
		entries = append(entries, PersistenceEntry{
			Type:    ptype,
			Name:    schedule,
			Command: cmd,
			Risk:    risk,
			Reason:  reason,
		})
	}
	return entries, nil
}

func scanShellProfile(path string) ([]PersistenceEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []PersistenceEntry
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		risk, reason := assessShellLine(line)
		if risk == "" {
			continue
		}

		entries = append(entries, PersistenceEntry{
			Type:    "shell-profile",
			Name:    fmt.Sprintf("%s:%d", filepath.Base(path), lineNum),
			Path:    path,
			Command: truncatePersistence(line, 120),
			Risk:    risk,
			Reason:  reason,
		})
	}
	return entries, nil
}

func assessShellLine(line string) (string, string) {
	l := strings.ToLower(line)

	if (strings.Contains(l, "curl") || strings.Contains(l, "wget")) &&
		(strings.Contains(l, "| sh") || strings.Contains(l, "| bash") || strings.Contains(l, "|sh") || strings.Contains(l, "|bash")) {
		return "high", "downloads and pipes to shell"
	}
	if strings.Contains(l, "eval") && (strings.Contains(l, "curl") || strings.Contains(l, "base64")) {
		return "high", "eval of downloaded or encoded content"
	}
	if strings.Contains(l, "source") && strings.Contains(l, "/tmp/") {
		return "high", "sources script from temp directory"
	}
	if strings.Contains(l, "export") && strings.Contains(l, "path=") && strings.Contains(l, "/tmp") {
		return "medium", "adds /tmp to PATH"
	}

	return "", ""
}

func assessCommandRisk(cmd string) (string, string) {
	c := strings.ToLower(cmd)

	if (strings.Contains(c, "curl") || strings.Contains(c, "wget")) &&
		(strings.Contains(c, "sh") || strings.Contains(c, "bash") || strings.Contains(c, "exec")) {
		return "high", "downloads and executes remote content"
	}
	if strings.Contains(c, "base64") && strings.Contains(c, "sh") {
		return "high", "base64 payload piped to shell"
	}
	if strings.Contains(c, "/tmp/") {
		return "high", "runs binary from /tmp"
	}
	if strings.Contains(c, "python") && strings.Contains(c, " -c ") {
		return "medium", "inline python execution"
	}
	if strings.Contains(c, "bash -c") || strings.Contains(c, "sh -c") {
		return "medium", "inline shell execution"
	}
	return "low", ""
}

func truncatePersistence(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
