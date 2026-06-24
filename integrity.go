package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// ── types ─────────────────────────────────────────────────────────────────────

type IntegrityEntry struct {
	Path    string      `json:"path"`
	Hash    string      `json:"hash"`
	Size    int64       `json:"size"`
	Mode    os.FileMode `json:"mode"`
	ModTime time.Time   `json:"mod_time"`
}

type IntegrityBaseline struct {
	CreatedAt time.Time                 `json:"created_at"`
	Host      string                    `json:"host"`
	Files     map[string]IntegrityEntry `json:"files"`
}

type IntegrityResult struct {
	Path    string
	Status  string // modified | added | removed | permission_changed
	Old     *IntegrityEntry
	Current *IntegrityEntry
}

// ── critical paths ────────────────────────────────────────────────────────────

func criticalPaths() []string {
	u, _ := user.Current()
	home := u.HomeDir

	paths := []string{
		// SSH
		filepath.Join(home, ".ssh", "authorized_keys"),
		filepath.Join(home, ".ssh", "config"),
		filepath.Join(home, ".ssh", "known_hosts"),
		// Shell profiles
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".zprofile"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".profile"),
		// Network config
		"/etc/hosts",
		"/etc/resolv.conf",
		// Privilege escalation
		"/etc/sudoers",
		"/etc/sudoers.d",
		// Cron
		"/etc/crontab",
		"/etc/cron.d",
	}

	switch runtime.GOOS {
	case "darwin":
		paths = append(paths,
			filepath.Join(home, "Library", "LaunchAgents"),
			"/Library/LaunchAgents",
			"/Library/LaunchDaemons",
			"/private/etc/hosts",
			"/private/etc/sudoers",
		)
	case "linux":
		paths = append(paths,
			"/etc/passwd",
			"/etc/shadow",
			"/etc/group",
			"/etc/ssh/sshd_config",
			"/etc/rc.local",
		)
	}

	return paths
}

// expandPaths resolves directories to their immediate children (one level).
func expandPaths(declared []string) []string {
	var out []string
	seen := map[string]bool{}

	for _, p := range declared {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			if !seen[p] {
				out = append(out, p)
				seen[p] = true
			}
			continue
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			child := filepath.Join(p, e.Name())
			if !seen[child] {
				out = append(out, child)
				seen[child] = true
			}
		}
	}
	return out
}

// ── hashing ───────────────────────────────────────────────────────────────────

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ── scan ──────────────────────────────────────────────────────────────────────

type scanResult struct {
	entries  map[string]IntegrityEntry
	warnings []string
}

func scanIntegrityFiles(extra []string) (*scanResult, error) {
	allPaths := append(criticalPaths(), extra...)
	files := expandPaths(allPaths)

	entries := make(map[string]IntegrityEntry)
	var warnings []string

	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}

		hash, err := sha256File(path)
		if err != nil {
			continue
		}

		entries[path] = IntegrityEntry{
			Path:    path,
			Hash:    hash,
			Size:    info.Size(),
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
		}

		mode := info.Mode()

		// World-writable is dangerous on any critical file
		if mode&0002 != 0 {
			warnings = append(warnings, fmt.Sprintf("[WORLD-WRITABLE] %s  (%s)", path, mode))
		}
		// SUID/SGID on non-system files is suspicious
		if mode&os.ModeSetuid != 0 {
			warnings = append(warnings, fmt.Sprintf("[SUID] %s", path))
		}
		if mode&os.ModeSetgid != 0 {
			warnings = append(warnings, fmt.Sprintf("[SGID] %s", path))
		}
		// SSH private keys readable by group or others
		if strings.Contains(path, ".ssh") && strings.Contains(path, "id_") && mode&0077 != 0 {
			warnings = append(warnings, fmt.Sprintf("[SSH KEY TOO OPEN] %s  (%s) — should be 0600", path, mode))
		}
		// SSH authorized_keys writable by group
		if strings.HasSuffix(path, "authorized_keys") && mode&0022 != 0 {
			warnings = append(warnings, fmt.Sprintf("[authorized_keys writable by group/others] %s  (%s)", path, mode))
		}
	}

	return &scanResult{entries: entries, warnings: warnings}, nil
}

// ── baseline persistence ──────────────────────────────────────────────────────

func defaultBaselinePath() string {
	u, _ := user.Current()
	return filepath.Join(u.HomeDir, ".mcp-guard-baseline.json")
}

func saveIntegrityBaseline(entries map[string]IntegrityEntry, path string) error {
	host, _ := os.Hostname()
	b := IntegrityBaseline{
		CreatedAt: time.Now(),
		Host:      host,
		Files:     entries,
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func loadIntegrityBaseline(path string) (*IntegrityBaseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b IntegrityBaseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// ── diff ──────────────────────────────────────────────────────────────────────

func diffIntegrity(current map[string]IntegrityEntry, baseline *IntegrityBaseline) []IntegrityResult {
	var results []IntegrityResult

	for path, curr := range current {
		old, exists := baseline.Files[path]
		if !exists {
			c := curr
			results = append(results, IntegrityResult{Path: path, Status: "added", Current: &c})
			continue
		}
		if curr.Hash != old.Hash {
			o, c := old, curr
			results = append(results, IntegrityResult{Path: path, Status: "modified", Old: &o, Current: &c})
		} else if curr.Mode != old.Mode {
			o, c := old, curr
			results = append(results, IntegrityResult{Path: path, Status: "permission_changed", Old: &o, Current: &c})
		}
	}

	for path, old := range baseline.Files {
		if _, exists := current[path]; !exists {
			o := old
			results = append(results, IntegrityResult{Path: path, Status: "removed", Old: &o})
		}
	}

	// Sort: modified first (highest signal), then added/removed, then permission
	order := map[string]int{"modified": 0, "added": 1, "removed": 2, "permission_changed": 3}
	sort.Slice(results, func(i, j int) bool {
		return order[results[i].Status] < order[results[j].Status]
	})

	return results
}
