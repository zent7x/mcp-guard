package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ── types ─────────────────────────────────────────────────────────────────────

type SCFinding struct {
	Package  string
	Version  string
	Severity string // high | medium | low
	Category string // lifecycle-script | eval-usage | typosquat | integrity
	Detail   string
	File     string
}

// ── suspicious patterns ───────────────────────────────────────────────────────

type scPattern struct {
	re   *regexp.Regexp
	desc string
	sev  string
}

var lifecyclePatterns = []scPattern{
	{regexp.MustCompile(`\bcurl\b[^|]+\|\s*(ba)?sh`), "downloads and pipes to shell", "high"},
	{regexp.MustCompile(`\bwget\b[^|]+\|\s*(ba)?sh`), "downloads and pipes to shell", "high"},
	{regexp.MustCompile(`base64\s+(--decode|-d)`), "base64 decode in install script", "high"},
	{regexp.MustCompile(`\beval\b\s*\(`), "eval() in install script", "high"},
	{regexp.MustCompile(`new\s+Function\s*\(`), "Function constructor in install script", "high"},
	{regexp.MustCompile(`process\.env\.(AWS_SECRET|AWS_ACCESS|GITHUB_TOKEN|NPM_TOKEN|CI_TOKEN|SECRET|PASSWORD)`), "reads sensitive env vars", "high"},
	{regexp.MustCompile(`require\(['"]child_process['"]\)`), "child_process in install script", "medium"},
	{regexp.MustCompile(`\bexec\s*\(`), "exec() call in install script", "medium"},
	{regexp.MustCompile(`\bspawn\s*\(`), "spawn() call in install script", "medium"},
	{regexp.MustCompile(`https?://[^\s]+`), "network request in install script", "medium"},
}

var jsSourcePatterns = []scPattern{
	{regexp.MustCompile(`\beval\s*\(\s*(?:Buffer|atob|require|process|global)`), "eval of runtime/buffer data", "high"},
	{regexp.MustCompile(`new\s+Function\s*\([^)]{0,200}\bprocess\b`), "Function constructor using process", "high"},
	{regexp.MustCompile(`\bprocess\.env\b.{0,80}(?:TOKEN|SECRET|PASSWORD|KEY|AWS)`), "process.env secret access", "medium"},
	{regexp.MustCompile(`require\(['"]fs['"]\).{0,40}require\(['"]child_process['"]\)`), "fs + child_process combo", "medium"},
}

// typosquat targets — edit distance 1-2 from these names
var popularPackages = []string{
	"lodash", "react", "express", "axios", "moment", "chalk", "commander",
	"webpack", "typescript", "jest", "mocha", "prettier", "dotenv", "uuid",
	"cors", "mongoose", "sequelize", "redis", "socket.io", "next", "vue",
	"angular", "svelte", "rollup", "vite", "nodemon", "pm2", "passport",
	"jsonwebtoken", "bcryptjs", "multer", "sharp", "cheerio", "puppeteer",
	"playwright", "cypress", "sinon", "chai", "supertest", "nock",
	"cross-env", "rimraf", "mkdirp", "glob", "minimatch", "semver",
	"debug", "ms", "yargs", "minimist", "inquirer", "ora", "boxen",
}

// ── package-lock parsing ──────────────────────────────────────────────────────

type lockfilePackage struct {
	Version   string            `json:"version"`
	Integrity string            `json:"integrity"`
	Scripts   map[string]string `json:"scripts"`
	Dev       bool              `json:"dev"`
}

type packageLockV3 struct {
	LockfileVersion int                        `json:"lockfileVersion"`
	Packages        map[string]lockfilePackage `json:"packages"`
}

// ── entry point ───────────────────────────────────────────────────────────────

func supplyChainAudit(projectPath string) ([]SCFinding, error) {
	lockPath := filepath.Join(projectPath, "package-lock.json")
	lockData, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("package-lock.json not found in %s — run `npm install` first", projectPath)
	}

	var lock packageLockV3
	if err := json.Unmarshal(lockData, &lock); err != nil {
		return nil, fmt.Errorf("failed to parse package-lock.json: %w", err)
	}

	nodeModules := filepath.Join(projectPath, "node_modules")
	if _, err := os.Stat(nodeModules); os.IsNotExist(err) {
		return nil, fmt.Errorf("node_modules not found — run `npm install` first")
	}

	var findings []SCFinding

	// Walk top-level installed packages
	topLevel, err := os.ReadDir(nodeModules)
	if err != nil {
		return nil, err
	}

	for _, entry := range topLevel {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()

		if strings.HasPrefix(name, "@") {
			// Scoped package — descend one more level
			scopePath := filepath.Join(nodeModules, name)
			subs, _ := os.ReadDir(scopePath)
			for _, sub := range subs {
				if !sub.IsDir() {
					continue
				}
				fullName := name + "/" + sub.Name()
				fs := auditPackage(fullName, filepath.Join(scopePath, sub.Name()), &lock)
				findings = append(findings, fs...)
			}
			continue
		}

		fs := auditPackage(name, filepath.Join(nodeModules, name), &lock)
		findings = append(findings, fs...)
	}

	return findings, nil
}

func auditPackage(name, pkgPath string, lock *packageLockV3) []SCFinding {
	var findings []SCFinding

	// Read installed package.json
	pkgJSONPath := filepath.Join(pkgPath, "package.json")
	raw, err := os.ReadFile(pkgJSONPath)
	if err != nil {
		return nil
	}

	var pkgJSON struct {
		Name    string            `json:"name"`
		Version string            `json:"version"`
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(raw, &pkgJSON); err != nil {
		return nil
	}

	version := pkgJSON.Version

	// 1. Lifecycle script analysis
	danger := []string{"preinstall", "install", "postinstall", "prepare", "prepack", "postpack"}
	for _, hook := range danger {
		script, ok := pkgJSON.Scripts[hook]
		if !ok {
			continue
		}
		for _, p := range lifecyclePatterns {
			if p.re.MatchString(script) {
				findings = append(findings, SCFinding{
					Package:  name,
					Version:  version,
					Severity: p.sev,
					Category: "lifecycle-script",
					Detail:   fmt.Sprintf("[%s] %s: %s", hook, p.desc, truncateSC(script, 100)),
					File:     pkgJSONPath,
				})
			}
		}
	}

	// 2. Typosquat check
	if similar := typosquatCheck(name); similar != "" {
		findings = append(findings, SCFinding{
			Package:  name,
			Version:  version,
			Severity: "medium",
			Category: "typosquat",
			Detail:   fmt.Sprintf("name is edit-distance 1 from popular package %q", similar),
			File:     pkgJSONPath,
		})
	}

	// 3. Scan JS source for dangerous patterns (index.js, main file only to keep it fast)
	mainFiles := []string{"index.js", "index.cjs", "index.mjs", "lib/index.js", "src/index.js"}
	for _, rel := range mainFiles {
		jsPath := filepath.Join(pkgPath, rel)
		fs := scanJSFile(jsPath, name, version)
		findings = append(findings, fs...)
		if len(fs) > 0 {
			break // one file per package to avoid noise
		}
	}

	return findings
}

func scanJSFile(path, pkg, version string) []SCFinding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// Skip minified files over 500KB — pattern matching on minified blobs produces false positives
	if len(data) > 512*1024 && !strings.Contains(string(data[:256]), "\n") {
		return nil
	}

	content := string(data)
	var findings []SCFinding

	for _, p := range jsSourcePatterns {
		if p.re.MatchString(content) {
			match := p.re.FindString(content)
			findings = append(findings, SCFinding{
				Package:  pkg,
				Version:  version,
				Severity: p.sev,
				Category: "eval-usage",
				Detail:   fmt.Sprintf("%s: %s", p.desc, truncateSC(match, 80)),
				File:     path,
			})
		}
	}
	return findings
}

// ── typosquat detection ───────────────────────────────────────────────────────

// Levenshtein distance — O(mn), fine for short package names
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	row := make([]int, lb+1)
	for j := range row {
		row[j] = j
	}

	for i := 1; i <= la; i++ {
		prev := row[0]
		row[0] = i
		for j := 1; j <= lb; j++ {
			tmp := row[j]
			if a[i-1] == b[j-1] {
				row[j] = prev
			} else {
				m := prev
				if row[j-1] < m {
					m = row[j-1]
				}
				if row[j] < m {
					m = row[j]
				}
				row[j] = m + 1
			}
			prev = tmp
		}
	}
	return row[lb]
}

func typosquatCheck(name string) string {
	// Strip scope — @org/lodaash → lodaash
	bare := name
	if idx := strings.LastIndex(name, "/"); idx != -1 {
		bare = name[idx+1:]
	}

	for _, popular := range popularPackages {
		if bare == popular {
			return "" // exact match, not a typosquat
		}
		if levenshtein(bare, popular) == 1 {
			return popular
		}
	}
	return ""
}

// ── helpers ───────────────────────────────────────────────────────────────────

func truncateSC(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
