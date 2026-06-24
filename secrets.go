package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type SecretFinding struct {
	File     string
	Line     int
	Type     string
	Match    string
	Severity string
}

type secretPattern struct {
	name     string
	re       *regexp.Regexp
	severity string
}

var patterns = []secretPattern{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "high"},
	{"AWS Secret Key", regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]`), "high"},
	{"GitHub Token", regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`), "high"},
	{"GitHub OAuth", regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`), "high"},
	{"GitHub App Token", regexp.MustCompile(`(ghu|ghs|ghr)_[0-9a-zA-Z]{36}`), "high"},
	{"Anthropic API Key", regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-_]{93}`), "high"},
	{"OpenAI API Key", regexp.MustCompile(`sk-[a-zA-Z0-9]{48}`), "high"},
	{"Stripe Secret Key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`), "high"},
	{"Stripe Publishable Key", regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24}`), "medium"},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}`), "high"},
	{"Slack Webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{9}/[a-zA-Z0-9]{24}`), "high"},
	{"Twilio SID", regexp.MustCompile(`AC[a-f0-9]{32}`), "medium"},
	{"Twilio Token", regexp.MustCompile(`(?i)twilio.{0,20}['\"][a-f0-9]{32}['\"]`), "high"},
	{"SendGrid Key", regexp.MustCompile(`SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}`), "high"},
	{"Private Key Block", regexp.MustCompile(`-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`), "high"},
	{"Generic Private Key", regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`), "high"},
	{"Database URL", regexp.MustCompile(`(postgres|mysql|mongodb|redis|amqp)://[^:]+:[^@]+@[^\s"']+`), "high"},
	{"JWT Secret", regexp.MustCompile(`(?i)(jwt.secret|jwt_secret|jwt-secret)\s*[=:]\s*['\"][^'"]{16,}['\"]`), "high"},
	{"Generic API Key", regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]`), "medium"},
	{"Generic Password", regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'"]{8,}['\"]`), "medium"},
	{"Generic Secret", regexp.MustCompile(`(?i)(secret|token)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]`), "medium"},
}

var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, "dist": true, "build": true,
	".next": true, "vendor": true, "__pycache__": true, ".cache": true,
	"target": true, "out": true, ".turbo": true,
}

var skipExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true,
	".svg": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".pdf": true, ".zip": true, ".tar": true, ".gz": true, ".lock": true,
	".sum": true, ".min.js": true,
}

func scanSecrets(root string) ([]SecretFinding, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("cannot stat %s: %w", root, err)
	}

	var findings []SecretFinding

	if !info.IsDir() {
		findings, err = scanFile(root)
		return findings, err
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if skipExts[ext] {
			return nil
		}

		found, _ := scanFile(path)
		findings = append(findings, found...)
		return nil
	})

	return findings, err
}

func scanFile(path string) ([]SecretFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}

	// Skip binary files
	if strings.Contains(string(data[:min(512, len(data))]), "\x00") {
		return nil, nil
	}

	lines := strings.Split(string(data), "\n")
	var findings []SecretFinding

	for lineNum, line := range lines {
		for _, p := range patterns {
			if match := p.re.FindString(line); match != "" {
				findings = append(findings, SecretFinding{
					File:     path,
					Line:     lineNum + 1,
					Type:     p.name,
					Match:    redact(match),
					Severity: p.severity,
				})
			}
		}
	}

	return findings, nil
}

func redact(s string) string {
	if len(s) <= 10 {
		return "***"
	}
	return s[:6] + "..." + s[len(s)-4:]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
