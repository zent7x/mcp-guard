package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"time"
)

type CVEFinding struct {
	Package  string
	Version  string
	Severity string
	ID       string
	Summary  string
	URL      string
}

type osvQuery struct {
	Version string     `json:"version"`
	Package osvPackage `json:"package"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Summary  string `json:"summary"`
			Database struct {
				Severity string `json:"severity"`
			} `json:"database_specific"`
		} `json:"vulns"`
	} `json:"results"`
}

var semverClean = regexp.MustCompile(`^[\^~>=<v]`)

func checkCVEs(pkgPath string) ([]CVEFinding, error) {
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", pkgPath, err)
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("invalid package.json: %w", err)
	}

	all := make(map[string]string)
	for k, v := range pkg.Dependencies {
		all[k] = v
	}
	for k, v := range pkg.DevDependencies {
		all[k] = v
	}

	if len(all) == 0 {
		return nil, nil
	}

	// Build queries
	queries := make([]osvQuery, 0, len(all))
	names := make([]string, 0, len(all))
	versions := make([]string, 0, len(all))

	for name, ver := range all {
		clean := semverClean.ReplaceAllString(ver, "")
		queries = append(queries, osvQuery{
			Version: clean,
			Package: osvPackage{Name: name, Ecosystem: "npm"},
		})
		names = append(names, name)
		versions = append(versions, clean)
	}

	// OSV batch API
	body, _ := json.Marshal(map[string]interface{}{"queries": queries})
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post("https://api.osv.dev/v1/querybatch", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("OSV API error: %w", err)
	}
	defer resp.Body.Close()

	var osvResp osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("OSV response parse error: %w", err)
	}

	var findings []CVEFinding
	for i, result := range osvResp.Results {
		if i >= len(names) {
			break
		}
		for _, vuln := range result.Vulns {
			sev := vuln.Database.Severity
			if sev == "" {
				sev = "UNKNOWN"
			}
			findings = append(findings, CVEFinding{
				Package:  names[i],
				Version:  versions[i],
				Severity: sev,
				ID:       vuln.ID,
				Summary:  vuln.Summary,
				URL:      "https://osv.dev/vulnerability/" + vuln.ID,
			})
		}
	}

	return findings, nil
}
