package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type HeaderCheck struct {
	Header   string
	Present  bool
	Value    string
	Required bool
	Note     string
}

type HeadersResult struct {
	URL     string
	Score   int
	Grade   string
	Checks  []HeaderCheck
	Missing []string
}

type headerRule struct {
	header   string
	required bool
	validate func(string) string
	note     string
}

var headerRules = []headerRule{
	{
		header:   "strict-transport-security",
		required: true,
		validate: func(v string) string {
			re := regexp.MustCompile(`max-age=(\d+)`)
			m := re.FindStringSubmatch(v)
			if m == nil {
				return "missing max-age"
			}
			n, _ := strconv.Atoi(m[1])
			if n < 31536000 {
				return fmt.Sprintf("max-age=%d is less than 1 year", n)
			}
			return ""
		},
		note: "Enforces HTTPS for future visits",
	},
	{
		header:   "content-security-policy",
		required: true,
		validate: func(v string) string {
			if strings.Contains(v, "unsafe-eval") {
				return "contains unsafe-eval"
			}
			if !strings.Contains(v, "default-src") {
				return "missing default-src directive"
			}
			return ""
		},
		note: "Controls which resources can be loaded",
	},
	{
		header:   "x-content-type-options",
		required: true,
		validate: func(v string) string {
			if strings.TrimSpace(v) != "nosniff" {
				return "should be 'nosniff'"
			}
			return ""
		},
		note: "Prevents MIME-type sniffing attacks",
	},
	{
		header:   "x-frame-options",
		required: true,
		validate: func(v string) string {
			norm := strings.ToUpper(strings.TrimSpace(v))
			if norm != "DENY" && norm != "SAMEORIGIN" {
				return "should be DENY or SAMEORIGIN"
			}
			return ""
		},
		note: "Prevents clickjacking via iframes",
	},
	{
		header:   "referrer-policy",
		required: true,
		note:     "Controls how much referrer info is sent",
	},
	{
		header:   "permissions-policy",
		required: false,
		note:     "Restricts browser feature access (camera, mic, geolocation)",
	},
	{
		header:   "x-powered-by",
		required: false,
		note:     "Should be absent to avoid leaking stack info",
	},
	{
		header:   "server",
		required: false,
		note:     "Should be absent or generic to avoid version leaks",
	},
}

func auditHeaders(url string) (*HeadersResult, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Head(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var checks []HeaderCheck
	var missing []string
	earned := 0
	possible := 0

	for _, rule := range headerRules {
		val := resp.Header.Get(rule.header)
		present := val != ""
		note := rule.note

		isLeakHeader := rule.header == "x-powered-by" || rule.header == "server"
		pts := 15
		if !rule.required {
			pts = 5
		}

		if isLeakHeader {
			possible += pts
			if !present {
				earned += pts
			} else {
				note = "leaks server info — consider removing"
			}
		} else {
			possible += pts
			if present {
				if rule.validate != nil {
					if warn := rule.validate(val); warn != "" {
						note = "Warning: " + warn
					} else {
						earned += pts
					}
				} else {
					earned += pts
				}
			} else if rule.required {
				missing = append(missing, rule.header)
			}
		}

		checks = append(checks, HeaderCheck{
			Header:   rule.header,
			Present:  present,
			Value:    val,
			Required: rule.required,
			Note:     note,
		})
	}

	score := 0
	if possible > 0 {
		score = (earned * 100) / possible
	}

	return &HeadersResult{
		URL:     resp.Request.URL.String(),
		Score:   score,
		Grade:   scoreGrade(score),
		Checks:  checks,
		Missing: missing,
	}, nil
}

func scoreGrade(score int) string {
	switch {
	case score >= 90:
		return "A+"
	case score >= 80:
		return "A"
	case score >= 70:
		return "B"
	case score >= 60:
		return "C"
	case score >= 50:
		return "D"
	default:
		return "F"
	}
}
