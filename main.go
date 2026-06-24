package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("mcp-guard", "0.5.0",
		server.WithToolCapabilities(true),
	)

	// ── port_scan ─────────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("port_scan",
		mcp.WithDescription("TCP port scan a host. Returns open ports with service guesses. Uses 200 concurrent goroutines — fast. Claude cannot do this natively."),
		mcp.WithString("host", mcp.Required(), mcp.Description("Hostname or IP address to scan")),
		mcp.WithNumber("start", mcp.Description("Start port (default 1)")),
		mcp.WithNumber("end", mcp.Description("End port (default 1024)")),
		mcp.WithNumber("timeout_ms", mcp.Description("Per-port timeout in ms (default 500)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		host := req.GetString("host", "")
		start := req.GetInt("start", 1)
		end := req.GetInt("end", 1024)
		timeout := req.GetInt("timeout_ms", 500)

		if host == "" {
			return mcp.NewToolResultError("host is required"), nil
		}
		if start < 1 || end > 65535 || start > end {
			return mcp.NewToolResultError("invalid port range"), nil
		}

		results := portScan(host, start, end, timeout)

		if len(results) == 0 {
			return mcp.NewToolResultText(fmt.Sprintf("No open ports on %s (scanned %d-%d)", host, start, end)), nil
		}

		out := fmt.Sprintf("Open ports on %s (%d-%d scanned)\n\n", host, start, end)
		for _, r := range results {
			out += fmt.Sprintf("  %-6d  %s\n", r.Port, r.Service)
		}
		return mcp.NewToolResultText(out), nil
	})

	// ── ssl_inspect ───────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("ssl_inspect",
		mcp.WithDescription("Inspect the full TLS certificate chain of a host. Returns expiry countdown, issuer chain, SANs, key size, and weak-config warnings."),
		mcp.WithString("host", mcp.Required(), mcp.Description("Hostname (e.g. github.com)")),
		mcp.WithNumber("port", mcp.Description("Port (default 443)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		host := req.GetString("host", "")
		port := req.GetInt("port", 443)

		if host == "" {
			return mcp.NewToolResultError("host is required"), nil
		}

		certs, err := sslInspect(host, port)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("TLS error: %v", err)), nil
		}

		out := fmt.Sprintf("TLS certificate chain: %s:%d\n\n", host, port)
		for i, c := range certs {
			label := "leaf"
			if len(certs) > 1 && i == len(certs)-1 {
				label = "root CA"
			} else if i > 0 {
				label = fmt.Sprintf("intermediate %d", i)
			}
			out += fmt.Sprintf("[%s]\n", label)
			out += fmt.Sprintf("  Subject:   %s\n", c.Subject)
			out += fmt.Sprintf("  Issuer:    %s\n", c.Issuer)
			out += fmt.Sprintf("  Expires:   %s  (%d days left)\n", c.NotAfter.Format("2006-01-02"), c.DaysLeft)
			out += fmt.Sprintf("  Algorithm: %s\n", c.Algorithm)
			if len(c.SANs) > 0 {
				out += fmt.Sprintf("  SANs:      %v\n", c.SANs)
			}
			for _, w := range c.Warnings {
				out += fmt.Sprintf("  WARNING:   %s\n", w)
			}
			out += "\n"
		}
		return mcp.NewToolResultText(out), nil
	})

	// ── dns_enum ──────────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("dns_enum",
		mcp.WithDescription("Enumerate all DNS records for a domain: A, AAAA, MX, NS, TXT, CNAME. Detects missing SPF/DMARC records."),
		mcp.WithString("domain", mcp.Required(), mcp.Description("Domain to enumerate (e.g. example.com)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		domain := req.GetString("domain", "")
		if domain == "" {
			return mcp.NewToolResultError("domain is required"), nil
		}

		records, warnings := dnsEnum(domain)
		if len(records) == 0 {
			return mcp.NewToolResultText(fmt.Sprintf("No DNS records found for %s", domain)), nil
		}

		out := fmt.Sprintf("DNS records for %s\n\n", domain)
		currentType := ""
		for _, r := range records {
			if r.Type != currentType {
				out += fmt.Sprintf("── %s ──\n", r.Type)
				currentType = r.Type
			}
			out += fmt.Sprintf("  %s\n", r.Value)
		}

		if len(warnings) > 0 {
			out += "\nMisconfiguration warnings:\n"
			for _, w := range warnings {
				out += fmt.Sprintf("  ! %s\n", w)
			}
		}

		return mcp.NewToolResultText(out), nil
	})

	// ── proc_list ─────────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("proc_list",
		mcp.WithDescription("List running processes on this machine. Optionally filter by name. Shows PID, CPU%, memory usage, and command."),
		mcp.WithString("filter", mcp.Description("Filter by process name substring (optional)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		filter := req.GetString("filter", "")

		procs, err := procList(filter)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("proc_list error: %v", err)), nil
		}

		if len(procs) == 0 {
			msg := "No processes found"
			if filter != "" {
				msg = fmt.Sprintf("No processes matching %q", filter)
			}
			return mcp.NewToolResultText(msg), nil
		}

		out := fmt.Sprintf("%-8s  %-6s  %-10s  %s\n", "PID", "CPU%", "MEM", "COMMAND")
		out += "─────────────────────────────────────────────────\n"
		for _, p := range procs {
			out += fmt.Sprintf("%-8d  %-6.1f  %-10s  %s\n", p.PID, p.CPU, p.Mem, p.Command)
		}
		return mcp.NewToolResultText(out), nil
	})

	// ── net_connections ───────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("net_connections",
		mcp.WithDescription("List active network connections on this machine (like netstat). Shows local/remote address and connection state."),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		conns, err := netConnections()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("net_connections error: %v", err)), nil
		}

		if len(conns) == 0 {
			return mcp.NewToolResultText("No active connections"), nil
		}

		out := fmt.Sprintf("%-30s  %-30s  %s\n", "LOCAL", "REMOTE", "STATE")
		out += "─────────────────────────────────────────────────────────────────────\n"
		for _, c := range conns {
			out += fmt.Sprintf("%-30s  %-30s  %s\n", c.Local, c.Remote, c.State)
		}
		return mcp.NewToolResultText(out), nil
	})

	// ── scan_secrets ──────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("scan_secrets",
		mcp.WithDescription("Scan a file or directory for hardcoded secrets: AWS keys, GitHub tokens, API keys, private key blocks, DB URLs, and more. 20+ patterns."),
		mcp.WithString("path", mcp.Required(), mcp.Description("Absolute path to a file or directory")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		path := req.GetString("path", "")
		if path == "" {
			return mcp.NewToolResultError("path is required"), nil
		}

		findings, err := scanSecrets(path)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("scan error: %v", err)), nil
		}

		if len(findings) == 0 {
			return mcp.NewToolResultText(fmt.Sprintf("No secrets found in %s", path)), nil
		}

		byFile := map[string][]SecretFinding{}
		high, med := 0, 0
		for _, f := range findings {
			byFile[f.File] = append(byFile[f.File], f)
			if f.Severity == "high" {
				high++
			} else {
				med++
			}
		}

		out := fmt.Sprintf("Found %d secret(s) — %d high, %d medium\n\n", len(findings), high, med)
		for file, items := range byFile {
			out += file + "\n"
			for _, item := range items {
				out += fmt.Sprintf("  Line %-5d [%s] %s: %s\n", item.Line, item.Severity, item.Type, item.Match)
			}
			out += "\n"
		}
		return mcp.NewToolResultText(out), nil
	})

	// ── audit_headers ─────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("audit_headers",
		mcp.WithDescription("Audit HTTP security headers of a URL. Checks HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy. Returns score/100 and grade."),
		mcp.WithString("url", mcp.Required(), mcp.Description("URL to audit (e.g. https://example.com)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		url := req.GetString("url", "")
		if url == "" {
			return mcp.NewToolResultError("url is required"), nil
		}

		result, err := auditHeaders(url)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("audit error: %v", err)), nil
		}

		out := fmt.Sprintf("Security headers: %s\nScore: %d/100  Grade: %s\n\n", result.URL, result.Score, result.Grade)
		if len(result.Missing) > 0 {
			out += fmt.Sprintf("Missing: %v\n\n", result.Missing)
		}
		out += "Breakdown:\n"
		for _, c := range result.Checks {
			status := "–"
			if c.Present {
				status = "✓"
			} else if c.Required {
				status = "✗"
			}
			val := ""
			if c.Value != "" {
				if len(c.Value) > 80 {
					val = "  →  " + c.Value[:80] + "…"
				} else {
					val = "  →  " + c.Value
				}
			}
			out += fmt.Sprintf("  %s  %-35s%s\n", status, c.Header, val)
		}
		return mcp.NewToolResultText(out), nil
	})

	// ── check_cves ────────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("check_cves",
		mcp.WithDescription("Check npm dependencies in a package.json against the OSV vulnerability database. No API key needed."),
		mcp.WithString("path", mcp.Required(), mcp.Description("Absolute path to a package.json file")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		path := req.GetString("path", "")
		if path == "" {
			return mcp.NewToolResultError("path is required"), nil
		}

		findings, err := checkCVEs(path)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("CVE check error: %v", err)), nil
		}

		if len(findings) == 0 {
			return mcp.NewToolResultText(fmt.Sprintf("No known vulnerabilities in %s", path)), nil
		}

		out := fmt.Sprintf("Found %d vulnerabilities in %s\n\n", len(findings), path)
		for _, f := range findings {
			out += fmt.Sprintf("[%s] %s@%s\n  %s\n  %s\n\n", f.Severity, f.Package, f.Version, f.Summary, f.URL)
		}
		return mcp.NewToolResultText(out), nil
	})

	// ── wifi_scan ─────────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("wifi_scan",
		mcp.WithDescription("Scan nearby Wi-Fi networks using local wireless hardware. Returns SSID, BSSID, signal strength, channel, and security type. Requires physical Wi-Fi hardware — impossible for Claude to do remotely."),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		networks, err := wifiScan()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("wifi_scan failed: %v", err)), nil
		}
		if len(networks) == 0 {
			return mcp.NewToolResultText("No Wi-Fi networks detected"), nil
		}
		out := fmt.Sprintf("Wi-Fi networks (%d found)\n\n", len(networks))
		out += fmt.Sprintf("%-32s  %-19s  %-8s  %-7s  %s\n", "SSID", "BSSID", "SIGNAL", "CHANNEL", "SECURITY")
		out += strings.Repeat("─", 90) + "\n"
		for _, n := range networks {
			out += fmt.Sprintf("%-32s  %-19s  %-8s  %-7s  %s\n", n.SSID, n.BSSID, n.Signal, n.Channel, n.Security)
		}
		return mcp.NewToolResultText(out), nil
	})

	// ── ping_sweep ────────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("ping_sweep",
		mcp.WithDescription("Send ICMP pings to all hosts in a CIDR range and return live hosts. Works on the local network — finds hosts even if they have no open TCP ports. Claude cannot send ICMP packets."),
		mcp.WithString("cidr", mcp.Required(), mcp.Description("CIDR range to sweep (e.g. 192.168.1.0/24)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cidr := req.GetString("cidr", "")
		if cidr == "" {
			return mcp.NewToolResultError("cidr is required"), nil
		}
		results, err := pingSweep(cidr)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("ping_sweep error: %v", err)), nil
		}
		if len(results) == 0 {
			return mcp.NewToolResultText(fmt.Sprintf("No live hosts in %s", cidr)), nil
		}
		out := fmt.Sprintf("Live hosts in %s (%d found)\n\n", cidr, len(results))
		for _, r := range results {
			out += fmt.Sprintf("  %-20s  %s\n", r.IP, r.Latency)
		}
		return mcp.NewToolResultText(out), nil
	})

	// ── arp_scan ──────────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("arp_scan",
		mcp.WithDescription("Layer 2 LAN host discovery — finds ALL devices on local network including those that block ICMP/TCP. Returns IP, MAC address, hostname, and vendor. Only possible from a machine on the same network segment."),
		mcp.WithString("cidr", mcp.Required(), mcp.Description("Local network CIDR (e.g. 192.168.1.0/24)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cidr := req.GetString("cidr", "")
		if cidr == "" {
			return mcp.NewToolResultError("cidr is required"), nil
		}
		entries, err := arpScan(cidr)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("arp_scan error: %v", err)), nil
		}
		if len(entries) == 0 {
			return mcp.NewToolResultText(fmt.Sprintf("No ARP entries found for %s", cidr)), nil
		}
		out := fmt.Sprintf("LAN devices in %s (%d found)\n\n", cidr, len(entries))
		out += fmt.Sprintf("%-18s  %-19s  %-20s  %s\n", "IP", "MAC", "HOSTNAME", "VENDOR")
		out += strings.Repeat("─", 80) + "\n"
		for _, e := range entries {
			out += fmt.Sprintf("%-18s  %-19s  %-20s  %s\n", e.IP, e.MAC, e.Hostname, e.Vendor)
		}
		return mcp.NewToolResultText(out), nil
	})

	// ── traceroute ────────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("traceroute",
		mcp.WithDescription("Trace the network path to a host hop-by-hop using ICMP TTL probes. Shows every router between this machine and the target. Requires raw packet sending — Claude cannot do this."),
		mcp.WithString("host", mcp.Required(), mcp.Description("Target hostname or IP")),
		mcp.WithNumber("max_hops", mcp.Description("Maximum hops (default 15)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		host := req.GetString("host", "")
		maxHops := req.GetInt("max_hops", 15)
		if host == "" {
			return mcp.NewToolResultError("host is required"), nil
		}
		hops, err := doTraceroute(host, maxHops)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("traceroute error: %v", err)), nil
		}
		out := fmt.Sprintf("Traceroute to %s (max %d hops)\n\n", host, maxHops)
		for _, h := range hops {
			if h.Timeout {
				out += fmt.Sprintf("  %2d  * * *  (no response)\n", h.Hop)
			} else {
				ip := h.IP
				if ip == "" {
					ip = "unknown"
				}
				rtt := h.RTT
				if rtt == "" {
					rtt = "?"
				}
				out += fmt.Sprintf("  %2d  %-20s  %s\n", h.Hop, ip, rtt)
			}
		}
		return mcp.NewToolResultText(out), nil
	})

	// ── banner_grab ───────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("banner_grab",
		mcp.WithDescription("Connect to a TCP port and capture the raw service banner. Unlike HTTP fetching, reads raw bytes from any protocol — SSH, FTP, SMTP, Redis, memcached, MySQL, etc."),
		mcp.WithString("host", mcp.Required(), mcp.Description("Hostname or IP to connect to")),
		mcp.WithNumber("port", mcp.Required(), mcp.Description("TCP port number")),
		mcp.WithNumber("timeout_ms", mcp.Description("Connection timeout in ms (default 3000)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		host := req.GetString("host", "")
		port := req.GetInt("port", 0)
		timeout := req.GetInt("timeout_ms", 3000)
		if host == "" || port == 0 {
			return mcp.NewToolResultError("host and port are required"), nil
		}
		banner, err := bannerGrab(host, port, timeout)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("banner_grab error: %v", err)), nil
		}
		out := fmt.Sprintf("Banner from %s:%d\n\n%s\n", host, port, banner)
		return mcp.NewToolResultText(out), nil
	})

	// ── file_watch ────────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("file_watch",
		mcp.WithDescription("Watch a file or directory for changes using kernel-level FS events (FSEvents on macOS, inotify on Linux). Captures creates, writes, deletes, renames in real time. A background MCP process can do this — Claude in a chat window never could."),
		mcp.WithString("path", mcp.Required(), mcp.Description("File or directory to watch")),
		mcp.WithNumber("seconds", mcp.Description("How long to watch in seconds (default 10, max 60)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		path := req.GetString("path", "")
		secs := req.GetInt("seconds", 10)
		if path == "" {
			return mcp.NewToolResultError("path is required"), nil
		}
		if secs > 60 {
			secs = 60
		}
		events, err := fileWatch(path, secs)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("file_watch error: %v", err)), nil
		}
		if len(events) == 0 {
			return mcp.NewToolResultText(fmt.Sprintf("No file system events in %s for %ds", path, secs)), nil
		}
		out := fmt.Sprintf("File system events in %s (%ds watch, %d events)\n\n", path, secs, len(events))
		for _, e := range events {
			out += fmt.Sprintf("  %s  %-12s  %s\n", e.Time, e.Op, e.Path)
		}
		return mcp.NewToolResultText(out), nil
	})

	// ── sys_info ──────────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("sys_info",
		mcp.WithDescription("Get detailed local system information: CPU model, RAM, disk space, uptime, network interfaces with IPs and MACs. Reads from local hardware — not available to any remote service."),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		info, err := sysInfo()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("sys_info error: %v", err)), nil
		}
		out := "System Information\n\n"
		out += fmt.Sprintf("  Hostname:   %s\n", info.Hostname)
		out += fmt.Sprintf("  OS:         %s/%s\n", info.OS, info.Arch)
		out += fmt.Sprintf("  CPU:        %s (%d cores)\n", info.CPU, info.Cores)
		out += fmt.Sprintf("  RAM:        %s total", info.TotalRAM)
		if info.FreeRAM != "" {
			out += fmt.Sprintf("  (%s available)", info.FreeRAM)
		}
		out += "\n"
		out += fmt.Sprintf("  Disk (/):   %s total, %s free\n", info.DiskTotal, info.DiskFree)
		out += fmt.Sprintf("  Uptime:     %s\n", info.Uptime)
		if len(info.Interfaces) > 0 {
			out += "\nNetwork interfaces:\n"
			for _, iface := range info.Interfaces {
				if iface.IP == "" && iface.MAC == "" {
					continue
				}
				out += fmt.Sprintf("  %-12s  IP: %-20s  MAC: %s\n", iface.Name, iface.IP, iface.MAC)
			}
		}
		return mcp.NewToolResultText(out), nil
	})

	// ── open_files ────────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("open_files",
		mcp.WithDescription("List files, sockets, and pipes currently open by processes on this machine. Filter by process name or PID. Uses lsof — shows exactly what a process is reading, writing, or listening on."),
		mcp.WithString("filter", mcp.Description("Process name or PID to filter (optional — leave empty for all)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		filter := req.GetString("filter", "")
		files, err := openFiles(filter)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("open_files error: %v", err)), nil
		}
		if len(files) == 0 {
			return mcp.NewToolResultText("No open files found"), nil
		}
		out := fmt.Sprintf("Open files/sockets (%d entries)\n\n", len(files))
		out += fmt.Sprintf("%-12s  %-8s  %-8s  %s\n", "PROCESS", "PID", "TYPE", "NAME")
		out += strings.Repeat("─", 70) + "\n"
		for _, f := range files {
			name := f.Name
			if len(name) > 60 {
				name = "..." + name[len(name)-57:]
			}
			out += fmt.Sprintf("%-12s  %-8s  %-8s  %s\n", f.Process, f.PID, f.Type, name)
		}
		return mcp.NewToolResultText(out), nil
	})

	// ── jwt_decode ────────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("jwt_decode",
		mcp.WithDescription("Decode and analyze a JWT token locally without sending it anywhere. Shows header, payload, expiry, algorithm, and security warnings (e.g. 'none' algorithm, expired token, weak signing)."),
		mcp.WithString("token", mcp.Required(), mcp.Description("JWT token string to decode")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		token := req.GetString("token", "")
		if token == "" {
			return mcp.NewToolResultError("token is required"), nil
		}
		info, err := jwtDecode(token)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("jwt_decode error: %v", err)), nil
		}
		headerJSON, _ := json.MarshalIndent(info.Header, "  ", "  ")
		payloadJSON, _ := json.MarshalIndent(info.Payload, "  ", "  ")
		out := "JWT Analysis\n\n"
		out += fmt.Sprintf("Algorithm: %s\n", info.Algorithm)
		if info.IssuedAt != "" {
			out += fmt.Sprintf("Issued:    %s\n", info.IssuedAt)
		}
		if info.Expires != "" {
			status := "valid"
			if info.Expired {
				status = "EXPIRED"
			}
			out += fmt.Sprintf("Expires:   %s  [%s]\n", info.Expires, status)
		}
		if len(info.Warnings) > 0 {
			out += "\nWarnings:\n"
			for _, w := range info.Warnings {
				out += fmt.Sprintf("  ! %s\n", w)
			}
		}
		out += "\nHeader:\n  " + string(headerJSON) + "\n"
		out += "\nPayload:\n  " + string(payloadJSON) + "\n"
		return mcp.NewToolResultText(out), nil
	})

	// ── hash_files ────────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("hash_files",
		mcp.WithDescription("Compute SHA-256 hashes of all files in a directory. Use to create integrity baselines, detect tampering, or verify files haven't changed. Reads local disk — not possible remotely."),
		mcp.WithString("path", mcp.Required(), mcp.Description("File or directory to hash recursively")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		path := req.GetString("path", "")
		if path == "" {
			return mcp.NewToolResultError("path is required"), nil
		}
		results, err := hashFiles(path)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("hash_files error: %v", err)), nil
		}
		if len(results) == 0 {
			return mcp.NewToolResultText(fmt.Sprintf("No files found in %s", path)), nil
		}
		out := fmt.Sprintf("SHA-256 hashes for %s (%d files)\n\n", path, len(results))
		for _, r := range results {
			out += fmt.Sprintf("%s  %s  (%s)\n", r.Hash[:16]+"…", r.Path, formatBytes(r.Size))
		}
		return mcp.NewToolResultText(out), nil
	})

	// ── bluetooth_scan ────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("bluetooth_scan",
		mcp.WithDescription("Scan for nearby Bluetooth devices using local Bluetooth hardware. Returns device name, address, type, and pairing status. Requires a physical Bluetooth adapter — architecturally impossible for any cloud service."),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		devices, err := bluetoothScan()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("bluetooth_scan failed: %v", err)), nil
		}
		if len(devices) == 0 {
			return mcp.NewToolResultText("No Bluetooth devices found"), nil
		}
		out := fmt.Sprintf("Bluetooth devices (%d found)\n\n", len(devices))
		out += fmt.Sprintf("%-30s  %-20s  %-20s  %s\n", "NAME", "ADDRESS", "TYPE", "STATUS")
		out += strings.Repeat("─", 85) + "\n"
		for _, d := range devices {
			status := "not paired"
			if d.Paired {
				status = "paired"
			}
			if d.RSSI != "" {
				status += "  RSSI:" + d.RSSI
			}
			out += fmt.Sprintf("%-30s  %-20s  %-20s  %s\n", d.Name, d.Address, d.Type, status)
		}
		return mcp.NewToolResultText(out), nil
	})

	// ── usb_devices ───────────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("usb_devices",
		mcp.WithDescription("List all USB devices currently connected to this machine. Returns device name, vendor, product ID, speed, and manufacturer. Reads the local USB bus — no remote service can enumerate your physical ports."),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		devices, err := usbDevices()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("usb_devices failed: %v", err)), nil
		}
		if len(devices) == 0 {
			return mcp.NewToolResultText("No USB devices found"), nil
		}
		out := fmt.Sprintf("USB devices (%d found)\n\n", len(devices))
		out += fmt.Sprintf("%-35s  %-10s  %-10s  %-15s  %s\n", "NAME", "VENDOR ID", "PROD ID", "SPEED", "MANUFACTURER")
		out += strings.Repeat("─", 90) + "\n"
		for _, d := range devices {
			out += fmt.Sprintf("%-35s  %-10s  %-10s  %-15s  %s\n", d.Name, d.VendorID, d.ProductID, d.Speed, d.Manufacturer)
		}
		return mcp.NewToolResultText(out), nil
	})

	// ── persistence_scan ─────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("persistence_scan",
		mcp.WithDescription("Scan this machine for malware persistence mechanisms: LaunchAgents/LaunchDaemons (macOS), systemd units (Linux), cron jobs, and shell profile injections. Flags high-risk patterns like curl-pipe-to-bash, base64-encoded payloads, and binaries executing from /tmp. Essential first step when investigating a potentially compromised machine."),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		entries, err := persistenceScan()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("persistence_scan failed: %v", err)), nil
		}
		if len(entries) == 0 {
			return mcp.NewToolResultText("No persistence entries found"), nil
		}

		// Group by risk
		var high, medium, low []PersistenceEntry
		for _, e := range entries {
			switch e.Risk {
			case "high":
				high = append(high, e)
			case "medium":
				medium = append(medium, e)
			default:
				low = append(low, e)
			}
		}

		out := fmt.Sprintf("Persistence scan: %d entries (%d high, %d medium, %d low)\n\n",
			len(entries), len(high), len(medium), len(low))

		printPersistenceGroup := func(label string, group []PersistenceEntry) {
			if len(group) == 0 {
				return
			}
			out += fmt.Sprintf("── %s (%d) ──\n", label, len(group))
			for _, e := range group {
				out += fmt.Sprintf("  [%s] %s\n", e.Type, e.Name)
				if e.Command != "" {
					out += fmt.Sprintf("    cmd:  %s\n", truncatePersistence(e.Command, 100))
				}
				if e.Path != "" {
					out += fmt.Sprintf("    path: %s\n", e.Path)
				}
				if e.Reason != "" {
					out += fmt.Sprintf("    why:  %s\n", e.Reason)
				}
				if !e.Modified.IsZero() {
					out += fmt.Sprintf("    mod:  %s\n", e.Modified.Format("2006-01-02 15:04"))
				}
				out += "\n"
			}
		}

		printPersistenceGroup("HIGH RISK", high)
		printPersistenceGroup("MEDIUM RISK", medium)
		printPersistenceGroup("LOW RISK", low)

		return mcp.NewToolResultText(out), nil
	})

	// ── supply_chain_audit ────────────────────────────────────────────────────
	s.AddTool(mcp.NewTool("supply_chain_audit",
		mcp.WithDescription("Audit a Node.js project's dependencies for supply chain attack indicators. Checks all packages in node_modules for: dangerous lifecycle scripts (postinstall that curl-pipe-to-bash, eval, base64 decode), typosquatting against 50+ popular package names (Levenshtein distance 1), and eval() of runtime data in source files. Reads local filesystem — no remote service can inspect your node_modules."),
		mcp.WithString("path", mcp.Required(), mcp.Description("Absolute path to the Node.js project root (must contain package-lock.json and node_modules)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		path := req.GetString("path", "")
		if path == "" {
			return mcp.NewToolResultError("path is required"), nil
		}

		findings, err := supplyChainAudit(path)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		if len(findings) == 0 {
			return mcp.NewToolResultText(fmt.Sprintf("No supply chain issues found in %s", path)), nil
		}

		// Group by severity
		bySev := map[string][]SCFinding{"high": {}, "medium": {}, "low": {}}
		for _, f := range findings {
			bySev[f.Severity] = append(bySev[f.Severity], f)
		}

		out := fmt.Sprintf("Supply chain audit: %d findings (%d high, %d medium, %d low)\n\n",
			len(findings), len(bySev["high"]), len(bySev["medium"]), len(bySev["low"]))

		for _, sev := range []string{"high", "medium", "low"} {
			group := bySev[sev]
			if len(group) == 0 {
				continue
			}
			out += fmt.Sprintf("── %s (%d) ──\n", strings.ToUpper(sev), len(group))
			for _, f := range group {
				out += fmt.Sprintf("  %s@%s  [%s]\n", f.Package, f.Version, f.Category)
				out += fmt.Sprintf("    %s\n", f.Detail)
				if f.File != "" {
					out += fmt.Sprintf("    %s\n", f.File)
				}
				out += "\n"
			}
		}

		return mcp.NewToolResultText(out), nil
	})

	if err := server.ServeStdio(s); err != nil {
		log.Fatal(err)
	}
}
