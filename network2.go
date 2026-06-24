package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ── ping_sweep ────────────────────────────────────────────────────────────────

type PingResult struct {
	IP      string
	Alive   bool
	Latency string
}

func pingSweep(cidr string) ([]PingResult, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	var ips []string
	for ip := cloneIP(network.IP.Mask(network.Mask)); network.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	if len(ips) > 1024 {
		return nil, fmt.Errorf("range too large (%d hosts) — use a /22 or smaller", len(ips))
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []PingResult
		sem     = make(chan struct{}, 64)
	)

	for _, ip := range ips {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			start := time.Now()
			var cmd *exec.Cmd
			// -c 1: one packet, -W/-w: timeout in ms/sec
			cmd = exec.Command("ping", "-c", "1", "-W", "1", addr)
			err := cmd.Run()
			latency := time.Since(start).Round(time.Millisecond).String()

			if err == nil {
				mu.Lock()
				results = append(results, PingResult{IP: addr, Alive: true, Latency: latency})
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()

	// sort results by IP
	sortIPs(results)
	return results, nil
}

// ── arp_scan ──────────────────────────────────────────────────────────────────

type ARPEntry struct {
	IP       string
	MAC      string
	Hostname string
	Vendor   string
}

func arpScan(cidr string) ([]ARPEntry, error) {
	// First do a ping sweep to populate the ARP cache
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	// Quick TCP connect sweep to populate ARP cache (ports 80, 22, 443, 445)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100)
	for ip := cloneIP(network.IP.Mask(network.Mask)); network.Contains(ip); incIP(ip) {
		for _, port := range []int{80, 22, 443, 445} {
			wg.Add(1)
			go func(addr string, p int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", addr, p), 300*time.Millisecond)
				if err == nil {
					conn.Close()
				}
			}(ip.String(), port)
		}
		incIP(ip)
	}
	wg.Wait()

	// Read ARP cache
	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return nil, fmt.Errorf("arp -a failed: %w", err)
	}

	var entries []ARPEntry
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "incomplete") || line == "" {
			continue
		}

		// Format: hostname (IP) at MAC on interface
		var hostname, ip, mac string

		// extract IP
		start := strings.Index(line, "(")
		end := strings.Index(line, ")")
		if start < 0 || end < 0 {
			continue
		}
		ip = line[start+1 : end]
		hostname = strings.TrimSpace(line[:start])
		if hostname == "?" {
			hostname = ""
		}

		// extract MAC
		atIdx := strings.Index(line, " at ")
		onIdx := strings.Index(line, " on ")
		if atIdx >= 0 && onIdx > atIdx {
			mac = strings.TrimSpace(line[atIdx+4 : onIdx])
		} else if atIdx >= 0 {
			parts := strings.Fields(line[atIdx+4:])
			if len(parts) > 0 {
				mac = parts[0]
			}
		}

		if mac == "" || mac == "(incomplete)" {
			continue
		}

		// Skip broadcast/multicast entries — these are not real hosts.
		// ff:ff:ff:ff:ff:ff is broadcast; 01:00:5e:* and 33:33:* are IPv4/IPv6 multicast.
		macLower := strings.ToLower(mac)
		if macLower == "ff:ff:ff:ff:ff:ff" ||
			strings.HasPrefix(macLower, "01:00:5e") ||
			strings.HasPrefix(macLower, "33:33") {
			continue
		}

		// Filter to requested CIDR
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil || !network.Contains(parsedIP) {
			continue
		}

		// Skip network and broadcast addresses of the subnet itself.
		if ip4 := parsedIP.To4(); ip4 != nil {
			last := ip4[3]
			if last == 0 || last == 255 {
				continue
			}
		}

		entries = append(entries, ARPEntry{
			IP:       ip,
			MAC:      mac,
			Hostname: hostname,
			Vendor:   ouiLookup(mac),
		})
	}

	return entries, nil
}

// ── traceroute ────────────────────────────────────────────────────────────────

type TraceHop struct {
	Hop     int
	IP      string
	RTT     string
	Timeout bool
}

func doTraceroute(host string, maxHops int) ([]TraceHop, error) {
	args := []string{"-m", fmt.Sprintf("%d", maxHops), "-w", "1", host}
	out, err := exec.Command("traceroute", args...).Output()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("traceroute failed: %w", err)
	}

	var hops []TraceHop
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// first field is hop number
		var hopNum int
		if _, err := fmt.Sscanf(fields[0], "%d", &hopNum); err != nil {
			continue
		}

		if fields[1] == "*" {
			hops = append(hops, TraceHop{Hop: hopNum, Timeout: true})
			continue
		}

		hop := TraceHop{Hop: hopNum}

		// IP may be in parens or bare
		for _, f := range fields[1:] {
			clean := strings.Trim(f, "()")
			if net.ParseIP(clean) != nil {
				hop.IP = clean
				break
			}
		}

		// find RTT (ends in "ms")
		for _, f := range fields {
			if strings.HasSuffix(f, "ms") {
				hop.RTT = f
				break
			}
		}
		if hop.RTT == "" {
			// look for float followed by "ms"
			for i, f := range fields {
				if f == "ms" && i > 0 {
					hop.RTT = fields[i-1] + "ms"
					break
				}
			}
		}

		hops = append(hops, hop)
	}

	return hops, nil
}

// ── banner_grab ───────────────────────────────────────────────────────────────

func bannerGrab(host string, port int, timeoutMs int) (string, error) {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", fmt.Errorf("connect failed: %w", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n == 0 {
		// try sending a probe for HTTP
		conn.SetWriteDeadline(time.Now().Add(timeout))
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, _ = conn.Read(buf)
	}

	if n == 0 {
		return "(no banner — port is open but no data received)", nil
	}

	banner := string(buf[:n])
	// clean non-printable chars
	var cleaned strings.Builder
	for _, r := range banner {
		if r >= 32 || r == '\n' || r == '\r' || r == '\t' {
			cleaned.WriteRune(r)
		}
	}
	return strings.TrimSpace(cleaned.String()), nil
}

// ── IP utilities ──────────────────────────────────────────────────────────────

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func sortIPs(results []PingResult) {
	// simple insertion sort by last octet
	for i := 1; i < len(results); i++ {
		for j := i; j > 0; j-- {
			if ipLess(results[j].IP, results[j-1].IP) {
				results[j], results[j-1] = results[j-1], results[j]
			} else {
				break
			}
		}
	}
}

func ipLess(a, b string) bool {
	pa := net.ParseIP(a)
	pb := net.ParseIP(b)
	if pa == nil || pb == nil {
		return a < b
	}
	pa = pa.To16()
	pb = pb.To16()
	for i := range pa {
		if pa[i] < pb[i] {
			return true
		}
		if pa[i] > pb[i] {
			return false
		}
	}
	return false
}

// minimal OUI vendor lookup for common prefixes
func ouiLookup(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	prefix := strings.ToUpper(mac[:8])
	vendors := map[string]string{
		"00:50:56": "VMware", "00:0C:29": "VMware", "00:1C:42": "Parallels",
		"08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
		"AC:BC:32": "Apple", "A4:C3:F0": "Apple", "F0:18:98": "Apple",
		"00:17:F2": "Apple", "00:1E:C2": "Apple", "00:23:32": "Apple",
		"B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
		"00:50:BA": "D-Link", "00:90:4C": "Epigram/Broadcom",
	}
	if v, ok := vendors[prefix]; ok {
		return v
	}
	return ""
}
