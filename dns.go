package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

type DNSRecord struct {
	Type  string
	Value string
}

func dnsEnum(domain string) ([]DNSRecord, []string) {
	var records []DNSRecord
	var warnings []string

	// A / AAAA
	ips, err := net.LookupIP(domain)
	if err == nil {
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				records = append(records, DNSRecord{"A", v4.String()})
			} else {
				records = append(records, DNSRecord{"AAAA", ip.String()})
			}
		}
	}

	// MX
	mxs, err := net.LookupMX(domain)
	if err == nil {
		for _, mx := range mxs {
			records = append(records, DNSRecord{"MX", fmt.Sprintf("%d %s", mx.Pref, mx.Host)})
		}
	}

	// NS
	nss, err := net.LookupNS(domain)
	if err == nil {
		for _, ns := range nss {
			records = append(records, DNSRecord{"NS", ns.Host})
		}
	}

	// TXT
	txts, err := net.LookupTXT(domain)
	if err == nil {
		hasSPF := false
		hasDMARC := false
		for _, txt := range txts {
			records = append(records, DNSRecord{"TXT", txt})
			if strings.HasPrefix(txt, "v=spf1") {
				hasSPF = true
			}
			if strings.Contains(txt, "v=DMARC1") {
				hasDMARC = true
			}
		}
		if !hasSPF {
			warnings = append(warnings, "No SPF record found — domain may be spoofable")
		}
		if !hasDMARC {
			warnings = append(warnings, "No DMARC record found — email authentication not enforced")
		}
	}

	// CNAME
	cname, err := net.LookupCNAME(domain)
	if err == nil && cname != domain+"." && cname != domain {
		records = append(records, DNSRecord{"CNAME", cname})
	}

	// Sort by type then value
	sort.Slice(records, func(i, j int) bool {
		if records[i].Type != records[j].Type {
			return records[i].Type < records[j].Type
		}
		return records[i].Value < records[j].Value
	})

	return records, warnings
}
