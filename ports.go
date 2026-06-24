package main

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

var commonServices = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 143: "imap", 443: "https", 465: "smtps",
	587: "submission", 993: "imaps", 995: "pop3s", 3306: "mysql",
	3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
	8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
	9200: "elasticsearch", 2181: "zookeeper", 9092: "kafka",
}

type PortResult struct {
	Port    int
	Open    bool
	Service string
}

func portScan(host string, start, end, timeoutMs int) []PortResult {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	results := make([]PortResult, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 200)

	for port := start; port <= end; port++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			addr := fmt.Sprintf("%s:%d", host, p)
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				conn.Close()
				svc := commonServices[p]
				if svc == "" {
					svc = "unknown"
				}
				mu.Lock()
				results = append(results, PortResult{Port: p, Open: true, Service: svc})
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})
	return results
}
