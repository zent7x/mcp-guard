package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

type CertInfo struct {
	Subject   string
	Issuer    string
	SANs      []string
	NotBefore time.Time
	NotAfter  time.Time
	DaysLeft  int
	Algorithm string
	KeyBits   int
	Warnings  []string
}

func sslInspect(host string, port int) ([]CertInfo, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName: host,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	var certs []CertInfo

	for _, cert := range state.PeerCertificates {
		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)

		info := CertInfo{
			Subject:   certName(cert.Subject.CommonName, cert.Subject.Organization),
			Issuer:    certName(cert.Issuer.CommonName, cert.Issuer.Organization),
			SANs:      cert.DNSNames,
			NotBefore: cert.NotBefore,
			NotAfter:  cert.NotAfter,
			DaysLeft:  daysLeft,
			Algorithm: cert.SignatureAlgorithm.String(),
		}

		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			info.KeyBits = pub.N.BitLen()
			info.Algorithm += fmt.Sprintf(" (RSA-%d)", info.KeyBits)
			if info.KeyBits < 2048 {
				info.Warnings = append(info.Warnings, fmt.Sprintf("RSA key too short: %d bits (minimum 2048)", info.KeyBits))
			}
		case *ecdsa.PublicKey:
			info.KeyBits = pub.Curve.Params().BitSize
			info.Algorithm += fmt.Sprintf(" (ECDSA P-%d)", info.KeyBits)
		}

		if daysLeft < 0 {
			info.Warnings = append(info.Warnings, "CERTIFICATE EXPIRED")
		} else if daysLeft < 14 {
			info.Warnings = append(info.Warnings, fmt.Sprintf("expires in %d days — renew immediately", daysLeft))
		} else if daysLeft < 30 {
			info.Warnings = append(info.Warnings, fmt.Sprintf("expires in %d days — renewal due soon", daysLeft))
		}

		if cert.SignatureAlgorithm == x509.SHA1WithRSA || cert.SignatureAlgorithm == x509.ECDSAWithSHA1 {
			info.Warnings = append(info.Warnings, "uses SHA-1 signature algorithm (deprecated)")
		}

		certs = append(certs, info)
	}

	return certs, nil
}

func certName(cn string, orgs []string) string {
	if cn != "" {
		return cn
	}
	if len(orgs) > 0 {
		return orgs[0]
	}
	return "(unknown)"
}
