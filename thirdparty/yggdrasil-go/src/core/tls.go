package core

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

func (c *Core) generateTLSConfig(cert *tls.Certificate) (*tls.Config, error) {
	config := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		ClientAuth:   tls.NoClientCert,
		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cert, nil
		},
		VerifyPeerCertificate: c.verifyTLSCertificate,
		VerifyConnection:      c.verifyTLSConnection,
		InsecureSkipVerify:    true,
		MinVersion:            tls.VersionTLS13,
	}
	return config, nil
}

func (c *Core) verifyTLSCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	c.log.Debugf("TLS verifyTLSCertificate invoked: raw=%d chains=%d", len(rawCerts), len(verifiedChains))
	return nil
}

func (c *Core) verifyTLSConnection(state tls.ConnectionState) error {
	logTLSState(c.log, "verify: ", state)
	return nil
}

func logTLSState(logger Logger, prefix string, state tls.ConnectionState) {
	peerCount := len(state.PeerCertificates)
	logger.Debugf("%sTLS state version=%s cipher=%s peerCerts=%d alpn=%q resumed=%v sni=%q", prefix, tlsVersionName(state.Version), tlsCipherSuiteName(state.CipherSuite), peerCount, state.NegotiatedProtocol, state.DidResume, state.ServerName)
	if peerCount > 0 {
		cert := state.PeerCertificates[0]
		logger.Traceln(prefix+"TLS peer cert subject=", cert.Subject.String(), "issuer=", cert.Issuer.String(), "dns=", cert.DNSNames, "ip=", cert.IPAddresses, "notBefore=", cert.NotBefore, "notAfter=", cert.NotAfter)
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func tlsCipherSuiteName(id uint16) string {
	if name := tls.CipherSuiteName(id); name != "" {
		return name
	}
	return fmt.Sprintf("0x%04x", id)
}
