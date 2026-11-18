// Package proxy — перехватывающий HTTP(S)-прокси (MITM) в духе Burp Suite:
// история запросов/ответов, Intercept (hold/forward/drop) и Repeater.
// Реализован на stdlib: собственный корневой CA и генерация листовых
// сертификатов на лету под каждый хост.
package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CA — корневой центр сертификации прокси и кэш листовых сертификатов.
type CA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
	der  []byte // DER корневого сертификата

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// LoadOrCreateCA читает CA из dir (ca.crt/ca.key) или генерирует новый.
func LoadOrCreateCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	crtPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	if crtPEM, err := os.ReadFile(crtPath); err == nil {
		if keyPEM, err := os.ReadFile(keyPath); err == nil {
			if ca, err := parseCA(crtPEM, keyPEM); err == nil {
				return ca, nil
			}
		}
	}

	ca, crtPEM, keyPEM, err := generateCA()
	if err != nil {
		return nil, err
	}
	_ = os.WriteFile(crtPath, crtPEM, 0o644)
	_ = os.WriteFile(keyPath, keyPEM, 0o600)
	return ca, nil
}

func parseCA(crtPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(crtPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return errNil()
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, der: cb.Bytes, leaves: map[string]*tls.Certificate{}}, nil
}

func errNil() (*CA, error) { return nil, os.ErrInvalid }

func generateCA() (*CA, []byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject: pkix.Name{
			CommonName:   "pentkit proxy CA",
			Organization: []string{"pentkit (authorized pentest)"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return &CA{cert: cert, key: key, der: der, leaves: map[string]*tls.Certificate{}}, crtPEM, keyPEM, nil
}

// CertPEM возвращает PEM корневого сертификата (для импорта в браузер/ОС).
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

// LeafFor выдаёт (и кэширует) листовой сертификат под конкретный хост.
func (c *CA) LeafFor(host string) (*tls.Certificate, error) {
	host = stripPort(host)
	if host == "" {
		host = "localhost"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if lc, ok := c.leaves[host]; ok {
		return lc, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{
		Certificate: [][]byte{der, c.der},
		PrivateKey:  key,
	}
	c.leaves[host] = leaf
	return leaf, nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
