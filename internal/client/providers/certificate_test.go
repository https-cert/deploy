package providers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// TestValidateCertificateMaterialCoversDomainAndExpiry verifies domain, wildcard, key matching and expiry checks.
func TestValidateCertificateMaterialCoversDomainAndExpiry(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	certificatePEM, privateKeyPEM := testCertificateMaterial(t, []string{"example.com", "*.example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
	certificate := CertificateMaterial{CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM}
	tests := []struct {
		name    string
		domain  string
		when    time.Time
		wantErr bool
	}{
		{name: "exact domain", domain: "example.com", when: now},
		{name: "wildcard child", domain: "www.example.com", when: now},
		{name: "unmatched domain", domain: "other.example.net", when: now, wantErr: true},
		{name: "expired", domain: "example.com", when: now.Add(2 * time.Hour), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateCertificateMaterial(certificate, test.domain, test.when)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateCertificateMaterial() error = %v, wantErr=%v", err, test.wantErr)
			}
		})
	}
}

// TestValidateCertificateMaterialRejectsMismatchedPrivateKey verifies the private key must match the certificate public key.
func TestValidateCertificateMaterialRejectsMismatchedPrivateKey(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	certificatePEM, _ := testCertificateMaterial(t, []string{"example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
	_, mismatchedKeyPEM := testCertificateMaterial(t, []string{"example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
	err := ValidateCertificateMaterial(CertificateMaterial{CertificatePEM: certificatePEM, PrivateKeyPEM: mismatchedKeyPEM}, "example.com", now)
	if err == nil {
		t.Fatal("ValidateCertificateMaterial() unexpectedly accepted mismatched private key")
	}
}

// testCertificateMaterial creates an offline self-signed certificate and matching RSA private key.
func testCertificateMaterial(t *testing.T, domains []string, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: domains[0]}, DNSNames: domains, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return string(certificatePEM), string(privateKeyPEM)
}
