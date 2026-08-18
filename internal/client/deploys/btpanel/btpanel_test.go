package btpanel

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestBTPanelCertificateFingerprintUsesLeaf 验证宝塔证书库回读校验使用叶证书指纹。
func TestBTPanelCertificateFingerprintUsesLeaf(t *testing.T) {
	sourceDir := t.TempDir()
	writeTestCertificatePair(t, sourceDir, "example.com")

	certificatePEM, err := os.ReadFile(sourceDir + "/cert.pem")
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}
	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		t.Fatal("certificate PEM block is missing")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}

	got, err := btPanelCertificateFingerprint(string(certificatePEM))
	if err != nil {
		t.Fatalf("btPanelCertificateFingerprint: %v", err)
	}
	want := sha256.Sum256(leaf.Raw)
	if got != want {
		t.Fatalf("unexpected certificate fingerprint: got %x, want %x", got, want)
	}
}

// writeTestCertificatePair 写入宝塔测试使用的自签证书和匹配私钥。
func writeTestCertificatePair(t *testing.T, dir, domain string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: domain},
		DNSNames:              []string{domain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certificatePEM, 0o644); err != nil {
		t.Fatalf("write cert.pem: %v", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err := os.WriteFile(filepath.Join(dir, "privateKey.key"), privateKeyPEM, 0o600); err != nil {
		t.Fatalf("write privateKey.key: %v", err)
	}
}
