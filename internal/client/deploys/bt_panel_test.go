package deploys

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
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
