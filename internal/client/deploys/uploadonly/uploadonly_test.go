package uploadonly

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestUploadOnlyTargetDirSanitizesDomain 验证泛域名保存目录会转换为安全路径。
func TestUploadOnlyTargetDirSanitizesDomain(t *testing.T) {
	got := UploadOnlyTargetDir("*.example.com")
	want := filepath.Join(UploadOnlyBaseDir(), "_.example.com")
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

// TestDeployToUploadOnlyCopiesFiles 验证仅保存模式会校验证书并发布到目标目录。
func TestDeployToUploadOnlyCopiesFiles(t *testing.T) {
	sourceDir := t.TempDir()
	workDir := t.TempDir()
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(workDir); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWD)
	})

	writeTestCertificatePair(t, sourceDir, "example.com")

	if err := Deploy(sourceDir, "example.com"); err != nil {
		t.Fatalf("DeployToUploadOnly: %v", err)
	}

	targetDir := UploadOnlyTargetDir("example.com")
	if _, err := os.Stat(filepath.Join(targetDir, "cert.pem")); err != nil {
		t.Fatalf("expected cert.pem in target dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "privateKey.key")); err != nil {
		t.Fatalf("expected privateKey.key in target dir: %v", err)
	}
}

// TestDeployToUploadOnlyRejectsMismatchedKey 验证证书和私钥不匹配时拒绝部署。
func TestDeployToUploadOnlyRejectsMismatchedKey(t *testing.T) {
	sourceDir := t.TempDir()
	writeTestCertificatePair(t, sourceDir, "example.com")

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	writePrivateKey(t, filepath.Join(sourceDir, "privateKey.key"), otherKey)

	if err := Deploy(sourceDir, "example.com"); err == nil {
		t.Fatal("DeployToUploadOnly expected mismatched key error")
	}
}

// TestDeployToUploadOnlyAcceptsWildcardDomain 验证泛域名证书可通过安全目录名校验。
func TestDeployToUploadOnlyAcceptsWildcardDomain(t *testing.T) {
	sourceDir := t.TempDir()
	workDir := t.TempDir()
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(workDir); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWD)
	})

	writeTestCertificatePair(t, sourceDir, "*.example.com")

	if err := Deploy(sourceDir, "*.example.com"); err != nil {
		t.Fatalf("DeployToUploadOnly wildcard: %v", err)
	}
}

// writeTestCertificatePair 写入测试用自签证书和匹配私钥。
func writeTestCertificatePair(t *testing.T, dir, domain string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o644); err != nil {
		t.Fatalf("write cert.pem: %v", err)
	}
	writePrivateKey(t, filepath.Join(dir, "privateKey.key"), privateKey)
}

// writePrivateKey 写入测试用 RSA 私钥。
func writePrivateKey(t *testing.T, path string, privateKey *rsa.PrivateKey) {
	t.Helper()

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err := os.WriteFile(path, keyPEM, 0o600); err != nil {
		t.Fatalf("write privateKey.key: %v", err)
	}
}
