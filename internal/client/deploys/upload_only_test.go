package deploys

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUploadOnlyTargetDirSanitizesDomain(t *testing.T) {
	got := UploadOnlyTargetDir("*.example.com")
	want := filepath.Join(UploadOnlyBaseDir(), "_.example.com")
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

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

	if err := os.WriteFile(filepath.Join(sourceDir, "cert.pem"), []byte("cert"), 0o644); err != nil {
		t.Fatalf("write cert.pem: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "privateKey.key"), []byte("key"), 0o644); err != nil {
		t.Fatalf("write privateKey.key: %v", err)
	}

	deployer := NewCertDeployer(nil)
	if err := deployer.DeployToUploadOnly(sourceDir, "example.com"); err != nil {
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
