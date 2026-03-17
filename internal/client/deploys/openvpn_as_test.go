package deploys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetOpenVPNASCABundlePathPrefersIssuer(t *testing.T) {
	sourceDir := t.TempDir()
	issuerPath := filepath.Join(sourceDir, "issuer.crt")
	fullChainPath := filepath.Join(sourceDir, "fullchain.pem")

	if err := os.WriteFile(issuerPath, []byte("issuer"), 0o644); err != nil {
		t.Fatalf("write issuer: %v", err)
	}
	if err := os.WriteFile(fullChainPath, []byte("fullchain"), 0o644); err != nil {
		t.Fatalf("write fullchain: %v", err)
	}

	got, err := getOpenVPNASCABundlePath(sourceDir)
	if err != nil {
		t.Fatalf("getOpenVPNASCABundlePath: %v", err)
	}

	if got != issuerPath {
		t.Fatalf("expected issuer path %q, got %q", issuerPath, got)
	}
}

func TestGetOpenVPNASCABundlePathFallsBackToFullChain(t *testing.T) {
	sourceDir := t.TempDir()
	fullChainPath := filepath.Join(sourceDir, "fullchain.pem")

	if err := os.WriteFile(fullChainPath, []byte("fullchain"), 0o644); err != nil {
		t.Fatalf("write fullchain: %v", err)
	}

	got, err := getOpenVPNASCABundlePath(sourceDir)
	if err != nil {
		t.Fatalf("getOpenVPNASCABundlePath: %v", err)
	}

	if got != fullChainPath {
		t.Fatalf("expected fullchain path %q, got %q", fullChainPath, got)
	}
}

func TestDeployToOpenVPNASRunsExpectedCommands(t *testing.T) {
	sourceDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourceDir, "cert.pem"), []byte("cert"), 0o644); err != nil {
		t.Fatalf("write cert.pem: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "privateKey.key"), []byte("key"), 0o644); err != nil {
		t.Fatalf("write privateKey.key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "issuer.crt"), []byte("issuer"), 0o644); err != nil {
		t.Fatalf("write issuer.crt: %v", err)
	}

	logFile := filepath.Join(t.TempDir(), "sacli.log")
	sacliPath := filepath.Join(t.TempDir(), "sacli")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$LOG_FILE\"\n"
	if err := os.WriteFile(sacliPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake sacli: %v", err)
	}

	originalCandidates := openVPNASSacliCandidates
	openVPNASSacliCandidates = []string{sacliPath}
	t.Cleanup(func() {
		openVPNASSacliCandidates = originalCandidates
	})

	if err := os.Setenv("LOG_FILE", logFile); err != nil {
		t.Fatalf("set LOG_FILE: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Unsetenv("LOG_FILE")
	})

	deployer := NewCertDeployer(nil)
	if err := deployer.DeployToOpenVPNAS(sourceDir); err != nil {
		t.Fatalf("DeployToOpenVPNAS: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read sacli log: %v", err)
	}

	logOutput := string(data)
	expectedFragments := []string{
		"--key cs.priv_key --value_file " + filepath.Join(sourceDir, "privateKey.key") + " ConfigPut",
		"--key cs.cert --value_file " + filepath.Join(sourceDir, "cert.pem") + " ConfigPut",
		"--key cs.ca_bundle --value_file " + filepath.Join(sourceDir, "issuer.crt") + " ConfigPut",
		"start",
	}
	for _, fragment := range expectedFragments {
		if !strings.Contains(logOutput, fragment) {
			t.Fatalf("expected log to contain %q, got %q", fragment, logOutput)
		}
	}
}
