package caddy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenerateCaddyTLSSnippet 验证 Caddy TLS 片段生成内容和证书路径。
func TestGenerateCaddyTLSSnippet(t *testing.T) {
	base := t.TempDir()
	safeDomain := "_.example.com"
	if err := os.MkdirAll(filepath.Join(base, safeDomain), 0755); err != nil {
		t.Fatal(err)
	}
	if err := GenerateCaddyTLSSnippet(base, safeDomain, safeDomain); err != nil {
		t.Fatalf("GenerateCaddyTLSSnippet() error = %v", err)
	}
	content, err := os.ReadFile(filepath.Join(base, safeDomain, safeDomain+".caddy"))
	if err != nil {
		t.Fatalf("read snippet: %v", err)
	}
	text := string(content)
	if !strings.Contains(text, "tls ") || !strings.Contains(text, "cert.pem") || !strings.Contains(text, "privateKey.key") {
		t.Fatalf("snippet missing tls directives:\n%s", text)
	}
}

// TestGenerateCaddyTLSSnippetRejectsInvalidDomain 验证非法域名不会生成 Caddy 片段。
func TestGenerateCaddyTLSSnippetRejectsInvalidDomain(t *testing.T) {
	if err := GenerateCaddyTLSSnippet(t.TempDir(), "bad", "bad/path"); err == nil {
		t.Fatal("invalid domain should fail")
	}
}
