package caddy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/https-cert/deploy/internal/client/deploys/shared"
	"github.com/https-cert/deploy/pkg/logger"
)

// Deploy 部署证书到 Caddy 证书目录并生成可 import 的 Caddyfile 片段。
func Deploy(sourceDir, caddyPath, folderName, safeDomain string) error {
	return DeployWithContext(context.Background(), sourceDir, caddyPath, folderName, safeDomain)
}

// DeployWithContext 部署证书并将调用方 context 传递给原子发布事务。
func DeployWithContext(ctx context.Context, sourceDir, caddyPath, folderName, safeDomain string) error {
	return deployWithContext(ctx, sourceDir, caddyPath, folderName, safeDomain, "")
}

// DeployAndReloadWithContext 将片段生成与可选 reload 纳入同一发布事务。
func DeployAndReloadWithContext(ctx context.Context, sourceDir, caddyPath, folderName, safeDomain, caddyConfig string) error {
	return deployWithContext(ctx, sourceDir, caddyPath, folderName, safeDomain, caddyConfig)
}

func deployWithContext(ctx context.Context, sourceDir, caddyPath, folderName, safeDomain, caddyConfig string) error {
	if err := shared.ValidateCertificateFiles(sourceDir, safeDomain); err != nil {
		return err
	}
	if err := os.MkdirAll(caddyPath, 0755); err != nil {
		return fmt.Errorf("创建 Caddy 证书目录失败: %w", err)
	}

	targetDir, err := shared.SafeJoinUnderBase(caddyPath, folderName)
	if err != nil {
		return err
	}
	return shared.PublishDirectoryWithValidationContext(ctx, sourceDir, targetDir, func() error {
		if err := GenerateCaddyTLSSnippet(caddyPath, folderName, safeDomain); err != nil {
			return fmt.Errorf("生成 Caddy TLS 配置失败: %w", err)
		}
		logger.Info("证书文件夹已更新", "path", targetDir)
		if caddyConfig != "" && IsCaddyAvailable() {
			if err := ValidateCaddyConfigWithContext(ctx, caddyConfig); err != nil {
				return fmt.Errorf("caddy 配置校验失败: %w", err)
			}
			if err := ReloadCaddyWithContext(ctx, caddyConfig); err != nil {
				return fmt.Errorf("caddy 重新加载失败: %w", err)
			}
		}
		return nil
	})
}

// GenerateCaddyTLSSnippet 生成可在站点 block 中 import 的 tls 指令片段。
func GenerateCaddyTLSSnippet(caddyPath, folderName, safeDomain string) error {
	if err := shared.ValidateSafeDomainName(safeDomain); err != nil {
		return fmt.Errorf("Caddy 域名无效: %w", err)
	}
	certDir, err := shared.SafeJoinUnderBase(caddyPath, folderName)
	if err != nil {
		return err
	}
	configFile := filepath.Join(certDir, fmt.Sprintf("%s.caddy", safeDomain))
	certPath := filepath.Join(certDir, "cert.pem")
	keyPath := filepath.Join(certDir, "privateKey.key")

	content := fmt.Sprintf(`# Caddy TLS 证书配置 - %s
# 在站点 block 内使用: import %s
tls %s %s
`, safeDomain, configFile, certPath, keyPath)

	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("写入 Caddy 配置文件失败: %w", err)
	}
	logger.Info("Caddy TLS 配置已生成", "file", configFile)
	logger.Info("使用方法: 在 Caddyfile 站点 block 中添加 import", configFile)
	return nil
}

// IsCaddyAvailable 检查 caddy 命令是否可用。
func IsCaddyAvailable() bool {
	_, err := exec.LookPath("caddy")
	return err == nil
}

// TestConnectionWithContext 检查 Caddy 目录，并在可用时校验 Caddyfile。
func TestConnectionWithContext(ctx context.Context, caddyPath, caddyConfig string) error {
	if caddyPath == "" {
		return fmt.Errorf("未配置 Caddy 证书目录 (ssl.caddy.path)")
	}
	info, err := os.Stat(caddyPath)
	if err != nil {
		return fmt.Errorf("Caddy 证书目录不可用: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("Caddy 证书路径不是目录: %s", caddyPath)
	}
	if caddyConfig == "" || !IsCaddyAvailable() {
		return nil
	}
	return ValidateCaddyConfigWithContext(ctx, caddyConfig)
}

// ValidateCaddyConfigWithContext 使用 caddy validate 校验配置。
func ValidateCaddyConfigWithContext(parent context.Context, caddyConfig string) error {
	if caddyConfig == "" {
		return fmt.Errorf("未配置 Caddyfile 路径 (ssl.caddy.config)")
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "caddy", "validate", "--config", caddyConfig, "--adapter", "caddyfile")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, string(output))
	}
	return nil
}

// ReloadCaddyWithContext 通过 caddy reload 热加载配置。
func ReloadCaddyWithContext(parent context.Context, caddyConfig string) error {
	if caddyConfig == "" {
		return fmt.Errorf("未配置 Caddyfile 路径 (ssl.caddy.config)")
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "caddy", "reload", "--config", caddyConfig, "--adapter", "caddyfile")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, string(output))
	}
	logger.Info("caddy 重新加载成功")
	return nil
}
