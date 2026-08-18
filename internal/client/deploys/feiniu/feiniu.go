package feiniu

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/deploys/shared"
	"github.com/https-cert/deploy/pkg/logger"
)

// FixedPath 是飞牛 OS 本机证书固定部署目录。
const FixedPath = "/usr/trim/var/trim_connect/ssls"

var feiniuNginxConfigFile = "/usr/trim/etc/network_gateway_cert.conf"

var feiniuDeploymentLock = make(chan struct{}, 1)

// acquireDeploymentLock 获取飞牛本地和远程部署共享的可取消锁。
func acquireDeploymentLock(ctx context.Context) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case feiniuDeploymentLock <- struct{}{}:
		return func() { <-feiniuDeploymentLock }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TestFeiNiuConnection 根据配置测试本机或 SSH 远程飞牛部署环境。
func TestFeiNiuConnection() error {
	return TestFeiNiuConnectionWithContext(context.Background())
}

// TestFeiNiuConnectionWithContext 使用调用方 context 测试本机或 SSH 远程飞牛环境。
func TestFeiNiuConnectionWithContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	configuration := shared.ConfigurationFromContext(ctx)
	if configuration == nil || configuration.SSL == nil {
		return fmt.Errorf("SSL 配置未初始化")
	}
	sshConfig := configuration.SSL.FeiNiu
	if sshConfig != nil {
		return TestRemoteFeiNiuConnectionWithContext(ctx, sshConfig)
	}
	return testLocalFeiNiuEnvironmentWithContext(ctx)
}

// testLocalFeiNiuEnvironmentWithContext 使用调用方 context 验证本机飞牛部署环境。
func testLocalFeiNiuEnvironmentWithContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for _, requiredPath := range []string{FixedPath, feiniuNginxConfigFile} {
		if _, err := os.Stat(requiredPath); err != nil {
			return fmt.Errorf("飞牛本机部署环境缺少 %s: %w", requiredPath, err)
		}
	}
	for _, command := range []string{"psql", "systemctl"} {
		if _, err := exec.LookPath(command); err != nil {
			return fmt.Errorf("飞牛本机部署环境缺少命令 %s: %w", command, err)
		}
	}
	if output, err := runFeiniuPSQLContext(ctx, map[string]string{}, "SELECT 1;\n"); err != nil {
		return fmt.Errorf("连接飞牛 trim_connect 数据库失败: %w, output: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// DeployLocal 部署证书到飞牛本机目录。
func DeployLocal(sourceDir, feiNiuPath, domain string) error {
	return DeployLocalWithContext(context.Background(), sourceDir, feiNiuPath, domain)
}

// DeployLocalWithContext 使用调用方 context 部署证书到飞牛本机目录。
func DeployLocalWithContext(ctx context.Context, sourceDir, feiNiuPath, domain string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := shared.OperationContextError(ctx); err != nil {
		return err
	}
	canonicalDomain, safeDomain, err := shared.NormalizeDeploymentDomain(domain)
	if err != nil {
		return err
	}
	domain = canonicalDomain
	if safeDomain == "" {
		return fmt.Errorf("生成飞牛安全域名失败")
	}
	if err := shared.ValidateCertificateFiles(sourceDir, canonicalDomain); err != nil {
		return fmt.Errorf("校验飞牛证书文件失败: %w", err)
	}
	release, err := acquireDeploymentLock(ctx)
	if err != nil {
		return err
	}
	defer release()

	timestamp := time.Now().Unix()
	domainDir, err := shared.SafeJoinUnderBase(feiNiuPath, safeDomain)
	if err != nil {
		return err
	}
	targetDir := filepath.Join(domainDir, fmt.Sprintf("%d", timestamp))
	previousTargetDir := latestFeiniuTargetDir(domainDir)
	stagingDomainDir, err := os.MkdirTemp(feiNiuPath, "."+safeDomain+".anssl-stage-*")
	if err != nil {
		if isPermissionError(err) {
			return fmt.Errorf("创建飞牛证书临时目录失败: 权限不足\n\n请在飞牛系统上执行以下命令修复权限:\n  sudo chown -R $USER %s\n\n原始错误: %w", feiNiuPath, err)
		}
		return fmt.Errorf("创建飞牛证书临时目录失败: %w", err)
	}
	defer os.RemoveAll(stagingDomainDir)
	stagingTargetDir := filepath.Join(stagingDomainDir, strconv.FormatInt(timestamp, 10))
	if err := os.MkdirAll(stagingTargetDir, 0755); err != nil {
		return fmt.Errorf("创建飞牛证书暂存目录失败: %w", err)
	}
	if err := shared.CopyFileWithModeContext(ctx, filepath.Join(sourceDir, "cert.pem"), filepath.Join(stagingTargetDir, safeDomain+".crt"), 0644); err != nil {
		return fmt.Errorf("复制飞牛证书文件失败: %w", err)
	}
	if err := shared.CopyFileWithModeContext(ctx, filepath.Join(sourceDir, "privateKey.key"), filepath.Join(stagingTargetDir, safeDomain+".key"), 0600); err != nil {
		return fmt.Errorf("复制飞牛私钥文件失败: %w", err)
	}

	certTimestamp := timestamp * 1000
	renewTimestamp := (timestamp + 90*24*60*60) * 1000
	if err := shared.PublishDirectoryWithValidationContext(ctx, stagingDomainDir, domainDir, func() error {
		if err := changeGroupToRootContext(ctx, targetDir); err != nil {
			return err
		}
		if err := updateFeiniuDatabaseContext(ctx, domain, targetDir, certTimestamp, renewTimestamp); err != nil {
			restoreLocalFeiniuReferences(previousTargetDir, domain, certTimestamp, renewTimestamp)
			return err
		}
		if err := updateFeiniuNginxConfigContext(ctx, domain, targetDir); err != nil {
			restoreLocalFeiniuReferences(previousTargetDir, domain, certTimestamp, renewTimestamp)
			return err
		}
		if err := reloadFeiniuServicesContext(ctx); err != nil {
			restoreLocalFeiniuReferences(previousTargetDir, domain, certTimestamp, renewTimestamp)
			return err
		}
		return nil
	}); err != nil {
		restoreLocalFeiniuReferences(previousTargetDir, domain, certTimestamp, renewTimestamp)
		return fmt.Errorf("发布飞牛证书失败: %w", err)
	}

	logger.Info("证书已部署到飞牛目录", "path", targetDir, "cert", safeDomain+".crt", "key", safeDomain+".key")
	return nil
}

// latestFeiniuTargetDir 返回旧域名目录中最新的证书版本目录。
func latestFeiniuTargetDir(domainDir string) string {
	entries, err := os.ReadDir(domainDir)
	if err != nil {
		return ""
	}
	latest := ""
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if latest == "" || entry.Name() > filepath.Base(latest) {
			latest = filepath.Join(domainDir, entry.Name())
		}
	}
	return latest
}

// restoreLocalFeiniuReferences 在发布失败后尽量把数据库和网关引用恢复到旧目录。
func restoreLocalFeiniuReferences(previousTargetDir, domain string, validFrom, validTo int64) {
	if previousTargetDir == "" {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := updateFeiniuDatabaseContext(cleanupCtx, domain, previousTargetDir, validFrom, validTo); err != nil {
		logger.Warn("恢复飞牛数据库证书引用失败", "error", err, "domain", domain)
	}
	if err := updateFeiniuNginxConfigContext(cleanupCtx, domain, previousTargetDir); err != nil {
		logger.Warn("恢复飞牛网关证书引用失败", "error", err, "domain", domain)
	}
}
