package feiniu

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/https-cert/deploy/internal/client/deploys/shared"
	"github.com/https-cert/deploy/pkg/logger"
)

// FixedPath 是飞牛 OS 本机证书固定部署目录。
const FixedPath = "/usr/trim/var/trim_connect/ssls"

var feiniuNginxConfigFile = "/usr/trim/etc/network_gateway_cert.conf"

var feiniuDeploymentMu sync.Mutex

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
		return TestRemoteFeiNiuConnection(sshConfig)
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
	feiniuDeploymentMu.Lock()
	defer feiniuDeploymentMu.Unlock()

	// 飞牛目标目录：/usr/trim/var/trim_connect/ssls/{域名}/{当前时间秒单位}
	timestamp := time.Now().Unix()
	domainDir, err := shared.SafeJoinUnderBase(feiNiuPath, safeDomain)
	if err != nil {
		return err
	}
	targetDir := filepath.Join(domainDir, fmt.Sprintf("%d", timestamp))

	// 检查域名目录是否存在，如果存在则删除
	if _, err := os.Stat(domainDir); err == nil {
		logger.Info("检测到旧证书目录，准备删除", "path", domainDir)
		if err := os.RemoveAll(domainDir); err != nil {
			if isPermissionError(err) {
				logger.Warn("普通权限删除失败，尝试使用 sudo", "error", err)
				output, err := runFeiniuCommandContext(ctx, feiniuCommandTimeout, "sudo", "rm", "-rf", domainDir)
				if err != nil {
					return fmt.Errorf("删除旧证书目录失败: %w, output: %s", err, string(output))
				}
			} else {
				return fmt.Errorf("删除旧证书目录失败: %w", err)
			}
		}
		logger.Info("已删除旧证书目录", "path", domainDir)
	}

	// 创建目标目录
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		// 检查是否为权限错误
		if isPermissionError(err) {
			return fmt.Errorf("创建飞牛证书目录失败: 权限不足\n\n请在飞牛系统上执行以下命令修复权限:\n  sudo chown -R $USER %s\n\n原始错误: %w", feiNiuPath, err)
		}
		return fmt.Errorf("创建飞牛证书目录失败: %w", err)
	}

	// 部署飞牛OS所需的证书文件（仅部署 .crt 和 .key）
	certFiles := []struct {
		src  string
		dst  string
		desc string
	}{
		{filepath.Join(sourceDir, "cert.pem"), filepath.Join(targetDir, safeDomain+".crt"), "证书文件"},
		{filepath.Join(sourceDir, "privateKey.key"), filepath.Join(targetDir, safeDomain+".key"), "私钥文件"},
	}

	for _, file := range certFiles {
		// 检查源文件是否存在
		if _, err := os.Stat(file.src); os.IsNotExist(err) {
			logger.Warn("源文件不存在，跳过", "file", file.src, "desc", file.desc)
			continue
		}

		// 复制文件
		mode := os.FileMode(0644)
		if strings.HasSuffix(file.dst, ".key") {
			mode = 0600
		}
		if err := shared.CopyFileWithMode(file.src, file.dst, mode); err != nil {
			if isPermissionError(err) {
				return fmt.Errorf("复制%s失败: 权限不足\n\n请在飞牛系统上执行以下命令修复权限:\n  sudo chown -R $USER %s\n\n原始错误: %w", file.desc, feiNiuPath, err)
			}
			return fmt.Errorf("复制%s失败: %w", file.desc, err)
		}
		logger.Info("已复制文件", "dst", file.dst, "desc", file.desc)
	}

	// 修改目录和文件的组为 root（飞牛系统要求）
	if err := changeGroupToRootContext(ctx, targetDir); err != nil {
		logger.Warn("修改组为root失败（可能影响飞牛系统读取证书）", "error", err, "path", targetDir)
	}

	// 获取证书时间戳（用于数据库）
	certTimestamp := timestamp * 1000 // 转为毫秒
	// 证书有效期：90天后（毫秒）
	renewTimestamp := (timestamp + 90*24*60*60) * 1000

	// 更新飞牛OS数据库
	if err := updateFeiniuDatabaseContext(ctx, domain, targetDir, certTimestamp, renewTimestamp); err != nil {
		logger.Warn("更新飞牛数据库失败（可能需要手动更新）", "error", err, "domain", domain)
	}

	// 更新飞牛OS Nginx配置
	if err := updateFeiniuNginxConfigContext(ctx, domain, targetDir); err != nil {
		logger.Warn("更新Nginx配置失败（可能需要手动更新）", "error", err, "domain", domain)
	}

	// 重启飞牛OS服务
	if err := reloadFeiniuServicesContext(ctx); err != nil {
		logger.Warn("重启飞牛服务失败（可能需要手动重启）", "error", err)
	}

	logger.Info("证书已部署到飞牛目录", "path", targetDir, "cert", safeDomain+".crt", "key", safeDomain+".key")
	return nil
}
