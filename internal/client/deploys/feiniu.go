package deploys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

const feiniuCommandTimeout = 30 * time.Second

var feiniuNginxConfigFile = "/usr/trim/etc/network_gateway_cert.conf"

// TestFeiNiuConnection 根据配置测试本机或 SSH 远程飞牛部署环境。
func TestFeiNiuConnection() error {
	sshConfig := config.GetConfig().SSL.FeiNiu
	if sshConfig != nil {
		return TestRemoteFeiNiuConnection(sshConfig)
	}
	return testLocalFeiNiuEnvironment()
}

// testLocalFeiNiuEnvironment 验证 CLI 所在机器具备飞牛内置部署所需的路径、命令和数据库。
func testLocalFeiNiuEnvironment() error {
	for _, requiredPath := range []string{FeiNiuFixedPath, feiniuNginxConfigFile} {
		if _, err := os.Stat(requiredPath); err != nil {
			return fmt.Errorf("飞牛本机部署环境缺少 %s: %w", requiredPath, err)
		}
	}
	for _, command := range []string{"psql", "systemctl"} {
		if _, err := exec.LookPath(command); err != nil {
			return fmt.Errorf("飞牛本机部署环境缺少命令 %s: %w", command, err)
		}
	}
	if output, err := runFeiniuPSQL(map[string]string{}, "SELECT 1;\n"); err != nil {
		return fmt.Errorf("连接飞牛 trim_connect 数据库失败: %w, output: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// DeployToFeiNiu 部署证书到飞牛目录
func (cd *CertDeployer) DeployToFeiNiu(sourceDir, feiNiuPath, domain string) error {
	canonicalDomain, safeDomain, err := NormalizeDeploymentDomain(domain)
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
	domainDir, err := SafeJoinUnderBase(feiNiuPath, safeDomain)
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
				output, err := runFeiniuCommand(feiniuCommandTimeout, "sudo", "rm", "-rf", domainDir)
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
		if err := CopyFileWithMode(file.src, file.dst, mode); err != nil {
			if isPermissionError(err) {
				return fmt.Errorf("复制%s失败: 权限不足\n\n请在飞牛系统上执行以下命令修复权限:\n  sudo chown -R $USER %s\n\n原始错误: %w", file.desc, feiNiuPath, err)
			}
			return fmt.Errorf("复制%s失败: %w", file.desc, err)
		}
		logger.Info("已复制文件", "dst", file.dst, "desc", file.desc)
	}

	// 修改目录和文件的组为 root（飞牛系统要求）
	if err := changeGroupToRoot(targetDir); err != nil {
		logger.Warn("修改组为root失败（可能影响飞牛系统读取证书）", "error", err, "path", targetDir)
	}

	// 获取证书时间戳（用于数据库）
	certTimestamp := timestamp * 1000 // 转为毫秒
	// 证书有效期：90天后（毫秒）
	renewTimestamp := (timestamp + 90*24*60*60) * 1000

	// 更新飞牛OS数据库
	if err := updateFeiniuDatabase(domain, targetDir, certTimestamp, renewTimestamp); err != nil {
		logger.Warn("更新飞牛数据库失败（可能需要手动更新）", "error", err, "domain", domain)
	}

	// 更新飞牛OS Nginx配置
	if err := updateFeiniuNginxConfig(domain, targetDir); err != nil {
		logger.Warn("更新Nginx配置失败（可能需要手动更新）", "error", err, "domain", domain)
	}

	// 重启飞牛OS服务
	if err := reloadFeiniuServices(); err != nil {
		logger.Warn("重启飞牛服务失败（可能需要手动重启）", "error", err)
	}

	logger.Info("证书已部署到飞牛目录", "path", targetDir, "cert", safeDomain+".crt", "key", safeDomain+".key")
	return nil
}

// changeGroupToRoot 修改目录和文件的组为 root
func changeGroupToRoot(targetDir string) error {
	// 尝试使用 chgrp 修改组为 root
	if _, err := runFeiniuCommand(feiniuCommandTimeout, "chgrp", "-R", "root", targetDir); err != nil {
		// 如果普通权限失败，尝试使用 sudo
		logger.Warn("普通权限修改组失败，尝试使用 sudo", "error", err)
		if output, err := runFeiniuCommand(feiniuCommandTimeout, "sudo", "chgrp", "-R", "root", targetDir); err != nil {
			return fmt.Errorf("修改组为root失败: %w, output: %s", err, string(output))
		}
	}
	logger.Info("已修改组为root", "path", targetDir)
	return nil
}

// updateFeiniuDatabase 更新飞牛OS数据库证书信息
func updateFeiniuDatabase(domain, certPath string, validFrom, validTo int64) error {
	safeDomain := SanitizeDomain(domain)
	if safeDomain == "" {
		return fmt.Errorf("飞牛证书域名无效")
	}
	// 获取证书文件路径
	certFile := path.Join(certPath, safeDomain+".crt")
	keyFile := path.Join(certPath, safeDomain+".key")
	issuerFile := "" // 不使用 issuer_certificate.crt

	// 获取当前时间戳（毫秒）
	currentTime := time.Now().UnixMilli()

	// 获取证书加密类型和颁发者（使用openssl）
	encryptType := "RSA" // 默认
	issuedBy := "Let's Encrypt"

	output, opensslErr := runFeiniuCommand(feiniuCommandTimeout, "openssl", "x509", "-in", certFile, "-noout", "-text")
	if opensslErr == nil {
		outputStr := string(output)
		// 检测加密类型
		if strings.Contains(outputStr, "ECDSA") || strings.Contains(outputStr, "ECC") {
			encryptType = "ECDSA"
		}
		// 获取颁发者
		if issuerOutput, err := runFeiniuCommand(feiniuCommandTimeout, "openssl", "x509", "-in", certFile, "-noout", "-issuer"); err == nil {
			issuerStr := string(issuerOutput)
			// 提取颁发者名称（取最后一个等号后的内容）
			parts := strings.Split(issuerStr, "=")
			if len(parts) > 0 {
				issuedBy = strings.TrimSpace(parts[len(parts)-1])
			}
		}
	}

	variables := map[string]string{
		"domain":       domain,
		"valid_from":   strconv.FormatInt(validFrom, 10),
		"valid_to":     strconv.FormatInt(validTo, 10),
		"encrypt_type": encryptType,
		"issued_by":    issuedBy,
		"current_time": strconv.FormatInt(currentTime, 10),
		"private_key":  keyFile,
		"certificate":  certFile,
		"issuer":       issuerFile,
	}
	output, err := runFeiniuPSQL(variables, feiniuUpsertSQL)
	if err != nil {
		return fmt.Errorf("更新飞牛数据库失败: %w, output: %s", err, strings.TrimSpace(string(output)))
	}
	logger.Info("已更新飞牛数据库证书信息", "domain", domain)
	return nil
}

const feiniuUpsertSQL = `
BEGIN;
LOCK TABLE cert IN EXCLUSIVE MODE;
SELECT EXISTS(SELECT 1 FROM cert WHERE domain = :'domain') AS cert_exists \gset
\if :cert_exists
UPDATE cert SET
    valid_from = :'valid_from'::bigint,
    valid_to = :'valid_to'::bigint,
    encrypt_type = :'encrypt_type',
    issued_by = :'issued_by',
    last_renew_time = :'current_time'::bigint,
    des = '由anssl自动部署的证书',
    private_key = :'private_key',
    certificate = :'certificate',
    issuer_certificate = :'issuer',
    status = 'suc',
    updated_time = :'current_time'::bigint
WHERE domain = :'domain';
\else
INSERT INTO cert VALUES (
    (SELECT COALESCE(MAX(id), 0) + 1 FROM cert),
    :'domain', '*' || :'domain' || ',' || :'domain',
    :'valid_from'::bigint, :'valid_to'::bigint, :'encrypt_type', :'issued_by', :'current_time'::bigint,
    '由anssl自动部署的证书', 0, null, 'upload', null,
    :'private_key', :'certificate', :'issuer', 'suc', :'current_time'::bigint, :'current_time'::bigint
);
\endif
COMMIT;
`

// runFeiniuPSQL executes a parameterized psql script with a strict timeout and transaction errors enabled.
func runFeiniuPSQL(variables map[string]string, script string) ([]byte, error) {
	args := buildFeiniuPSQLArgs(variables)

	ctx, cancel := context.WithTimeout(context.Background(), feiniuCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "psql", args...)
	cmd.Stdin = strings.NewReader(script)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("psql 执行超时")
	}
	return output, err
}

// buildFeiniuPSQLArgs keeps all untrusted SQL values in psql variables instead of SQL source text.
func buildFeiniuPSQLArgs(variables map[string]string) []string {
	args := []string{"-X", "--set=ON_ERROR_STOP=1", "-U", "postgres", "-d", "trim_connect"}
	keys := make([]string, 0, len(variables))
	for key := range variables {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--set="+key+"="+variables[key])
	}
	return args
}

// updateFeiniuNginxConfig 更新飞牛OS Nginx配置文件
func updateFeiniuNginxConfig(domain, certPath string) error {
	return updateFeiniuNginxConfigFile(feiniuNginxConfigFile, domain, certPath)
}

// updateFeiniuNginxConfigFile updates a Feiniu gateway certificate JSON file atomically.
func updateFeiniuNginxConfigFile(configFile, domain, certPath string) error {
	if SanitizeDomain(domain) == "" {
		return fmt.Errorf("飞牛证书域名无效")
	}

	resolvedConfigFile, err := filepath.EvalSymlinks(configFile)
	if err != nil {
		return fmt.Errorf("解析Nginx配置路径失败: %w", err)
	}
	content, err := os.ReadFile(resolvedConfigFile)
	if err != nil {
		return fmt.Errorf("读取Nginx配置失败: %w", err)
	}
	newContent, err := renderFeiniuNginxConfig(content, domain, certPath)
	if err != nil {
		return err
	}

	info, err := os.Stat(resolvedConfigFile)
	if err != nil {
		return fmt.Errorf("读取Nginx配置权限失败: %w", err)
	}
	backupFile := fmt.Sprintf("%s.%d.bak", resolvedConfigFile, time.Now().UnixNano())
	if err := CopyFileWithMode(resolvedConfigFile, backupFile, info.Mode().Perm()); err != nil {
		return fmt.Errorf("备份Nginx配置失败: %w", err)
	}
	if err := writeFileAtomically(resolvedConfigFile, newContent, info.Mode().Perm()); err != nil {
		return fmt.Errorf("写入Nginx配置失败: %w", err)
	}

	logger.Info("已更新飞牛Nginx配置", "domain", domain)
	return nil
}

// renderFeiniuNginxConfig 在内存中更新飞牛网关证书配置，供本机和 SSH 部署复用。
func renderFeiniuNginxConfig(content []byte, domain, certPath string) ([]byte, error) {
	safeDomain := SanitizeDomain(domain)
	if safeDomain == "" {
		return nil, fmt.Errorf("飞牛证书域名无效")
	}
	certFile := path.Join(certPath, safeDomain+".crt")
	keyFile := path.Join(certPath, safeDomain+".key")

	var entries []map[string]any
	if err := json.Unmarshal(content, &entries); err != nil {
		return nil, fmt.Errorf("解析Nginx配置失败，原文件未修改: %w", err)
	}
	replacement := map[string]any{"host": domain, "cert": certFile, "key": keyFile}
	found := false
	for index, entry := range entries {
		if host, ok := entry["host"].(string); ok && host == domain {
			updated := make(map[string]any, len(entry)+3)
			for key, value := range entry {
				updated[key] = value
			}
			updated["host"] = domain
			updated["cert"] = certFile
			updated["key"] = keyFile
			entries[index] = updated
			found = true
		}
	}
	if !found {
		entries = append([]map[string]any{replacement}, entries...)
	}
	newContent, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("序列化Nginx配置失败: %w", err)
	}
	newContent = append(newContent, '\n')
	return newContent, nil
}

// writeFileAtomically writes data through a same-directory temporary file and rename.
func writeFileAtomically(path string, data []byte, mode os.FileMode) (err error) {
	tempFile, err := os.CreateTemp(filepath.Dir(path), ".anssl-config-*")
	if err != nil {
		return err
	}
	tempPath := tempFile.Name()
	defer func() {
		_ = tempFile.Close()
		if err != nil {
			_ = os.Remove(tempPath)
		}
	}()
	if err = tempFile.Chmod(mode); err != nil {
		return err
	}
	if _, err = tempFile.Write(data); err != nil {
		return err
	}
	if err = tempFile.Sync(); err != nil {
		return err
	}
	if err = tempFile.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

// reloadFeiniuServices 重启飞牛OS相关服务
func reloadFeiniuServices() error {
	services := []string{"webdav.service", "smbftpd.service", "trim_nginx.service"}

	for _, service := range services {
		if output, err := runFeiniuCommand(feiniuCommandTimeout, "systemctl", "restart", service); err != nil {
			logger.Warn("重启服务失败", "service", service, "error", err, "output", string(output))
			// 尝试使用 sudo
			if output, err := runFeiniuCommand(feiniuCommandTimeout, "sudo", "systemctl", "restart", service); err != nil {
				logger.Warn("使用sudo重启服务也失败", "service", service, "error", err, "output", string(output))
			}
		} else {
			logger.Info("已重启服务", "service", service)
		}
	}

	return nil
}

// runFeiniuCommand executes a Feiniu system command with a bounded timeout.
func runFeiniuCommand(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("命令执行超时: %s", name)
	}
	return output, err
}

// isPermissionError 检查错误是否为权限错误
func isPermissionError(err error) bool {
	if err == nil {
		return false
	}

	// 检查是否为 EACCES (Permission denied) 或 EPERM (Operation not permitted)
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		// 同时检查错误类型和错误字符串
		if errors.Is(pathErr.Err, syscall.EACCES) || errors.Is(pathErr.Err, syscall.EPERM) {
			return true
		}
		// 检查错误字符串（兼容不同系统）
		errStr := pathErr.Err.Error()
		if errStr == "permission denied" || errStr == "operation not permitted" {
			return true
		}
	}

	return false
}

// DeployCertificateToFeiNiu 仅部署证书到飞牛
func (cd *CertDeployer) DeployCertificateToFeiNiu(domain, url string) error {
	sslConfig := config.GetConfig().SSL

	canonicalDomain, _, extractDir, cleanup, err := cd.prepareCertificateArchive(domain, url)
	if err != nil {
		return err
	}
	defer cleanup()
	domain = canonicalDomain
	if sslConfig.FeiNiu != nil {
		if err := cd.DeployToRemoteFeiNiu(extractDir, domain, sslConfig.FeiNiu); err != nil {
			return fmt.Errorf("通过 SSH 部署到飞牛失败: %w", err)
		}
		logger.InfoLocal("飞牛远程证书部署完成", "domain", domain, "host", sslConfig.FeiNiu.Host)
		return nil
	}

	// 部署到飞牛目录（使用固定路径）
	if err := cd.DeployToFeiNiu(extractDir, FeiNiuFixedPath, domain); err != nil {
		return fmt.Errorf("部署到飞牛失败: %w", err)
	}

	logger.Info("飞牛证书部署完成", "domain", domain)
	return nil
}
