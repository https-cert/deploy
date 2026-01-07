package deploys

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

// DeployToFeiNiu 部署证书到飞牛目录
func (cd *CertDeployer) DeployToFeiNiu(sourceDir, feiNiuPath, domain string) error {
	// 飞牛目标目录：/usr/trim/var/trim_connect/ssls/{域名}/{当前时间秒单位}
	timestamp := time.Now().Unix()
	domainDir := filepath.Join(feiNiuPath, domain)
	targetDir := filepath.Join(domainDir, fmt.Sprintf("%d", timestamp))

	// 检查域名目录是否存在，如果存在则删除
	if _, err := os.Stat(domainDir); err == nil {
		logger.Info("检测到旧证书目录，准备删除", "path", domainDir)
		if err := os.RemoveAll(domainDir); err != nil {
			if isPermissionError(err) {
				logger.Warn("普通权限删除失败，尝试使用 sudo", "error", err)
				cmd := exec.Command("sudo", "rm", "-rf", domainDir)
				if output, err := cmd.CombinedOutput(); err != nil {
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
		{filepath.Join(sourceDir, "cert.pem"), filepath.Join(targetDir, domain+".crt"), "证书文件"},
		{filepath.Join(sourceDir, "privateKey.key"), filepath.Join(targetDir, domain+".key"), "私钥文件"},
	}

	for _, file := range certFiles {
		// 检查源文件是否存在
		if _, err := os.Stat(file.src); os.IsNotExist(err) {
			logger.Warn("源文件不存在，跳过", "file", file.src, "desc", file.desc)
			continue
		}

		// 复制文件
		if err := CopyFileWithMode(file.src, file.dst, 0755); err != nil {
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

	logger.Info("证书已部署到飞牛目录", "path", targetDir, "cert", domain+".crt", "key", domain+".key")
	return nil
}

// changeGroupToRoot 修改目录和文件的组为 root
func changeGroupToRoot(targetDir string) error {
	// 尝试使用 chgrp 修改组为 root
	cmd := exec.Command("chgrp", "-R", "root", targetDir)
	if _, err := cmd.CombinedOutput(); err != nil {
		// 如果普通权限失败，尝试使用 sudo
		logger.Warn("普通权限修改组失败，尝试使用 sudo", "error", err)
		cmd = exec.Command("sudo", "chgrp", "-R", "root", targetDir)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("修改组为root失败: %w, output: %s", err, string(output))
		}
	}
	logger.Info("已修改组为root", "path", targetDir)
	return nil
}

// updateFeiniuDatabase 更新飞牛OS数据库证书信息
func updateFeiniuDatabase(domain, certPath string, validFrom, validTo int64) error {
	// 获取证书文件路径
	certFile := filepath.Join(certPath, domain+".crt")
	keyFile := filepath.Join(certPath, domain+".key")
	issuerFile := "" // 不使用 issuer_certificate.crt

	// 获取当前时间戳（毫秒）
	currentTime := time.Now().UnixMilli()

	// 获取证书加密类型和颁发者（使用openssl）
	encryptType := "RSA" // 默认
	issuedBy := "Let's Encrypt"

	cmd := exec.Command("openssl", "x509", "-in", certFile, "-noout", "-text")
	if output, err := cmd.CombinedOutput(); err == nil {
		outputStr := string(output)
		// 检测加密类型
		if strings.Contains(outputStr, "ECDSA") || strings.Contains(outputStr, "ECC") {
			encryptType = "ECDSA"
		}
		// 获取颁发者
		cmd = exec.Command("openssl", "x509", "-in", certFile, "-noout", "-issuer")
		if issuerOutput, err := cmd.CombinedOutput(); err == nil {
			issuerStr := string(issuerOutput)
			// 提取颁发者名称（取最后一个等号后的内容）
			parts := strings.Split(issuerStr, "=")
			if len(parts) > 0 {
				issuedBy = strings.TrimSpace(parts[len(parts)-1])
			}
		}
	}

	// 检查证书是否已存在
	checkSQL := fmt.Sprintf("SELECT domain FROM cert WHERE domain = '%s';", domain)
	cmd = exec.Command("psql", "-t", "-A", "-U", "postgres", "-d", "trim_connect", "-c", checkSQL)
	output, err := cmd.CombinedOutput()

	if err == nil && strings.TrimSpace(string(output)) != "" {
		// 证书存在，执行UPDATE
		updateSQL := fmt.Sprintf(`UPDATE cert SET
			valid_from = %d,
			valid_to = %d,
			encrypt_type = '%s',
			issued_by = '%s',
			last_renew_time = %d,
			des = '由anssl自动部署的证书',
			private_key = '%s',
			certificate = '%s',
			issuer_certificate = '%s',
			status = 'suc',
			updated_time = %d
			WHERE domain = '%s';`,
			validFrom, validTo, encryptType, issuedBy, currentTime,
			keyFile, certFile, issuerFile, currentTime, domain)

		cmd = exec.Command("psql", "-U", "postgres", "-d", "trim_connect", "-c", updateSQL)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("更新数据库失败: %w, output: %s", err, string(output))
		}
		logger.Info("已更新飞牛数据库证书信息", "domain", domain)
	} else {
		// 证书不存在，执行INSERT
		// 获取下一个ID
		getIDSQL := "SELECT COALESCE(MAX(id), 0) + 1 FROM cert;"
		cmd = exec.Command("psql", "-t", "-A", "-U", "postgres", "-d", "trim_connect", "-c", getIDSQL)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("获取下一个ID失败: %w", err)
		}
		nextID := strings.TrimSpace(string(output))

		insertSQL := fmt.Sprintf(`INSERT INTO cert VALUES (
			%s, '%s', '*%s,%s', %d, %d, '%s', '%s', %d,
			'由anssl自动部署的证书', 0, null, 'upload', null,
			'%s', '%s', '%s', 'suc', %d, %d);`,
			nextID, domain, domain, domain, validFrom, validTo, encryptType, issuedBy, currentTime,
			keyFile, certFile, issuerFile, currentTime, currentTime)

		cmd = exec.Command("psql", "-U", "postgres", "-d", "trim_connect", "-c", insertSQL)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("插入数据库失败: %w, output: %s", err, string(output))
		}
		logger.Info("已插入飞牛数据库证书信息", "domain", domain)
	}

	return nil
}

// updateFeiniuNginxConfig 更新飞牛OS Nginx配置文件
func updateFeiniuNginxConfig(domain, certPath string) error {
	configFile := "/usr/trim/etc/network_gateway_cert.conf"
	certFile := filepath.Join(certPath, domain+".crt") // 使用 .crt 而不是 fullchain.crt
	keyFile := filepath.Join(certPath, domain+".key")

	// 备份配置文件
	backupFile := fmt.Sprintf("%s.%d.bak", configFile, time.Now().Unix())
	cmd := exec.Command("cp", "-fL", configFile, backupFile)
	if err := cmd.Run(); err != nil {
		logger.Warn("备份Nginx配置失败", "error", err)
	}

	// 读取配置文件
	content, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("读取Nginx配置失败: %w", err)
	}

	// 新的证书配置条目
	newEntry := fmt.Sprintf(`{"host":"%s","cert":"%s","key":"%s"},`, domain, certFile, keyFile)

	contentStr := string(content)
	var newContent string

	// 检查域名是否已存在
	if strings.Contains(contentStr, `"host":"`+domain+`"`) {
		// 已存在，替换旧配置
		// 使用正则表达式替换（简化处理，直接字符串查找替换）
		lines := strings.Split(contentStr, "\n")
		for i, line := range lines {
			if strings.Contains(line, `"host":"`+domain+`"`) {
				lines[i] = newEntry
			}
		}
		newContent = strings.Join(lines, "\n")
	} else {
		// 不存在，添加到数组开头
		// 移除开头的 [
		contentStr = strings.TrimLeft(contentStr, "[\n ")
		newContent = "[" + newEntry + "\n" + contentStr
	}

	// 写回配置文件
	if err := os.WriteFile(configFile, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("写入Nginx配置失败: %w", err)
	}

	// 验证配置是否包含新证书路径
	verifyContent, _ := os.ReadFile(configFile)
	if !strings.Contains(string(verifyContent), certPath) {
		return fmt.Errorf("验证Nginx配置失败：未找到证书路径")
	}

	logger.Info("已更新飞牛Nginx配置", "domain", domain)
	return nil
}

// reloadFeiniuServices 重启飞牛OS相关服务
func reloadFeiniuServices() error {
	services := []string{"webdav.service", "smbftpd.service", "trim_nginx.service"}

	for _, service := range services {
		cmd := exec.Command("systemctl", "restart", service)
		if output, err := cmd.CombinedOutput(); err != nil {
			logger.Warn("重启服务失败", "service", service, "error", err, "output", string(output))
			// 尝试使用 sudo
			cmd = exec.Command("sudo", "systemctl", "restart", service)
			if output, err := cmd.CombinedOutput(); err != nil {
				logger.Warn("使用sudo重启服务也失败", "service", service, "error", err, "output", string(output))
			}
		} else {
			logger.Info("已重启服务", "service", service)
		}
	}

	return nil
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

	if !sslConfig.FeiNiuEnabled {
		return fmt.Errorf("未启用飞牛部署 (ssl.feiNiuEnabled)")
	}

	// 创建certs目录
	if err := os.MkdirAll(CertsDir, 0755); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	safeDomain := SanitizeDomain(domain)
	fileName := fmt.Sprintf("%s_certificates.zip", safeDomain)
	zipFile := filepath.Join(CertsDir, fileName)

	// 下载zip文件
	if err := cd.downloadFunc(url, zipFile); err != nil {
		return fmt.Errorf("下载证书失败: %w", err)
	}

	logger.Info("证书下载完成", "file", zipFile)

	defer func() {
		if _, err := os.Stat(zipFile); err == nil {
			os.Remove(zipFile)
		}
	}()

	folderName := safeDomain + "_certificates"
	extractDir := filepath.Join(CertsDir, folderName)

	if err := ExtractZip(zipFile, extractDir); err != nil {
		os.RemoveAll(extractDir)
		return fmt.Errorf("解压证书失败: %w", err)
	}
	defer os.RemoveAll(extractDir)

	// 部署到飞牛目录（使用固定路径）
	if err := cd.DeployToFeiNiu(extractDir, FeiNiuFixedPath, domain); err != nil {
		return fmt.Errorf("部署到飞牛失败: %w", err)
	}

	logger.Info("飞牛证书部署完成", "domain", domain)
	return nil
}
