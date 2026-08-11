package deploys

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

const feiNiuEnvironmentCheckCommand = "test -d /usr/trim/var/trim_connect/ssls && " +
	"test -f /usr/trim/etc/network_gateway_cert.conf && " +
	"command -v psql >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1 && " +
	"psql -X --set=ON_ERROR_STOP=1 -U postgres -d trim_connect -Atqc 'SELECT 1'"

// TestRemoteFeiNiuConnection 验证 SSH 登录、sudo 权限和飞牛核心部署环境。
func TestRemoteFeiNiuConnection(sshConfig *config.FeiNiuSSHConfig) error {
	if sshConfig == nil {
		return errors.New("飞牛 SSH 配置不能为空")
	}
	executor, err := newSSHExecutor(sshConfig, "飞牛", "anssl-feiniu")
	if err != nil {
		return err
	}
	defer executor.close()

	if _, err := executor.run(feiNiuEnvironmentCheckCommand, nil, true); err != nil {
		return fmt.Errorf("飞牛 SSH 已登录，但部署环境检查失败: %w", err)
	}
	return nil
}

// DeployToRemoteFeiNiu 通过 SSH 将证书部署到未安装 anssl CLI 的飞牛 OS。
func (cd *CertDeployer) DeployToRemoteFeiNiu(sourceDir, domain string, sshConfig *config.FeiNiuSSHConfig) error {
	if sshConfig == nil {
		return errors.New("飞牛 SSH 配置不能为空")
	}
	canonicalDomain, safeDomain, err := NormalizeDeploymentDomain(domain)
	if err != nil {
		return err
	}
	certificatePEM, err := os.ReadFile(filepath.Join(sourceDir, "cert.pem"))
	if err != nil {
		return fmt.Errorf("读取飞牛证书文件失败: %w", err)
	}
	privateKeyPEM, err := os.ReadFile(filepath.Join(sourceDir, "privateKey.key"))
	if err != nil {
		return fmt.Errorf("读取飞牛私钥文件失败: %w", err)
	}

	feiniuDeploymentMu.Lock()
	defer feiniuDeploymentMu.Unlock()

	executor, err := newSSHExecutor(sshConfig, "飞牛", "anssl-feiniu")
	if err != nil {
		return err
	}
	defer executor.close()

	remoteTempDir, err := executor.createTempDir()
	if err != nil {
		return err
	}
	defer func() {
		if cleanupErr := executor.removeTempDir(remoteTempDir); cleanupErr != nil {
			logger.Warn("清理飞牛 SSH 临时目录失败", "error", cleanupErr, "host", sshConfig.Host)
		}
	}()

	remoteCertificateFile := path.Join(remoteTempDir, "cert.pem")
	remotePrivateKeyFile := path.Join(remoteTempDir, "privateKey.key")
	if err := executor.upload(remoteCertificateFile, certificatePEM); err != nil {
		return fmt.Errorf("上传飞牛证书失败: %w", err)
	}
	if err := executor.upload(remotePrivateKeyFile, privateKeyPEM); err != nil {
		return fmt.Errorf("上传飞牛私钥失败: %w", err)
	}

	timestamp := time.Now().Unix()
	targetDir := path.Join(FeiNiuFixedPath, safeDomain, strconv.FormatInt(timestamp, 10))
	if err := executor.installCertificate(remoteCertificateFile, remotePrivateKeyFile, targetDir, safeDomain); err != nil {
		return err
	}
	if err := executor.updateDatabase(remoteTempDir, canonicalDomain, targetDir, certificatePEM, timestamp); err != nil {
		logger.Warn("远程更新飞牛数据库失败（可能需要手动更新）", "error", err, "domain", canonicalDomain)
	}
	if err := executor.updateNginxConfig(remoteTempDir, canonicalDomain, targetDir); err != nil {
		logger.Warn("远程更新飞牛网关配置失败（可能需要手动更新）", "error", err, "domain", canonicalDomain)
	}
	if err := executor.reloadServices(); err != nil {
		logger.Warn("远程重启飞牛服务失败（可能需要手动重启）", "error", err, "host", sshConfig.Host)
	}

	logger.Info("证书已通过 SSH 部署到飞牛", "host", sshConfig.Host, "path", targetDir, "domain", canonicalDomain)
	return nil
}

// installCertificate 将临时证书原子复制到飞牛固定证书目录。
func (executor *sshExecutor) installCertificate(remoteCertificateFile, remotePrivateKeyFile, targetDir, safeDomain string) error {
	domainDir := path.Dir(targetDir)
	targetCertificateFile := path.Join(targetDir, safeDomain+".crt")
	targetPrivateKeyFile := path.Join(targetDir, safeDomain+".key")
	command := strings.Join([]string{
		"rm -rf -- " + quotePOSIXShellArg(domainDir),
		"mkdir -p -- " + quotePOSIXShellArg(targetDir),
		"install -m 0644 " + quotePOSIXShellArg(remoteCertificateFile) + " " + quotePOSIXShellArg(targetCertificateFile),
		"install -m 0600 " + quotePOSIXShellArg(remotePrivateKeyFile) + " " + quotePOSIXShellArg(targetPrivateKeyFile),
		"chgrp -R root -- " + quotePOSIXShellArg(targetDir),
	}, " && ")
	if _, err := executor.run(command, nil, true); err != nil {
		return fmt.Errorf("安装飞牛远程证书失败: %w", err)
	}
	return nil
}

// updateDatabase 通过远端 psql 更新飞牛证书记录。
func (executor *sshExecutor) updateDatabase(remoteTempDir, domain, targetDir string, certificatePEM []byte, timestamp int64) error {
	encryptType, issuedBy := feiNiuCertificateMetadata(certificatePEM)
	variables := map[string]string{
		"domain":       domain,
		"valid_from":   strconv.FormatInt(timestamp*1000, 10),
		"valid_to":     strconv.FormatInt((timestamp+90*24*60*60)*1000, 10),
		"encrypt_type": encryptType,
		"issued_by":    issuedBy,
		"current_time": strconv.FormatInt(time.Now().UnixMilli(), 10),
		"private_key":  path.Join(targetDir, SanitizeDomain(domain)+".key"),
		"certificate":  path.Join(targetDir, SanitizeDomain(domain)+".crt"),
		"issuer":       "",
	}
	remoteSQLFile := path.Join(remoteTempDir, "feiniu.sql")
	if err := executor.upload(remoteSQLFile, []byte(feiniuUpsertSQL)); err != nil {
		return fmt.Errorf("上传飞牛数据库脚本失败: %w", err)
	}
	if _, err := executor.run(buildRemoteFeiNiuPSQLCommand(variables, remoteSQLFile), nil, true); err != nil {
		return fmt.Errorf("执行飞牛数据库更新失败: %w", err)
	}
	return nil
}

// feiNiuCertificateMetadata 从叶证书提取飞牛数据库需要的加密类型和颁发者。
func feiNiuCertificateMetadata(certificatePEM []byte) (encryptType, issuedBy string) {
	encryptType = "RSA"
	issuedBy = "Let's Encrypt"
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return encryptType, issuedBy
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return encryptType, issuedBy
	}
	if certificate.PublicKeyAlgorithm == x509.ECDSA {
		encryptType = "ECDSA"
	}
	if certificate.Issuer.CommonName != "" {
		issuedBy = certificate.Issuer.CommonName
	} else if certificate.Issuer.String() != "" {
		issuedBy = certificate.Issuer.String()
	}
	return encryptType, issuedBy
}

// buildRemoteFeiNiuPSQLCommand 使用独立 shell 参数传递 psql 变量，避免拼接进 SQL 源码。
func buildRemoteFeiNiuPSQLCommand(variables map[string]string, remoteSQLFile string) string {
	arguments := []string{"psql", "-X", "--set=ON_ERROR_STOP=1", "-U", "postgres", "-d", "trim_connect"}
	keys := make([]string, 0, len(variables))
	for key := range variables {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		arguments = append(arguments, "--set="+key+"="+variables[key])
	}
	arguments = append(arguments, "-f", remoteSQLFile)
	quotedArguments := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		quotedArguments = append(quotedArguments, quotePOSIXShellArg(argument))
	}
	return strings.Join(quotedArguments, " ")
}

// updateNginxConfig 在本地解析 JSON 后，通过 SSH 备份并原子替换飞牛网关配置。
func (executor *sshExecutor) updateNginxConfig(remoteTempDir, domain, targetDir string) error {
	resolvedOutput, err := executor.run("readlink -f "+quotePOSIXShellArg(feiniuNginxConfigFile), nil, false)
	if err != nil {
		return fmt.Errorf("解析飞牛远程网关配置路径失败: %w", err)
	}
	resolvedConfigFile := strings.TrimSpace(string(resolvedOutput))
	if !strings.HasPrefix(resolvedConfigFile, "/usr/trim/") || path.Clean(resolvedConfigFile) != resolvedConfigFile {
		return fmt.Errorf("飞牛远程网关配置路径不安全: %q", resolvedConfigFile)
	}
	content, err := executor.run("cat "+quotePOSIXShellArg(resolvedConfigFile), nil, true)
	if err != nil {
		return fmt.Errorf("读取飞牛远程网关配置失败: %w", err)
	}
	newContent, err := renderFeiniuNginxConfig(content, domain, targetDir)
	if err != nil {
		return err
	}
	remoteConfigFile := path.Join(remoteTempDir, "network_gateway_cert.conf")
	if err := executor.upload(remoteConfigFile, newContent); err != nil {
		return fmt.Errorf("上传飞牛远程网关配置失败: %w", err)
	}
	backupFile := resolvedConfigFile + "." + strconv.FormatInt(time.Now().UnixNano(), 10) + ".bak"
	stagingFile := resolvedConfigFile + ".anssl.tmp." + strconv.FormatInt(time.Now().UnixNano(), 10)
	command := "staging=" + quotePOSIXShellArg(stagingFile) + "; " +
		"trap 'rm -f -- \"$staging\"' EXIT; " +
		"cp -p " + quotePOSIXShellArg(resolvedConfigFile) + " " + quotePOSIXShellArg(backupFile) + " && " +
		"cp -p " + quotePOSIXShellArg(resolvedConfigFile) + " \"$staging\" && " +
		"cat " + quotePOSIXShellArg(remoteConfigFile) + " > \"$staging\" && " +
		"mv \"$staging\" " + quotePOSIXShellArg(resolvedConfigFile) + "; " +
		"result=$?; trap - EXIT; rm -f -- \"$staging\"; exit $result"
	if _, err := executor.run(command, nil, true); err != nil {
		return fmt.Errorf("写入飞牛远程网关配置失败: %w", err)
	}
	return nil
}

// reloadServices 重启飞牛使用证书的系统服务。
func (executor *sshExecutor) reloadServices() error {
	_, err := executor.run("systemctl restart webdav.service smbftpd.service trim_nginx.service", nil, true)
	return err
}
