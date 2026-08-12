package deploys

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

var remoteRustFSDeploymentMu sync.Mutex

// TestRustFSConnection 根据配置验证 RustFS 本机目录或 SSH 远程写入能力。
func TestRustFSConnection() error {
	rustFS := config.GetConfig().SSL.RustFS
	if rustFS == nil || rustFS.Path == "" {
		return errors.New("未配置 RustFS TLS 目录 (ssl.rustFS.path)")
	}
	if config.IsSSHConfigured(&rustFS.SSHConfig) {
		return testRemoteRustFSConnection(rustFS)
	}
	probeDir, err := os.MkdirTemp(rustFS.Path, ".anssl-rustfs-check-*")
	if err != nil {
		return fmt.Errorf("RustFS 本机目录不可写: %w", err)
	}
	return os.RemoveAll(probeDir)
}

// testRemoteRustFSConnection 验证 SSH 登录、目标目录创建权限和远端基础命令。
func testRemoteRustFSConnection(rustFS *config.RustFSConfig) error {
	executor, err := newSSHExecutor(&rustFS.SSHConfig, "RustFS", "anssl-rustfs")
	if err != nil {
		return err
	}
	defer executor.close()

	for _, command := range []string{"install", "mktemp", "mv", "rm"} {
		if _, err := executor.run("command -v "+quotePOSIXShellArg(command)+" >/dev/null 2>&1", nil, false); err != nil {
			return fmt.Errorf("RustFS SSH 环境缺少命令 %s: %w", command, err)
		}
	}
	privileged, err := executor.needsPrivilegeForPath(rustFS.Path)
	if err != nil {
		return fmt.Errorf("检查 RustFS 远程目录权限失败: %w", err)
	}
	probeFile := path.Join(rustFS.Path, ".anssl-write-check-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	command := "install -d -m 0755 -- " + quotePOSIXShellArg(rustFS.Path) + " && " +
		"umask 077 && : > " + quotePOSIXShellArg(probeFile) + " && rm -f -- " + quotePOSIXShellArg(probeFile)
	if _, err := executor.run(command, nil, privileged); err != nil {
		return fmt.Errorf("RustFS 远程目录不可写: %w", err)
	}
	return nil
}

// DeployToRustFS 部署证书到 RustFS 目录
func (cd *CertDeployer) DeployToRustFS(sourceDir, rustFSBasePath, safeDomain string) error {
	if err := ValidateCertificateFiles(sourceDir, safeDomain); err != nil {
		return err
	}

	// RustFS 目标目录（使用域名作为子目录）
	targetDir, err := SafeJoinUnderBase(rustFSBasePath, safeDomain)
	if err != nil {
		return err
	}
	stagingDir, err := os.MkdirTemp(filepath.Dir(targetDir), filepath.Base(targetDir)+".prepare-*")
	if err != nil {
		return fmt.Errorf("创建RustFS临时目录失败: %w", err)
	}
	defer os.RemoveAll(stagingDir)

	// 复制并重命名证书文件
	// cert.pem -> rustfs_cert.pem
	srcCert := filepath.Join(sourceDir, "cert.pem")
	dstCert := filepath.Join(stagingDir, "rustfs_cert.pem")
	if err := CopyFileWithMode(srcCert, dstCert, 0644); err != nil {
		return fmt.Errorf("复制证书文件失败: %w", err)
	}

	// 复制并重命名私钥文件
	// privateKey.key -> rustfs_key.pem
	srcKey := filepath.Join(sourceDir, "privateKey.key")
	dstKey := filepath.Join(stagingDir, "rustfs_key.pem")
	if err := CopyFileWithMode(srcKey, dstKey, 0600); err != nil {
		return fmt.Errorf("复制私钥文件失败: %w", err)
	}

	if err := PublishDirectoryWithRollback(stagingDir, targetDir); err != nil {
		return fmt.Errorf("发布RustFS证书目录失败: %w", err)
	}

	logger.Info("证书已部署到RustFS目录", "path", targetDir, "cert", "rustfs_cert.pem", "key", "rustfs_key.pem")
	return nil
}

// DeployToRemoteRustFS 通过 SSH 将 RustFS 证书原子发布到远程目录。
func (cd *CertDeployer) DeployToRemoteRustFS(sourceDir, safeDomain string, rustFS *config.RustFSConfig) error {
	if rustFS == nil {
		return errors.New("RustFS SSH 配置不能为空")
	}
	if err := ValidateCertificateFiles(sourceDir, safeDomain); err != nil {
		return err
	}
	certificatePEM, err := os.ReadFile(filepath.Join(sourceDir, "cert.pem"))
	if err != nil {
		return fmt.Errorf("读取 RustFS 证书文件失败: %w", err)
	}
	privateKeyPEM, err := os.ReadFile(filepath.Join(sourceDir, "privateKey.key"))
	if err != nil {
		return fmt.Errorf("读取 RustFS 私钥文件失败: %w", err)
	}

	remoteRustFSDeploymentMu.Lock()
	defer remoteRustFSDeploymentMu.Unlock()

	executor, err := newSSHExecutor(&rustFS.SSHConfig, "RustFS", "anssl-rustfs")
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
			logger.WarnLocal("清理 RustFS SSH 临时目录失败", "error", cleanupErr, "host", rustFS.Host)
		}
	}()

	remoteCertificateFile := path.Join(remoteTempDir, "rustfs_cert.pem")
	remotePrivateKeyFile := path.Join(remoteTempDir, "rustfs_key.pem")
	if err := executor.upload(remoteCertificateFile, certificatePEM); err != nil {
		return fmt.Errorf("上传 RustFS 证书失败: %w", err)
	}
	if err := executor.upload(remotePrivateKeyFile, privateKeyPEM); err != nil {
		return fmt.Errorf("上传 RustFS 私钥失败: %w", err)
	}
	if err := executor.publishRustFSCertificate(remoteCertificateFile, remotePrivateKeyFile, rustFS.Path, safeDomain); err != nil {
		return err
	}

	logger.InfoLocal("证书已通过 SSH 部署到 RustFS", "host", rustFS.Host, "path", path.Join(rustFS.Path, safeDomain), "domain", safeDomain)
	return nil
}

// needsPrivilegeForPath 判断创建或替换目标路径是否需要 root/sudo 权限。
func (executor *sshExecutor) needsPrivilegeForPath(targetPath string) (bool, error) {
	if executor.isRoot {
		return false, nil
	}
	command := "target=" + quotePOSIXShellArg(targetPath) + "; " +
		"while [ ! -e \"$target\" ]; do parent=$(dirname -- \"$target\"); " +
		"[ \"$parent\" != \"$target\" ] || exit 1; target=$parent; done; " +
		"test -d \"$target\" && test -w \"$target\""
	if _, err := executor.run(command, nil, false); err == nil {
		return false, nil
	}
	if _, err := executor.run("true", nil, true); err != nil {
		return false, fmt.Errorf("当前 SSH 用户无目录写入权限且无法 sudo: %w", err)
	}
	return true, nil
}

// publishRustFSCertificate 在远端同级目录中暂存并带回滚地替换域名证书目录。
func (executor *sshExecutor) publishRustFSCertificate(remoteCertificateFile, remotePrivateKeyFile, basePath, safeDomain string) error {
	targetDir := path.Join(basePath, safeDomain)
	token := strconv.FormatInt(time.Now().UnixNano(), 10)
	stagingDir := path.Join(basePath, "."+safeDomain+".anssl-stage."+token)
	backupDir := path.Join(basePath, "."+safeDomain+".anssl-backup."+token)
	privileged, err := executor.needsPrivilegeForPath(basePath)
	if err != nil {
		return err
	}

	commands := []string{
		"set -eu",
		"install -d -m 0755 -- " + quotePOSIXShellArg(basePath),
		"rm -rf -- " + quotePOSIXShellArg(stagingDir) + " " + quotePOSIXShellArg(backupDir),
		"install -d -m 0755 -- " + quotePOSIXShellArg(stagingDir),
		"install -m 0644 -- " + quotePOSIXShellArg(remoteCertificateFile) + " " + quotePOSIXShellArg(path.Join(stagingDir, "rustfs_cert.pem")),
		"install -m 0600 -- " + quotePOSIXShellArg(remotePrivateKeyFile) + " " + quotePOSIXShellArg(path.Join(stagingDir, "rustfs_key.pem")),
		"if [ -e " + quotePOSIXShellArg(targetDir) + " ]; then mv -- " + quotePOSIXShellArg(targetDir) + " " + quotePOSIXShellArg(backupDir) + "; fi",
		"if mv -- " + quotePOSIXShellArg(stagingDir) + " " + quotePOSIXShellArg(targetDir) + "; then " +
			"rm -rf -- " + quotePOSIXShellArg(backupDir) + "; else " +
			"rm -rf -- " + quotePOSIXShellArg(targetDir) + "; " +
			"if [ -e " + quotePOSIXShellArg(backupDir) + " ]; then mv -- " + quotePOSIXShellArg(backupDir) + " " + quotePOSIXShellArg(targetDir) + "; fi; exit 1; fi",
	}
	if _, err := executor.run(strings.Join(commands, "; "), nil, privileged); err != nil {
		return fmt.Errorf("发布 RustFS 远程证书目录失败: %w", err)
	}
	return nil
}

// DeployCertificateToRustFS 仅部署证书到 RustFS
func (cd *CertDeployer) DeployCertificateToRustFS(domain, url string) error {
	sslConfig := config.GetConfig().SSL
	rustFS := sslConfig.RustFS
	if rustFS == nil || rustFS.Path == "" {
		return fmt.Errorf("未配置 RustFS TLS 目录 (ssl.rustFS.path)")
	}

	canonicalDomain, safeDomain, extractDir, cleanup, err := cd.prepareCertificateArchive(domain, url)
	if err != nil {
		return err
	}
	defer cleanup()
	domain = canonicalDomain

	var deployErr error
	if config.IsSSHConfigured(&rustFS.SSHConfig) {
		deployErr = cd.DeployToRemoteRustFS(extractDir, safeDomain, rustFS)
	} else {
		deployErr = cd.DeployToRustFS(extractDir, rustFS.Path, safeDomain)
	}
	if deployErr != nil {
		return fmt.Errorf("部署到RustFS失败: %w", deployErr)
	}

	logger.Info("RustFS证书部署完成", "domain", domain)
	return nil
}
