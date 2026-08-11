package deploys

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	feiNiuSSHConnectTimeout = 15 * time.Second
	feiNiuSSHCommandTimeout = 30 * time.Second
)

var feiNiuKnownHostsMu sync.Mutex

const feiNiuEnvironmentCheckCommand = "test -d /usr/trim/var/trim_connect/ssls && " +
	"test -f /usr/trim/etc/network_gateway_cert.conf && " +
	"command -v psql >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1 && " +
	"psql -X --set=ON_ERROR_STOP=1 -U postgres -d trim_connect -Atqc 'SELECT 1'"

// feiNiuSSHExecutor 封装飞牛远端命令执行及 sudo 提权。
type feiNiuSSHExecutor struct {
	client   *ssh.Client // client 已完成主机密钥校验的 SSH 客户端
	password string      // password SSH 登录及 sudo 使用的密码
	isRoot   bool        // isRoot 表示 SSH 会话是否已经是 root 用户
}

// sshCommandResult 保存异步 SSH 命令的完整结果。
type sshCommandResult struct {
	output []byte // output 仅包含供调用方消费的标准输出
	stderr []byte // stderr 保存远端诊断信息，不混入 JSON 等机器可读输出
	err    error  // err SSH 会话返回的执行错误
}

// TestRemoteFeiNiuConnection 验证 SSH 登录、sudo 权限和飞牛核心部署环境。
func TestRemoteFeiNiuConnection(sshConfig *config.FeiNiuSSHConfig) error {
	if sshConfig == nil {
		return errors.New("飞牛 SSH 配置不能为空")
	}
	executor, err := newFeiNiuSSHExecutor(sshConfig)
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

	executor, err := newFeiNiuSSHExecutor(sshConfig)
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

// newFeiNiuSSHExecutor 建立带超时、密码认证和 TOFU 主机密钥校验的 SSH 连接。
func newFeiNiuSSHExecutor(sshConfig *config.FeiNiuSSHConfig) (*feiNiuSSHExecutor, error) {
	hostKeyCallback, err := newFeiNiuHostKeyCallback(config.GetSSHKnownHostsFile())
	if err != nil {
		return nil, err
	}
	clientConfig := &ssh.ClientConfig{
		User:            sshConfig.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(sshConfig.Password)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         feiNiuSSHConnectTimeout,
	}
	address := net.JoinHostPort(sshConfig.Host, strconv.Itoa(sshConfig.Port))
	client, err := ssh.Dial("tcp", address, clientConfig)
	if err != nil {
		return nil, fmt.Errorf("连接飞牛 SSH %s 失败: %w", address, err)
	}
	executor := &feiNiuSSHExecutor{client: client, password: sshConfig.Password}
	output, err := executor.run("id -u", nil, false)
	if err != nil {
		executor.close()
		return nil, fmt.Errorf("读取飞牛 SSH 用户身份失败: %w", err)
	}
	executor.isRoot = strings.TrimSpace(string(output)) == "0"
	return executor, nil
}

// newFeiNiuHostKeyCallback 首次记录主机密钥，并在后续密钥变化时拒绝连接。
func newFeiNiuHostKeyCallback(knownHostsFile string) (ssh.HostKeyCallback, error) {
	if err := ensureKnownHostsFile(knownHostsFile); err != nil {
		return nil, fmt.Errorf("准备 SSH known_hosts 失败: %w", err)
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		feiNiuKnownHostsMu.Lock()
		defer feiNiuKnownHostsMu.Unlock()

		verifier, err := knownhosts.New(knownHostsFile)
		if err != nil {
			return fmt.Errorf("读取 SSH known_hosts 失败: %w", err)
		}
		verificationErr := verifier(hostname, remote, key)
		if verificationErr == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if !errors.As(verificationErr, &keyErr) || len(keyErr.Want) > 0 {
			return fmt.Errorf("飞牛 SSH 主机密钥校验失败: %w", verificationErr)
		}

		file, err := os.OpenFile(knownHostsFile, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("写入 SSH known_hosts 失败: %w", err)
		}
		line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
		if _, err := file.WriteString(line + "\n"); err != nil {
			_ = file.Close()
			return fmt.Errorf("记录 SSH 主机密钥失败: %w", err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return fmt.Errorf("同步 SSH known_hosts 失败: %w", err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("关闭 SSH known_hosts 失败: %w", err)
		}
		logger.Info("已首次信任飞牛 SSH 主机密钥", "host", hostname, "fingerprint", ssh.FingerprintSHA256(key))
		return nil
	}, nil
}

// ensureKnownHostsFile 创建并收紧自动维护的 SSH known_hosts 文件权限。
func ensureKnownHostsFile(knownHostsFile string) error {
	if err := os.MkdirAll(filepath.Dir(knownHostsFile), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(knownHostsFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// close 关闭 SSH 客户端连接。
func (executor *feiNiuSSHExecutor) close() {
	if executor != nil && executor.client != nil {
		_ = executor.client.Close()
	}
}

// run 执行单条 SSH 命令；非 root 会话的特权命令自动通过 sudo 提权。
func (executor *feiNiuSSHExecutor) run(command string, input []byte, privileged bool) ([]byte, error) {
	if privileged && !executor.isRoot {
		command = "sudo -S -p '' sh -c " + quotePOSIXShellArg(command)
		input = append([]byte(executor.password+"\n"), input...)
	}
	return runSSHCommand(executor.client, command, input, feiNiuSSHCommandTimeout)
}

// runSSHCommand 在超时后主动关闭会话，避免远端命令无限阻塞部署 ACK。
func runSSHCommand(client *ssh.Client, command string, input []byte, timeout time.Duration) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	if len(input) > 0 {
		session.Stdin = bytes.NewReader(input)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	resultChannel := make(chan sshCommandResult, 1)
	go func() {
		commandErr := session.Run(command)
		resultChannel <- sshCommandResult{output: stdout.Bytes(), stderr: stderr.Bytes(), err: commandErr}
	}()

	select {
	case result := <-resultChannel:
		_ = session.Close()
		if result.err != nil {
			return result.output, fmt.Errorf("远端命令执行失败: %w, stderr: %s", result.err, strings.TrimSpace(string(result.stderr)))
		}
		return result.output, nil
	case <-time.After(timeout):
		_ = session.Close()
		return nil, fmt.Errorf("远端命令执行超时: %s", commandName(command))
	}
}

// commandName 仅返回命令首词，避免超时错误泄露完整远端参数。
func commandName(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return "unknown"
	}
	return fields[0]
}

// createTempDir 在远端创建仅 SSH 用户可读写的临时目录。
func (executor *feiNiuSSHExecutor) createTempDir() (string, error) {
	output, err := executor.run("umask 077 && mktemp -d /tmp/anssl-feiniu.XXXXXX", nil, false)
	if err != nil {
		return "", fmt.Errorf("创建飞牛 SSH 临时目录失败: %w", err)
	}
	tempDir := strings.TrimSpace(string(output))
	if !isSafeFeiNiuTempDir(tempDir) {
		return "", fmt.Errorf("飞牛 SSH 返回了非法临时目录: %q", tempDir)
	}
	return tempDir, nil
}

// isSafeFeiNiuTempDir 限制清理目标只能是 mktemp 生成的飞牛专用目录。
func isSafeFeiNiuTempDir(tempDir string) bool {
	const prefix = "/tmp/anssl-feiniu."
	if !strings.HasPrefix(tempDir, prefix) || len(tempDir) <= len(prefix) || path.Clean(tempDir) != tempDir {
		return false
	}
	return strings.IndexFunc(strings.TrimPrefix(tempDir, prefix), func(character rune) bool {
		return !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9'))
	}) < 0
}

// removeTempDir 清理经过固定前缀校验的 SSH 临时目录。
func (executor *feiNiuSSHExecutor) removeTempDir(tempDir string) error {
	if !isSafeFeiNiuTempDir(tempDir) {
		return fmt.Errorf("拒绝清理非法 SSH 临时目录: %q", tempDir)
	}
	_, err := executor.run("rm -rf -- "+quotePOSIXShellArg(tempDir), nil, false)
	return err
}

// upload 通过 SSH 标准输入将敏感文件写入远端受限临时目录。
func (executor *feiNiuSSHExecutor) upload(remoteFile string, content []byte) error {
	if !isSafeFeiNiuTempDir(path.Dir(remoteFile)) {
		return fmt.Errorf("拒绝写入非法 SSH 临时路径: %q", remoteFile)
	}
	_, err := executor.run("umask 077 && cat > "+quotePOSIXShellArg(remoteFile), content, false)
	return err
}

// installCertificate 将临时证书原子复制到飞牛固定证书目录。
func (executor *feiNiuSSHExecutor) installCertificate(remoteCertificateFile, remotePrivateKeyFile, targetDir, safeDomain string) error {
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
func (executor *feiNiuSSHExecutor) updateDatabase(remoteTempDir, domain, targetDir string, certificatePEM []byte, timestamp int64) error {
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
func (executor *feiNiuSSHExecutor) updateNginxConfig(remoteTempDir, domain, targetDir string) error {
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
func (executor *feiNiuSSHExecutor) reloadServices() error {
	_, err := executor.run("systemctl restart webdav.service smbftpd.service trim_nginx.service", nil, true)
	return err
}

// quotePOSIXShellArg 将单个值安全编码为 POSIX shell 参数。
func quotePOSIXShellArg(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
