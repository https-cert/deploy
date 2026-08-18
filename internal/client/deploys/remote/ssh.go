package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"runtime"
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
	sshConnectTimeout = 15 * time.Second
	sshCommandTimeout = 30 * time.Second
)

var sshKnownHostsMu sync.Mutex

// Executor 封装通用 SSH 认证、远端命令执行和受限临时文件传输。
type Executor struct {
	client       *ssh.Client // client 是已完成主机密钥校验的 SSH 客户端
	sudoPassword string      // sudoPassword 是非 root 用户执行特权命令时使用的密码
	isRoot       bool        // isRoot 表示 SSH 会话是否已经是 root 用户
	purpose      string      // purpose 是本地日志和错误中的部署目标名称
	tempPrefix   string      // tempPrefix 限制临时目录只能使用预定义业务前缀
}

// sshCommandResult 保存异步 SSH 命令的完整结果。
type sshCommandResult struct {
	output []byte // output 仅包含供调用方消费的标准输出
	stderr []byte // stderr 保存远端诊断信息，不混入机器可读输出
	err    error  // err 是 SSH 会话返回的执行错误
}

// NewExecutor 建立支持密码或私钥认证并带 TOFU 主机密钥校验的 SSH 连接。
func NewExecutor(sshConfig *config.SSHConfig, purpose, tempPrefix string, knownHostsFiles ...string) (*Executor, error) {
	return NewExecutorContext(context.Background(), sshConfig, purpose, tempPrefix, knownHostsFiles...)
}

// NewExecutorContext 建立可由调用方取消的 SSH 连接。
func NewExecutorContext(ctx context.Context, sshConfig *config.SSHConfig, purpose, tempPrefix string, knownHostsFiles ...string) (*Executor, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if sshConfig == nil {
		return nil, fmt.Errorf("%s SSH 配置不能为空", purpose)
	}
	if !isSafeSSHTempPrefix(tempPrefix) {
		return nil, fmt.Errorf("%s SSH 临时目录前缀无效", purpose)
	}
	knownHostsFile := ""
	if len(knownHostsFiles) > 0 {
		knownHostsFile = knownHostsFiles[0]
	}
	if knownHostsFile == "" {
		knownHostsFile = "known_hosts"
	}
	hostKeyCallback, err := newSSHHostKeyCallback(knownHostsFile)
	if err != nil {
		return nil, err
	}
	authMethods, err := buildSSHAuthMethods(sshConfig)
	if err != nil {
		return nil, fmt.Errorf("加载%s SSH 认证失败: %w", purpose, err)
	}
	clientConfig := &ssh.ClientConfig{
		User:            sshConfig.Username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         sshConnectTimeout,
	}
	address := net.JoinHostPort(sshConfig.Host, strconv.Itoa(sshConfig.Port))
	dialCtx, cancel := context.WithTimeout(ctx, sshConnectTimeout)
	defer cancel()
	networkConnection, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("连接%s SSH %s 失败: %w", purpose, address, err)
	}
	_ = networkConnection.SetDeadline(time.Now().Add(sshConnectTimeout))
	handshakeDone := make(chan struct{})
	go func() {
		select {
		case <-dialCtx.Done():
			_ = networkConnection.Close()
		case <-handshakeDone:
		}
	}()
	sshConnection, channels, requests, err := ssh.NewClientConn(networkConnection, address, clientConfig)
	close(handshakeDone)
	if err != nil {
		_ = networkConnection.Close()
		return nil, fmt.Errorf("连接%s SSH %s 失败: %w", purpose, address, err)
	}
	_ = networkConnection.SetDeadline(time.Time{})
	client := ssh.NewClient(sshConnection, channels, requests)
	executor := &Executor{
		client:       client,
		sudoPassword: sshConfig.Password,
		purpose:      purpose,
		tempPrefix:   tempPrefix,
	}
	output, err := executor.RunContext(ctx, "id -u", nil, false)
	if err != nil {
		executor.Close()
		return nil, fmt.Errorf("读取%s SSH 用户身份失败: %w", purpose, err)
	}
	executor.isRoot = strings.TrimSpace(string(output)) == "0"
	return executor, nil
}

// buildSSHAuthMethods 根据私钥优先规则构造单一且确定的 SSH 认证方式。
func buildSSHAuthMethods(sshConfig *config.SSHConfig) ([]ssh.AuthMethod, error) {
	if sshConfig.PrivateKeyPath == "" {
		if sshConfig.Password == "" {
			return nil, errors.New("密码和私钥路径不能同时为空")
		}
		return []ssh.AuthMethod{ssh.Password(sshConfig.Password)}, nil
	}

	privateKeyPEM, err := os.ReadFile(sshConfig.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("读取私钥文件失败: %w", err)
	}
	if runtime.GOOS != "windows" {
		if info, statErr := os.Stat(sshConfig.PrivateKeyPath); statErr == nil && info.Mode().Perm()&0077 != 0 {
			logger.WarnLocal("SSH 私钥文件权限过宽，建议调整为 0600", "path", sshConfig.PrivateKeyPath, "mode", info.Mode().Perm())
		}
	}

	var signer ssh.Signer
	if sshConfig.PrivateKeyPassphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(privateKeyPEM, []byte(sshConfig.PrivateKeyPassphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(privateKeyPEM)
	}
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %w", err)
	}
	return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
}

// newSSHHostKeyCallback 首次记录主机密钥，并在后续密钥变化时拒绝连接。
func newSSHHostKeyCallback(knownHostsFile string) (ssh.HostKeyCallback, error) {
	if err := ensureKnownHostsFile(knownHostsFile); err != nil {
		return nil, fmt.Errorf("准备 SSH known_hosts 失败: %w", err)
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		sshKnownHostsMu.Lock()
		defer sshKnownHostsMu.Unlock()

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
			return fmt.Errorf("SSH 主机密钥校验失败: %w", verificationErr)
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
		logger.InfoLocal("已首次信任 SSH 主机密钥", "host", hostname, "fingerprint", ssh.FingerprintSHA256(key))
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

// Close 关闭 SSH 客户端连接。
func (executor *Executor) Close() {
	if executor != nil && executor.client != nil {
		_ = executor.client.Close()
	}
}

// Run 执行单条 SSH 命令；非 root 会话的特权命令自动通过 sudo 提权。
func (executor *Executor) Run(command string, input []byte, privileged bool) ([]byte, error) {
	return executor.RunContext(context.Background(), command, input, privileged)
}

// RunContext 执行 SSH 命令，并在取消或硬超时后关闭会话并等待其退出。
func (executor *Executor) RunContext(ctx context.Context, command string, input []byte, privileged bool) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if privileged && !executor.isRoot {
		command = "sudo -S -p '' sh -c " + QuotePOSIXShellArg(command)
		input = append([]byte(executor.sudoPassword+"\n"), input...)
	}
	return runSSHCommandContext(ctx, executor.client, command, input, sshCommandTimeout)
}

// runSSHCommandContext 在调用方取消或硬超时后主动关闭会话，并等待执行 goroutine 收敛。
func runSSHCommandContext(ctx context.Context, client *ssh.Client, command string, input []byte, timeout time.Duration) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
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

	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case result := <-resultChannel:
		_ = session.Close()
		if result.err != nil {
			return result.output, fmt.Errorf("远端命令执行失败: %w, stderr: %s", result.err, strings.TrimSpace(string(result.stderr)))
		}
		return result.output, nil
	case <-commandCtx.Done():
		_ = session.Close()
		result := <-resultChannel
		if errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
			return result.output, fmt.Errorf("远端命令执行超时: %s: %w", commandName(command), context.DeadlineExceeded)
		}
		return result.output, commandCtx.Err()
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

// CreateTempDir 在远端创建仅 SSH 用户可读写的业务专用临时目录。
func (executor *Executor) CreateTempDir() (string, error) {
	return executor.CreateTempDirContext(context.Background())
}

// CreateTempDirContext 在远端创建临时目录并响应调用方取消。
func (executor *Executor) CreateTempDirContext(ctx context.Context) (string, error) {
	pattern := "/tmp/" + executor.tempPrefix + ".XXXXXX"
	output, err := executor.RunContext(ctx, "umask 077 && mktemp -d "+QuotePOSIXShellArg(pattern), nil, false)
	if err != nil {
		return "", fmt.Errorf("创建%s SSH 临时目录失败: %w", executor.purpose, err)
	}
	tempDir := strings.TrimSpace(string(output))
	if !executor.isSafeTempDir(tempDir) {
		return "", fmt.Errorf("%s SSH 返回了非法临时目录: %q", executor.purpose, tempDir)
	}
	return tempDir, nil
}

// isSafeSSHTempPrefix 验证代码内定义的 SSH 临时目录前缀不含路径字符。
func isSafeSSHTempPrefix(prefix string) bool {
	if !strings.HasPrefix(prefix, "anssl-") || len(prefix) <= len("anssl-") {
		return false
	}
	return strings.IndexFunc(prefix, func(character rune) bool {
		return !((character >= 'a' && character <= 'z') || character == '-')
	}) < 0
}

// isSafeTempDir 限制清理目标只能是当前业务通过 mktemp 创建的目录。
func (executor *Executor) isSafeTempDir(tempDir string) bool {
	prefix := "/tmp/" + executor.tempPrefix + "."
	if !strings.HasPrefix(tempDir, prefix) || len(tempDir) <= len(prefix) || path.Clean(tempDir) != tempDir {
		return false
	}
	return strings.IndexFunc(strings.TrimPrefix(tempDir, prefix), func(character rune) bool {
		return !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9'))
	}) < 0
}

// RemoveTempDir 清理经过固定前缀校验的 SSH 临时目录。
func (executor *Executor) RemoveTempDir(tempDir string) error {
	return executor.RemoveTempDirContext(context.Background(), tempDir)
}

// RemoveTempDirContext 清理经过固定前缀校验的远端临时目录。
func (executor *Executor) RemoveTempDirContext(ctx context.Context, tempDir string) error {
	if !executor.isSafeTempDir(tempDir) {
		return fmt.Errorf("拒绝清理非法 SSH 临时目录: %q", tempDir)
	}
	_, err := executor.RunContext(ctx, "rm -rf -- "+QuotePOSIXShellArg(tempDir), nil, false)
	return err
}

// Upload 通过 SSH 标准输入将敏感文件写入远端受限临时目录。
func (executor *Executor) Upload(remoteFile string, content []byte) error {
	return executor.UploadContext(context.Background(), remoteFile, content)
}

// UploadContext 通过 SSH 标准输入写入文件并响应调用方取消。
func (executor *Executor) UploadContext(ctx context.Context, remoteFile string, content []byte) error {
	if !executor.isSafeTempDir(path.Dir(remoteFile)) {
		return fmt.Errorf("拒绝写入非法 SSH 临时路径: %q", remoteFile)
	}
	_, err := executor.RunContext(ctx, "umask 077 && cat > "+QuotePOSIXShellArg(remoteFile), content, false)
	return err
}

// IsRoot 返回当前 SSH 会话是否使用 root 用户。
func (executor *Executor) IsRoot() bool {
	return executor != nil && executor.isRoot
}

// QuotePOSIXShellArg 将单个值安全编码为 POSIX shell 参数。
func QuotePOSIXShellArg(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
