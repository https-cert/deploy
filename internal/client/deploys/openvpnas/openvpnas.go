package openvpnas

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/https-cert/deploy/pkg/logger"
)

const (
	openVPNASSacliPath = "/usr/local/openvpn_as/scripts/sacli"
)

var openVPNASSacliCandidates = []string{
	openVPNASSacliPath,
	"sacli",
}

// Deploy 将证书导入 OpenVPN-AS 并重新启动服务。
func Deploy(ctx context.Context, sourceDir string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	sacliPath, err := getOpenVPNASSacliPath()
	if err != nil {
		return err
	}

	certPath := filepath.Join(sourceDir, "cert.pem")
	keyPath := filepath.Join(sourceDir, "privateKey.key")
	caBundlePath, err := getOpenVPNASCABundlePath(sourceDir)
	if err != nil {
		return err
	}

	if err := ensureRegularFile(certPath); err != nil {
		return fmt.Errorf("OpenVPN-AS 证书文件不可用: %w", err)
	}
	if err := ensureRegularFile(keyPath); err != nil {
		return fmt.Errorf("OpenVPN-AS 私钥文件不可用: %w", err)
	}

	if filepath.Base(caBundlePath) == "fullchain.pem" {
		logger.Warn("OpenVPN-AS 未找到 issuer.crt，回退使用 fullchain.pem 作为 CA Bundle", "path", caBundlePath)
	}

	commands := [][]string{
		{"--key", "cs.priv_key", "--value_file", keyPath, "ConfigPut"},
		{"--key", "cs.cert", "--value_file", certPath, "ConfigPut"},
		{"--key", "cs.ca_bundle", "--value_file", caBundlePath, "ConfigPut"},
		{"start"},
	}

	for _, args := range commands {
		if err := runOpenVPNASSacli(ctx, sacliPath, args...); err != nil {
			return err
		}
	}

	logger.Info("OpenVPN-AS 证书部署完成", "sacli", sacliPath)
	return nil
}

func getOpenVPNASSacliPath() (string, error) {
	for _, candidate := range openVPNASSacliCandidates {
		path, err := exec.LookPath(candidate)
		if err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("未找到 OpenVPN-AS sacli 命令，请确认已安装 OpenVPN-AS（默认路径: %s）", openVPNASSacliPath)
}

func getOpenVPNASCABundlePath(sourceDir string) (string, error) {
	candidates := []string{
		filepath.Join(sourceDir, "issuer.crt"),
		filepath.Join(sourceDir, "fullchain.pem"),
	}

	for _, candidate := range candidates {
		if err := ensureRegularFile(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("未找到 OpenVPN-AS CA Bundle 文件（issuer.crt 或 fullchain.pem）")
}

func ensureRegularFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s 是目录", path)
	}
	return nil
}

func runOpenVPNASSacli(parent context.Context, sacliPath string, args ...string) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, sacliPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("执行 OpenVPN-AS 命令失败: %w\n%s", err, string(output))
	}

	return nil
}
