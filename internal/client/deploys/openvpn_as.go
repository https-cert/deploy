package deploys

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

var openVPNASWebSSLPath = "/usr/local/openvpn_as/etc/web-ssl"

// DeployToOpenVPNAS 将证书导入 OpenVPN-AS 并重新启动服务。
func (cd *CertDeployer) DeployToOpenVPNAS(sourceDir string) error {
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
		if err := runOpenVPNASSacli(sacliPath, args...); err != nil {
			return err
		}
	}

	logger.Info("OpenVPN-AS 证书部署完成", "sacli", sacliPath)
	return nil
}

// DeployCertificateToOpenVPNAS 仅部署证书到 OpenVPN-AS。
func (cd *CertDeployer) DeployCertificateToOpenVPNAS(domain, url string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	if err := os.MkdirAll(CertsDir, 0755); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	safeDomain := SanitizeDomain(domain)
	fileName := fmt.Sprintf("%s_certificates.zip", safeDomain)
	zipFile := filepath.Join(CertsDir, fileName)

	if err := cd.downloadFunc(url, zipFile); err != nil {
		return fmt.Errorf("下载证书失败: %w", err)
	}

	logger.Info("证书下载完成", "file", zipFile)

	defer func() {
		if _, err := os.Stat(zipFile); err == nil {
			_ = os.Remove(zipFile)
		}
	}()

	extractDir := filepath.Join(CertsDir, safeDomain)
	if err := ExtractZip(zipFile, extractDir); err != nil {
		_ = os.RemoveAll(extractDir)
		return fmt.Errorf("解压证书失败: %w", err)
	}
	defer os.RemoveAll(extractDir)

	if err := cd.DeployToOpenVPNAS(extractDir); err != nil {
		return err
	}

	logger.Info("OpenVPN-AS 证书上传完成", "domain", domain)
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

func runOpenVPNASSacli(sacliPath string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, sacliPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("执行 OpenVPN-AS 命令失败: %w\n%s", err, string(output))
	}

	return nil
}
