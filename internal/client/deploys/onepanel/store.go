package onepanel

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/https-cert/deploy/pkg/logger"
)

// TestOnePanelConnection 通过兼容入口验证 1Panel 证书管理权限。
func TestOnePanelConnection() error {
	return TestOnePanelConnectionWithContext(context.Background())
}

// TestOnePanelConnectionWithContext 使用调用方 context 验证 1Panel 连接。
func TestOnePanelConnectionWithContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	apiURL, apiKey, err := getOnePanelConfig(ctx)
	if err != nil {
		return err
	}

	requestBody := map[string]any{
		"page":     1,
		"pageSize": 1,
	}
	if err := requestOnePanelAPI(ctx, apiURL, apiKey, http.MethodPost, onePanelSSLSearchPath, requestBody, nil); err != nil {
		return fmt.Errorf("1Panel 连接测试失败: %w", err)
	}
	return nil
}

// DeployToStore 上传证书到 1Panel 证书库，保留原有非网站级行为。
func DeployToStore(ctx context.Context, sourceDir, domain string) error {
	apiURL, apiKey, err := getOnePanelConfig(ctx)
	if err != nil {
		return err
	}

	certContent, err := osReadFile(sourceDir, "cert.pem")
	if err != nil {
		return fmt.Errorf("读取证书文件失败: %w", err)
	}
	keyContent, err := osReadFile(sourceDir, "privateKey.key")
	if err != nil {
		return fmt.Errorf("读取私钥文件失败: %w", err)
	}
	certData := map[string]any{
		"type":        "paste",
		"certificate": string(certContent),
		"privateKey":  string(keyContent),
		"description": onePanelWebsiteDescription,
	}
	if err := requestOnePanelAPI(ctx, apiURL, apiKey, http.MethodPost, onePanelSSLUploadPath, certData, nil); err != nil {
		return err
	}
	logger.Info("证书已上传到 1Panel 证书库", "domain", domain)
	return nil
}

// osReadFile 读取证书目录下的固定文件名，便于集中约束路径拼接。
func osReadFile(sourceDir, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(sourceDir, name))
}
