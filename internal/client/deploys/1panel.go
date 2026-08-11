package deploys

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

const (
	onePanelRequestTimeout      = 30 * time.Second
	onePanelMaxResponseBodySize = 1024 * 1024
	onePanelSSLSearchPath       = "/api/v2/websites/ssl/search"
	onePanelSSLUploadPath       = "/api/v2/websites/ssl/upload"
)

// onePanelHTTPClient 禁止自动跟随重定向，避免把面板鉴权头发送到非预期地址。
var onePanelHTTPClient = &http.Client{
	Timeout: onePanelRequestTimeout,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// OnePanelAPIResponse API 响应结构
type OnePanelAPIResponse struct {
	Code    int    `json:"code"`    // Code 是 1Panel 业务状态码，200 表示成功。
	Message string `json:"message"` // Message 是 1Panel 返回的诊断信息。
	Data    any    `json:"data"`    // Data 是接口返回的数据，本客户端只校验响应是否合法。
}

// TestOnePanelConnection 通过只读证书列表接口验证面板地址、API 密钥和证书管理权限。
func TestOnePanelConnection() error {
	apiURL, apiKey, err := getOnePanelConfig()
	if err != nil {
		return err
	}

	requestBody := map[string]any{
		"page":     1,
		"pageSize": 1,
	}
	if err := requestOnePanelAPI(apiURL, apiKey, onePanelSSLSearchPath, requestBody); err != nil {
		return fmt.Errorf("1Panel 连接测试失败: %w", err)
	}
	return nil
}

// DeployTo1Panel 部署证书到 1Panel
func (cd *CertDeployer) DeployTo1Panel(sourceDir, domain string) error {
	apiURL, apiKey, err := getOnePanelConfig()
	if err != nil {
		return err
	}

	// 读取证书文件
	certFile := filepath.Join(sourceDir, "cert.pem")
	keyFile := filepath.Join(sourceDir, "privateKey.key")

	certContent, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("读取证书文件失败: %w", err)
	}

	keyContent, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("读取私钥文件失败: %w", err)
	}

	// 构建请求数据
	certData := map[string]any{
		"type":        "paste",             // 上传类型: paste、local
		"certificate": string(certContent), // 证书内容
		"privateKey":  string(keyContent),  // 私钥内容
		"description": "由anssl自动部署",
	}

	// 通过 multipart 上传证书
	if err := upload1PanelCertificate(apiURL, apiKey, domain, certData); err != nil {
		return err
	}

	logger.Info("证书已上传到1Panel", "domain", domain)
	return nil
}

// md5Sum 计算 MD5 哈希
func md5Sum(data string) string {
	h := md5.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// getOnePanelConfig 读取并校验本地 1Panel API 配置，避免鉴权信息被拼接到异常 URL。
func getOnePanelConfig() (string, string, error) {
	configuration := config.GetConfig()
	if configuration == nil || configuration.SSL == nil || configuration.SSL.OnePanel == nil {
		return "", "", fmt.Errorf("未配置1Panel (ssl.onePanel)")
	}

	apiURL := strings.TrimRight(strings.TrimSpace(configuration.SSL.OnePanel.URL), "/")
	apiKey := strings.TrimSpace(configuration.SSL.OnePanel.APIKey)
	if apiURL == "" {
		return "", "", fmt.Errorf("1Panel API地址未配置 (ssl.onePanel.url)")
	}
	if apiKey == "" {
		return "", "", fmt.Errorf("1Panel API密钥未配置 (ssl.onePanel.apiKey)")
	}
	parsedURL, err := url.Parse(apiURL)
	if err != nil || parsedURL.Host == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return "", "", fmt.Errorf("1Panel API地址必须是合法的 HTTP 或 HTTPS 地址")
	}
	if parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return "", "", fmt.Errorf("1Panel API地址不能包含用户凭据、查询参数或片段")
	}
	return apiURL, apiKey, nil
}

// upload1PanelCertificate 上传证书到 1Panel
func upload1PanelCertificate(apiURL, apiKey, domain string, certData map[string]any) error {
	if err := requestOnePanelAPI(apiURL, apiKey, onePanelSSLUploadPath, certData); err != nil {
		return err
	}
	logger.Info("证书上传成功", "domain", domain)
	return nil
}

// requestOnePanelAPI 使用统一鉴权方式调用 1Panel API，并限制响应大小和重定向行为。
func requestOnePanelAPI(apiURL, apiKey, endpoint string, requestBody any) error {
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	token := md5Sum("1panel" + apiKey + timestamp)

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("序列化 1Panel 请求失败: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiURL+endpoint, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("创建 1Panel 请求失败: %w", err)
	}
	req.Header.Set("1Panel-Token", token)
	req.Header.Set("1Panel-Timestamp", timestamp)
	req.Header.Set("Content-Type", "application/json")

	resp, err := onePanelHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("请求 1Panel API 失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, onePanelMaxResponseBodySize+1))
	if err != nil {
		return fmt.Errorf("读取 1Panel 响应失败: %w", err)
	}
	if len(respBody) > onePanelMaxResponseBodySize {
		return fmt.Errorf("1Panel 响应体超过最大限制")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("1Panel API 返回 HTTP %d", resp.StatusCode)
	}

	var apiResp OnePanelAPIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return fmt.Errorf("解析 1Panel 响应失败: %w", err)
	}
	if apiResp.Code != http.StatusOK {
		message := strings.TrimSpace(apiResp.Message)
		if message == "" {
			message = "未知错误"
		}
		return fmt.Errorf("1Panel API 返回错误: %s", message)
	}
	return nil
}

// DeployCertificateTo1Panel 仅部署证书到 1Panel
func (cd *CertDeployer) DeployCertificateTo1Panel(domain, url string) error {
	sslConfig := config.GetConfig().SSL

	if sslConfig.OnePanel == nil || sslConfig.OnePanel.URL == "" {
		return fmt.Errorf("未配置1Panel (ssl.onePanel.url)")
	}

	canonicalDomain, _, extractDir, cleanup, err := cd.prepareCertificateArchive(domain, url)
	if err != nil {
		return err
	}
	defer cleanup()
	domain = canonicalDomain

	// 部署到 1Panel
	if err := cd.DeployTo1Panel(extractDir, domain); err != nil {
		return err
	}

	logger.Info("1Panel证书上传完成", "domain", domain)
	return nil
}
