package deploys

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

// OnePanelAPIResponse API 响应结构
type OnePanelAPIResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

// DeployTo1Panel 部署证书到 1Panel
func (cd *CertDeployer) DeployTo1Panel(sourceDir, domain string) error {
	// 获取配置
	sslConfig := config.GetConfig().SSL
	if sslConfig.OnePanel == nil {
		return fmt.Errorf("未配置1Panel (ssl.onePanel)")
	}

	apiURL := sslConfig.OnePanel.URL
	apiKey := sslConfig.OnePanel.APIKey

	if apiURL == "" {
		return fmt.Errorf("1Panel API地址未配置 (ssl.onePanel.url)")
	}

	if apiKey == "" {
		return fmt.Errorf("1Panel API密钥未配置 (ssl.onePanel.apiKey)")
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
	err = upload1PanelCertificate(apiURL, apiKey, domain, certData)
	if err != nil {
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

// upload1PanelCertificate 上传证书到 1Panel
func upload1PanelCertificate(apiURL, apiKey, domain string, certData map[string]any) error {
	// 构建 API URL
	url := fmt.Sprintf("%s/api/v2/websites/ssl/upload", strings.TrimRight(apiURL, "/"))

	// 生成时间戳和 Token
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	token := md5Sum("1panel" + apiKey + timestamp)

	jsonData, err := json.Marshal(certData)
	if err != nil {
		return fmt.Errorf("序列化证书数据失败: %w", err)
	}

	// 创建 HTTP 请求
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}

	// 设置请求头
	req.Header.Set("1Panel-Token", token)
	req.Header.Set("1Panel-Timestamp", timestamp)
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 读取响应
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API返回错误状态码: %d, 响应: %s", resp.StatusCode, string(respBody))
	}

	// 解析响应
	var apiResp OnePanelAPIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return fmt.Errorf("解析响应失败: %w, 响应内容: %s", err, string(respBody))
	}

	if apiResp.Code != 200 {
		return fmt.Errorf("API返回错误: %s", apiResp.Message)
	}

	logger.Info("证书上传成功", "domain", domain)
	return nil
}

// DeployCertificateTo1Panel 仅部署证书到 1Panel
func (cd *CertDeployer) DeployCertificateTo1Panel(domain, url string) error {
	sslConfig := config.GetConfig().SSL

	if sslConfig.OnePanel == nil || sslConfig.OnePanel.URL == "" {
		return fmt.Errorf("未配置1Panel (ssl.onePanel.url)")
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

	folderName := safeDomain
	extractDir := filepath.Join(CertsDir, folderName)

	if err := ExtractZip(zipFile, extractDir); err != nil {
		os.RemoveAll(extractDir)
		return fmt.Errorf("解压证书失败: %w", err)
	}
	defer os.RemoveAll(extractDir)

	// 部署到 1Panel
	if err := cd.DeployTo1Panel(extractDir, domain); err != nil {
		return err
	}

	logger.Info("1Panel证书上传完成", "domain", domain)
	return nil
}
