package onepanel

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DeployCertificateTo1PanelWebsite 精确部署 targetRef 对应网站的证书，并回读指纹确认。
func DeployCertificateTo1PanelWebsite(ctx context.Context, targetRef, certificatePEM, privateKeyPEM string) error {
	targetRef = strings.TrimSpace(targetRef)
	if targetRef == "" {
		return fmt.Errorf("1Panel 网站 targetRef 不能为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	apiURL, apiKey, err := getOnePanelConfig(ctx)
	if err != nil {
		return err
	}
	record, err := findOnePanelWebsiteByTargetRef(ctx, targetRef)
	if err != nil {
		return err
	}
	if isOnePanelWebsiteStopped(record.Resource.Status) {
		return fmt.Errorf("1Panel 网站未运行")
	}
	expectedFingerprint, err := validateOnePanelWebsiteCertificate(certificatePEM, privateKeyPEM, record.Resource.Domains, time.Now())
	if err != nil {
		return err
	}

	current, err := getOnePanelWebsiteHTTPS(ctx, apiURL, apiKey, record.ID)
	if err != nil {
		return fmt.Errorf("读取 1Panel 网站 HTTPS 配置失败: %w", err)
	}
	requestBody := buildOnePanelWebsiteHTTPSUpdate(record.ID, current, certificatePEM, privateKeyPEM)
	endpoint := fmt.Sprintf(onePanelWebsiteHTTPSPath, record.ID)
	if err := requestOnePanelAPI(ctx, apiURL, apiKey, http.MethodPost, endpoint, requestBody, nil); err != nil {
		return fmt.Errorf("更新 1Panel 网站证书失败: %w", err)
	}

	updated, err := getOnePanelWebsiteHTTPS(ctx, apiURL, apiKey, record.ID)
	if err != nil {
		return fmt.Errorf("回读 1Panel 网站 HTTPS 配置失败: %w", err)
	}
	actualFingerprint, err := onePanelCertificateFingerprint(updated.SSL.PEM)
	if err != nil {
		return fmt.Errorf("解析 1Panel 回读证书失败: %w", err)
	}
	if actualFingerprint != expectedFingerprint {
		return fmt.Errorf("1Panel 网站证书回读指纹不一致")
	}
	return nil
}

// getOnePanelWebsiteHTTPS 读取一个网站的当前 HTTPS 配置。
func getOnePanelWebsiteHTTPS(ctx context.Context, apiURL, apiKey string, websiteID uint64) (*onePanelWebsiteHTTPS, error) {
	var httpsConfig onePanelWebsiteHTTPS
	endpoint := fmt.Sprintf(onePanelWebsiteHTTPSPath, websiteID)
	if err := requestOnePanelAPI(ctx, apiURL, apiKey, http.MethodGet, endpoint, nil, &httpsConfig); err != nil {
		return nil, err
	}
	return &httpsConfig, nil
}

// onePanelHTTPSPorts 合并新版数组字段和旧版逗号字段，确保更新时不改变监听端口。
func onePanelHTTPSPorts(config *onePanelWebsiteHTTPS) []int {
	if config == nil {
		return nil
	}
	ports := append([]int(nil), config.HTTPSPorts...)
	seen := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		seen[port] = struct{}{}
	}
	for _, rawPort := range strings.Split(config.HTTPSPort, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(rawPort))
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

// buildOnePanelWebsiteHTTPSUpdate 保留现有 HTTPS 参数，或为首次部署采用 1Panel 的安全默认值。
func buildOnePanelWebsiteHTTPSUpdate(websiteID uint64, current *onePanelWebsiteHTTPS, certificatePEM, privateKeyPEM string) onePanelWebsiteHTTPSUpdate {
	httpConfig := ""
	sslProtocol := []string(nil)
	algorithm := ""
	hsts := false
	hstsIncludeSubDomains := false
	httpsPorts := []int(nil)
	http3 := false

	if current != nil && current.Enable {
		httpConfig = strings.TrimSpace(current.HTTPConfig)
		sslProtocol = append([]string(nil), current.SSLProtocol...)
		algorithm = current.Algorithm
		hsts = current.HSTS
		hstsIncludeSubDomains = current.HSTSIncludeSubDomains
		httpsPorts = onePanelHTTPSPorts(current)
		http3 = current.HTTP3
	}
	if httpConfig == "" {
		// 1Panel 空 HTTPS 配置没有可保留的跳转策略，首次部署统一升级 HTTP 请求。
		httpConfig = onePanelDefaultHTTPConfig
	}

	return onePanelWebsiteHTTPSUpdate{
		WebsiteID:             websiteID,
		Enable:                true,
		Type:                  "manual",
		PrivateKey:            privateKeyPEM,
		Certificate:           certificatePEM,
		ImportType:            "paste",
		HTTPConfig:            httpConfig,
		SSLProtocol:           sslProtocol,
		Algorithm:             algorithm,
		HSTS:                  hsts,
		HSTSIncludeSubDomains: hstsIncludeSubDomains,
		HTTPSPorts:            httpsPorts,
		HTTP3:                 http3,
	}
}
