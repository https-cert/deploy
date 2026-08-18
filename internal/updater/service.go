package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/https-cert/deploy/internal/config"
)

// Service 持有一次更新操作所需的显式配置和 HTTP 依赖。
type Service struct {
	// Runtime 是更新镜像和代理配置的只读快照。
	Runtime *config.Runtime
	// HTTPClient 是检查 Release 时使用的客户端。
	HTTPClient *http.Client
	// ReleaseURL 是 Release API 地址，空值使用 GitHub 默认地址。
	ReleaseURL string
	// CurrentVersion 覆盖默认编译版本，便于离线测试。
	CurrentVersion string
}

// NewService 创建显式依赖的更新服务。
func NewService(runtime *config.Runtime, httpClient *http.Client) *Service {
	if httpClient == nil {
		httpClient = newHTTPClientForRuntime(runtime)
	}
	return &Service{Runtime: runtime, HTTPClient: httpClient, ReleaseURL: githubAPIURL, CurrentVersion: config.Version}
}

// newHTTPClientForRuntime 创建带运行时代理配置的 HTTP 客户端。
func newHTTPClientForRuntime(runtime *config.Runtime) *http.Client {
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if runtime != nil && runtime.Config != nil && runtime.Config.Update != nil {
		if rawProxy := strings.TrimSpace(runtime.Config.Update.Proxy); rawProxy != "" {
			if proxyURL, err := url.Parse(rawProxy); err == nil {
				transport.Proxy = http.ProxyURL(proxyURL)
			}
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   downloadTimeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("更新请求重定向次数超过限制")
			}
			return nil
		},
	}
}

// CheckUpdate 使用 Service 的 HTTP 客户端检查最新 Release。
func (s *Service) CheckUpdate(ctx context.Context) (*UpdateInfo, error) {
	if s == nil {
		return nil, fmt.Errorf("更新服务不能为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	currentVersion := strings.TrimSpace(s.CurrentVersion)
	if currentVersion == "" {
		currentVersion = "dev"
	}
	release, err := s.fetchRelease(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取最新版本失败: %w", err)
	}
	info := &UpdateInfo{CurrentVersion: currentVersion, LatestVersion: release.TagName, ReleaseNotes: release.Body, BinaryName: getBinaryName()}
	info.HasUpdate = compareVersions(currentVersion, release.TagName)
	if !info.HasUpdate {
		return info, nil
	}
	for _, asset := range release.Assets {
		if asset == nil {
			continue
		}
		switch asset.Name {
		case info.BinaryName:
			info.DownloadURL = s.transformDownloadURL(asset.BrowserDownloadURL)
		case "checksums.txt":
			info.ChecksumURL = s.transformDownloadURL(asset.BrowserDownloadURL)
		}
	}
	if info.DownloadURL == "" || info.ChecksumURL == "" {
		//lint:ignore ST1005 Release 是既有用户错误文本中的产品术语。
		return nil, fmt.Errorf("Release 缺少当前平台二进制或 checksums.txt")
	}
	return info, nil
}

// PerformUpdate 执行更新流程并复用现有原子替换实现。
func (s *Service) PerformUpdate(ctx context.Context, info *UpdateInfo) error {
	if s == nil {
		return fmt.Errorf("更新服务不能为空")
	}
	return performUpdate(ctx, info, s.HTTPClient)
}

// Rollback 回滚上一次更新保留的备份二进制。
func (s *Service) Rollback() error {
	return Rollback()
}

// fetchRelease 使用 Service 的 HTTP 客户端读取 Release API。
func (s *Service) fetchRelease(ctx context.Context) (*GitHubRelease, error) {
	endpoint := strings.TrimSpace(s.ReleaseURL)
	if endpoint == "" {
		endpoint = githubAPIURL
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "anssl-updater")
	response, err := s.HTTPClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		//lint:ignore ST1005 Release 是既有用户错误文本中的产品术语。
		return nil, fmt.Errorf("Release API 返回错误状态码: %d", response.StatusCode)
	}
	var release GitHubRelease
	if err := json.NewDecoder(response.Body).Decode(&release); err != nil {
		return nil, err
	}
	return &release, nil
}

// transformDownloadURL 根据 Runtime 快照转换镜像地址。
func (s *Service) transformDownloadURL(originalURL string) string {
	if s == nil || s.Runtime == nil || s.Runtime.Config == nil || s.Runtime.Config.Update == nil {
		return strings.Replace(originalURL, "https://github.com", mirrorMap[mirrorGHProxy], 1)
	}
	update := s.Runtime.Config.Update
	switch update.Mirror {
	case mirrorGitHub:
		return originalURL
	case mirrorCustom:
		if update.CustomURL != "" {
			return strings.Replace(originalURL, "https://github.com", update.CustomURL, 1)
		}
	case mirrorGHProxy:
		return strings.Replace(originalURL, "https://github.com", mirrorMap[mirrorGHProxy], 1)
	}
	return originalURL
}
