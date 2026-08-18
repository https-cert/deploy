// Package lecdn implements LeCDN certificate discovery and in-place CDN deployment.
package lecdn

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
)

const (
	pageSize            = 100
	maxPages            = 100
	maxResources        = 10000
	defaultHTTPTimeout  = 30 * time.Second
	defaultSyncTimeout  = 2 * time.Minute
	defaultPollInterval = 2 * time.Second
	maxResponseBytes    = 8 << 20
)

var (
	_ providers.DeploymentResourceProvider = (*Provider)(nil)
	_ providers.ConnectionTester           = (*Provider)(nil)
)

// HTTPClient 是 LeCDN provider 使用的最小 HTTP 客户端接口。
type HTTPClient interface {
	Do(request *http.Request) (*http.Response, error)
}

// Options 提供测试可替换的 HTTP 客户端和同步轮询参数。
type Options struct {
	HTTPClient   HTTPClient    // HTTPClient 执行 LeCDN 控制面请求。
	PollInterval time.Duration // PollInterval 是同步状态轮询间隔。
	SyncTimeout  time.Duration // SyncTimeout 是单个站点同步等待上限。
}

// Provider 保存 LeCDN API Token 和控制面访问参数。
type Provider struct {
	apiBaseURL   string        // apiBaseURL 是包含 /prod-api 或 /api/client 的完整前缀。
	apiToken     string        // apiToken 是通过 Authorization 原样发送的 API Token。
	httpClient   HTTPClient    // httpClient 执行带上下文的 HTTP 请求。
	pollInterval time.Duration // pollInterval 控制同步状态读取频率。
	syncTimeout  time.Duration // syncTimeout 限制单个站点同步等待时间。
}

// New 创建使用生产控制面参数的 LeCDN provider。
func New(apiBaseURL, apiToken string) *Provider {
	return NewWithOptions(apiBaseURL, apiToken, nil)
}

// NewWithOptions 创建支持注入 HTTP 客户端和轮询参数的 LeCDN provider。
func NewWithOptions(apiBaseURL, apiToken string, options *Options) *Provider {
	resolved := Options{}
	if options != nil {
		resolved = *options
	}
	if resolved.HTTPClient == nil {
		resolved.HTTPClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	if resolved.PollInterval <= 0 {
		resolved.PollInterval = defaultPollInterval
	}
	if resolved.SyncTimeout <= 0 {
		resolved.SyncTimeout = defaultSyncTimeout
	}
	return &Provider{
		apiBaseURL:   strings.TrimRight(strings.TrimSpace(apiBaseURL), "/"),
		apiToken:     strings.TrimSpace(apiToken),
		httpClient:   resolved.HTTPClient,
		pollInterval: resolved.PollInterval,
		syncTimeout:  resolved.SyncTimeout,
	}
}

// TestConnection 验证 API Token 可以读取 LeCDN 证书目录。
func (p *Provider) TestConnection(ctx context.Context) (bool, error) {
	if err := p.validateConfiguration(); err != nil {
		return false, err
	}
	query := url.Values{"current_page": {"1"}, "page_size": {"1"}}
	_, _, err := p.request(ctx, "测试连接", http.MethodGet, "/certificate?"+query.Encode(), nil)
	return err == nil, toDeploymentError("测试连接", err)
}
