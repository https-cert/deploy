// Package baidu implements Baidu Cloud certificate-center upload and CDN deployment.
package baidu

import (
	"context"
	"fmt"
	"strings"
	"time"

	cdnservice "github.com/baidubce/bce-sdk-go/services/cdn"
	cdnapi "github.com/baidubce/bce-sdk-go/services/cdn/api"
	certservice "github.com/baidubce/bce-sdk-go/services/cert"
	"github.com/https-cert/deploy/internal/client/providers"
)

// contextError 返回调用方上下文的取消或超时状态。
func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

const (
	cdnEndpoint         = "https://cdn.baidubce.com"
	certificateEndpoint = "https://certificate.baidubce.com"
	maxResourcePages    = 100
	maxResourceCount    = 10000
)

var (
	_ providers.ProviderHandler            = (*Provider)(nil)
	_ providers.DeploymentResourceProvider = (*Provider)(nil)
)

// cdnClient 是百度云 CDN 资源发现和 HTTPS 配置所需的最小官方 SDK 接口。
type cdnClient interface {
	ListDomains(marker string) ([]string, string, error)
	GetDomainConfig(domain string) (*cdnapi.DomainConfig, error)
	GetDomainHttps(domain string) (*cdnapi.HTTPSConfig, error)
	SetDomainHttps(domain string, httpsConfig *cdnapi.HTTPSConfig) error
}

// certificateClient 是百度云证书托管上传和回读所需的最小官方 SDK 接口。
type certificateClient interface {
	CreateCert(args *certservice.CreateCertArgs) (*certservice.CreateCertResult, error)
	ListCertDetail() (*certservice.ListCertDetailResult, error)
	GetCertDetail(id string) (*certservice.CertificateDetailMeta, error)
}

// Provider 保存百度云凭据及官方 SDK 客户端。
type Provider struct {
	accessKey         string            // accessKey 是百度云 Access Key ID。
	secretKey         string            // secretKey 是百度云 Secret Access Key。
	cdnClient         cdnClient         // cdnClient 负责 CDN 域名和 HTTPS 配置操作。
	certificateClient certificateClient // certificateClient 负责证书托管操作。
}

// New 使用 HTTPS 控制面创建百度云 provider。
func New(accessKey, secretKey string) (*Provider, error) {
	cdn, err := cdnservice.NewClient(strings.TrimSpace(accessKey), strings.TrimSpace(secretKey), cdnEndpoint)
	if err != nil {
		return nil, fmt.Errorf("初始化百度云 CDN 客户端失败: %w", err)
	}
	certificate, err := certservice.NewClient(strings.TrimSpace(accessKey), strings.TrimSpace(secretKey), certificateEndpoint)
	if err != nil {
		return nil, fmt.Errorf("初始化百度云证书客户端失败: %w", err)
	}
	return newWithClients(accessKey, secretKey, cdn, certificate), nil
}

// newWithClients 创建支持单元测试注入的百度云 provider。
func newWithClients(accessKey, secretKey string, cdn cdnClient, certificate certificateClient) *Provider {
	return &Provider{
		accessKey:         strings.TrimSpace(accessKey),
		secretKey:         strings.TrimSpace(secretKey),
		cdnClient:         cdn,
		certificateClient: certificate,
	}
}

// TestConnection 验证凭据至少可以读取一页 CDN 域名目录。
func (p *Provider) TestConnection(ctx context.Context) (bool, error) {
	if err := contextError(ctx); err != nil {
		return false, err
	}
	if err := p.validateCredentials(); err != nil {
		return false, err
	}
	if p.cdnClient == nil {
		return false, providers.NewDeploymentError("百度云 CDN 客户端未初始化", false, "", nil)
	}
	_, _, err := p.cdnClient.ListDomains("")
	if contextErr := contextError(ctx); contextErr != nil {
		return false, contextErr
	}
	if err != nil {
		return false, toDeploymentError("测试连接", err)
	}
	return true, nil
}

// UploadCertificate 上传或复用百度云证书托管中的同一张叶证书，并回读验收。
func (p *Provider) UploadCertificate(ctx context.Context, certificate providers.CertificateMaterial) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := providers.ValidateCertificateMaterial(certificate, certificate.Domain, time.Now()); err != nil {
		return providers.NewDeploymentError("百度云上传证书校验失败", false, "", err)
	}
	_, err := p.ensureCertificate(ctx, certificate)
	return toDeploymentError("上传证书", err)
}
