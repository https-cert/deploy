// Package jdcloud implements JD Cloud certificate-center upload and CDN deployment.
package jdcloud

import (
	"context"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/jdcloud-api/jdcloud-sdk-go/core"
	cdnapi "github.com/jdcloud-api/jdcloud-sdk-go/services/cdn/apis"
	cdnclient "github.com/jdcloud-api/jdcloud-sdk-go/services/cdn/client"
	sslapi "github.com/jdcloud-api/jdcloud-sdk-go/services/ssl/apis"
	sslclient "github.com/jdcloud-api/jdcloud-sdk-go/services/ssl/client"
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
	resourcePageSize = 50
	resourceMaxPages = 100
	resourceMaxCount = 10000
	taskPollAttempts = 20
	taskPollInterval = 500 * time.Millisecond
)

var (
	_ providers.ProviderHandler            = (*Provider)(nil)
	_ providers.DeploymentResourceProvider = (*Provider)(nil)
)

// cdnClient 是京东云 CDN 资源和配置操作所需的最小官方 SDK 接口。
type cdnClient interface {
	GetDomainList(request *cdnapi.GetDomainListRequest) (*cdnapi.GetDomainListResponse, error)
	GetDomainDetail(request *cdnapi.GetDomainDetailRequest) (*cdnapi.GetDomainDetailResponse, error)
	SetHttpType(request *cdnapi.SetHttpTypeRequest) (*cdnapi.SetHttpTypeResponse, error)
	QueryDomainConfigStatus(request *cdnapi.QueryDomainConfigStatusRequest) (*cdnapi.QueryDomainConfigStatusResponse, error)
}

// certificateClient 是京东云 SSL 证书上传和回读所需的最小官方 SDK 接口。
type certificateClient interface {
	UploadCert(request *sslapi.UploadCertRequest) (*sslapi.UploadCertResponse, error)
	DescribeCert(request *sslapi.DescribeCertRequest) (*sslapi.DescribeCertResponse, error)
	DescribeCerts(request *sslapi.DescribeCertsRequest) (*sslapi.DescribeCertsResponse, error)
}

// Provider 保存京东云访问密钥和官方 SDK 客户端。
type Provider struct {
	accessKey         string            // accessKey 是京东云 Access Key ID。
	secretKey         string            // secretKey 是京东云 Secret Access Key。
	cdnClient         cdnClient         // cdnClient 负责 CDN 域名和配置操作。
	certificateClient certificateClient // certificateClient 负责 SSL 证书中心操作。
	pollInterval      time.Duration     // pollInterval 是异步配置任务的轮询间隔。
}

// New 创建使用京东云生产 HTTPS Endpoint 的 provider。
func New(accessKey, secretKey string) *Provider {
	credential := core.NewCredentials(strings.TrimSpace(accessKey), strings.TrimSpace(secretKey))
	cdn := cdnclient.NewCdnClient(credential)
	certificate := sslclient.NewSslClient(credential)
	cdn.DisableLogger()
	certificate.DisableLogger()
	return newWithClients(accessKey, secretKey, cdn, certificate)
}

// newWithClients 创建支持单元测试注入的京东云 provider。
func newWithClients(accessKey, secretKey string, cdn cdnClient, certificate certificateClient) *Provider {
	return &Provider{
		accessKey:         strings.TrimSpace(accessKey),
		secretKey:         strings.TrimSpace(secretKey),
		cdnClient:         cdn,
		certificateClient: certificate,
		pollInterval:      taskPollInterval,
	}
}

// TestConnection 验证京东云凭据可以读取 CDN 域名目录。
func (p *Provider) TestConnection(ctx context.Context) (bool, error) {
	if err := contextError(ctx); err != nil {
		return false, err
	}
	if err := p.validateCredentials(); err != nil {
		return false, err
	}
	if p.cdnClient == nil {
		return false, providers.NewDeploymentError("京东云 CDN 客户端未初始化", false, "", nil)
	}
	request := cdnapi.NewGetDomainListRequest()
	request.SetPageNumber(1)
	request.SetPageSize(1)
	response, err := p.cdnClient.GetDomainList(request)
	if contextErr := contextError(ctx); contextErr != nil {
		return false, contextErr
	}
	if err != nil {
		return false, toDeploymentError("测试连接", err)
	}
	if err := checkResponse("测试连接", responseRequestID(response), responseError(response)); err != nil {
		return false, toDeploymentError("测试连接", err)
	}
	return true, nil
}

// UploadCertificate 上传或复用京东云 SSL 证书，并通过详情接口回读验收。
func (p *Provider) UploadCertificate(ctx context.Context, certificate providers.CertificateMaterial) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := providers.ValidateCertificateMaterial(certificate, certificate.Domain, time.Now()); err != nil {
		return providers.NewDeploymentError("京东云上传证书校验失败", false, "", err)
	}
	_, _, err := p.ensureCertificate(ctx, certificate)
	return toDeploymentError("上传证书", err)
}
