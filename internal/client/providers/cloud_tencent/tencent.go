/*
文档：
- SSL UploadCertificate：https://cloud.tencent.com/document/product/400/41665
SDK：https://github.com/TencentCloud/tencentcloud-sdk-go
*/

package cloud_tencent

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	tencentcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tencenterrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	cvm "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cvm/v20170312"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

const (
	tencentSSLHost     = "ssl.tencentcloudapi.com"
	defaultSSLRegion   = "ap-guangzhou"
	defaultTimeoutInS  = 30
	certificateTypeSVR = "SVR"
)

var (
	_ providers.ProviderHandler    = (*Provider)(nil)
	_ providers.ResourceDiscoverer = (*Provider)(nil)
)

// regionClient 定义腾讯云公开地域目录接口。
type regionClient interface {
	// DescribeRegionsWithContext 查询当前账户可用地域。
	DescribeRegionsWithContext(ctx context.Context, request *cvm.DescribeRegionsRequest) (*cvm.DescribeRegionsResponse, error)
}

// regionClientFactory 创建地域目录客户端。
type regionClientFactory func(secretID, secretKey string) (regionClient, error)

// sslClient 定义腾讯云 SSL SDK 的最小调用集合，便于测试替换。
type sslClient interface {
	DescribeCertificatesWithContext(ctx context.Context, request *ssl.DescribeCertificatesRequest) (*ssl.DescribeCertificatesResponse, error)
	DescribeCertificateDetailWithContext(ctx context.Context, request *ssl.DescribeCertificateDetailRequest) (*ssl.DescribeCertificateDetailResponse, error)
	UploadCertificateWithContext(ctx context.Context, request *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error)
}

// clientFactory 负责构建腾讯云 SSL SDK 客户端。
type clientFactory func(secretID, secretKey string) (sslClient, error)

// Provider 腾讯云 SSL 证书和云资源部署 Provider。
type Provider struct {
	SecretId        string                  // SecretId 腾讯云 API SecretId，禁止写入日志。
	SecretKey       string                  // SecretKey 腾讯云 API SecretKey，禁止写入日志。
	client          sslClient               // client 缓存 SSL SDK 客户端。
	newClient       clientFactory           // newClient 创建 SSL SDK 客户端。
	cdnClient       cdnClient               // cdnClient 缓存 CDN SDK 客户端。
	teoClient       teoClient               // teoClient 缓存 EdgeOne SDK 客户端。
	newCDNClient    cdnClientFactory        // newCDNClient 创建 CDN SDK 客户端。
	newTEOClient    teoClientFactory        // newTEOClient 创建 EdgeOne SDK 客户端。
	newCOSClient    cosClientFactory        // newCOSClient 创建绑定到指定 Bucket 的 COS SDK 客户端。
	cosService      cosServiceClient        // cosService 缓存账户级 COS Bucket 目录客户端。
	newCOSService   cosServiceClientFactory // newCOSService 创建账户级 COS Bucket 目录客户端。
	clbClients      map[string]clbClient    // clbClients 按地域缓存腾讯云 CLB SDK 客户端。
	newCLBClient    clbClientFactory        // newCLBClient 创建绑定到指定地域的 CLB SDK 客户端。
	regionClient    regionClient            // regionClient 缓存公开地域目录客户端。
	newRegionClient regionClientFactory     // newRegionClient 创建地域目录客户端。
}

// certificateUploadResult 保留腾讯云 SSL 上传接口返回的证书和请求标识。
type certificateUploadResult struct {
	CertificateID string // CertificateID 是后续 CDN、EdgeOne 或 CLB 绑定所需的证书 ID。
	RequestID     string // RequestID 是 SSL 上传请求 ID。
}

// New 创建腾讯云 Provider 实例。
func New(secretId, secretKey string) *Provider {
	return &Provider{
		SecretId:        strings.TrimSpace(secretId),
		SecretKey:       strings.TrimSpace(secretKey),
		newClient:       defaultClientFactory,
		newCDNClient:    defaultCDNClientFactory,
		newTEOClient:    defaultTEOClientFactory,
		newCOSClient:    defaultCOSClientFactory,
		newCOSService:   defaultCOSServiceClientFactory,
		clbClients:      make(map[string]clbClient),
		newCLBClient:    defaultCLBClientFactory,
		newRegionClient: defaultRegionClientFactory,
	}
}

// defaultRegionClientFactory 构建 CVM 地域目录客户端。
func defaultRegionClientFactory(secretID, secretKey string) (regionClient, error) {
	clientProfile := profile.NewClientProfile()
	httpProfile := profile.NewHttpProfile()
	httpProfile.Endpoint = "cvm.tencentcloudapi.com"
	httpProfile.ReqTimeout = defaultTimeoutInS
	clientProfile.HttpProfile = httpProfile
	return cvm.NewClient(tencentcommon.NewCredential(secretID, secretKey), "", clientProfile)
}

// defaultClientFactory 基于官方 SDK 构建 SSL 客户端。
func defaultClientFactory(secretID, secretKey string) (sslClient, error) {
	credential := tencentcommon.NewCredential(secretID, secretKey)
	clientProfile := profile.NewClientProfile()
	httpProfile := profile.NewHttpProfile()
	httpProfile.Endpoint = tencentSSLHost
	httpProfile.ReqTimeout = defaultTimeoutInS
	clientProfile.HttpProfile = httpProfile

	return ssl.NewClient(credential, defaultSSLRegion, clientProfile)
}

// getClient 获取或初始化腾讯云 SSL SDK 客户端。
func (p *Provider) getClient() (sslClient, error) {
	if p.client != nil {
		return p.client, nil
	}
	if p.newClient == nil {
		p.newClient = defaultClientFactory
	}

	client, err := p.newClient(p.SecretId, p.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("初始化腾讯云 SSL SDK 客户端失败: %w", err)
	}
	p.client = client
	return p.client, nil
}

// TestConnection 测试腾讯云 SSL API 连接。
func (p *Provider) TestConnection() (bool, error) {
	client, err := p.getClient()
	if err != nil {
		return false, err
	}

	request := ssl.NewDescribeCertificatesRequest()
	request.Offset = tencentcommon.Uint64Ptr(0)
	request.Limit = tencentcommon.Uint64Ptr(1)

	_, err = client.DescribeCertificatesWithContext(context.Background(), request)
	if err != nil {
		return false, wrapTencentSDKError("DescribeCertificates", err)
	}
	return true, nil
}

// UploadCertificate 上传证书到腾讯云 SSL 证书服务。
func (p *Provider) UploadCertificate(name, domain, cert, key string) error {
	_, err := p.uploadCertificateWithContext(context.Background(), name, domain, cert, key)
	if err != nil {
		var sdkError *tencenterrors.TencentCloudSDKError
		if errors.As(err, &sdkError) {
			return wrapTencentSDKError("UploadCertificate", err)
		}
	}
	return err
}

// uploadCertificateWithContext 上传证书并保留后续云产品绑定所需的 CertificateId 和请求 ID。
func (p *Provider) uploadCertificateWithContext(ctx context.Context, name, domain, cert, key string) (certificateUploadResult, error) {
	_ = domain

	client, err := p.getClient()
	if err != nil {
		return certificateUploadResult{}, err
	}

	request := ssl.NewUploadCertificateRequest()
	request.CertificatePublicKey = tencentcommon.StringPtr(cert)
	request.CertificatePrivateKey = tencentcommon.StringPtr(key)
	request.CertificateType = tencentcommon.StringPtr(certificateTypeSVR)
	request.Repeatable = tencentcommon.BoolPtr(false)

	trimmedName := strings.TrimSpace(name)
	if trimmedName != "" {
		request.Alias = tencentcommon.StringPtr(trimmedName)
	}

	response, err := client.UploadCertificateWithContext(ctx, request)
	if err != nil {
		return certificateUploadResult{}, err
	}
	if response == nil || response.Response == nil {
		return certificateUploadResult{}, fmt.Errorf("腾讯云上传证书返回格式异常: 缺少 Response 字段")
	}

	certificateID := strings.TrimSpace(stringValue(response.Response.CertificateId))
	repeatCertID := strings.TrimSpace(stringValue(response.Response.RepeatCertId))
	if certificateID == "" {
		certificateID = repeatCertID
	}
	requestID := strings.TrimSpace(stringValue(response.Response.RequestId))
	if certificateID == "" {
		return certificateUploadResult{}, fmt.Errorf("腾讯云上传证书返回缺少证书ID: requestId=%s", requestID)
	}

	return certificateUploadResult{
		CertificateID: certificateID,
		RequestID:     requestID,
	}, nil
}

// verifyCertificateFingerprint 读取腾讯云 SSL 证书正文并校验叶证书 SHA-256 指纹。
func (p *Provider) verifyCertificateFingerprint(ctx context.Context, certificateID, expectedPEM string) (string, error) {
	client, err := p.getClient()
	if err != nil {
		return "", newTencentDeploymentError("初始化 SSL 客户端", err)
	}
	request := ssl.NewDescribeCertificateDetailRequest()
	request.CertificateId = tencentcommon.StringPtr(strings.TrimSpace(certificateID))
	response, err := client.DescribeCertificateDetailWithContext(ctx, request)
	if err != nil {
		return "", newTencentDeploymentError("回读 SSL 证书详情", err)
	}
	if response == nil || response.Response == nil {
		return "", providers.NewDeploymentError("腾讯云 SSL 证书详情响应格式异常", true, "", nil)
	}
	requestID := strings.TrimSpace(stringValue(response.Response.RequestId))
	if !strings.EqualFold(strings.TrimSpace(stringValue(response.Response.CertificateId)), strings.TrimSpace(certificateID)) {
		return requestID, providers.NewDeploymentError("腾讯云 SSL 证书详情 ID 不匹配", false, requestID, nil)
	}
	publicKey := strings.TrimSpace(stringValue(response.Response.CertificatePublicKey))
	if publicKey == "" {
		return requestID, providers.NewDeploymentError("腾讯云 SSL 证书详情缺少公钥证书", true, requestID, nil)
	}
	if err := providers.VerifyLeafCertificateSHA256(expectedPEM, publicKey); err != nil {
		return requestID, providers.NewDeploymentError("腾讯云 SSL 证书指纹回读校验失败", false, requestID, err)
	}
	return requestID, nil
}

// stringValue 安全读取 SDK 字符串指针字段。
func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// wrapTencentSDKError 统一包装腾讯云 SDK 错误信息。
func wrapTencentSDKError(action string, err error) error {
	if sdkError, ok := err.(*tencenterrors.TencentCloudSDKError); ok {
		return fmt.Errorf("腾讯云接口错误(action=%s, code=%s, requestId=%s): %s", action, sdkError.GetCode(), sdkError.GetRequestId(), sdkError.GetMessage())
	}
	return fmt.Errorf("调用腾讯云接口失败(action=%s): %w", action, err)
}
