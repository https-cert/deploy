/*
文档：
- SSL UploadCertificate：https://cloud.tencent.com/document/product/400/41665
SDK：https://github.com/TencentCloud/tencentcloud-sdk-go
*/

package cloud_tencent

import (
	"fmt"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	tencentcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tencenterrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

const (
	tencentSSLHost     = "ssl.tencentcloudapi.com"
	defaultSSLRegion   = "ap-guangzhou"
	defaultTimeoutInS  = 30
	certificateTypeSVR = "SVR"
)

var _ providers.ProviderHandler = (*Provider)(nil)

// sslClient 定义腾讯云 SSL SDK 的最小调用集合，便于测试替换。
type sslClient interface {
	DescribeCertificates(request *ssl.DescribeCertificatesRequest) (*ssl.DescribeCertificatesResponse, error)
	UploadCertificate(request *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error)
}

// clientFactory 负责构建腾讯云 SSL SDK 客户端。
type clientFactory func(secretID, secretKey string) (sslClient, error)

// Provider 腾讯云 SSL Provider。
type Provider struct {
	SecretId  string
	SecretKey string
	client    sslClient
	newClient clientFactory
}

// New 创建腾讯云 Provider 实例。
func New(secretId, secretKey string) *Provider {
	return &Provider{
		SecretId:  strings.TrimSpace(secretId),
		SecretKey: strings.TrimSpace(secretKey),
		newClient: defaultClientFactory,
	}
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

	_, err = client.DescribeCertificates(request)
	if err != nil {
		return false, wrapTencentSDKError("DescribeCertificates", err)
	}
	return true, nil
}

// UploadCertificate 上传证书到腾讯云 SSL 证书服务。
func (p *Provider) UploadCertificate(name, domain, cert, key string) error {
	_ = domain

	client, err := p.getClient()
	if err != nil {
		return err
	}

	request := ssl.NewUploadCertificateRequest()
	request.CertificatePublicKey = tencentcommon.StringPtr(cert)
	request.CertificatePrivateKey = tencentcommon.StringPtr(key)
	request.CertificateType = tencentcommon.StringPtr(certificateTypeSVR)
	request.Repeatable = tencentcommon.BoolPtr(true)

	trimmedName := strings.TrimSpace(name)
	if trimmedName != "" {
		request.Alias = tencentcommon.StringPtr(trimmedName)
	}

	response, err := client.UploadCertificate(request)
	if err != nil {
		return wrapTencentSDKError("UploadCertificate", err)
	}
	if response == nil || response.Response == nil {
		return fmt.Errorf("腾讯云上传证书返回格式异常: 缺少 Response 字段")
	}

	certificateID := strings.TrimSpace(stringValue(response.Response.CertificateId))
	repeatCertID := strings.TrimSpace(stringValue(response.Response.RepeatCertId))
	if certificateID == "" && repeatCertID == "" {
		requestID := strings.TrimSpace(stringValue(response.Response.RequestId))
		return fmt.Errorf("腾讯云上传证书返回缺少证书ID: requestId=%s", requestID)
	}

	return nil
}

// DeployToOSS 当前不支持该业务类型。
func (p *Provider) DeployToOSS(certID string, domain string) (string, error) {
	_, _ = certID, domain
	return "", fmt.Errorf("不支持 OSS 证书部署业务")
}

// DeployToCDN 当前不支持该业务类型。
func (p *Provider) DeployToCDN(certID string, domain string) (string, error) {
	_, _ = certID, domain
	return "", fmt.Errorf("不支持 CDN 证书部署业务")
}

// DeployToDCND 当前不支持该业务类型。
func (p *Provider) DeployToDCND(certID string, domain string) (string, error) {
	_, _ = certID, domain
	return "", fmt.Errorf("暂不支持 DCND 证书部署业务")
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
