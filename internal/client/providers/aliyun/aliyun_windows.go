//go:build windows

package aliyun

import (
	"fmt"

	"github.com/orange-juzipi/cert-deploy/internal/client/providers"
)

var _ providers.ProviderHandler = (*Provider)(nil)

type Provider struct {
	AccessKeyId     string
	AccessKeySecret string
}

// New 创建实例
func New(accessKeyId, accessKeySecret string) (*Provider, error) {
	return &Provider{
		AccessKeyId:     accessKeyId,
		AccessKeySecret: accessKeySecret,
	}, nil
}

// TestConnection 测试连接
func (p *Provider) TestConnection() (bool, error) {
	return false, fmt.Errorf("阿里云 provider 不支持 Windows 平台")
}

// UploadCertificate 上传证书
func (p *Provider) UploadCertificate(name, cert, key string) error {
	return fmt.Errorf("阿里云 provider 不支持 Windows 平台")
}

// DeployToOSS 部署证书到 OSS
func (p *Provider) DeployToOSS(certID string, domain string) (string, error) {
	return "", fmt.Errorf("阿里云 provider 不支持 Windows 平台")
}

// DeployToCDN 部署证书到 CDN
func (p *Provider) DeployToCDN(certID string, domain string) (string, error) {
	return "", fmt.Errorf("阿里云 provider 不支持 Windows 平台")
}

// DeployToDCND 部署证书到 DCND
func (p *Provider) DeployToDCND(certID string, domain string) (string, error) {
	return "", fmt.Errorf("阿里云 provider 不支持 Windows 平台")
}
