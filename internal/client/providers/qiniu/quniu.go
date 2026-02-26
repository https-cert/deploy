/*
文档：https://developer.qiniu.com/kodo
*/

package qiniu

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/qiniu/go-sdk/v7/auth"
	"github.com/qiniu/go-sdk/v7/cdn"
)

var _ providers.ProviderHandler = (*Provider)(nil)
var baseURL = "https://api.qiniu.com"

type Provider struct {
	AccessKey    string
	AccessSecret string
	cdnClient    *cdn.CdnManager
}

// New 创建实例
func New(accessKey, accessSecret string) *Provider {
	credentials := auth.New(accessKey, accessSecret)

	return &Provider{
		AccessKey:    accessKey,
		AccessSecret: accessSecret,
		cdnClient:    cdn.NewCdnManager(credentials),
	}
}

// getToken 获取授权 token
func (p *Provider) getToken(path string) (string, error) {
	credentials := auth.New(p.AccessKey, p.AccessSecret)

	token, err := credentials.SignRequest(&http.Request{
		Method: http.MethodGet,
		URL: &url.URL{
			Scheme: "https",
			Host:   "api.qiniu.com",
			Path:   path,
		},
	})
	if err != nil {
		return "", err
	}

	return token, nil
}

// TestConnection 测试连接
// 验证 AccessKey 是否有效,请求的是 证书列表
func (p *Provider) TestConnection() (bool, error) {
	token, err := p.getToken("/sslcert")
	if err != nil {
		return false, err
	}

	req := providers.RequestOptions{
		Method:  http.MethodGet,
		Path:    "/sslcert",
		BaseURL: baseURL,
		Headers: map[string]string{
			"Authorization": "QBox " + token,
		},
	}

	resp, err := providers.Execute(req)
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return true, nil
}

// UploadCertificate 上传证书
func (p *Provider) UploadCertificate(name, domain, cert, key string) error {
	token, err := p.getToken("/sslcert")
	if err != nil {
		return err
	}

	req := providers.RequestOptions{
		Method:  http.MethodPost,
		Path:    "/sslcert",
		BaseURL: baseURL,
		Headers: map[string]string{
			"Authorization": "QBox " + token,
		},
		Body: map[string]any{
			"Name": name,
			"Ca":   cert,
			"Pri":  key,
		},
	}

	resp, err := providers.Execute(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// DeployToOSS 部署证书到 OSS
func (p *Provider) DeployToOSS(certID string, domain string) (string, error) {

	return "", nil
}

// DeployToCDN 部署证书到 CDN
func (p *Provider) DeployToCDN(certID string, domain string) (string, error) {

	return "", nil
}

// DeployToDCND 部署证书到 DCND
func (p *Provider) DeployToDCND(certID string, domain string) (string, error) {

	return "", nil
}
