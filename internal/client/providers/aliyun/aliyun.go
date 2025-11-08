/*
文档：https://help.aliyun.com/zh/ssl-certificate/use-cases/automatic-certificate-deployment-to-cloud-services?utm_source=chatgpt.com
调试控制台：https://next.api.aliyun.com/api/cas/2020-04-07/UploadUserCertificate
*/

package aliyun

import (
	cas20200407 "github.com/alibabacloud-go/cas-20200407/v4/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/darabonba-openapi/v2/models"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/orange-juzipi/cert-deploy/internal/client/providers"
)

var _ providers.ProviderHandler = (*Provider)(nil)

type Provider struct {
	AccessKeyId     string
	AccessKeySecret string
	client          *cas20200407.Client
}

// New 创建实例
func New(accessKeyId, accessKeySecret string) (*Provider, error) {
	config := &openapi.Config{
		AccessKeyId:     tea.String(accessKeyId),
		AccessKeySecret: tea.String(accessKeySecret),
	}
	config.Endpoint = tea.String("cas.aliyuncs.com")

	client, err := cas20200407.NewClient(config)
	if err != nil {
		return nil, err
	}

	return &Provider{
		AccessKeyId:     accessKeyId,
		AccessKeySecret: accessKeySecret,
		client:          client,
	}, nil
}

// getParams 统一配置 API 参数
func (p *Provider) getParams(action string) *models.Params {
	return &models.Params{
		Action:      tea.String(action),
		Version:     tea.String("2020-04-07"),
		Protocol:    tea.String("HTTPS"),
		Method:      tea.String("POST"),
		AuthType:    tea.String("AK"),
		Style:       tea.String("RPC"),
		Pathname:    tea.String("/"),
		ReqBodyType: tea.String("json"),
		BodyType:    tea.String("json"),
	}
}

// TestConnection 测试连接
// 验证 AccessKey 是否有效,请求的是查询 CSR 列表接口
func (p *Provider) TestConnection() (bool, error) {
	params := p.getParams("ListCsr")
	req := &models.OpenApiRequest{}
	runtime := &util.RuntimeOptions{}
	_, err := p.client.CallApi(params, req, runtime)
	if err != nil {
		return false, err
	}

	return true, nil
}

// UploadCertificate 上传证书
func (p *Provider) UploadCertificate(name, cert, key string) error {
	params := p.getParams("UploadUserCertificate")
	req := &models.OpenApiRequest{
		Query: map[string]*string{
			"Name": tea.String(name),
			"Cert": tea.String(cert),
			"Key":  tea.String(key),
		},
	}
	runtime := &util.RuntimeOptions{}
	_, err := p.client.CallApi(params, req, runtime)
	if err != nil {
		return err
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
