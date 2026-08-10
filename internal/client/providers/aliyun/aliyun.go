/*
文档：https://help.aliyun.com/zh/ssl-certificate/use-cases/automatic-certificate-deployment-to-cloud-services
调试控制台：https://next.api.aliyun.com/api/cas/2020-04-07/UploadUserCertificate
*/

package aliyun

import (
	"fmt"
	"strings"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/darabonba-openapi/v2/models"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/https-cert/deploy/internal/client/providers"
)

var (
	_ providers.ProviderHandler            = (*Provider)(nil)
	_ providers.DeploymentResourceDeployer = (*Provider)(nil)
)

// Provider 管理阿里云证书中心和精确云资源部署所需的客户端。
type Provider struct {
	// AccessKeyId 是阿里云访问密钥标识，不得写入日志。
	AccessKeyId string
	// AccessKeySecret 是阿里云访问密钥密钥，不得写入日志。
	AccessKeySecret string
	// casClient 执行阿里云证书中心上传和连接测试。
	casClient *openapi.Client
	// deploymentAPI 执行 CDN、DCDN、ESA、CLB、ALB 和 NLB 资源的精确 OpenAPI 调用。
	deploymentAPI deploymentAPI
	// ossAPI 执行 OSS Bucket CNAME 的上下文感知读写操作。
	ossAPI ossCnameAPI
}

// New 创建实例
func New(accessKeyId, accessKeySecret string) (*Provider, error) {
	provider := &Provider{
		AccessKeyId:     accessKeyId,
		AccessKeySecret: accessKeySecret,
	}

	var err error
	provider.casClient, err = buildOpenAPIClient(accessKeyId, accessKeySecret, "cas.aliyuncs.com")
	if err != nil {
		return nil, err
	}

	provider.deploymentAPI, err = newOpenAPIDeploymentAPI(accessKeyId, accessKeySecret)
	if err != nil {
		return nil, fmt.Errorf("初始化阿里云产品 API 客户端失败: %w", err)
	}
	provider.ossAPI = newSignedOSSCnameAPI(accessKeyId, accessKeySecret, nil)

	return provider, nil
}

// buildOpenAPIClient 构建阿里云 OpenAPI 客户端
func buildOpenAPIClient(accessKeyID, accessKeySecret, endpoint string) (*openapi.Client, error) {
	config := &openapi.Config{
		AccessKeyId:     new(accessKeyID),
		AccessKeySecret: new(accessKeySecret),
		Endpoint:        new(endpoint),
	}

	client, err := openapi.NewClient(config)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// getParams 统一构建 RPC 请求参数
func getParams(action, version, method string) *models.Params {
	if strings.TrimSpace(method) == "" {
		method = "POST"
	}
	return &models.Params{
		Action:      new(action),
		Version:     new(version),
		Protocol:    new("HTTPS"),
		Method:      new(method),
		AuthType:    new("AK"),
		Style:       new("RPC"),
		Pathname:    new("/"),
		ReqBodyType: new("json"),
		BodyType:    new("json"),
	}
}

// callRPC 使用 POST 方式调用阿里云 RPC 接口
func (p *Provider) callRPC(client *openapi.Client, action, version string, query map[string]*string) (map[string]any, error) {
	return p.callRPCWithMethod(client, action, version, "POST", query)
}

// callRPCWithMethod 按指定 HTTP Method 调用阿里云 RPC 接口
func (p *Provider) callRPCWithMethod(client *openapi.Client, action, version, method string, query map[string]*string) (map[string]any, error) {
	if client == nil {
		return nil, fmt.Errorf("阿里云 client 未初始化: action=%s", action)
	}

	req := &models.OpenApiRequest{}
	if query != nil {
		req.Query = query
	}

	runtime := &util.RuntimeOptions{}
	resp, err := client.CallApi(getParams(action, version, method), req, runtime)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// TestConnection 测试连接
func (p *Provider) TestConnection() (bool, error) {
	_, err := p.callRPC(p.casClient, "ListCsr", "2020-04-07", nil)
	if err != nil {
		return false, err
	}
	return true, nil
}

// UploadCertificate 上传证书
func (p *Provider) UploadCertificate(name, domain, cert, key string) error {
	_ = domain
	return p.uploadCASCertificate(name, cert, key)
}

// uploadCASCertificate 通过 CAS 接口上传证书
func (p *Provider) uploadCASCertificate(name, cert, key string) error {
	_, err := p.callRPC(p.casClient, "UploadUserCertificate", "2020-04-07", map[string]*string{
		"Name": new(name),
		"Cert": new(cert),
		"Key":  new(key),
	})
	if err != nil {
		return err
	}
	return nil
}
