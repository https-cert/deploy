//go:build !windows

/*
文档：https://help.aliyun.com/zh/ssl-certificate/use-cases/automatic-certificate-deployment-to-cloud-services
调试控制台：https://next.api.aliyun.com/api/cas/2020-04-07/UploadUserCertificate
ESA 文档：https://help.aliyun.com/zh/edge-security-acceleration/esa/api-esa-2024-09-10-setcertificate
*/

package aliyun

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/darabonba-openapi/v2/models"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/https-cert/deploy/internal/client/providers"
)

var _ providers.ProviderHandler = (*Provider)(nil)

type Provider struct {
	AccessKeyId     string
	AccessKeySecret string
	casClient       *openapi.Client
	esaClient       *openapi.Client
	options         Options
}

// New 创建实例
func New(accessKeyId, accessKeySecret string, options *Options) (*Provider, error) {
	opts, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}

	provider := &Provider{
		AccessKeyId:     accessKeyId,
		AccessKeySecret: accessKeySecret,
		options:         opts,
	}

	switch opts.Service {
	case ServiceCAS:
		provider.casClient, err = buildOpenAPIClient(accessKeyId, accessKeySecret, "cas.aliyuncs.com")
	case ServiceESA:
		provider.esaClient, err = buildOpenAPIClient(accessKeyId, accessKeySecret, defaultESAEndpoint)
	default:
		return nil, fmt.Errorf("不支持的阿里云服务类型: %s", opts.Service)
	}
	if err != nil {
		return nil, err
	}

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

// normalizeOptions 归一化并校验阿里云 Provider 配置
func normalizeOptions(options *Options) (Options, error) {
	opts := Options{
		Service: ServiceCAS,
	}
	if options != nil {
		opts = *options
	}

	opts.Service = strings.ToLower(strings.TrimSpace(opts.Service))
	opts.ESASiteID = strings.TrimSpace(opts.ESASiteID)
	if opts.Service == "" {
		opts.Service = ServiceCAS
	}
	if opts.Service != ServiceCAS && opts.Service != ServiceESA {
		return opts, fmt.Errorf("阿里云 service 配置无效: %s (支持: %s, %s)", opts.Service, ServiceCAS, ServiceESA)
	}
	if opts.Service == ServiceESA && opts.ESASiteID == "" {
		return opts, fmt.Errorf("ESA 模式缺少 SiteId：请配置 provider.auth.esaSiteId")
	}

	return opts, nil
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
	switch p.options.Service {
	case ServiceCAS:
		_, err := p.callRPC(p.casClient, "ListCsr", "2020-04-07", nil)
		if err != nil {
			return false, err
		}
		return true, nil
	case ServiceESA:
		_, err := p.callRPCWithMethod(p.esaClient, "ListSites", "2024-09-10", "GET", map[string]*string{
			"PageNumber": new(strconv.Itoa(1)),
			"PageSize":   new(strconv.Itoa(10)),
		})
		if err != nil {
			return false, err
		}
		return true, nil
	default:
		return false, fmt.Errorf("不支持的阿里云服务类型: %s", p.options.Service)
	}
}

// UploadCertificate 上传证书
func (p *Provider) UploadCertificate(name, domain, cert, key string) error {
	switch p.options.Service {
	case ServiceCAS:
		return p.uploadCASCertificate(name, cert, key)
	case ServiceESA:
		return p.uploadESACertificate(name, domain, cert, key)
	default:
		return fmt.Errorf("不支持的阿里云服务类型: %s", p.options.Service)
	}
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

// uploadESACertificate 通过 ESA 接口上传证书并处理重名回退
func (p *Provider) uploadESACertificate(name, domain, cert, key string) error {
	err := p.setESACertificate(name, "", cert, key)
	if err == nil {
		return nil
	}
	if !isESAErrorCode(err, "Certificate.Duplicated") {
		return fmt.Errorf("ESA 设置证书失败(siteId=%s, domain=%s): %w", p.options.ESASiteID, domain, err)
	}

	existingID, resolveErr := p.findESACertificateIDByName(name)
	if resolveErr != nil {
		existingID, resolveErr = p.findESACertificateIDByUploadedCert(cert)
	}
	if resolveErr == nil {
		retryErr := p.setESACertificate(name, existingID, cert, key)
		if retryErr == nil {
			return nil
		}

		fallbackName := buildUniqueESACertificateName(name, domain, time.Now().UTC())
		fallbackErr := p.setESACertificate(fallbackName, "", cert, key)
		if fallbackErr == nil {
			return nil
		}

		return fmt.Errorf("ESA 设置证书失败(siteId=%s, domain=%s): %w; 使用已有证书ID重试失败(certId=%s): %v; 更换唯一名称重试失败(name=%s): %v", p.options.ESASiteID, domain, err, existingID, retryErr, fallbackName, fallbackErr)
	}

	fallbackName := buildUniqueESACertificateName(name, domain, time.Now().UTC())
	fallbackErr := p.setESACertificate(fallbackName, "", cert, key)
	if fallbackErr == nil {
		return nil
	}

	return fmt.Errorf("ESA 设置证书失败(siteId=%s, domain=%s): %w; 处理重名证书失败: %v; 更换唯一名称重试失败(name=%s): %v", p.options.ESASiteID, domain, err, resolveErr, fallbackName, fallbackErr)
}

// setESACertificate 调用 ESA SetCertificate 接口设置证书
func (p *Provider) setESACertificate(name, certificateID, cert, key string) error {
	query := map[string]*string{
		"Type":        new("upload"),
		"SiteId":      new(p.options.ESASiteID),
		"Name":        new(name),
		"CertName":    new(name),
		"Certificate": new(cert),
		"PrivateKey":  new(key),
	}
	if strings.TrimSpace(certificateID) != "" {
		normalizedID := strings.TrimSpace(certificateID)
		query["Id"] = new(normalizedID)
		query["CertId"] = new(normalizedID)
	}

	_, err := p.callRPC(p.esaClient, "SetCertificate", "2024-09-10", query)
	return err
}

// findESACertificateIDByName 按证书名称查找 ESA 证书 ID
func (p *Provider) findESACertificateIDByName(name string) (string, error) {
	records, err := p.listESACertificates(strings.TrimSpace(name))
	if err != nil {
		return "", err
	}
	return selectESACertificateIDByName(records, name)
}

// findESACertificateIDByUploadedCert 按上传证书内容匹配 ESA 证书 ID
func (p *Provider) findESACertificateIDByUploadedCert(cert string) (string, error) {
	records, err := p.listESACertificates("")
	if err != nil {
		return "", err
	}

	targetFingerprint, targetSerial, parseErr := extractCertFingerprintAndSerial(cert)
	if parseErr != nil {
		return "", parseErr
	}

	return selectESACertificateIDByFingerprintOrSerial(records, targetFingerprint, targetSerial)
}

// listESACertificates 分页查询指定站点下的 ESA 证书列表
func (p *Provider) listESACertificates(keyword string) ([]any, error) {
	pageSize := 100
	pageNumber := 1
	var records []any

	for pageNumber <= 20 {
		query := map[string]*string{
			"SiteId":     new(p.options.ESASiteID),
			"PageNumber": new(strconv.Itoa(pageNumber)),
			"PageSize":   new(strconv.Itoa(pageSize)),
		}
		if strings.TrimSpace(keyword) != "" {
			query["Keyword"] = new(strings.TrimSpace(keyword))
		}
		query["ValidOnly"] = new("false")

		resp, err := p.callRPCWithMethod(p.esaClient, "ListCertificates", "2024-09-10", "GET", query)
		if err != nil && isESAErrorCode(err, "InvalidValidOnly") {
			delete(query, "ValidOnly")
			resp, err = p.callRPCWithMethod(p.esaClient, "ListCertificates", "2024-09-10", "GET", query)
		}
		if err != nil {
			return nil, fmt.Errorf("调用 ESA ListCertificates 失败(page=%d): %w", pageNumber, err)
		}

		result, parseErr := parseESAListCertificatesResult(resp)
		if parseErr != nil {
			return nil, parseErr
		}
		records = append(records, result...)
		if len(result) < pageSize {
			break
		}
		pageNumber++
	}

	return records, nil
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
