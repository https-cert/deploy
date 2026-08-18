package qiniu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

// DeployCertificate 为明确的七牛 CDN 或 DCDN 业务部署精确域名证书。
func (p *Provider) DeployCertificate(ctx context.Context, certificate providers.CertificateMaterial, deploymentType deployPB.DeploymentType, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	if strings.TrimSpace(target.TargetRef) == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("七牛云 targetRef 不能为空", false, "", nil)
	}
	product, err := productForDeploymentType(deploymentType)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("七牛云不支持该部署业务", false, "", nil)
	}

	certificateName := strings.TrimSpace(certificate.Name)
	if certificateName == "" {
		certificateName = strings.TrimSpace(target.Label)
	}
	if certificateName == "" {
		certificateName = strings.TrimSpace(target.Domain)
	}

	result, err := p.DeployTargetCertificate(
		ctx,
		product,
		certificateName,
		target.Domain,
		certificate.CertificatePEM,
		certificate.PrivateKeyPEM,
	)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError(err)
	}

	productName := "CDN"
	if product == ProductDCDN {
		productName = "DCDN"
	}
	return providers.DeploymentResult{
		RequestID: result.ProviderRequestID,
		Message:   fmt.Sprintf("七牛云 %s 域名证书部署成功", productName),
	}, nil
}

// DeployTargetCertificate validates one exact Qiniu domain, uploads a certificate, binds it, and reads it back.
func (p *Provider) DeployTargetCertificate(ctx context.Context, product Product, name, domain, cert, key string) (*TargetDeploymentResult, error) {
	if err := p.validateProduct(product); err != nil {
		return nil, err
	}
	if err := p.validateCertificateInput("部署证书", name, domain, cert, key); err != nil {
		return nil, err
	}
	if err := p.validateCredentials("部署证书"); err != nil {
		return nil, err
	}

	if _, err := p.readAndValidateDomain(ctx, product, domain); err != nil {
		return nil, err
	}

	uploaded, err := p.UploadCertificateWithContext(ctx, name, domain, cert, key)
	if err != nil {
		return nil, err
	}

	result, err := p.bindValidatedCertificate(ctx, product, domain, uploaded.CertificateID)
	if err != nil {
		return nil, err
	}
	result.UploadRequestID = uploaded.ProviderRequestID
	return result, nil
}

// BindCertificate validates one exact Qiniu domain, binds an existing certID, and reads it back.
func (p *Provider) BindCertificate(ctx context.Context, product Product, certID, domain string) (*TargetDeploymentResult, error) {
	if err := p.validateProduct(product); err != nil {
		return nil, err
	}
	if strings.TrimSpace(certID) == "" {
		return nil, newValidationError("绑定证书", "certID 不能为空")
	}
	if strings.TrimSpace(domain) == "" {
		return nil, newValidationError("绑定证书", "域名不能为空")
	}
	if err := p.validateCredentials("绑定证书"); err != nil {
		return nil, err
	}

	if _, err := p.readAndValidateDomain(ctx, product, domain); err != nil {
		return nil, err
	}
	return p.bindValidatedCertificate(ctx, product, domain, certID)
}

// readAndValidateDomain reads the exact domain and rejects a mismatched product or non-HTTPS configuration.
func (p *Provider) readAndValidateDomain(ctx context.Context, product Product, domain string) (*domainInfo, error) {
	domainInfo, err := p.getDomain(ctx, domain)
	if err != nil {
		return nil, err
	}
	if domainInfo.Name != "" && !strings.EqualFold(strings.TrimSpace(domainInfo.Name), strings.TrimSpace(domain)) {
		return nil, newValidationError("读取域名配置", "七牛返回的域名与目标域名不一致")
	}
	if !strings.EqualFold(strings.TrimSpace(domainInfo.Product), string(product)) {
		return nil, newValidationError("读取域名配置", fmt.Sprintf("目标域名产品类型为 %q，不是 %q", domainInfo.Product, product))
	}
	if !strings.EqualFold(strings.TrimSpace(domainInfo.Protocol), "https") {
		return nil, newValidationError("读取域名配置", "目标域名未启用 HTTPS")
	}
	return domainInfo, nil
}

// bindValidatedCertificate updates a domain already checked by readAndValidateDomain and verifies its certID.
func (p *Provider) bindValidatedCertificate(ctx context.Context, product Product, domain, certID string) (*TargetDeploymentResult, error) {
	body, err := json.Marshal(httpsConfigurationRequest{CertificateID: certID})
	if err != nil {
		return nil, newLocalError("编码 HTTPS 配置请求", err)
	}

	response, err := p.execute(ctx, "更新域名 HTTPS 证书", http.MethodPut, p.apiBaseURL, domainHTTPSConfigurationPath(domain), authorizationQiniuV2, body)
	if err != nil {
		return nil, err
	}

	domainInfo, err := p.getDomain(ctx, domain)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(domainInfo.HTTPS.CertificateID), strings.TrimSpace(certID)) {
		return nil, &APIError{
			Operation:         "验证域名 HTTPS 证书",
			StatusCode:        response.StatusCode,
			ProviderRequestID: response.ProviderRequestID,
			Retryable:         true,
			Message:           "控制面回读的 certId 与提交值不一致",
		}
	}

	return &TargetDeploymentResult{
		CertificateID:     certID,
		Domain:            domain,
		Product:           product,
		ProviderRequestID: response.ProviderRequestID,
	}, nil
}

// toDeploymentError converts Qiniu provider metadata into the shared cloud deployment error contract.
func toDeploymentError(err error) error {
	var apiError *APIError
	if errors.As(err, &apiError) {
		return providers.NewDeploymentError(
			apiError.Error(),
			apiError.Retryable,
			apiError.ProviderRequestID,
			apiError,
		)
	}
	return providers.NewDeploymentError("七牛云资源部署失败", false, "", err)
}
