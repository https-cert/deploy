package aliyun

import (
	"context"
	"fmt"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
)

// acceleratedProduct 描述一种需要先校验 HTTPS 的阿里云加速域名产品。
type acceleratedProduct struct {
	// DisplayName 是用于安全结果说明的产品名称。
	DisplayName string
	// Endpoint 是对应产品的 OpenAPI endpoint。
	Endpoint string
	// Version 是对应产品的 API 版本。
	Version string
	// PreflightAction 是读取精确域名配置的 action。
	PreflightAction string
	// WriteAction 是写入上传证书的 action。
	WriteAction string
	// ReadbackAction 是回读域名证书信息的 action。
	ReadbackAction string
	// DetailKey 是前置响应中域名详情对象的键。
	DetailKey string
	// HTTPSKey 是详情对象中 HTTPS 是否启用的键。
	HTTPSKey string
}

// deployCDN 部署证书到一个已配置的阿里云 CDN 精确域名。
func (p *Provider) deployCDN(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	return p.deployAcceleratedDomain(ctx, certificate, target, acceleratedProduct{
		DisplayName:     "CDN",
		Endpoint:        aliyunCDNEndpoint,
		Version:         aliyunCDNVersion,
		PreflightAction: "DescribeCdnDomainDetail",
		WriteAction:     "SetCdnDomainSSLCertificate",
		ReadbackAction:  "DescribeDomainCertificateInfo",
		DetailKey:       "GetDomainDetailModel",
		HTTPSKey:        "ServerCertificateStatus",
	})
}

// deployDCDN 部署证书到一个已配置的阿里云 DCDN 精确域名。
func (p *Provider) deployDCDN(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	return p.deployAcceleratedDomain(ctx, certificate, target, acceleratedProduct{
		DisplayName:     "DCDN",
		Endpoint:        aliyunDCDNEndpoint,
		Version:         aliyunDCDNVersion,
		PreflightAction: "DescribeDcdnDomainDetail",
		WriteAction:     "SetDcdnDomainSSLCertificate",
		ReadbackAction:  "DescribeDcdnDomainCertificateInfo",
		DetailKey:       "DomainDetail",
		HTTPSKey:        "SSLProtocol",
	})
}

// deployAcceleratedDomain 执行加速域名的精确预检、写入和控制面回读。
func (p *Provider) deployAcceleratedDomain(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource, product acceleratedProduct) (providers.DeploymentResult, error) {
	if p == nil || p.deploymentAPI == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云部署客户端未初始化", false, "", nil)
	}

	preflight, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: product.Endpoint,
		Action:   product.PreflightAction,
		Version:  product.Version,
		Method:   "POST",
		Query: map[string]string{
			"DomainName": target.Domain,
		},
	})
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("读取"+product.DisplayName+"域名配置", err)
	}
	if err := validateAcceleratedDomain(preflight.Body, target.Domain, product); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云"+product.DisplayName+"目标校验失败", false, preflight.RequestID, newSafeAliyunCause("目标校验", err))
	}

	certificateName := deploymentCertificateName(certificate)
	written, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: product.Endpoint,
		Action:   product.WriteAction,
		Version:  product.Version,
		Method:   "POST",
		Query: map[string]string{
			"CertName":    certificateName,
			"CertType":    "upload",
			"DomainName":  target.Domain,
			"SSLPri":      certificate.PrivateKeyPEM,
			"SSLProtocol": "on",
			"SSLPub":      certificate.CertificatePEM,
		},
	})
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("更新"+product.DisplayName+"域名证书", err)
	}

	readback, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: product.Endpoint,
		Action:   product.ReadbackAction,
		Version:  product.Version,
		Method:   "POST",
		Query: map[string]string{
			"DomainName": target.Domain,
		},
	})
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("回读"+product.DisplayName+"域名证书", written.RequestID, err)
	}
	if matched, applying := acceleratedCertificateReadback(readback.Body, certificateName); !matched && !applying {
		requestID := firstNonEmpty(written.RequestID, readback.RequestID)
		return providers.DeploymentResult{}, providers.NewDeploymentError(
			"阿里云"+product.DisplayName+"控制面尚未确认新证书",
			true,
			requestID,
			newSafeAliyunCause("控制面回读", fmt.Errorf("未找到提交的证书配置")),
		)
	}

	return providers.DeploymentResult{
		RequestID: firstNonEmpty(written.RequestID, readback.RequestID),
		Message:   "阿里云" + product.DisplayName + "域名证书部署成功",
	}, nil
}

// validateAcceleratedDomain 确认读取到的就是目标域名，且该域名当前启用了 HTTPS。
func validateAcceleratedDomain(body map[string]any, targetDomain string, product acceleratedProduct) error {
	detailValue, found := getMapValue(body, product.DetailKey)
	if !found {
		return fmt.Errorf("响应缺少域名详情")
	}
	detail, ok := normalizeToMap(detailValue)
	if !ok {
		return fmt.Errorf("域名详情格式异常")
	}
	returnedDomain := strings.TrimSpace(mapString(detail, "DomainName"))
	if returnedDomain == "" || !strings.EqualFold(returnedDomain, strings.TrimSpace(targetDomain)) {
		return fmt.Errorf("云端返回的域名与目标不一致")
	}
	if !strings.EqualFold(strings.TrimSpace(mapString(detail, product.HTTPSKey)), "on") {
		return fmt.Errorf("目标域名未启用 HTTPS")
	}
	return nil
}

// acceleratedCertificateReadback 判断证书详情是否已经显示本次提交的证书名称或处于控制面应用中。
func acceleratedCertificateReadback(body map[string]any, certificateName string) (matched bool, applying bool) {
	certInfosValue, found := getMapValue(body, "CertInfos")
	if !found {
		return false, responseHasApplyingStatus(body)
	}
	certInfos, ok := normalizeToMap(certInfosValue)
	if !ok {
		return false, responseHasApplyingStatus(body)
	}
	for _, record := range mapSlice(certInfos, "CertInfo") {
		if strings.EqualFold(strings.TrimSpace(mapString(record, "CertName")), strings.TrimSpace(certificateName)) {
			return true, false
		}
		if isApplyingStatus(mapString(record, "Status"), mapString(record, "CertStatus")) {
			applying = true
		}
	}
	return false, applying || responseHasApplyingStatus(body)
}
