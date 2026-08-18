package cloud_tencent

import (
	"context"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/tencentyun/cos-go-sdk-v5"
)

// deployCOSCertificate 校验 Bucket 自定义域名，写入 PEM 证书和私钥，并回读确认。
func (p *Provider) deployCOSCertificate(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	client, err := p.getCOSClient(target)
	if err != nil {
		return providers.DeploymentResult{}, newTencentDeploymentError("初始化 COS 客户端", err)
	}

	domains, response, err := client.GetDomains(ctx)
	if err != nil {
		return providers.DeploymentResult{}, newCOSDeploymentError("查询 COS 自定义域名", err)
	}
	readRequestID := cosRequestID(response)
	if domains == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 COS 自定义域名查询响应格式异常", true, readRequestID, nil)
	}
	if !containsEnabledCOSDomain(domains, target.Domain) {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 COS 未找到已启用的精确自定义域名", false, readRequestID, nil)
	}

	putResponse, err := client.PutDomainCertificate(ctx, &cos.BucketPutDomainCertificateOptions{
		CertificateInfo: &cos.BucketDomainCertificateInfo{
			CertType: cosCustomCertType,
			CustomCert: &cos.BucketDomainCustomCert{
				Cert:       certificate.CertificatePEM,
				PrivateKey: certificate.PrivateKeyPEM,
			},
		},
		DomainList: []string{strings.TrimSpace(target.Domain)},
	})
	if err != nil {
		return providers.DeploymentResult{}, newCOSDeploymentError("更新 COS 自定义域名证书", err)
	}
	requestID := cosRequestID(putResponse)

	readBack, readBackResponse, err := client.GetDomainCertificate(ctx, strings.TrimSpace(target.Domain))
	if err != nil {
		return providers.DeploymentResult{}, newCOSDeploymentError("回读 COS 自定义域名证书", err)
	}
	if requestID == "" {
		requestID = cosRequestID(readBackResponse)
	}
	if readBack == nil || !strings.EqualFold(strings.TrimSpace(readBack.Status), cosDomainStatusReady) {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 COS 证书回读尚未生效", true, requestID, nil)
	}
	if readBack.CertificateInfo == nil || strings.TrimSpace(readBack.CertificateInfo.CertId) == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 COS 证书回读缺少证书 ID", true, requestID, nil)
	}
	fingerprintRequestID, err := p.verifyCertificateFingerprint(ctx, readBack.CertificateInfo.CertId, certificate.CertificatePEM)
	if err != nil {
		return providers.DeploymentResult{}, err
	}

	return providers.DeploymentResult{
		RequestID: firstTencentRequestID(requestID, fingerprintRequestID),
		Message:   "腾讯云 COS 自定义域名证书部署成功",
	}, nil
}

// containsEnabledCOSDomain 检查 Bucket 域名目录中是否存在完全匹配且启用的自定义域名。
func containsEnabledCOSDomain(result *cos.BucketGetDomainResult, domain string) bool {
	if result == nil {
		return false
	}
	for _, rule := range result.Rules {
		if strings.EqualFold(strings.TrimSpace(rule.Name), strings.TrimSpace(domain)) &&
			strings.EqualFold(strings.TrimSpace(rule.Status), cosDomainStatusReady) {
			return true
		}
	}
	return false
}
