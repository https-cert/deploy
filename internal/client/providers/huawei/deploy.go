package huawei

import (
	"context"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

// DeployCertificate 将证书部署到精确的华为云资源并执行控制面回读验收。
func (p *Provider) DeployCertificate(ctx context.Context, certificate providers.CertificateMaterial, deploymentType deployPB.DeploymentType, resource providers.DeploymentResource) (providers.DeploymentResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(resource.TargetRef) == "" || strings.TrimSpace(resource.Domain) == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("华为云目标缺少 targetRef 或域名", false, "", nil)
	}
	targetDomains := resource.Domains
	if len(targetDomains) == 0 {
		targetDomains = []string{resource.Domain}
	}
	if err := providers.ValidateCertificateForDomains(certificate, targetDomains, time.Now()); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("华为云证书校验失败", false, "", err)
	}
	scmCertificateID, requestID, err := p.ensureCertificate(ctx, certificate)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("上传证书", err)
	}

	var message string
	switch deploymentType {
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN:
		requestID, err = p.deployCDN(ctx, certificate, deploymentType, resource, scmCertificateID, requestID)
		message = "华为云 CDN 证书部署成功"
		if deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN {
			message = "华为云 DCDN 证书部署成功"
		}
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_OBS_CUSTOM_DOMAIN:
		requestID, err = p.deployOBS(ctx, certificate, resource, scmCertificateID, requestID)
		message = "华为云 OBS 自定义域名证书部署成功"
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_ELB:
		requestID, err = p.deployELB(ctx, certificate, resource, scmCertificateID, requestID)
		message = "华为云 ELB 证书部署成功"
	default:
		return providers.DeploymentResult{}, providers.NewDeploymentError("华为云不支持该部署业务", false, requestID, nil)
	}
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("部署证书", err)
	}
	return providers.DeploymentResult{RequestID: requestID, Message: message}, nil
}
