package baidu

import (
	"context"
	"strings"
	"time"

	cdnapi "github.com/baidubce/bce-sdk-go/services/cdn/api"
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

// DeployCertificate 上传或复用证书，更新精确 CDN 域名并回读证书 ID。
func (p *Provider) DeployCertificate(ctx context.Context, certificate providers.CertificateMaterial, deploymentType deployPB.DeploymentType, resource providers.DeploymentResource) (providers.DeploymentResult, error) {
	if deploymentType != deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN {
		return providers.DeploymentResult{}, providers.NewDeploymentError("百度云不支持该部署业务", false, "", nil)
	}
	if strings.TrimSpace(resource.TargetRef) == "" || strings.TrimSpace(resource.Domain) == "" || strings.TrimSpace(resource.CreatedAt) == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("百度云 CDN 目标缺少 targetRef、域名或创建时间", false, "", nil)
	}
	if err := providers.ValidateCertificateMaterial(certificate, resource.Domain, time.Now()); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("百度云 CDN 证书校验失败", false, "", err)
	}
	if err := ctx.Err(); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("百度云 CDN 部署已取消", false, "", err)
	}
	current, err := p.cdnClient.GetDomainConfig(resource.Domain)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("读取 CDN 域名", err)
	}
	if err := validateCurrentResource(resource, current); err != nil {
		return providers.DeploymentResult{}, err
	}

	certificateID, err := p.ensureCertificate(ctx, certificate)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("上传证书", err)
	}
	if err := ctx.Err(); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("百度云 CDN 部署已取消", false, "", err)
	}
	httpsConfig, err := p.cdnClient.GetDomainHttps(resource.Domain)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("读取 CDN HTTPS 配置", err)
	}
	if httpsConfig == nil {
		httpsConfig = &cdnapi.HTTPSConfig{}
	}
	updated := *httpsConfig
	updated.Enabled = true
	updated.CertId = certificateID
	if err := p.cdnClient.SetDomainHttps(resource.Domain, &updated); err != nil {
		return providers.DeploymentResult{}, toDeploymentError("更新 CDN HTTPS 配置", err)
	}
	readback, err := p.cdnClient.GetDomainHttps(resource.Domain)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("回读 CDN HTTPS 配置", err)
	}
	if readback == nil || !readback.Enabled || strings.TrimSpace(readback.CertId) != certificateID {
		return providers.DeploymentResult{}, providers.NewDeploymentError("百度云 CDN 证书回读尚未生效", true, "", nil)
	}
	return providers.DeploymentResult{Message: "百度云 CDN 证书部署成功"}, nil
}

// validateCurrentResource 防止同名域名删除重建后沿用旧 targetRef 部署。
func validateCurrentResource(resource providers.DeploymentResource, current *cdnapi.DomainConfig) error {
	if current == nil {
		return providers.NewDeploymentError("百度云 CDN 域名不存在", false, "", nil)
	}
	domain, err := providers.NormalizeDomain(current.Domain)
	if err != nil || domain != resource.Domain || strings.TrimSpace(current.CreateTime) != strings.TrimSpace(resource.CreatedAt) {
		return providers.NewDeploymentError("百度云 CDN 域名身份已变化，请重新关联资源", false, "", err)
	}
	if strings.ToUpper(strings.TrimSpace(current.Status)) != "RUNNING" {
		return providers.NewDeploymentError("百度云 CDN 域名当前不可部署", false, "", nil)
	}
	return nil
}
