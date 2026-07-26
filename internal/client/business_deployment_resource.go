package client

import (
	"context"
	"fmt"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
)

// deploymentResourceDeployerFactory 根据明确业务和已解析资源创建对应云厂商部署器。
type deploymentResourceDeployerFactory func(providerName string, business deployPB.ExecuteBusinesType) (providers.DeploymentResourceDeployer, error)

// BusinessRequest 描述一次由 WebSocket 下发的业务执行请求。
type BusinessRequest struct {
	ProviderName       string                      // ProviderName 云服务提供商配置名称。
	ExecuteBusinesType deployPB.ExecuteBusinesType // ExecuteBusinesType 明确的执行业务类型。
	TargetRef          string                      // TargetRef 本地配置自动生成的稳定资源引用。
	Domain             string                      // Domain 证书申请或旧部署业务使用的域名。
	DownloadURL        string                      // DownloadURL 本地部署使用的证书下载地址。
	Remark             string                      // Remark 证书中心上传时使用的备注。
	CertificatePEM     string                      // CertificatePEM 资源部署使用的完整证书链。
	PrivateKeyPEM      string                      // PrivateKeyPEM 资源部署使用的私钥。
}

// ExecuteWithContext 执行一条支持 context 和结构化结果的业务请求。
func (be *BusinessExecutor) ExecuteWithContext(ctx context.Context, request BusinessRequest) (providers.DeploymentResult, error) {
	if !config.IsDeploymentResourceBusiness(request.ExecuteBusinesType) {
		if err := be.ExecuteBusiness(
			request.ProviderName,
			request.ExecuteBusinesType,
			request.Domain,
			request.DownloadURL,
			request.Remark,
			request.CertificatePEM,
			request.PrivateKeyPEM,
		); err != nil {
			return providers.DeploymentResult{}, err
		}
		return providers.DeploymentResult{Message: "业务执行成功"}, nil
	}

	return be.executeDeploymentResource(ctx, request)
}

// executeDeploymentResource 按 provider、明确业务和 targetRef 精确解析配置并执行部署。
func (be *BusinessExecutor) executeDeploymentResource(ctx context.Context, request BusinessRequest) (providers.DeploymentResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if request.ProviderName == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("部署资源缺少 provider", false, "", nil)
	}
	if request.TargetRef == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("部署资源缺少 targetRef", false, "", nil)
	}
	if !config.IsDeploymentResourceBusiness(request.ExecuteBusinesType) {
		return providers.DeploymentResult{}, providers.NewDeploymentError("请求不是资源部署业务", false, "", nil)
	}

	configuredResource, ok := config.GetDeploymentResource(request.ProviderName, request.ExecuteBusinesType, request.TargetRef)
	if !ok || configuredResource == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError(
			fmt.Sprintf("部署资源不存在: provider=%s, business=%s, targetRef=%s", request.ProviderName, request.ExecuteBusinesType.String(), request.TargetRef),
			false,
			"",
			nil,
		)
	}

	resource := providers.DeploymentResource{
		TargetRef: configuredResource.TargetRef,
		Label:     configuredResource.Label,
		Domain:    configuredResource.Domain,
		Region:    configuredResource.Region,
		Endpoint:  configuredResource.Endpoint,
		Bucket:    configuredResource.Bucket,
		SiteID:    configuredResource.SiteID,
		ZoneID:    configuredResource.ZoneID,
	}
	certificate := providers.CertificateMaterial{
		Name:           request.Remark,
		Domain:         request.Domain,
		CertificatePEM: request.CertificatePEM,
		PrivateKeyPEM:  request.PrivateKeyPEM,
	}
	if err := providers.ValidateCertificateMaterial(certificate, resource.Domain, time.Now()); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("部署资源证书校验失败: "+err.Error(), false, "", err)
	}

	factory := be.deploymentResourceDeployerFactory
	if factory == nil {
		factory = be.getDeploymentResourceDeployer
	}
	deployer, err := factory(request.ProviderName, request.ExecuteBusinesType)
	if err != nil {
		return providers.DeploymentResult{}, err
	}
	result, err := deployer.DeployCertificate(ctx, certificate, request.ExecuteBusinesType, resource)
	if err != nil {
		return result, err
	}
	if result.Message == "" {
		result.Message = "证书部署成功"
	}
	return result, nil
}
