package client

import (
	"context"
	"fmt"
	"time"

	"github.com/https-cert/deploy/internal/client/deploys"
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
)

// deploymentResourceProviderFactory 根据明确业务创建支持发现和部署的云厂商适配器。
type deploymentResourceProviderFactory func(providerName string, business deployPB.ExecuteBusinesType) (providers.DeploymentResourceProvider, error)

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
	if request.ExecuteBusinesType == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ANSSL_CLI_1PANEL_WEBSITE_CERT {
		return be.executeOnePanelWebsiteResource(ctx, request)
	}

	factory := be.deploymentResourceProviderFactory
	if factory == nil {
		factory = be.getDeploymentResourceProvider
	}
	resourceProvider, err := factory(request.ProviderName, request.ExecuteBusinesType)
	if err != nil {
		return providers.DeploymentResult{}, err
	}
	resource, err := resourceProvider.ResolveResource(ctx, request.ExecuteBusinesType, request.TargetRef)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("部署资源已失效，请删除后重新关联", false, "", err)
	}
	if err := providers.EnsureResourceReady(resource); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("部署资源当前不可用", false, "", err)
	}
	certificate := providers.CertificateMaterial{
		Name:           request.Remark,
		Domain:         request.Domain,
		CertificatePEM: request.CertificatePEM,
		PrivateKeyPEM:  request.PrivateKeyPEM,
	}
	domains := resource.Domains
	if len(domains) == 0 {
		domains = []string{resource.Domain}
	}
	if err := providers.ValidateCertificateForDomains(certificate, domains, time.Now()); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("部署资源证书校验失败: "+err.Error(), false, "", err)
	}
	result, err := resourceProvider.DeployCertificate(ctx, certificate, request.ExecuteBusinesType, resource)
	if err != nil {
		return result, err
	}
	if result.Message == "" {
		result.Message = "证书部署成功"
	}
	return result, nil
}

// executeOnePanelWebsiteResource 在客户端本地重新解析网站引用并精确替换所选网站证书。
func (be *BusinessExecutor) executeOnePanelWebsiteResource(ctx context.Context, request BusinessRequest) (providers.DeploymentResult, error) {
	if request.ProviderName != "ansslCli" {
		return providers.DeploymentResult{}, providers.NewDeploymentError(localDeploymentFailureMessage, false, "", fmt.Errorf("1Panel 网站业务 provider 不匹配"))
	}
	if err := deploys.DeployCertificateTo1PanelWebsite(ctx, request.TargetRef, request.CertificatePEM, request.PrivateKeyPEM); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError(
			localDeploymentFailureMessage,
			deploys.IsOnePanelErrorRetryable(err),
			"",
			err,
		)
	}
	return providers.DeploymentResult{Message: "1Panel 网站证书部署成功"}, nil
}
