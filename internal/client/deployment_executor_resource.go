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

const (
	// deploymentResourceExecutionTimeout 为后端等待窗口预留结构化 ACK 发送时间。
	deploymentResourceExecutionTimeout = 55 * time.Second
	// localDeploymentFailureMessage 避免把本机路径、SSH 主机和远端诊断回传到后端。
	localDeploymentFailureMessage = "部署失败，请查看 deploy 客户端日志"
)

// deploymentResourceProviderFactory 根据 v2 provider/type 创建云厂商资源适配器。
type deploymentResourceProviderFactory func(provider deployPB.Provider, deploymentType deployPB.DeploymentType) (providers.DeploymentResourceProvider, error)

// DeploymentExecutionRequest 描述一次由 v2 WebSocket 下发的部署请求。
type DeploymentExecutionRequest struct {
	Provider       deployPB.Provider       // Provider 是 v2 部署平台。
	DeploymentType deployPB.DeploymentType // DeploymentType 是 v2 部署类型。
	TargetRef      string                  // TargetRef 是客户端生成的不透明稳定资源引用。
	Domain         string                  // Domain 是证书的规范化主域名。
	DownloadURL    string                  // DownloadURL 是本地部署使用的证书下载地址。
	Remark         string                  // Remark 是证书中心上传时使用的备注。
	CertificatePEM string                  // CertificatePEM 是资源部署使用的完整证书链。
	PrivateKeyPEM  string                  // PrivateKeyPEM 是资源部署使用的私钥。
}

// Execute 执行一条支持 context 和结构化结果的 v2 部署请求。
func (be *DeploymentExecutor) Execute(ctx context.Context, request DeploymentExecutionRequest) (providers.DeploymentResult, error) {
	if !config.IsDeploymentResourceType(request.DeploymentType) {
		if err := be.executeNonResourceDeployment(
			request.Provider,
			request.DeploymentType,
			request.Domain,
			request.DownloadURL,
			request.Remark,
			request.CertificatePEM,
			request.PrivateKeyPEM,
		); err != nil {
			return providers.DeploymentResult{}, err
		}
		return providers.DeploymentResult{Message: "证书部署成功"}, nil
	}

	return be.executeDeploymentResource(ctx, request)
}

// executeDeploymentResource 按 provider、明确业务和 targetRef 精确解析配置并执行部署。
func (be *DeploymentExecutor) executeDeploymentResource(ctx context.Context, request DeploymentExecutionRequest) (providers.DeploymentResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if request.Provider == deployPB.Provider_PROVIDER_UNSPECIFIED {
		return providers.DeploymentResult{}, providers.NewDeploymentError("部署资源缺少 provider", false, "", nil)
	}
	if request.TargetRef == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("部署资源缺少 targetRef", false, "", nil)
	}
	if !config.IsDeploymentResourceType(request.DeploymentType) {
		return providers.DeploymentResult{}, providers.NewDeploymentError("请求不是动态资源部署类型", false, "", nil)
	}
	if request.DeploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_WEBSITE_CERT {
		return be.executeOnePanelWebsiteResource(ctx, request)
	}
	if request.DeploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_BT_PANEL_WEBSITE_CERT {
		return be.executeBTPanelWebsiteResource(ctx, request)
	}

	factory := be.deploymentResourceProviderFactory
	if factory == nil {
		factory = newDeploymentResourceProvider
	}
	resourceProvider, err := factory(request.Provider, request.DeploymentType)
	if err != nil {
		return providers.DeploymentResult{}, err
	}
	resource, err := resourceProvider.ResolveResource(ctx, request.DeploymentType, request.TargetRef)
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
	result, err := resourceProvider.DeployCertificate(ctx, certificate, request.DeploymentType, resource)
	if err != nil {
		return result, err
	}
	if result.Message == "" {
		result.Message = "证书部署成功"
	}
	return result, nil
}

// executeBTPanelWebsiteResource 在客户端本地重新解析宝塔网站引用并精确替换所选网站证书。
func (be *DeploymentExecutor) executeBTPanelWebsiteResource(ctx context.Context, request DeploymentExecutionRequest) (providers.DeploymentResult, error) {
	if request.Provider != deployPB.Provider_PROVIDER_ANSSL_CLI {
		return providers.DeploymentResult{}, providers.NewDeploymentError(localDeploymentFailureMessage, false, "", fmt.Errorf("宝塔网站部署平台不匹配"))
	}
	if err := deploys.DeployCertificateToBTPanelWebsite(ctx, request.TargetRef, request.CertificatePEM, request.PrivateKeyPEM); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError(
			localDeploymentFailureMessage,
			deploys.IsBTPanelErrorRetryable(err),
			"",
			err,
		)
	}
	return providers.DeploymentResult{Message: "宝塔网站证书部署成功"}, nil
}

// executeOnePanelWebsiteResource 在客户端本地重新解析网站引用并精确替换所选网站证书。
func (be *DeploymentExecutor) executeOnePanelWebsiteResource(ctx context.Context, request DeploymentExecutionRequest) (providers.DeploymentResult, error) {
	if request.Provider != deployPB.Provider_PROVIDER_ANSSL_CLI {
		return providers.DeploymentResult{}, providers.NewDeploymentError(localDeploymentFailureMessage, false, "", fmt.Errorf("1Panel 网站部署平台不匹配"))
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
