package client

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/https-cert/deploy/internal/client/deploys"
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

const localDeploymentFailureMessage = "部署失败，请查看 deploy 客户端日志"

// deploymentOperationTimeout 为后端等待窗口预留结构化 ACK 发送时间，测试可临时缩短。
var deploymentOperationTimeout = 55 * time.Second

// deploymentResourceProviderFactory 根据 v2 provider/type 创建云厂商资源适配器。
type deploymentResourceProviderFactory func(provider deployPB.Provider, deploymentType deployPB.DeploymentType) (providers.DeploymentResourceProvider, error)

// DeploymentExecutionRequest 描述一次由 v2 WebSocket 下发的部署请求。
type DeploymentExecutionRequest struct {
	// ExecutionKind 明确指定本次执行是本地部署、云上传或云动态资源部署。
	ExecutionKind  deploymentExecutionKind
	Provider       deployPB.Provider       // Provider 是 v2 部署平台。
	DeploymentType deployPB.DeploymentType // DeploymentType 是 v2 部署类型。
	TargetRef      string                  // TargetRef 是客户端生成的不透明稳定资源引用。
	Domain         string                  // Domain 是证书的规范化主域名。
	DownloadURL    string                  // DownloadURL 是本地部署使用的证书下载地址。
	Remark         string                  // Remark 是证书中心上传时使用的备注。
	CertificatePEM string                  // CertificatePEM 是资源部署使用的完整证书链。
	PrivateKeyPEM  string                  // PrivateKeyPEM 是资源部署使用的私钥。
}

// deploymentExecutionKind 表示 v2 handler 的确定执行分支。
type deploymentExecutionKind uint8

const (
	// deploymentExecutionLocalNone 表示本地无动态资源部署。
	deploymentExecutionLocalNone deploymentExecutionKind = iota + 1
	// deploymentExecutionLocalResource 表示本地面板网站动态资源部署。
	deploymentExecutionLocalResource
	// deploymentExecutionCloudUpload 表示云证书中心上传。
	deploymentExecutionCloudUpload
	// deploymentExecutionCloudResource 表示云动态资源部署。
	deploymentExecutionCloudResource
)

// Execute 执行一条支持 context 和结构化结果的 v2 部署请求。
func (be *DeploymentExecutor) Execute(ctx context.Context, request DeploymentExecutionRequest) (providers.DeploymentResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	operationCtx, cancel := context.WithTimeout(ctx, deploymentOperationTimeout)
	defer cancel()
	var dynamic bool
	switch request.ExecutionKind {
	case deploymentExecutionLocalNone:
		if request.Provider != deployPB.Provider_PROVIDER_ANSSL_CLI {
			return providers.DeploymentResult{}, providers.NewDeploymentError("本地部署执行类型与 provider 不匹配", false, "", nil)
		}
	case deploymentExecutionCloudUpload:
		if request.Provider == deployPB.Provider_PROVIDER_ANSSL_CLI {
			return providers.DeploymentResult{}, providers.NewDeploymentError("云证书上传执行类型与 provider 不匹配", false, "", nil)
		}
	case deploymentExecutionLocalResource, deploymentExecutionCloudResource:
		dynamic = true
	default:
		return providers.DeploymentResult{}, providers.NewDeploymentError("部署请求缺少明确执行类型", false, "", nil)
	}
	if !dynamic {
		if err := be.executeNonResourceDeployment(
			operationCtx,
			request.Provider,
			request.DeploymentType,
			request.Domain,
			request.DownloadURL,
			request.Remark,
			request.CertificatePEM,
			request.PrivateKeyPEM,
		); err != nil {
			return providers.DeploymentResult{}, classifyDeploymentContextError(err, operationCtx)
		}
		return providers.DeploymentResult{Message: "证书部署成功"}, nil
	}

	result, err := be.executeDeploymentResource(operationCtx, request)
	return result, classifyDeploymentContextError(err, operationCtx)
}

// classifyDeploymentContextError 将部署超时和取消转换为统一的可重试错误分类。
func classifyDeploymentContextError(err error, ctx context.Context) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || (ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded)) {
		return providers.NewDeploymentError("部署操作超时", true, "", err)
	}
	if errors.Is(err, context.Canceled) {
		return providers.NewDeploymentError("部署操作已取消", true, "", err)
	}
	return err
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
	if request.ExecutionKind != deploymentExecutionLocalResource && request.ExecutionKind != deploymentExecutionCloudResource {
		return providers.DeploymentResult{}, providers.NewDeploymentError("请求执行类型与动态资源不匹配", false, "", nil)
	}
	if request.DeploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_WEBSITE_CERT {
		return be.executeOnePanelWebsiteResource(ctx, request)
	}
	if request.DeploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_BT_PANEL_WEBSITE_CERT {
		return be.executeBTPanelWebsiteResource(ctx, request)
	}

	factory := be.deploymentResourceProviderFactory
	var resourceProvider providers.DeploymentResourceProvider
	var err error
	if factory != nil {
		resourceProvider, err = factory(request.Provider, request.DeploymentType)
	} else {
		resourceProvider, err = newDeploymentResourceProvider(request.Provider, request.DeploymentType, be.runtime)
	}
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
	if err := deploys.DeployCertificateToBTPanelWebsite(deploys.WithRuntime(ctx, be.runtime), request.TargetRef, request.CertificatePEM, request.PrivateKeyPEM); err != nil {
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
	if err := deploys.DeployCertificateTo1PanelWebsite(deploys.WithRuntime(ctx, be.runtime), request.TargetRef, request.CertificatePEM, request.PrivateKeyPEM); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError(
			localDeploymentFailureMessage,
			deploys.IsOnePanelErrorRetryable(err),
			"",
			err,
		)
	}
	return providers.DeploymentResult{Message: "1Panel 网站证书部署成功"}, nil
}
