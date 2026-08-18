package aliyun

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

// DeployCertificate 将证书部署到一个明确阿里云业务下精确解析出的资源。
func (p *Provider) DeployCertificate(ctx context.Context, certificate providers.CertificateMaterial, deploymentType deployPB.DeploymentType, resource providers.DeploymentResource) (providers.DeploymentResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("资源部署", err)
	}
	if err := validateAliyunDeploymentResource(deploymentType, resource); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云部署资源配置无效", false, "", newSafeAliyunCause("资源校验", err))
	}
	if err := providers.ValidateCertificateMaterial(certificate, resource.Domain, time.Now()); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云部署资源证书校验失败", false, "", newSafeAliyunCause("证书校验", err))
	}

	switch deploymentType {
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN:
		return p.deployCDN(ctx, certificate, resource)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN:
		return p.deployDCDN(ctx, certificate, resource)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA:
		return p.deployESA(ctx, certificate, resource)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_OSS_CUSTOM_DOMAIN:
		return p.deployOSS(ctx, certificate, resource)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CLB:
		return p.deployCLB(ctx, certificate, resource)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_ALB:
		return p.deployALB(ctx, certificate, resource)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_NLB:
		return p.deployNLB(ctx, certificate, resource)
	default:
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云不支持该部署业务", false, "", nil)
	}
}

// validateAliyunDeploymentResource 拒绝缺少引用和产品专属定位字段的直接调用。
func validateAliyunDeploymentResource(deploymentType deployPB.DeploymentType, resource providers.DeploymentResource) error {
	if strings.TrimSpace(resource.TargetRef) == "" {
		return fmt.Errorf("targetRef 不能为空")
	}
	if strings.TrimSpace(resource.Domain) == "" {
		return fmt.Errorf("目标域名不能为空")
	}

	switch deploymentType {
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN:
		return nil
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA:
		if _, err := parseESASiteID(resource.SiteID); err != nil {
			return err
		}
		return nil
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_OSS_CUSTOM_DOMAIN:
		if strings.TrimSpace(resource.Region) == "" || strings.TrimSpace(resource.Bucket) == "" {
			return fmt.Errorf("OSS 目标缺少地域或 Bucket")
		}
		return nil
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CLB:
		if strings.TrimSpace(resource.Region) == "" || strings.TrimSpace(resource.LoadBalancerID) == "" {
			return fmt.Errorf("CLB 目标缺少地域或负载均衡实例")
		}
		if resource.ListenerPort < 1 || resource.ListenerPort > 65535 {
			return fmt.Errorf("CLB 监听端口无效")
		}
		return nil
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_ALB:
		if strings.TrimSpace(resource.Region) == "" || strings.TrimSpace(resource.LoadBalancerID) == "" || strings.TrimSpace(resource.ListenerID) == "" {
			return fmt.Errorf("ALB 目标缺少地域、负载均衡实例或监听器")
		}
		return nil
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_NLB:
		if strings.TrimSpace(resource.Region) == "" || strings.TrimSpace(resource.LoadBalancerID) == "" || strings.TrimSpace(resource.ListenerID) == "" {
			return fmt.Errorf("NLB 目标缺少地域、负载均衡实例或监听器")
		}
		return nil
	default:
		return fmt.Errorf("不支持的阿里云部署业务")
	}
}

// parseESASiteID 校验 ESA Site ID 为正整数，但不在错误中回显其值。
func parseESASiteID(rawSiteID string) (string, error) {
	siteID := strings.TrimSpace(rawSiteID)
	if siteID == "" {
		return "", fmt.Errorf("ESA 目标缺少 SiteId")
	}
	parsed, err := strconv.ParseInt(siteID, 10, 64)
	if err != nil || parsed <= 0 {
		return "", fmt.Errorf("ESA SiteId 格式无效")
	}
	return siteID, nil
}
