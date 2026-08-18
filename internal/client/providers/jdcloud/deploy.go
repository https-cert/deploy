package jdcloud

import (
	"context"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	cdnapi "github.com/jdcloud-api/jdcloud-sdk-go/services/cdn/apis"
)

// DeployCertificate 上传或复用证书，绑定精确 CDN 域名并等待配置任务完成后回读。
func (p *Provider) DeployCertificate(ctx context.Context, certificate providers.CertificateMaterial, deploymentType deployPB.DeploymentType, resource providers.DeploymentResource) (providers.DeploymentResult, error) {
	if deploymentType != deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN {
		return providers.DeploymentResult{}, providers.NewDeploymentError("京东云不支持该部署业务", false, "", nil)
	}
	if strings.TrimSpace(resource.TargetRef) == "" || strings.TrimSpace(resource.Domain) == "" || strings.TrimSpace(resource.CreatedAt) == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("京东云 CDN 目标缺少 targetRef、域名或创建时间", false, "", nil)
	}
	if err := providers.ValidateCertificateMaterial(certificate, resource.Domain, time.Now()); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("京东云 CDN 证书校验失败", false, "", err)
	}
	preflight, requestID, err := p.getDomainDetail(ctx, resource.Domain)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("读取 CDN 域名", err)
	}
	if err := validateCurrentResource(resource, preflight); err != nil {
		return providers.DeploymentResult{}, err
	}
	certificateID, uploadRequestID, err := p.ensureCertificate(ctx, certificate)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("上传证书", err)
	}
	requestID = firstNonEmpty(uploadRequestID, requestID)
	setRequest := cdnapi.NewSetHttpTypeRequest(resource.Domain)
	setRequest.SetHttpType("https")
	setRequest.SetCertFrom("ssl")
	setRequest.SetSslCertId(certificateID)
	setRequest.SetSyncToSsl(false)
	jumpType := strings.TrimSpace(preflight.JumpType)
	if jumpType == "" {
		jumpType = "default"
	}
	setRequest.SetJumpType(jumpType)
	response, err := p.cdnClient.SetHttpType(setRequest)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("更新 CDN HTTPS 配置", err)
	}
	requestID = firstNonEmpty(responseRequestID(response), requestID)
	if err := checkResponse("更新 CDN HTTPS 配置", responseRequestID(response), responseError(response)); err != nil {
		return providers.DeploymentResult{}, toDeploymentError("更新 CDN HTTPS 配置", err)
	}
	if taskID := strings.TrimSpace(response.Result.TaskId); taskID != "" {
		taskRequestID, waitErr := p.waitTask(ctx, taskID)
		requestID = firstNonEmpty(taskRequestID, requestID)
		if waitErr != nil {
			return providers.DeploymentResult{}, toDeploymentError("等待 CDN 配置任务", waitErr)
		}
	}
	readback, readRequestID, err := p.getDomainDetail(ctx, resource.Domain)
	requestID = firstNonEmpty(readRequestID, requestID)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("回读 CDN 域名", err)
	}
	if !strings.EqualFold(strings.TrimSpace(readback.HttpType), "https") || strings.TrimSpace(readback.SslCertId) != certificateID {
		return providers.DeploymentResult{}, providers.NewDeploymentError("京东云 CDN 证书回读尚未生效", true, requestID, nil)
	}
	return providers.DeploymentResult{RequestID: requestID, Message: "京东云 CDN 证书部署成功"}, nil
}

// getDomainDetail 读取一个京东云 CDN 域名详情并校验业务响应。
func (p *Provider) getDomainDetail(ctx context.Context, domain string) (cdnapi.GetDomainDetailResult, string, error) {
	if err := ctx.Err(); err != nil {
		return cdnapi.GetDomainDetailResult{}, "", err
	}
	response, err := p.cdnClient.GetDomainDetail(cdnapi.NewGetDomainDetailRequest(domain))
	if err != nil {
		return cdnapi.GetDomainDetailResult{}, "", err
	}
	if err := checkResponse("读取 CDN 域名", responseRequestID(response), responseError(response)); err != nil {
		return cdnapi.GetDomainDetailResult{}, responseRequestID(response), err
	}
	return response.Result, response.RequestID, nil
}

// waitTask 等待京东云 CDN 异步配置任务成功，未知状态不会被误判为成功。
func (p *Provider) waitTask(ctx context.Context, taskID string) (string, error) {
	lastRequestID := ""
	for attempt := 0; attempt < taskPollAttempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(p.pollInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return lastRequestID, ctx.Err()
			case <-timer.C:
			}
		}
		response, err := p.cdnClient.QueryDomainConfigStatus(cdnapi.NewQueryDomainConfigStatusRequest(taskID))
		if err != nil {
			return lastRequestID, err
		}
		lastRequestID = firstNonEmpty(responseRequestID(response), lastRequestID)
		if err := checkResponse("查询 CDN 配置任务", responseRequestID(response), responseError(response)); err != nil {
			return lastRequestID, err
		}
		switch strings.ToLower(strings.TrimSpace(response.Result.TaskStatus)) {
		case "success", "succeeded", "finished":
			return lastRequestID, nil
		case "fail", "failed", "error":
			return lastRequestID, providers.NewDeploymentError("京东云 CDN 配置任务失败", false, lastRequestID, nil)
		case "running", "pending", "processing", "wait", "":
			continue
		default:
			return lastRequestID, providers.NewDeploymentError("京东云 CDN 配置任务返回未知状态", true, lastRequestID, nil)
		}
	}
	return lastRequestID, providers.NewDeploymentError("京东云 CDN 配置任务等待超时", true, lastRequestID, nil)
}

// validateCurrentResource 防止同名 CDN 域名删除重建后沿用旧 targetRef。
func validateCurrentResource(resource providers.DeploymentResource, detail cdnapi.GetDomainDetailResult) error {
	domain, err := providers.NormalizeDomain(detail.Domain)
	if err != nil || domain != resource.Domain || strings.TrimSpace(detail.Created) != strings.TrimSpace(resource.CreatedAt) {
		return providers.NewDeploymentError("京东云 CDN 域名身份已变化，请重新关联资源", false, "", err)
	}
	if !strings.EqualFold(strings.TrimSpace(detail.Status), "online") {
		return providers.NewDeploymentError("京东云 CDN 域名当前不可部署", false, "", nil)
	}
	return nil
}
