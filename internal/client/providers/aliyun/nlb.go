package aliyun

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
)

const nlbCertificatePageSize = 100

// deployNLB 将证书部署到配置的阿里云 NLB TCPSSL 监听器。
func (p *Provider) deployNLB(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	if p == nil || p.deploymentAPI == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 NLB 部署客户端未初始化", false, "", nil)
	}
	listener, err := p.describeNLBListener(ctx, target)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("读取 NLB 监听器", err)
	}
	defaultCertificateIDs, listenerState, err := validateNLBListener(listener.Body, target)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 NLB 监听器校验失败", false, listener.RequestID, newSafeAliyunCause("NLB 监听器校验", err))
	}
	listenerUsable, listenerRetryable := classifyLoadBalancerListenerStatus(listenerState)
	if listenerRetryable {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 NLB 监听器仍在配置中", true, listener.RequestID, nil)
	}
	if !listenerUsable {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 NLB 监听器状态不支持部署", false, listener.RequestID, nil)
	}

	listenerCertificatesResponse, err := p.listNLBListenerCertificates(ctx, target)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("读取 NLB 监听器证书", listener.RequestID, err)
	}
	if err := validateListenerCertificatesStable(listenerCertificatesResponse.Certificates); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 NLB 监听器证书仍在异步变更", true, firstNonEmpty(listenerCertificatesResponse.RequestID, listener.RequestID), newSafeAliyunCause("NLB 证书状态", err))
	}

	casCertificates, casRequestID, err := p.listCASCertificates(ctx)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("读取 CAS 证书", firstNonEmpty(listenerCertificatesResponse.RequestID, listener.RequestID), err)
	}
	slot, err := selectLoadBalancerCertificateSlot(target.Domain, target.Region, defaultCertificateIDs, listenerCertificatesResponse.Certificates, casCertificates)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 NLB 证书槽位校验失败", false, firstNonEmpty(casRequestID, listenerCertificatesResponse.RequestID, listener.RequestID), newSafeAliyunCause("NLB 证书槽位", err))
	}

	certificateID, uploadRequestID, err := p.findOrUploadCASCertificate(ctx, certificate, target.Region, slot.CurrentCertificateID, casCertificates)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("准备 NLB 证书", firstNonEmpty(casRequestID, listenerCertificatesResponse.RequestID, listener.RequestID), err)
	}
	if strings.EqualFold(strings.TrimSpace(slot.CurrentCertificateID), strings.TrimSpace(certificateID)) {
		return providers.DeploymentResult{
			RequestID: firstNonEmpty(uploadRequestID, casRequestID, listenerCertificatesResponse.RequestID, listener.RequestID),
			Message:   "阿里云 NLB 监听器已配置当前证书",
		}, nil
	}

	if slot.IsDefault {
		written, err := p.updateNLBDefaultCertificate(ctx, target, certificateID)
		if err != nil {
			return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("更新 NLB 默认服务器证书", firstNonEmpty(uploadRequestID, listener.RequestID), err)
		}
		jobID := strings.TrimSpace(mapString(written.Body, "JobId"))
		jobRequestID, err := p.waitNLBJob(ctx, target.Region, jobID)
		if err != nil {
			return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 NLB 默认证书异步任务未完成", true, firstNonEmpty(jobRequestID, written.RequestID, jobID, uploadRequestID), newSafeAliyunCause("NLB 默认证书任务", err))
		}
		readbackRequestID, err := p.waitNLBListenerCertificateSlot(ctx, target, certificateID, true, "")
		if err != nil {
			return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 NLB 默认服务器证书回读超时", true, firstNonEmpty(jobRequestID, written.RequestID, readbackRequestID, uploadRequestID), newSafeAliyunCause("NLB 默认证书回读", err))
		}
		return providers.DeploymentResult{
			RequestID: firstNonEmpty(written.RequestID, jobRequestID, readbackRequestID, uploadRequestID),
			Message:   "阿里云 NLB 默认服务器证书部署成功",
		}, nil
	}

	associated, err := p.associateNLBAdditionalCertificate(ctx, target, certificateID)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("关联 NLB SNI 证书", firstNonEmpty(uploadRequestID, listener.RequestID), err)
	}
	associateJobID := strings.TrimSpace(mapString(associated.Body, "JobId"))
	associateJobRequestID, err := p.waitNLBJob(ctx, target.Region, associateJobID)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 NLB 新 SNI 证书异步任务未完成", true, firstNonEmpty(associateJobRequestID, associated.RequestID, associateJobID, uploadRequestID), newSafeAliyunCause("NLB SNI 关联任务", err))
	}
	readbackRequestID, err := p.waitNLBListenerCertificateSlot(ctx, target, certificateID, false, "")
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 NLB 新 SNI 证书回读超时", true, firstNonEmpty(associateJobRequestID, associated.RequestID, readbackRequestID, uploadRequestID), newSafeAliyunCause("NLB SNI 证书回读", err))
	}
	if slot.CurrentCertificateID == "" {
		return providers.DeploymentResult{
			RequestID: firstNonEmpty(associated.RequestID, associateJobRequestID, readbackRequestID, uploadRequestID),
			Message:   "阿里云 NLB SNI 证书部署成功",
		}, nil
	}

	dissociated, err := p.dissociateNLBAdditionalCertificate(ctx, target, slot.CurrentCertificateID)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("解除 NLB 旧 SNI 证书", firstNonEmpty(associated.RequestID, uploadRequestID), err)
	}
	dissociateJobID := strings.TrimSpace(mapString(dissociated.Body, "JobId"))
	dissociateJobRequestID, err := p.waitNLBJob(ctx, target.Region, dissociateJobID)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 NLB 旧 SNI 证书异步任务未完成", true, firstNonEmpty(dissociateJobRequestID, dissociated.RequestID, dissociateJobID, uploadRequestID), newSafeAliyunCause("NLB SNI 解除任务", err))
	}
	removedRequestID, err := p.waitNLBListenerCertificateSlot(ctx, target, certificateID, false, slot.CurrentCertificateID)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 NLB 旧 SNI 证书解除超时", true, firstNonEmpty(dissociateJobRequestID, dissociated.RequestID, removedRequestID, uploadRequestID), newSafeAliyunCause("NLB 旧 SNI 证书回读", err))
	}
	return providers.DeploymentResult{
		RequestID: firstNonEmpty(dissociated.RequestID, dissociateJobRequestID, removedRequestID, associated.RequestID, uploadRequestID),
		Message:   "阿里云 NLB SNI 证书部署成功",
	}, nil
}

// describeNLBListener 查询 NLB 监听器属性。
func (p *Provider) describeNLBListener(ctx context.Context, target providers.DeploymentResource) (cloudAPIResponse, error) {
	endpoint, err := aliyunRegionalEndpoint("nlb", target.Region)
	if err != nil {
		return cloudAPIResponse{}, err
	}
	return p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: endpoint,
		Action:   "GetListenerAttribute",
		Version:  aliyunNLBVersion,
		Method:   "POST",
		Query: map[string]string{
			"RegionId":   target.Region,
			"ListenerId": target.ListenerID,
		},
	})
}

// validateNLBListener 校验监听器实例、ID 和 TCPSSL 协议，并提取服务器证书 ID。
func validateNLBListener(body map[string]any, target providers.DeploymentResource) ([]string, string, error) {
	if !strings.EqualFold(mapString(body, "ListenerId"), strings.TrimSpace(target.ListenerID)) {
		return nil, "", fmt.Errorf("云端返回的监听器 ID 不匹配")
	}
	if !strings.EqualFold(mapString(body, "LoadBalancerId"), strings.TrimSpace(target.LoadBalancerID)) {
		return nil, "", fmt.Errorf("云端返回的负载均衡实例不匹配")
	}
	if !strings.EqualFold(strings.TrimSpace(mapString(body, "ListenerProtocol")), "TCPSSL") {
		return nil, "", fmt.Errorf("监听器不是支持的 TCPSSL 协议")
	}
	certificateIDs := mapStringList(body, "CertificateIds")
	return certificateIDs, mapString(body, "ListenerStatus"), nil
}

// listNLBListenerCertificates 分页读取 NLB 监听器的默认和扩展服务器证书。
func (p *Provider) listNLBListenerCertificates(ctx context.Context, target providers.DeploymentResource) (nlbListenerCertificatesResponse, error) {
	result := nlbListenerCertificatesResponse{Certificates: make([]listenerCertificateMetadata, 0)}
	endpoint, err := aliyunRegionalEndpoint("nlb", target.Region)
	if err != nil {
		return result, err
	}
	nextToken := ""
	for page := 0; page < casCertificateMaxPages; page++ {
		body := map[string]string{
			"RegionId":   target.Region,
			"ListenerId": target.ListenerID,
			"CertType":   "Server",
			"MaxResults": fmt.Sprintf("%d", nlbCertificatePageSize),
		}
		if nextToken != "" {
			body["NextToken"] = nextToken
		}
		response, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{
			Endpoint: endpoint,
			Action:   "ListListenerCertificates",
			Version:  aliyunNLBVersion,
			Method:   "POST",
			Body:     body,
		})
		if err != nil {
			return result, err
		}
		result.RequestID = firstNonEmpty(response.RequestID, result.RequestID)
		for _, record := range mapSlice(response.Body, "Certificates") {
			certificateID := strings.TrimSpace(mapString(record, "CertificateId"))
			if certificateID == "" {
				return result, fmt.Errorf("NLB 监听器证书记录缺少证书 ID")
			}
			result.Certificates = append(result.Certificates, listenerCertificateMetadata{
				CertificateID: certificateID,
				IsDefault:     mapBool(record, "IsDefault"),
				Status:        mapString(record, "Status"),
			})
		}
		nextToken = strings.TrimSpace(mapString(response.Body, "NextToken"))
		if nextToken == "" {
			return result, nil
		}
	}
	return result, fmt.Errorf("NLB 监听器证书列表超过安全分页上限")
}

// updateNLBDefaultCertificate 更新 NLB 默认服务器证书。
func (p *Provider) updateNLBDefaultCertificate(ctx context.Context, target providers.DeploymentResource, certificateID string) (cloudAPIResponse, error) {
	endpoint, err := aliyunRegionalEndpoint("nlb", target.Region)
	if err != nil {
		return cloudAPIResponse{}, err
	}
	return p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: endpoint,
		Action:   "UpdateListenerAttribute",
		Version:  aliyunNLBVersion,
		Method:   "POST",
		Body: map[string]string{
			"RegionId":         target.Region,
			"ListenerId":       target.ListenerID,
			"CertificateIds.1": certificateID,
		},
	})
}

// associateNLBAdditionalCertificate 关联一个新的 NLB SNI 扩展证书。
func (p *Provider) associateNLBAdditionalCertificate(ctx context.Context, target providers.DeploymentResource, certificateID string) (cloudAPIResponse, error) {
	endpoint, err := aliyunRegionalEndpoint("nlb", target.Region)
	if err != nil {
		return cloudAPIResponse{}, err
	}
	return p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: endpoint,
		Action:   "AssociateAdditionalCertificatesWithListener",
		Version:  aliyunNLBVersion,
		Method:   "POST",
		Body: map[string]string{
			"RegionId":                   target.Region,
			"ListenerId":                 target.ListenerID,
			"AdditionalCertificateIds.1": certificateID,
		},
	})
}

// dissociateNLBAdditionalCertificate 解除指定 NLB SNI 扩展证书的关联。
func (p *Provider) dissociateNLBAdditionalCertificate(ctx context.Context, target providers.DeploymentResource, certificateID string) (cloudAPIResponse, error) {
	endpoint, err := aliyunRegionalEndpoint("nlb", target.Region)
	if err != nil {
		return cloudAPIResponse{}, err
	}
	return p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: endpoint,
		Action:   "DisassociateAdditionalCertificatesWithListener",
		Version:  aliyunNLBVersion,
		Method:   "POST",
		Body: map[string]string{
			"RegionId":                   target.Region,
			"ListenerId":                 target.ListenerID,
			"AdditionalCertificateIds.1": certificateID,
		},
	})
}

// waitNLBJob 按官方 GetJobStatus 轮询 NLB 异步任务。
func (p *Provider) waitNLBJob(ctx context.Context, region, jobID string) (string, error) {
	if strings.TrimSpace(jobID) == "" {
		return "", fmt.Errorf("NLB 写请求未返回 JobId")
	}
	endpoint, err := aliyunRegionalEndpoint("nlb", region)
	if err != nil {
		return "", err
	}
	lastRequestID := ""
	for {
		response, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{
			Endpoint: endpoint,
			Action:   "GetJobStatus",
			Version:  aliyunNLBVersion,
			Method:   "POST",
			Query:    map[string]string{"JobId": jobID},
		})
		if err != nil {
			return lastRequestID, err
		}
		lastRequestID = firstNonEmpty(response.RequestID, lastRequestID)
		switch strings.ToLower(strings.TrimSpace(mapString(response.Body, "Status"))) {
		case "succeeded", "success":
			return lastRequestID, nil
		case "processing", "running", "pending":
		default:
			return lastRequestID, fmt.Errorf("NLB 异步任务返回失败或未知状态")
		}
		select {
		case <-ctx.Done():
			return lastRequestID, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// waitNLBListenerCertificateSlot 轮询 NLB 证书列表确认新证书和旧证书状态。
func (p *Provider) waitNLBListenerCertificateSlot(ctx context.Context, target providers.DeploymentResource, expectedCertificateID string, wantDefault bool, removedCertificateID string) (string, error) {
	for {
		response, err := p.listNLBListenerCertificates(ctx, target)
		if err != nil {
			return response.RequestID, err
		}
		if listenerCertificateSlotMatches(response.Certificates, expectedCertificateID, wantDefault) && (removedCertificateID == "" || !listenerCertificateExists(response.Certificates, removedCertificateID)) {
			return response.RequestID, nil
		}
		select {
		case <-ctx.Done():
			return response.RequestID, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// nlbListenerCertificatesResponse 保存 NLB 证书列表和最近请求编号。
type nlbListenerCertificatesResponse struct {
	Certificates []listenerCertificateMetadata // Certificates 是默认及扩展服务器证书。
	RequestID    string                        // RequestID 是最近一次列表请求编号。
}
