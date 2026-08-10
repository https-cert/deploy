package aliyun

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
)

const albCertificatePageSize = 100

// deployALB 将证书部署到配置的阿里云 ALB HTTPS 或 QUIC 监听器。
func (p *Provider) deployALB(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	if p == nil || p.deploymentAPI == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ALB 部署客户端未初始化", false, "", nil)
	}
	listener, err := p.describeALBListener(ctx, target.Region, target.ListenerID)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("读取 ALB 监听器", err)
	}
	defaultCertificateIDs, listenerState, err := validateALBListener(listener.Body, target)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ALB 监听器校验失败", false, listener.RequestID, newSafeAliyunCause("ALB 监听器校验", err))
	}
	listenerUsable, listenerRetryable := classifyLoadBalancerListenerStatus(listenerState)
	if listenerRetryable {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ALB 监听器仍在配置中", true, listener.RequestID, nil)
	}
	if !listenerUsable {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ALB 监听器状态不支持部署", false, listener.RequestID, nil)
	}

	listenerCertificatesResponse, err := p.listALBListenerCertificates(ctx, target.Region, target.ListenerID)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("读取 ALB 监听器证书", listener.RequestID, err)
	}
	if err := validateListenerCertificatesStable(listenerCertificatesResponse.Certificates); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ALB 监听器证书仍在异步变更", true, firstNonEmpty(listenerCertificatesResponse.RequestID, listener.RequestID), newSafeAliyunCause("ALB 证书状态", err))
	}

	casCertificates, casRequestID, err := p.listCASCertificates(ctx)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("读取 CAS 证书", firstNonEmpty(listenerCertificatesResponse.RequestID, listener.RequestID), err)
	}
	slot, err := selectLoadBalancerCertificateSlot(target.Domain, target.Region, defaultCertificateIDs, listenerCertificatesResponse.Certificates, casCertificates)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ALB 证书槽位校验失败", false, firstNonEmpty(casRequestID, listenerCertificatesResponse.RequestID, listener.RequestID), newSafeAliyunCause("ALB 证书槽位", err))
	}

	certificateID, uploadRequestID, err := p.findOrUploadCASCertificate(ctx, certificate, target.Region, slot.CurrentCertificateID, casCertificates)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("准备 ALB 证书", firstNonEmpty(casRequestID, listenerCertificatesResponse.RequestID, listener.RequestID), err)
	}
	if strings.EqualFold(strings.TrimSpace(slot.CurrentCertificateID), strings.TrimSpace(certificateID)) {
		return providers.DeploymentResult{
			RequestID: firstNonEmpty(uploadRequestID, casRequestID, listenerCertificatesResponse.RequestID, listener.RequestID),
			Message:   "阿里云 ALB 监听器已配置当前证书",
		}, nil
	}

	if slot.IsDefault {
		written, err := p.updateALBDefaultCertificate(ctx, target.Region, target.ListenerID, certificateID)
		if err != nil {
			return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("更新 ALB 默认服务器证书", firstNonEmpty(uploadRequestID, listener.RequestID), err)
		}
		jobID := strings.TrimSpace(mapString(written.Body, "JobId"))
		if jobID == "" {
			return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ALB 默认证书写请求未返回 JobId", true, firstNonEmpty(written.RequestID, uploadRequestID), nil)
		}
		readbackRequestID, err := p.waitALBCertificateSlot(ctx, target.Region, target.ListenerID, certificateID, true, "")
		if err != nil {
			return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ALB 默认服务器证书回读超时", true, firstNonEmpty(written.RequestID, jobID, uploadRequestID, readbackRequestID), newSafeAliyunCause("ALB 默认证书回读", err))
		}
		return providers.DeploymentResult{
			RequestID: firstNonEmpty(written.RequestID, readbackRequestID, uploadRequestID),
			Message:   "阿里云 ALB 默认服务器证书部署成功",
		}, nil
	}

	associated, err := p.associateALBAdditionalCertificate(ctx, target.Region, target.ListenerID, certificateID)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("关联 ALB SNI 证书", firstNonEmpty(uploadRequestID, listener.RequestID), err)
	}
	associateJobID := strings.TrimSpace(mapString(associated.Body, "JobId"))
	if associateJobID == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ALB SNI 证书关联请求未返回 JobId", true, firstNonEmpty(associated.RequestID, uploadRequestID), nil)
	}
	readbackRequestID, err := p.waitALBCertificateSlot(ctx, target.Region, target.ListenerID, certificateID, false, "")
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ALB 新 SNI 证书回读超时", true, firstNonEmpty(associated.RequestID, associateJobID, uploadRequestID, readbackRequestID), newSafeAliyunCause("ALB SNI 证书回读", err))
	}
	if slot.CurrentCertificateID == "" {
		return providers.DeploymentResult{
			RequestID: firstNonEmpty(associated.RequestID, readbackRequestID, uploadRequestID),
			Message:   "阿里云 ALB SNI 证书部署成功",
		}, nil
	}

	dissociated, err := p.dissociateALBAdditionalCertificate(ctx, target.Region, target.ListenerID, slot.CurrentCertificateID)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("解除 ALB 旧 SNI 证书", firstNonEmpty(associated.RequestID, uploadRequestID), err)
	}
	dissociateJobID := strings.TrimSpace(mapString(dissociated.Body, "JobId"))
	if dissociateJobID == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ALB 旧 SNI 证书解除请求未返回 JobId", true, firstNonEmpty(dissociated.RequestID, associated.RequestID, uploadRequestID), nil)
	}
	removedRequestID, err := p.waitALBCertificateSlot(ctx, target.Region, target.ListenerID, certificateID, false, slot.CurrentCertificateID)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ALB 旧 SNI 证书解除超时", true, firstNonEmpty(dissociated.RequestID, dissociateJobID, associated.RequestID, uploadRequestID, removedRequestID), newSafeAliyunCause("ALB 旧 SNI 证书回读", err))
	}
	return providers.DeploymentResult{
		RequestID: firstNonEmpty(dissociated.RequestID, removedRequestID, associated.RequestID, uploadRequestID),
		Message:   "阿里云 ALB SNI 证书部署成功",
	}, nil
}

// describeALBListener 查询 ALB 监听器属性，返回默认服务器证书 ID 和监听器状态。
func (p *Provider) describeALBListener(ctx context.Context, region, listenerID string) (cloudAPIResponse, error) {
	endpoint, err := aliyunRegionalEndpoint("alb", region)
	if err != nil {
		return cloudAPIResponse{}, err
	}
	return p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: endpoint,
		Action:   "GetListenerAttribute",
		Version:  aliyunALBVersion,
		Method:   "POST",
		Query:    map[string]string{"ListenerId": listenerID},
	})
}

// validateALBListener 校验监听器 ID、实例 ID和协议，并提取默认服务器证书列表。
func validateALBListener(body map[string]any, target providers.DeploymentResource) ([]string, string, error) {
	if !strings.EqualFold(mapString(body, "ListenerId"), strings.TrimSpace(target.ListenerID)) {
		return nil, "", fmt.Errorf("云端返回的监听器 ID 不匹配")
	}
	if !strings.EqualFold(mapString(body, "LoadBalancerId"), strings.TrimSpace(target.LoadBalancerID)) {
		return nil, "", fmt.Errorf("云端返回的负载均衡实例不匹配")
	}
	protocol := strings.ToUpper(strings.TrimSpace(mapString(body, "ListenerProtocol")))
	if protocol != "HTTPS" && protocol != "QUIC" {
		return nil, "", fmt.Errorf("监听器不是支持的 HTTPS 或 QUIC 协议")
	}
	certificateIDs := make([]string, 0)
	for _, record := range mapSlice(body, "Certificates") {
		if certificateID := strings.TrimSpace(mapString(record, "CertificateId")); certificateID != "" {
			certificateIDs = append(certificateIDs, certificateID)
		}
	}
	if len(certificateIDs) == 0 {
		certificateIDs = mapStringList(body, "CertificateIds")
	}
	return certificateIDs, mapString(body, "ListenerStatus"), nil
}

// listALBListenerCertificates 分页读取 ALB 监听器的默认和扩展服务器证书。
func (p *Provider) listALBListenerCertificates(ctx context.Context, region, listenerID string) (albListenerCertificatesResponse, error) {
	result := albListenerCertificatesResponse{Certificates: make([]listenerCertificateMetadata, 0)}
	endpoint, err := aliyunRegionalEndpoint("alb", region)
	if err != nil {
		return result, err
	}
	nextToken := ""
	for page := 0; page < casCertificateMaxPages; page++ {
		query := map[string]string{
			"ListenerId":      listenerID,
			"CertificateType": "Server",
			"MaxResults":      fmt.Sprintf("%d", albCertificatePageSize),
		}
		if nextToken != "" {
			query["NextToken"] = nextToken
		}
		response, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{
			Endpoint: endpoint,
			Action:   "ListListenerCertificates",
			Version:  aliyunALBVersion,
			Method:   "POST",
			Query:    query,
		})
		if err != nil {
			return result, err
		}
		result.RequestID = firstNonEmpty(response.RequestID, result.RequestID)
		for _, record := range mapSlice(response.Body, "Certificates") {
			certificateID := strings.TrimSpace(mapString(record, "CertificateId"))
			if certificateID == "" {
				return result, fmt.Errorf("ALB 监听器证书记录缺少证书 ID")
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
	return result, fmt.Errorf("ALB 监听器证书列表超过安全分页上限")
}

// updateALBDefaultCertificate 更新 ALB 默认服务器证书，不携带客户端 CA 字段。
func (p *Provider) updateALBDefaultCertificate(ctx context.Context, region, listenerID, certificateID string) (cloudAPIResponse, error) {
	endpoint, err := aliyunRegionalEndpoint("alb", region)
	if err != nil {
		return cloudAPIResponse{}, err
	}
	return p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: endpoint,
		Action:   "UpdateListenerAttribute",
		Version:  aliyunALBVersion,
		Method:   "POST",
		Query: map[string]string{
			"ListenerId":                   listenerID,
			"Certificates.1.CertificateId": certificateID,
		},
	})
}

// associateALBAdditionalCertificate 关联一个新的 ALB SNI 扩展证书。
func (p *Provider) associateALBAdditionalCertificate(ctx context.Context, region, listenerID, certificateID string) (cloudAPIResponse, error) {
	endpoint, err := aliyunRegionalEndpoint("alb", region)
	if err != nil {
		return cloudAPIResponse{}, err
	}
	return p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: endpoint,
		Action:   "AssociateAdditionalCertificatesWithListener",
		Version:  aliyunALBVersion,
		Method:   "POST",
		Query: map[string]string{
			"ListenerId":                   listenerID,
			"Certificates.1.CertificateId": certificateID,
		},
	})
}

// dissociateALBAdditionalCertificate 解除指定 ALB SNI 扩展证书的关联。
func (p *Provider) dissociateALBAdditionalCertificate(ctx context.Context, region, listenerID, certificateID string) (cloudAPIResponse, error) {
	endpoint, err := aliyunRegionalEndpoint("alb", region)
	if err != nil {
		return cloudAPIResponse{}, err
	}
	return p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: endpoint,
		Action:   "DissociateAdditionalCertificatesFromListener",
		Version:  aliyunALBVersion,
		Method:   "POST",
		Query: map[string]string{
			"ListenerId":                   listenerID,
			"Certificates.1.CertificateId": certificateID,
		},
	})
}

// waitALBCertificateSlot 轮询 ALB 证书列表，确认新证书生效并按需确认旧证书已解除。
func (p *Provider) waitALBCertificateSlot(ctx context.Context, region, listenerID, expectedCertificateID string, wantDefault bool, removedCertificateID string) (string, error) {
	for {
		response, err := p.listALBListenerCertificates(ctx, region, listenerID)
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

// listenerCertificateSlotMatches 判断证书是否已位于期望的默认或扩展槽位。
func listenerCertificateSlotMatches(certificates []listenerCertificateMetadata, expectedCertificateID string, wantDefault bool) bool {
	for _, certificate := range certificates {
		if strings.EqualFold(strings.TrimSpace(certificate.CertificateID), strings.TrimSpace(expectedCertificateID)) && certificate.IsDefault == wantDefault && strings.EqualFold(strings.TrimSpace(certificate.Status), "associated") {
			return true
		}
	}
	return false
}

// listenerCertificateExists 判断证书 ID 是否仍在监听器关联列表中。
func listenerCertificateExists(certificates []listenerCertificateMetadata, certificateID string) bool {
	for _, certificate := range certificates {
		if strings.EqualFold(strings.TrimSpace(certificate.CertificateID), strings.TrimSpace(certificateID)) {
			return true
		}
	}
	return false
}

// albListenerCertificatesResponse 保存 ALB 证书列表和最近请求编号。
type albListenerCertificatesResponse struct {
	Certificates []listenerCertificateMetadata // Certificates 是默认及扩展服务器证书。
	RequestID    string                        // RequestID 是最近一次列表请求编号。
}

// mapStringList 从响应 map 中读取一个可转换为字符串列表的字段。
func mapStringList(data map[string]any, key string) []string {
	value, found := getMapValue(data, key)
	if !found {
		return nil
	}
	normalized := normalizeValue(value)
	result := make([]string, 0)
	switch typedValue := normalized.(type) {
	case []any:
		for _, item := range typedValue {
			if value := strings.TrimSpace(anyToString(item)); value != "" {
				result = append(result, value)
			}
		}
	case string:
		if value := strings.TrimSpace(typedValue); value != "" {
			result = append(result, value)
		}
	}
	return result
}
