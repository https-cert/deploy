package aliyun

import (
	"context"
	"fmt"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
)

// deployESA 部署证书到一个 Site 中精确匹配的 ESA Record。
func (p *Provider) deployESA(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	if p == nil || p.deploymentAPI == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云部署客户端未初始化", false, "", nil)
	}
	siteID, err := parseESASiteID(target.SiteID)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ESA 目标配置无效", false, "", newSafeAliyunCause("目标校验", err))
	}

	preflight, err := p.listESACertificatesByRecord(ctx, siteID, target.Domain)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("读取 ESA Record 证书配置", err)
	}
	preflightRecord, found := findESARecord(preflight.Body, target.Domain)
	if !found {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ESA 目标校验失败", false, preflight.RequestID, newSafeAliyunCause("目标校验", fmt.Errorf("未找到精确 Record")))
	}

	fingerprint, _, fingerprintErr := extractCertFingerprintAndSerial(certificate.CertificatePEM)
	if fingerprintErr != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ESA 证书校验失败", false, preflight.RequestID, newSafeAliyunCause("证书指纹", fingerprintErr))
	}
	if strings.EqualFold(strings.TrimSpace(mapString(preflightRecord, "Status")), "configured") && esaRecordContainsFingerprint(preflightRecord, fingerprint) {
		return providers.DeploymentResult{
			RequestID: preflight.RequestID,
			Message:   "阿里云 ESA Record 已配置当前证书",
		}, nil
	}

	written, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: aliyunESAEndpoint,
		Action:   "SetCertificate",
		Version:  aliyunESAVersion,
		Method:   "POST",
		Body: map[string]string{
			"Certificate": certificate.CertificatePEM,
			"Name":        deploymentCertificateName(certificate),
			"PrivateKey":  certificate.PrivateKeyPEM,
			"SiteId":      siteID,
			"Type":        "upload",
		},
	})
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("更新 ESA 证书", err)
	}

	readback, err := p.listESACertificatesByRecord(ctx, siteID, target.Domain)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("回读 ESA Record 证书配置", written.RequestID, err)
	}
	readbackRecord, found := findESARecord(readback.Body, target.Domain)
	if !found {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 ESA 控制面未返回目标 Record", true, firstNonEmpty(written.RequestID, readback.RequestID), nil)
	}
	status := strings.ToLower(strings.TrimSpace(mapString(readbackRecord, "Status")))
	if esaRecordContainsFingerprint(readbackRecord, fingerprint) && (status == "configured" || isApplyingStatus(status)) {
		return providers.DeploymentResult{
			RequestID: firstNonEmpty(written.RequestID, readback.RequestID),
			Message:   "阿里云 ESA Record 证书部署成功",
		}, nil
	}
	if isApplyingStatus(status) {
		return providers.DeploymentResult{
			RequestID: firstNonEmpty(written.RequestID, readback.RequestID),
			Message:   "阿里云 ESA Record 证书已提交，控制面正在应用",
		}, nil
	}
	//lint:ignore ST1005 Record 是厂商字段名称，错误文本需保持兼容。
	controlPlaneCause := fmt.Errorf("Record 指纹或状态未确认")
	return providers.DeploymentResult{}, providers.NewDeploymentError(
		"阿里云 ESA 控制面尚未确认新证书",
		true,
		firstNonEmpty(written.RequestID, readback.RequestID),
		newSafeAliyunCause("控制面回读", controlPlaneCause),
	)
}

// listESACertificatesByRecord 只查询指定 Site 和精确 Record，不扫描其他站点或记录。
func (p *Provider) listESACertificatesByRecord(ctx context.Context, siteID, recordName string) (cloudAPIResponse, error) {
	if p == nil || p.deploymentAPI == nil {
		return cloudAPIResponse{}, &cloudAPIError{Message: "阿里云 ESA 客户端未初始化"}
	}
	return p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: aliyunESAEndpoint,
		Action:   "ListCertificatesByRecord",
		Version:  aliyunESAVersion,
		Method:   "POST",
		Query: map[string]string{
			"Detail":     "true",
			"RecordName": recordName,
			"SiteId":     siteID,
			"ValidOnly":  "false",
		},
	})
}

// findESARecord 从 ListCertificatesByRecord 响应中找出唯一的精确 Record。
func findESARecord(body map[string]any, targetDomain string) (map[string]any, bool) {
	var matched map[string]any
	for _, record := range mapSlice(body, "Result") {
		if !strings.EqualFold(strings.TrimSpace(mapString(record, "RecordName")), strings.TrimSpace(targetDomain)) {
			continue
		}
		if matched != nil {
			return nil, false
		}
		matched = record
	}
	return matched, matched != nil
}

// esaRecordContainsFingerprint 判断 ESA Record 中是否包含当前 PEM 的 SHA-256 指纹。
func esaRecordContainsFingerprint(record map[string]any, fingerprint string) bool {
	targetFingerprint := normalizeComparableToken(fingerprint)
	if targetFingerprint == "" {
		return false
	}
	for _, certificate := range mapSlice(record, "Certificates") {
		for _, key := range []string{"FingerprintSha256", "Fingerprint", "CertFingerprint"} {
			value := normalizeComparableToken(mapString(certificate, key))
			if value != "" && value == targetFingerprint {
				return true
			}
		}
	}
	return false
}
