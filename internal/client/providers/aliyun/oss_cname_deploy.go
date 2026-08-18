package aliyun

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
)

// deployOSS 部署证书到一个精确的 OSS Bucket 自定义域名。
func (p *Provider) deployOSS(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	if p == nil || p.ossAPI == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 OSS 客户端未初始化", false, "", nil)
	}
	preflight, err := p.ossAPI.ListCname(ctx, target)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("读取 OSS 自定义域名", err)
	}
	if strings.TrimSpace(preflight.Bucket) != "" && !strings.EqualFold(strings.TrimSpace(preflight.Bucket), strings.TrimSpace(target.Bucket)) {
		//lint:ignore ST1005 Bucket 是厂商字段名称，错误文本需保持兼容。
		targetCause := fmt.Errorf("Bucket 与响应不一致")
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 OSS 目标校验失败", false, preflight.RequestID, newSafeAliyunCause("目标校验", targetCause))
	}
	record, found := findExactOSSCname(preflight.Records, target.Domain)
	if !found {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 OSS 目标校验失败", false, preflight.RequestID, newSafeAliyunCause("目标校验", fmt.Errorf("未找到精确自定义域名")))
	}

	fingerprint, err := certificateSHA1Fingerprint(certificate.CertificatePEM)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 OSS 证书校验失败", false, preflight.RequestID, newSafeAliyunCause("证书指纹", err))
	}
	if ossFingerprintMatches(record.Certificate.Fingerprint, fingerprint) && strings.EqualFold(strings.TrimSpace(record.Certificate.Status), "enabled") {
		return providers.DeploymentResult{
			RequestID: preflight.RequestID,
			Message:   "阿里云 OSS 自定义域名已配置当前证书",
		}, nil
	}

	previousCertificateID := strings.TrimSpace(record.Certificate.CertificateID)
	written, err := p.ossAPI.PutCname(ctx, ossCnamePutRequest{
		Target:                target,
		CertificatePEM:        certificate.CertificatePEM,
		PrivateKeyPEM:         certificate.PrivateKeyPEM,
		PreviousCertificateID: previousCertificateID,
		Force:                 previousCertificateID == "",
	})
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("更新 OSS 自定义域名证书", err)
	}

	readback, err := p.ossAPI.ListCname(ctx, target)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("回读 OSS 自定义域名证书", written.RequestID, err)
	}
	readbackRecord, found := findExactOSSCname(readback.Records, target.Domain)
	if !found {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 OSS 控制面未返回目标域名", true, firstNonEmpty(written.RequestID, readback.RequestID), nil)
	}
	certificateStatus := strings.ToLower(strings.TrimSpace(readbackRecord.Certificate.Status))
	if ossFingerprintMatches(readbackRecord.Certificate.Fingerprint, fingerprint) && certificateStatus == "enabled" {
		return providers.DeploymentResult{
			RequestID: firstNonEmpty(written.RequestID, readback.RequestID),
			Message:   "阿里云 OSS 自定义域名证书部署成功",
		}, nil
	}
	if isApplyingStatus(certificateStatus, readbackRecord.Status) {
		return providers.DeploymentResult{
			RequestID: firstNonEmpty(written.RequestID, readback.RequestID),
			Message:   "阿里云 OSS 自定义域名证书已提交，控制面正在应用",
		}, nil
	}
	return providers.DeploymentResult{}, providers.NewDeploymentError(
		"阿里云 OSS 控制面尚未确认新证书",
		true,
		firstNonEmpty(written.RequestID, readback.RequestID),
		newSafeAliyunCause("控制面回读", fmt.Errorf("证书指纹或状态未确认")),
	)
}

// findExactOSSCname 查找唯一的精确自定义域名，拒绝重复或模糊匹配。
func findExactOSSCname(records []ossCnameRecord, targetDomain string) (ossCnameRecord, bool) {
	var matched ossCnameRecord
	found := false
	for _, record := range records {
		if !strings.EqualFold(strings.TrimSpace(record.Domain), strings.TrimSpace(targetDomain)) {
			continue
		}
		if found {
			return ossCnameRecord{}, false
		}
		matched = record
		found = true
	}
	return matched, found
}

// certificateSHA1Fingerprint 提取 OSS ListCname 使用的叶证书 SHA-1 指纹。
func certificateSHA1Fingerprint(certificatePEM string) (string, error) {
	rest := []byte(certificatePEM)
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if !strings.EqualFold(strings.TrimSpace(block.Type), "CERTIFICATE") {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("解析证书失败: %w", err)
		}
		digest := sha1.Sum(certificate.Raw)
		return fmt.Sprintf("%x", digest[:]), nil
	}
	return "", fmt.Errorf("证书内容中未找到 CERTIFICATE 块")
}

// ossFingerprintMatches 兼容 OSS 返回带冒号或部分掩码的 SHA-1 指纹。
func ossFingerprintMatches(actual, expected string) bool {
	normalizedActual := normalizeComparableToken(actual)
	normalizedExpected := normalizeComparableToken(expected)
	if normalizedActual == "" || normalizedExpected == "" {
		return false
	}
	if normalizedActual == normalizedExpected {
		return true
	}
	return len(normalizedActual) >= 24 && strings.HasPrefix(normalizedExpected, normalizedActual)
}
