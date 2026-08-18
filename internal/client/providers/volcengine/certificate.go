package volcengine

import (
	"context"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	cdnapi "github.com/volcengine/volcengine-go-sdk/service/cdn"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
)

// ensureCertificate 按叶证书 SHA-256 指纹复用或导入火山证书中心证书。
func (p *Provider) ensureCertificate(ctx context.Context, certificate providers.CertificateMaterial) (string, string, error) {
	if p.cdn == nil {
		return "", "", providers.NewDeploymentError("火山引擎 CDN 客户端未初始化", false, "", nil)
	}
	fingerprint, err := providers.LeafCertificateSHA256(certificate.CertificatePEM)
	if err != nil {
		return "", "", err
	}
	certificateID, requestID, err := p.findCertificate(ctx, fingerprint)
	if err != nil {
		return "", requestID, err
	}
	if certificateID != "" {
		return certificateID, requestID, nil
	}
	if err := ctx.Err(); err != nil {
		return "", requestID, err
	}
	input := &cdnapi.AddCertificateInput{Certificate: volcengine.String(certificate.CertificatePEM), PrivateKey: volcengine.String(certificate.PrivateKeyPEM), Repeatable: volcengine.Bool(false), Source: volcengine.String(certificateSource)}
	output, err := p.cdn.AddCertificateWithContext(ctx, input)
	if err != nil {
		if duplicateID := certificateIDFromError(err); duplicateID != "" {
			return duplicateID, requestIDFromError(err), nil
		}
		return "", requestIDFromError(err), err
	}
	if output == nil {
		return "", requestID, providers.NewDeploymentError("火山引擎上传证书响应为空", true, requestID, nil)
	}
	requestID = metadataRequestID(output.Metadata)
	if output.CertId == nil || strings.TrimSpace(*output.CertId) == "" {
		return "", requestID, providers.NewDeploymentError("火山引擎上传证书响应缺少 certId", false, requestID, nil)
	}
	readbackID, readbackRequestID, err := p.findCertificateByID(ctx, *output.CertId, fingerprint)
	requestID = firstNonEmpty(readbackRequestID, requestID)
	if err != nil {
		return "", requestID, err
	}
	if readbackID != *output.CertId {
		return "", requestID, providers.NewDeploymentError("火山引擎证书指纹回读不一致", true, requestID, nil)
	}
	return *output.CertId, requestID, nil
}

// findCertificate 分页查找拥有目标叶证书指纹的证书。
func (p *Provider) findCertificate(ctx context.Context, fingerprint string) (string, string, error) {
	for page := int32(1); page <= maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return "", "", err
		}
		output, err := p.cdn.ListCertInfoWithContext(ctx, &cdnapi.ListCertInfoInput{Source: volcengine.String(certificateSource), PageNum: volcengine.Int32(page), PageSize: volcengine.Int32(pageSize)})
		if err != nil {
			return "", requestIDFromError(err), err
		}
		if output == nil {
			return "", "", providers.NewDeploymentError("火山引擎证书列表响应为空", true, "", nil)
		}
		for _, item := range output.CertInfo {
			if item != nil && strings.TrimSpace(stringValue(item.CertId)) != "" && certFingerprintMatches(item.CertFingerprint, fingerprint) {
				return stringValue(item.CertId), metadataRequestID(output.Metadata), nil
			}
		}
		if output.Total == nil || int64(page)*int64(pageSize) >= *output.Total || len(output.CertInfo) < pageSize {
			return "", metadataRequestID(output.Metadata), nil
		}
	}
	return "", "", providers.NewDeploymentError("火山引擎证书分页超过安全上限", false, "", nil)
}

// findCertificateByID 回读指定证书并核对叶证书指纹。
func (p *Provider) findCertificateByID(ctx context.Context, certificateID, fingerprint string) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	output, err := p.cdn.ListCertInfoWithContext(ctx, &cdnapi.ListCertInfoInput{Source: volcengine.String(certificateSource), CertId: volcengine.String(certificateID), PageNum: volcengine.Int32(1), PageSize: volcengine.Int32(1)})
	if err != nil {
		return "", requestIDFromError(err), err
	}
	if output == nil {
		return "", "", providers.NewDeploymentError("火山引擎证书详情响应为空", true, "", nil)
	}
	for _, item := range output.CertInfo {
		if item != nil && stringValue(item.CertId) == certificateID && certFingerprintMatches(item.CertFingerprint, fingerprint) {
			return certificateID, metadataRequestID(output.Metadata), nil
		}
	}
	return "", metadataRequestID(output.Metadata), nil
}
