package baidu

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	certservice "github.com/baidubce/bce-sdk-go/services/cert"
	"github.com/https-cert/deploy/internal/client/providers"
)

// ensureCertificate 按叶证书指纹派生的稳定名称复用证书，或上传后回读验收。
func (p *Provider) ensureCertificate(ctx context.Context, certificate providers.CertificateMaterial) (string, error) {
	if err := p.validateCredentials(); err != nil {
		return "", err
	}
	if p.certificateClient == nil {
		return "", providers.NewDeploymentError("百度云证书客户端未初始化", false, "", nil)
	}
	sha256Fingerprint, err := providers.LeafCertificateSHA256(certificate.CertificatePEM)
	if err != nil {
		return "", err
	}
	sha1Fingerprint, err := leafCertificateSHA1(certificate.CertificatePEM)
	if err != nil {
		return "", err
	}
	certificateName := "anssl-" + sha256Fingerprint[:32]

	if err := ctx.Err(); err != nil {
		return "", err
	}
	list, err := p.certificateClient.ListCertDetail()
	if err != nil {
		return "", err
	}
	if list != nil {
		for index := range list.Certs {
			existing := &list.Certs[index]
			if strings.TrimSpace(existing.CertName) != certificateName || strings.TrimSpace(existing.CertId) == "" || existing.Expired {
				continue
			}
			if fingerprintMatches(existing.CertFingerprint, sha256Fingerprint, sha1Fingerprint) {
				return existing.CertId, nil
			}
		}
	}

	if err := ctx.Err(); err != nil {
		return "", err
	}
	created, err := p.certificateClient.CreateCert(&certservice.CreateCertArgs{
		CertName:        certificateName,
		CertServerData:  certificate.CertificatePEM,
		CertPrivateData: certificate.PrivateKeyPEM,
	})
	if err != nil {
		return "", err
	}
	if created == nil || strings.TrimSpace(created.CertId) == "" {
		return "", providers.NewDeploymentError("百度云上传证书响应缺少 certId", false, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	detail, err := p.certificateClient.GetCertDetail(created.CertId)
	if err != nil {
		return "", err
	}
	if detail == nil || strings.TrimSpace(detail.CertId) != strings.TrimSpace(created.CertId) || strings.TrimSpace(detail.CertName) != certificateName || detail.Expired {
		return "", providers.NewDeploymentError("百度云证书回读结果与上传请求不一致", true, "", nil)
	}
	if !fingerprintMatches(detail.CertFingerprint, sha256Fingerprint, sha1Fingerprint) {
		return "", providers.NewDeploymentError("百度云证书指纹回读不一致", false, "", nil)
	}
	return strings.TrimSpace(created.CertId), nil
}

// leafCertificateSHA1 计算百度云可能返回的叶证书 SHA-1 指纹格式。
func leafCertificateSHA1(certificatePEM string) (string, error) {
	remaining := []byte(certificatePEM)
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", err
		}
		fingerprint := sha1.Sum(certificate.Raw)
		return hex.EncodeToString(fingerprint[:]), nil
	}
	return "", fmt.Errorf("未找到 PEM 叶证书")
}

// fingerprintMatches 兼容百度云返回 SHA-1、SHA-256、冒号或短横线分隔格式。
func fingerprintMatches(actual string, expected ...string) bool {
	normalizedActual := normalizeFingerprint(actual)
	if normalizedActual == "" {
		return true
	}
	for _, value := range expected {
		if normalizedActual == normalizeFingerprint(value) {
			return true
		}
	}
	return false
}

// normalizeFingerprint 移除常见算法前缀和分隔符，只保留十六进制指纹。
func normalizeFingerprint(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range []string{"sha-256:", "sha256:", "sha-1:", "sha1:"} {
		normalized = strings.TrimPrefix(normalized, prefix)
	}
	var builder strings.Builder
	for _, character := range normalized {
		if (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') {
			builder.WriteRune(character)
		}
	}
	return builder.String()
}
