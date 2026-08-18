package onepanel

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// validateOnePanelWebsiteCertificate 校验证书、私钥、有效期，并要求至少覆盖网站的一个绑定域名。
func validateOnePanelWebsiteCertificate(certificatePEM, privateKeyPEM string, domains []string, now time.Time) ([sha256.Size]byte, error) {
	var emptyFingerprint [sha256.Size]byte
	keyPair, err := tls.X509KeyPair([]byte(certificatePEM), []byte(privateKeyPEM))
	if err != nil {
		return emptyFingerprint, fmt.Errorf("1Panel 网站证书和私钥无效: %w", err)
	}
	if len(keyPair.Certificate) == 0 {
		return emptyFingerprint, fmt.Errorf("1Panel 网站证书不包含叶证书")
	}
	leaf, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return emptyFingerprint, fmt.Errorf("解析 1Panel 网站证书失败: %w", err)
	}
	if now.IsZero() {
		now = time.Now()
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return emptyFingerprint, fmt.Errorf("1Panel 网站证书不在有效期内")
	}
	if len(domains) == 0 {
		return emptyFingerprint, fmt.Errorf("1Panel 网站没有可校验的绑定域名")
	}
	for _, domain := range domains {
		if err := verifyOnePanelCertificateDomain(leaf, domain); err == nil {
			return sha256.Sum256(leaf.Raw), nil
		}
	}
	return emptyFingerprint, fmt.Errorf("证书未覆盖 1Panel 网站的任何绑定域名")
}

// verifyOnePanelCertificateDomain 校验普通域名/IP，并允许网站通配符与证书 SAN 精确匹配。
func verifyOnePanelCertificateDomain(certificate *x509.Certificate, domain string) error {
	if certificate == nil {
		return fmt.Errorf("证书为空")
	}
	trimmedDomain := strings.TrimSpace(domain)
	if !strings.HasPrefix(trimmedDomain, "*.") {
		normalized := normalizeOnePanelDomain(trimmedDomain)
		if normalized == "" {
			return fmt.Errorf("网站域名无效")
		}
		return certificate.VerifyHostname(normalized)
	}
	wildcardDomain := normalizeOnePanelWildcardDomain(trimmedDomain)
	if wildcardDomain == "" {
		return fmt.Errorf("网站通配符域名无效")
	}
	for _, certificateDomain := range certificate.DNSNames {
		if normalizeOnePanelWildcardDomain(certificateDomain) == wildcardDomain {
			return nil
		}
	}
	return fmt.Errorf("证书 SAN 不包含 %s", wildcardDomain)
}

// normalizeOnePanelWildcardDomain 规范化证书 SAN 中的通配符域名。
func normalizeOnePanelWildcardDomain(raw string) string {
	return normalizeOnePanelDomain(raw)
}

// onePanelCertificateFingerprint 解析回读证书并计算叶证书 SHA-256 指纹。
func onePanelCertificateFingerprint(certificatePEM string) ([sha256.Size]byte, error) {
	var emptyFingerprint [sha256.Size]byte
	data := []byte(certificatePEM)
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return emptyFingerprint, err
		}
		return sha256.Sum256(certificate.Raw), nil
	}
	return emptyFingerprint, fmt.Errorf("未找到 PEM 叶证书")
}
