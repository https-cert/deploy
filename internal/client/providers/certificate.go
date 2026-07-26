package providers

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// ValidateCertificateMaterial 校验证书有效期、域名覆盖关系和证书私钥匹配关系。
func ValidateCertificateMaterial(certificate CertificateMaterial, targetDomain string, now time.Time) error {
	domain := strings.TrimSpace(targetDomain)
	if domain == "" {
		return fmt.Errorf("目标域名不能为空")
	}

	leaf, err := parseLeafCertificate([]byte(certificate.CertificatePEM))
	if err != nil {
		return fmt.Errorf("证书内容不可用: %w", err)
	}
	privateKey, err := parsePrivateKey([]byte(certificate.PrivateKeyPEM))
	if err != nil {
		return fmt.Errorf("私钥内容不可用: %w", err)
	}

	if now.IsZero() {
		now = time.Now()
	}
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("证书尚未生效: %s", leaf.NotBefore.Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("证书已过期: %s", leaf.NotAfter.Format(time.RFC3339))
	}
	if err := verifyCertificateDomain(leaf, domain); err != nil {
		return err
	}
	if err := verifyPrivateKeyMatchesCertificate(leaf, privateKey); err != nil {
		return err
	}
	return nil
}

// parseLeafCertificate 解析 PEM 中第一个证书块。
func parseLeafCertificate(certPEM []byte) (*x509.Certificate, error) {
	for len(certPEM) > 0 {
		block, rest := pem.Decode(certPEM)
		if block == nil {
			break
		}
		certPEM = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return certificate, nil
	}
	return nil, fmt.Errorf("未找到 PEM 证书块")
}

// parsePrivateKey 解析 PKCS#8、PKCS#1 或 EC PEM 私钥。
func parsePrivateKey(keyPEM []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("未找到 PEM 私钥块")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("无法解析私钥格式")
}

// verifyCertificateDomain 校验证书是否覆盖目标域名。
func verifyCertificateDomain(certificate *x509.Certificate, targetDomain string) error {
	domain := strings.ToLower(strings.TrimSpace(targetDomain))
	if strings.HasPrefix(domain, "*.") {
		for _, dnsName := range certificate.DNSNames {
			if strings.EqualFold(strings.TrimSpace(dnsName), domain) {
				return nil
			}
		}
		if strings.EqualFold(strings.TrimSpace(certificate.Subject.CommonName), domain) {
			return nil
		}
		return fmt.Errorf("证书域名不匹配: 未覆盖 %s", targetDomain)
	}
	if err := certificate.VerifyHostname(domain); err != nil {
		return fmt.Errorf("证书域名不匹配: %w", err)
	}
	return nil
}

// verifyPrivateKeyMatchesCertificate 校验证书公钥和私钥公钥是否一致。
func verifyPrivateKeyMatchesCertificate(certificate *x509.Certificate, privateKey crypto.PrivateKey) error {
	privatePublicKey, err := publicKeyFromPrivateKey(privateKey)
	if err != nil {
		return err
	}
	certificateDER, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return fmt.Errorf("序列化证书公钥失败: %w", err)
	}
	privateDER, err := x509.MarshalPKIXPublicKey(privatePublicKey)
	if err != nil {
		return fmt.Errorf("序列化私钥公钥失败: %w", err)
	}
	if string(certificateDER) != string(privateDER) {
		return fmt.Errorf("证书和私钥不匹配")
	}
	return nil
}

// publicKeyFromPrivateKey 从私钥提取对应公钥。
func publicKeyFromPrivateKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	case ed25519.PrivateKey:
		return key.Public(), nil
	default:
		return nil, fmt.Errorf("不支持的私钥类型: %T", privateKey)
	}
}
