package deploys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ValidateCertificateFiles 校验证书文件、私钥文件、域名覆盖关系和证书私钥匹配关系。
func ValidateCertificateFiles(sourceDir, domain string) error {
	if strings.TrimSpace(domain) == "" {
		return fmt.Errorf("域名不能为空")
	}

	certPath := filepath.Join(sourceDir, "cert.pem")
	keyPath := filepath.Join(sourceDir, "privateKey.key")

	cert, err := parseLeafCertificate(certPath)
	if err != nil {
		return fmt.Errorf("证书文件不可用: %w", err)
	}

	privateKey, err := parsePrivateKey(keyPath)
	if err != nil {
		return fmt.Errorf("私钥文件不可用: %w", err)
	}

	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("证书尚未生效: %s", cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("证书已过期: %s", cert.NotAfter.Format(time.RFC3339))
	}

	if err := verifyCertificateDomain(cert, domain); err != nil {
		return err
	}

	if err := verifyPrivateKeyMatchesCertificate(cert, privateKey); err != nil {
		return err
	}

	return nil
}

// parseLeafCertificate 读取 PEM 证书文件并解析第一个 CERTIFICATE 块。
func parseLeafCertificate(certPath string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	for {
		block, rest := pem.Decode(certPEM)
		if block == nil {
			return nil, fmt.Errorf("未找到 PEM 证书块")
		}
		certPEM = rest

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert, nil
	}
}

// parsePrivateKey 读取 PEM 私钥文件并兼容 PKCS#1、PKCS#8 和 EC 私钥格式。
func parsePrivateKey(keyPath string) (crypto.PrivateKey, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

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

// verifyCertificateDomain 校验证书是否覆盖目标域名，泛域名证书按精确通配符匹配。
func verifyCertificateDomain(cert *x509.Certificate, domain string) error {
	normalizedDomain := normalizeCertificateDomain(domain)
	if strings.HasPrefix(normalizedDomain, "*.") {
		if certificateHasWildcardName(cert, normalizedDomain) {
			return nil
		}
		return fmt.Errorf("证书域名不匹配: 未覆盖 %s", domain)
	}

	if err := cert.VerifyHostname(normalizedDomain); err != nil {
		return fmt.Errorf("证书域名不匹配: %w", err)
	}
	return nil
}

// normalizeCertificateDomain 将部署目录使用的安全域名还原为证书校验域名。
func normalizeCertificateDomain(domain string) string {
	normalizedDomain := strings.ToLower(strings.TrimSpace(domain))
	if strings.HasPrefix(normalizedDomain, "_.") {
		return "*." + strings.TrimPrefix(normalizedDomain, "_.")
	}
	return normalizedDomain
}

// certificateHasWildcardName 判断证书 DNSName 或 CommonName 是否包含目标泛域名。
func certificateHasWildcardName(cert *x509.Certificate, wildcardDomain string) bool {
	for _, dnsName := range cert.DNSNames {
		if strings.EqualFold(strings.TrimSpace(dnsName), wildcardDomain) {
			return true
		}
	}
	return strings.EqualFold(strings.TrimSpace(cert.Subject.CommonName), wildcardDomain)
}

// verifyPrivateKeyMatchesCertificate 校验证书公钥和私钥公钥是否一致。
func verifyPrivateKeyMatchesCertificate(cert *x509.Certificate, privateKey crypto.PrivateKey) error {
	privatePublicKey, err := publicKeyFromPrivateKey(privateKey)
	if err != nil {
		return err
	}

	certPublicKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("序列化证书公钥失败: %w", err)
	}
	privatePublicKeyDER, err := x509.MarshalPKIXPublicKey(privatePublicKey)
	if err != nil {
		return fmt.Errorf("序列化私钥公钥失败: %w", err)
	}

	if string(certPublicKeyDER) != string(privatePublicKeyDER) {
		return fmt.Errorf("证书和私钥不匹配")
	}
	return nil
}

// publicKeyFromPrivateKey 从私钥中提取对应公钥。
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
