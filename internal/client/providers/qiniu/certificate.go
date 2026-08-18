package qiniu

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
)

// UploadCertificate 将证书上传到七牛云证书中心，供 v2 无资源部署类型复用。
// 需要七牛云 certID 时使用 UploadCertificateWithContext。
func (p *Provider) UploadCertificate(ctx context.Context, certificate providers.CertificateMaterial) error {
	_, err := p.UploadCertificateWithContext(ctx, certificate.Name, certificate.Domain, certificate.CertificatePEM, certificate.PrivateKeyPEM)
	return err
}

// UploadCertificateWithContext uploads a PEM certificate with QBox authentication and retains certID.
func (p *Provider) UploadCertificateWithContext(ctx context.Context, name, domain, cert, key string) (*CertificateUploadResult, error) {
	if err := p.validateCertificateInput("上传证书", name, domain, cert, key); err != nil {
		return nil, err
	}
	if err := p.validateCredentials("上传证书"); err != nil {
		return nil, err
	}

	body, err := json.Marshal(certificateUploadRequest{
		Name:        name,
		PrivateKey:  key,
		Certificate: cert,
	})
	if err != nil {
		return nil, newLocalError("编码证书上传请求", err)
	}

	response, err := p.execute(ctx, "上传证书", http.MethodPost, p.fusionBaseURL, "/sslcert", authorizationQBox, body)
	if err != nil {
		return nil, err
	}

	var uploadResponse certificateUploadResponse
	if err := json.Unmarshal(response.Body, &uploadResponse); err != nil {
		return nil, newLocalError("解析证书上传响应", err)
	}
	if strings.TrimSpace(uploadResponse.CertificateID) == "" {
		return nil, &APIError{
			Operation:         "上传证书",
			StatusCode:        response.StatusCode,
			ProviderRequestID: response.ProviderRequestID,
			Retryable:         false,
			Message:           "响应中缺少 certID",
		}
	}

	return &CertificateUploadResult{
		CertificateID:     uploadResponse.CertificateID,
		ProviderRequestID: response.ProviderRequestID,
	}, nil
}
