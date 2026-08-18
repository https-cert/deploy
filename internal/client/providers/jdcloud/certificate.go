package jdcloud

import (
	"context"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	sslapi "github.com/jdcloud-api/jdcloud-sdk-go/services/ssl/apis"
)

// ensureCertificate 按叶证书指纹生成稳定名称，复用或上传证书并回读详情。
func (p *Provider) ensureCertificate(ctx context.Context, certificate providers.CertificateMaterial) (string, string, error) {
	if err := p.validateCredentials(); err != nil {
		return "", "", err
	}
	if p.certificateClient == nil {
		return "", "", providers.NewDeploymentError("京东云 SSL 客户端未初始化", false, "", nil)
	}
	fingerprint, err := providers.LeafCertificateSHA256(certificate.CertificatePEM)
	if err != nil {
		return "", "", err
	}
	certificateName := "anssl-" + fingerprint[:32]
	existingID, requestID, err := p.findCertificate(ctx, certificateName, certificate.Domain)
	if err != nil {
		return "", requestID, err
	}
	if existingID != "" {
		return existingID, requestID, nil
	}
	if err := ctx.Err(); err != nil {
		return "", requestID, err
	}
	uploadRequest := sslapi.NewUploadCertRequest(certificateName, certificate.PrivateKeyPEM, certificate.CertificatePEM)
	uploadRequest.SetAliasName(certificateName)
	response, err := p.certificateClient.UploadCert(uploadRequest)
	if err != nil {
		return "", requestID, err
	}
	requestID = firstNonEmpty(responseRequestID(response), requestID)
	if err := checkResponse("上传证书", responseRequestID(response), responseError(response)); err != nil {
		return "", requestID, err
	}
	certificateID := strings.TrimSpace(response.Result.CertId)
	if certificateID == "" {
		return "", requestID, providers.NewDeploymentError("京东云上传证书响应缺少 certId", false, requestID, nil)
	}
	detail, detailRequestID, err := p.describeCertificate(ctx, certificateID)
	requestID = firstNonEmpty(detailRequestID, requestID)
	if err != nil {
		return "", requestID, err
	}
	if strings.TrimSpace(detail.CertId) != certificateID || strings.TrimSpace(detail.CertName) != certificateName || !containsDomain(detail.DnsNames, certificate.Domain) {
		return "", requestID, providers.NewDeploymentError("京东云证书回读结果与上传请求不一致", true, requestID, nil)
	}
	return certificateID, requestID, nil
}

// findCertificate 分页查找由同一叶证书指纹派生的证书名称。
func (p *Provider) findCertificate(ctx context.Context, certificateName, domain string) (string, string, error) {
	lastRequestID := ""
	for page := 1; page <= resourceMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return "", lastRequestID, err
		}
		request := sslapi.NewDescribeCertsRequest()
		request.SetPageNumber(page)
		request.SetPageSize(resourcePageSize)
		response, err := p.certificateClient.DescribeCerts(request)
		if err != nil {
			return "", lastRequestID, err
		}
		lastRequestID = firstNonEmpty(responseRequestID(response), lastRequestID)
		if err := checkResponse("读取证书列表", responseRequestID(response), responseError(response)); err != nil {
			return "", lastRequestID, err
		}
		for _, item := range response.Result.CertListDetails {
			if strings.TrimSpace(item.CertName) == certificateName && strings.TrimSpace(item.CertId) != "" && containsDomain(item.DnsNames, domain) {
				return strings.TrimSpace(item.CertId), lastRequestID, nil
			}
		}
		if page*resourcePageSize >= response.Result.TotalCount || len(response.Result.CertListDetails) < resourcePageSize {
			return "", lastRequestID, nil
		}
	}
	return "", lastRequestID, providers.NewDeploymentError("京东云证书分页超过安全上限", false, lastRequestID, nil)
}

// describeCertificate 读取一个京东云 SSL 证书详情并校验业务响应。
func (p *Provider) describeCertificate(ctx context.Context, certificateID string) (sslapi.DescribeCertResult, string, error) {
	if err := ctx.Err(); err != nil {
		return sslapi.DescribeCertResult{}, "", err
	}
	response, err := p.certificateClient.DescribeCert(sslapi.NewDescribeCertRequest(certificateID))
	if err != nil {
		return sslapi.DescribeCertResult{}, "", err
	}
	if err := checkResponse("回读证书", responseRequestID(response), responseError(response)); err != nil {
		return sslapi.DescribeCertResult{}, responseRequestID(response), err
	}
	return response.Result, response.RequestID, nil
}

// containsDomain 判断云端域名集合是否包含规范化目标域名。
func containsDomain(domains []string, target string) bool {
	normalizedTarget, err := providers.NormalizeDomain(target)
	if err != nil {
		return false
	}
	for _, rawDomain := range domains {
		domain, normalizeErr := providers.NormalizeDomain(rawDomain)
		if normalizeErr == nil && domain == normalizedTarget {
			return true
		}
	}
	return false
}
