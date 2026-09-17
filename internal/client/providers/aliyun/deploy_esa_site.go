package aliyun

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
)

// deployESASiteCertificate 按官方站点级契约上传证书，再用返回的证书 ID 回读确认。
// https://api.aliyun.com/api/ESA/2024-09-10/SetCertificate
// https://api.aliyun.com/api/ESA/2024-09-10/GetCertificate
func (p *Provider) deployESASiteCertificate(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	certificates, err := p.listESASiteCertificates(ctx, target.SiteID)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("读取 ESA 站点证书", err)
	}
	fingerprint, err := providers.LeafCertificateSHA256(certificate.CertificatePEM)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("ESA 证书内容无效", false, "", err)
	}
	// 名称在续期前后保持稳定，只更新由当前域名的 anSSL 目标管理的 upload 证书。
	domain, err := providers.NormalizeDomain(certificate.Domain)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("ESA 证书主域名无效", false, "", err)
	}
	identity := sha256.Sum256([]byte(domain))
	name := fmt.Sprintf("anssl-site-%x", identity[:12])
	existingID := ""
	for _, existing := range certificates {
		id := mapString(existing, "Id")
		if id == "" {
			continue
		}
		if normalizeComparableToken(mapString(existing, "FingerprintSha256")) == fingerprint {
			return p.confirmESASiteCertificate(ctx, target.SiteID, id, certificate, "")
		}
		if mapString(existing, "Name") == name && mapString(existing, "Type") == "upload" {
			if existingID != "" {
				return providers.DeploymentResult{}, providers.NewDeploymentError("ESA 站点存在多个同名托管证书", false, "", nil)
			}
			existingID = id
		}
	}
	body := map[string]string{
		"SiteId": target.SiteID, "Type": "upload", "Name": name,
		"Certificate": certificate.CertificatePEM, "PrivateKey": certificate.PrivateKeyPEM,
	}
	if existingID != "" {
		body["Id"] = existingID
	}
	written, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: aliyunESAEndpoint, Action: "SetCertificate", Version: aliyunESAVersion, Method: "POST", Body: body,
	})
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("上传 ESA 站点证书", err)
	}
	id := mapString(written.Body, "Id")
	if id == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("ESA 未返回证书 ID", true, written.RequestID, nil)
	}
	return p.confirmESASiteCertificate(ctx, target.SiteID, id, certificate, written.RequestID)
}

// listESASiteCertificates 使用官方页码分页读取完整证书列表，失败时不继续写入以免重复创建。
// https://api.aliyun.com/api/ESA/2024-09-10/ListCertificates
func (p *Provider) listESASiteCertificates(ctx context.Context, siteID string) ([]map[string]any, error) {
	certificates := make([]map[string]any, 0)
	for page := 1; page <= aliyunCatalogMaxPages; page++ {
		response, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{
			Endpoint: aliyunESAEndpoint, Action: "ListCertificates", Version: aliyunESAVersion, Method: "GET",
			Query: map[string]string{"SiteId": siteID, "PageNumber": strconv.Itoa(page), "PageSize": strconv.Itoa(aliyunCatalogPageSize), "ValidOnly": "false"},
		})
		if err != nil {
			return nil, err
		}
		records := mapSlice(response.Body, "Result")
		certificates = append(certificates, records...)
		total, hasTotal := mapInt64(response.Body, "TotalCount")
		if hasTotal && int64(len(certificates)) >= total || !hasTotal && len(records) < aliyunCatalogPageSize {
			return certificates, nil
		}
		if len(records) == 0 {
			return nil, fmt.Errorf("ESA 证书分页未返回完整目录")
		}
	}
	return nil, fmt.Errorf("ESA 证书目录超过安全分页上限")
}

// confirmESASiteCertificate 验证站点、证书 ID、实际 PEM 指纹和有效状态，避免把提交成功当作部署完成。
func (p *Provider) confirmESASiteCertificate(ctx context.Context, siteID, certificateID string, certificate providers.CertificateMaterial, writeRequestID string) (providers.DeploymentResult, error) {
	response, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: aliyunESAEndpoint, Action: "GetCertificate", Version: aliyunESAVersion, Method: "GET",
		Query: map[string]string{"SiteId": siteID, "Id": certificateID},
	})
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("回读 ESA 站点证书", writeRequestID, err)
	}
	requestID := firstNonEmpty(writeRequestID, response.RequestID)
	result, _ := normalizeToMap(response.Body["Result"])
	if mapString(response.Body, "SiteId") != siteID || mapString(result, "Id") != certificateID {
		return providers.DeploymentResult{}, providers.NewDeploymentError("ESA 回读证书与目标不一致", true, requestID, nil)
	}
	if err := providers.VerifyLeafCertificateSHA256(certificate.CertificatePEM, mapString(response.Body, "Certificate")); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("ESA 尚未确认新证书内容", true, requestID, newSafeAliyunCause("证书回读", err))
	}
	status := strings.ToLower(firstNonEmpty(mapString(response.Body, "Status"), mapString(result, "Status")))
	if status != "ok" && status != "expiring" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("ESA 站点证书尚未就绪", true, requestID, nil)
	}
	return providers.DeploymentResult{RequestID: requestID, Message: "阿里云 ESA 站点证书上传成功"}, nil
}
