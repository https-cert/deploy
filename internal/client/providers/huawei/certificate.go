package huawei

import (
	"context"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	scmmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/scm/v3/model"
)

// UploadCertificate 导入或复用相同叶证书，并通过 SCM 详情指纹回读验收。
func (p *Provider) UploadCertificate(ctx context.Context, certificate providers.CertificateMaterial) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := providers.ValidateCertificateMaterial(certificate, certificate.Domain, time.Now()); err != nil {
		return providers.NewDeploymentError("华为云上传证书校验失败", false, "", err)
	}
	_, _, err := p.ensureCertificate(ctx, certificate)
	return toDeploymentError("上传证书", err)
}

// ensureCertificate 按稳定名称和叶证书 SHA-1 指纹复用或导入 SCM 证书。
func (p *Provider) ensureCertificate(ctx context.Context, certificate providers.CertificateMaterial) (string, string, error) {
	if p.scm == nil {
		return "", "", providers.NewDeploymentError("华为云 SCM 客户端未初始化", false, "", nil)
	}
	sha256Fingerprint, err := providers.LeafCertificateSHA256(certificate.CertificatePEM)
	if err != nil {
		return "", "", err
	}
	sha1Fingerprint, err := leafCertificateSHA1(certificate.CertificatePEM)
	if err != nil {
		return "", "", err
	}
	certificateName := "anssl-" + sha256Fingerprint[:32]
	certificateID, err := p.findCertificate(ctx, certificateName, sha1Fingerprint)
	if err != nil {
		return "", requestIDFromError(err), err
	}
	if certificateID != "" {
		return certificateID, "", nil
	}
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	duplicateCheck := false
	response, err := p.scm.ImportCertificate(&scmmodel.ImportCertificateRequest{Body: &scmmodel.ImportCertificateRequestBody{
		Name:           certificateName,
		Certificate:    certificate.CertificatePEM,
		PrivateKey:     certificate.PrivateKeyPEM,
		DuplicateCheck: &duplicateCheck,
	}})
	if err != nil {
		return "", requestIDFromError(err), err
	}
	if response == nil || response.CertificateId == nil || strings.TrimSpace(*response.CertificateId) == "" {
		return "", "", providers.NewDeploymentError("华为云 SCM 导入响应缺少证书 ID", true, "", nil)
	}
	certificateID = strings.TrimSpace(*response.CertificateId)
	if err := p.verifySCMCertificate(ctx, certificateID, sha1Fingerprint); err != nil {
		return "", requestIDFromError(err), err
	}
	return certificateID, "", nil
}

// findCertificate 分页查找名称和 SHA-1 指纹均匹配的 SCM 证书。
func (p *Provider) findCertificate(ctx context.Context, certificateName, fingerprint string) (string, error) {
	limit := int32(scmPageSize)
	ownedBySelf := true
	for page := 0; page < maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		offset := int32(page * scmPageSize)
		response, err := p.scm.ListCertificates(&scmmodel.ListCertificatesRequest{
			Limit:       &limit,
			Offset:      &offset,
			Content:     &certificateName,
			OwnedBySelf: &ownedBySelf,
		})
		if err != nil {
			return "", err
		}
		if response == nil {
			return "", providers.NewDeploymentError("华为云 SCM 证书列表响应为空", true, "", nil)
		}
		items := []scmmodel.CertificateDetail{}
		if response.Certificates != nil {
			items = *response.Certificates
		}
		for _, item := range items {
			if item.Name != certificateName || strings.TrimSpace(item.Id) == "" {
				continue
			}
			matched, err := p.scmCertificateMatches(ctx, item.Id, fingerprint)
			if err != nil {
				return "", err
			}
			if matched {
				return strings.TrimSpace(item.Id), nil
			}
		}
		if len(items) < scmPageSize || response.TotalCount == nil || offset+int32(len(items)) >= *response.TotalCount {
			return "", nil
		}
	}
	return "", providers.NewDeploymentError("华为云 SCM 证书分页超过安全上限", false, "", nil)
}

// scmCertificateMatches 回读 SCM 证书详情并比较状态和 SHA-1 指纹。
func (p *Provider) scmCertificateMatches(ctx context.Context, certificateID, fingerprint string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	response, err := p.scm.ShowCertificate(&scmmodel.ShowCertificateRequest{CertificateId: certificateID})
	if err != nil {
		return false, err
	}
	if response == nil || response.Id == nil || strings.TrimSpace(*response.Id) != strings.TrimSpace(certificateID) {
		return false, nil
	}
	status := strings.ToUpper(stringPointerValue(response.Status))
	if status != "UPLOAD" && status != "ISSUED" {
		return false, nil
	}
	return normalizeFingerprint(stringPointerValue(response.Fingerprint)) == normalizeFingerprint(fingerprint), nil
}

// verifySCMCertificate 确认导入后的 SCM 证书 ID、状态和指纹均正确。
func (p *Provider) verifySCMCertificate(ctx context.Context, certificateID, fingerprint string) error {
	matched, err := p.scmCertificateMatches(ctx, certificateID, fingerprint)
	if err != nil {
		return err
	}
	if !matched {
		return providers.NewDeploymentError("华为云 SCM 证书指纹回读不一致", true, "", nil)
	}
	return nil
}
