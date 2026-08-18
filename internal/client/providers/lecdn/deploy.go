package lecdn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

// DeployCertificate 原地更新 certificate_id，回读证书后同步全部引用站点。
func (p *Provider) DeployCertificate(ctx context.Context, certificate providers.CertificateMaterial, deploymentType deployPB.DeploymentType, resource providers.DeploymentResource) (providers.DeploymentResult, error) {
	if deploymentType != deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN {
		return providers.DeploymentResult{}, providers.NewDeploymentError("LeCDN 不支持该部署业务", false, "", nil)
	}
	if strings.TrimSpace(resource.TargetRef) == "" || strings.TrimSpace(resource.ResourceID) == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("LeCDN 部署资源缺少 targetRef 或 certificate_id", false, "", nil)
	}
	if len(resource.Domains) == 0 || len(resource.SiteIDs) == 0 {
		return providers.DeploymentResult{}, providers.NewDeploymentError("LeCDN 证书没有可验证的域名或站点引用", false, "", nil)
	}
	if err := providers.ValidateCertificateForDomains(certificate, resource.Domains, time.Now()); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("LeCDN 证书未覆盖全部引用域名", false, "", err)
	}

	detail, requestID, err := p.getCertificate(ctx, resource.ResourceID)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("读取证书详情", err)
	}
	if strings.TrimSpace(stringValue(detail["name"])) == "" {
		detail["name"] = firstNonEmpty(certificate.Name, resource.Label, resource.Domain)
	}
	detail["ssl_pem"] = base64.StdEncoding.EncodeToString([]byte(certificate.CertificatePEM))
	detail["ssl_key"] = base64.StdEncoding.EncodeToString([]byte(certificate.PrivateKeyPEM))
	delete(detail, "id")

	writeRequestID, err := p.updateCertificate(ctx, resource.ResourceID, detail)
	requestID = firstNonEmpty(writeRequestID, requestID)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("更新证书", err)
	}
	readback, readRequestID, err := p.getCertificate(ctx, resource.ResourceID)
	requestID = firstNonEmpty(readRequestID, requestID)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("回读证书", err)
	}
	if err := verifyCertificateReadback(certificate.CertificatePEM, readback); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("LeCDN 证书回读尚未生效", true, requestID, err)
	}

	for _, siteID := range resource.SiteIDs {
		forceRequestID, err := p.forceSync(ctx, siteID)
		requestID = firstNonEmpty(forceRequestID, requestID)
		if err != nil {
			return providers.DeploymentResult{}, toDeploymentError("触发站点同步", err)
		}
		statusRequestID, err := p.waitForSync(ctx, siteID)
		requestID = firstNonEmpty(statusRequestID, requestID)
		if err != nil {
			return providers.DeploymentResult{}, toDeploymentError("等待站点同步", err)
		}
	}

	return providers.DeploymentResult{RequestID: requestID, Message: "LeCDN CDN 证书部署并同步成功"}, nil
}

// getCertificate 读取证书详情并保留未知字段供原地更新。
func (p *Provider) getCertificate(ctx context.Context, certificateID string) (map[string]any, string, error) {
	data, requestID, err := p.request(ctx, "读取证书详情", http.MethodGet, "/certificate/"+url.PathEscape(certificateID), nil)
	if err != nil {
		return nil, requestID, err
	}
	var detail map[string]any
	if err := json.Unmarshal(data, &detail); err != nil {
		return nil, requestID, &apiError{Operation: "解析证书详情", RequestID: requestID, Retryable: true, Cause: err}
	}
	if detail == nil {
		return nil, requestID, &apiError{Operation: "读取证书详情", RequestID: requestID, Retryable: true}
	}
	return detail, requestID, nil
}

// updateCertificate 使用相同 certificate_id 原地更新证书材料。
func (p *Provider) updateCertificate(ctx context.Context, certificateID string, detail map[string]any) (string, error) {
	body, err := json.Marshal(detail)
	if err != nil {
		return "", &apiError{Operation: "编码证书更新请求", Retryable: false, Cause: err}
	}
	_, requestID, err := p.request(ctx, "更新证书", http.MethodPut, "/certificate/"+url.PathEscape(certificateID), body)
	return requestID, err
}

// forceSync 强制创建一个站点同步任务。
func (p *Provider) forceSync(ctx context.Context, siteID string) (string, error) {
	_, requestID, err := p.request(ctx, "触发站点同步", http.MethodPost, "/site/"+url.PathEscape(siteID)+"/force_sync", []byte("{}"))
	return requestID, err
}

// waitForSync 轮询站点同步状态直到明确成功、失败或超时。
func (p *Provider) waitForSync(ctx context.Context, siteID string) (string, error) {
	waitContext, cancel := context.WithTimeout(ctx, p.syncTimeout)
	defer cancel()
	requestID := ""
	for {
		data, currentRequestID, err := p.request(waitContext, "读取站点同步状态", http.MethodGet, "/site/"+url.PathEscape(siteID)+"/sync_status", nil)
		requestID = firstNonEmpty(currentRequestID, requestID)
		if err != nil {
			return requestID, err
		}
		var status syncStatus
		if err := json.Unmarshal(data, &status); err != nil {
			return requestID, &apiError{Operation: "解析站点同步状态", RequestID: requestID, Retryable: true, Cause: err}
		}
		switch strings.ToLower(strings.TrimSpace(status.Status)) {
		case "success":
			return requestID, nil
		case "fail":
			return requestID, &apiError{Operation: "等待站点同步", RequestID: firstNonEmpty(string(status.TaskID), requestID), Retryable: false}
		case "wait", "running":
			// 正常中间态继续等待。
		default:
			return requestID, &apiError{Operation: "等待站点同步未知状态", RequestID: firstNonEmpty(string(status.TaskID), requestID), Retryable: true}
		}

		timer := time.NewTimer(p.pollInterval)
		select {
		case <-waitContext.Done():
			timer.Stop()
			return requestID, &apiError{Operation: "等待站点同步超时", RequestID: requestID, Retryable: true, Cause: waitContext.Err()}
		case <-timer.C:
		}
	}
}

// verifyCertificateReadback 解码 LeCDN 证书并核对叶证书指纹和状态。
func verifyCertificateReadback(expectedCertificatePEM string, detail map[string]any) error {
	encodedPEM := strings.TrimSpace(stringValue(detail["ssl_pem"]))
	if encodedPEM == "" {
		return errors.New("LeCDN 证书详情缺少 ssl_pem")
	}
	actualPEM, err := base64.StdEncoding.DecodeString(encodedPEM)
	if err != nil {
		return fmt.Errorf("LeCDN ssl_pem Base64 解码失败: %w", err)
	}
	if err := providers.VerifyLeafCertificateSHA256(expectedCertificatePEM, string(actualPEM)); err != nil {
		return err
	}
	status := strings.ToLower(strings.TrimSpace(stringValue(detail["status"])))
	if status != "" && status != "active" {
		return fmt.Errorf("LeCDN 证书状态异常: %s", status)
	}
	if strings.TrimSpace(stringValue(detail["not_after"])) == "" {
		return errors.New("LeCDN 证书详情缺少 not_after")
	}
	return nil
}
