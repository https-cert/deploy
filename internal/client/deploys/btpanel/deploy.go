package btpanel

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// DeployCertificateToBTPanelWebsite 精确部署 targetRef 对应宝塔网站的证书，并回读结果确认。
func DeployCertificateToBTPanelWebsite(ctx context.Context, targetRef, certificatePEM, privateKeyPEM string) error {
	targetRef = strings.TrimSpace(targetRef)
	if targetRef == "" {
		return fmt.Errorf("宝塔网站 targetRef 不能为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	apiURL, apiKey, insecureSkipVerify, err := getBTPanelConfig(ctx)
	if err != nil {
		return err
	}
	record, err := findBTPanelWebsiteByTargetRef(ctx, targetRef)
	if err != nil {
		return err
	}
	if record.Resource.Status == btPanelStatusStopped {
		return fmt.Errorf("宝塔网站未运行")
	}
	leaf, expectedFingerprint, err := validateBTPanelWebsiteCertificate(certificatePEM, privateKeyPEM, record.Resource.Domains, time.Now())
	if err != nil {
		return err
	}

	var response btPanelActionResponse
	if err := requestBTPanelAPI(ctx, apiURL, apiKey, insecureSkipVerify, btPanelSitePath, url.Values{
		"action":   {"SetSSL"},
		"siteName": {record.SiteName},
		"key":      {privateKeyPEM},
		"csr":      {certificatePEM},
	}, &response); err != nil {
		return fmt.Errorf("更新宝塔网站证书失败: %w", err)
	}
	if !response.Status {
		message := strings.TrimSpace(response.Msg)
		if message == "" {
			message = "面板拒绝写入证书"
		}
		return &btPanelRequestError{Retryable: false, Cause: fmt.Errorf("更新宝塔网站证书失败: %s", message)}
	}

	updated, err := getBTPanelWebsiteSSL(ctx, apiURL, apiKey, insecureSkipVerify, record.SiteName)
	if err != nil {
		return fmt.Errorf("回读宝塔网站 SSL 配置失败: %w", err)
	}
	if !updated.Status {
		return fmt.Errorf("宝塔网站证书写入后仍未启用 SSL")
	}
	if err := verifyBTPanelCertificateMetadata(updated.CertData, leaf, expectedFingerprint); err != nil {
		return fmt.Errorf("校验宝塔回读证书失败: %w", err)
	}
	return nil
}
