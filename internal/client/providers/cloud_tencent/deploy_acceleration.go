package cloud_tencent

import (
	"context"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	tencentcdn "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cdn/v20180606"
	tencentcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tencentteo "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/teo/v20220901"
)

// deployCDNCertificate 精确读取 CDN HTTPS 配置，仅替换服务端证书 ID，并回读确认。
func (p *Provider) deployCDNCertificate(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	client, err := p.getCDNClient()
	if err != nil {
		return providers.DeploymentResult{}, newTencentDeploymentError("初始化 CDN 客户端", err)
	}

	domainConfig, _, err := describeCDNDomain(ctx, client, target.Domain)
	if err != nil {
		return providers.DeploymentResult{}, err
	}
	if domainConfig.Https == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 CDN 目标缺少可保留的 HTTPS 配置", false, "", nil)
	}
	if !strings.EqualFold(strings.TrimSpace(stringValue(domainConfig.Https.Switch)), "on") {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 CDN 目标尚未启用 HTTPS", false, "", nil)
	}

	uploaded, err := p.uploadCertificateForDeployment(ctx, certificate, target)
	if err != nil {
		return providers.DeploymentResult{}, err
	}

	// UpdateDomainConfig 对复杂对象执行整对象更新，因此复制当前 HTTPS 策略并只替换 CertInfo。
	httpsConfig := *domainConfig.Https
	httpsConfig.CertInfo = &tencentcdn.ServerCert{CertId: tencentcommon.StringPtr(uploaded.CertificateID)}
	request := tencentcdn.NewUpdateDomainConfigRequest()
	request.Domain = tencentcommon.StringPtr(strings.TrimSpace(target.Domain))
	request.Https = &httpsConfig
	response, err := client.UpdateDomainConfigWithContext(ctx, request)
	if err != nil {
		return providers.DeploymentResult{}, newTencentDeploymentError("更新 CDN 域名证书", err)
	}
	if response == nil || response.Response == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 CDN 更新响应格式异常", true, "", nil)
	}
	requestID := strings.TrimSpace(stringValue(response.Response.RequestId))

	readBack, _, err := describeCDNDomain(ctx, client, target.Domain)
	if err != nil {
		return providers.DeploymentResult{}, err
	}
	if readBack.Https == nil || readBack.Https.CertInfo == nil ||
		strings.TrimSpace(stringValue(readBack.Https.CertInfo.CertId)) != uploaded.CertificateID {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 CDN 证书回读尚未生效", true, requestID, nil)
	}
	fingerprintRequestID, err := p.verifyCertificateFingerprint(ctx, uploaded.CertificateID, certificate.CertificatePEM)
	if err != nil {
		return providers.DeploymentResult{}, err
	}

	return providers.DeploymentResult{
		RequestID: firstTencentRequestID(requestID, fingerprintRequestID),
		Message:   "腾讯云 CDN 域名证书部署成功",
	}, nil
}

// describeCDNDomain 使用精确域名过滤并再次校验响应，避免修改相似域名。
func describeCDNDomain(ctx context.Context, client cdnClient, domain string) (*tencentcdn.DetailDomain, string, error) {
	request := tencentcdn.NewDescribeDomainsConfigRequest()
	request.Offset = tencentcommon.Int64Ptr(0)
	request.Limit = tencentcommon.Int64Ptr(5)
	request.Filters = []*tencentcdn.DomainFilter{
		{
			Name:  tencentcommon.StringPtr("domain"),
			Value: []*string{tencentcommon.StringPtr(strings.TrimSpace(domain))},
			Fuzzy: tencentcommon.BoolPtr(false),
		},
	}
	response, err := client.DescribeDomainsConfigWithContext(ctx, request)
	if err != nil {
		return nil, "", newTencentDeploymentError("查询 CDN 域名配置", err)
	}
	if response == nil || response.Response == nil {
		return nil, "", providers.NewDeploymentError("腾讯云 CDN 查询响应格式异常", true, "", nil)
	}
	requestID := strings.TrimSpace(stringValue(response.Response.RequestId))
	for _, candidate := range response.Response.Domains {
		if candidate != nil && strings.EqualFold(strings.TrimSpace(stringValue(candidate.Domain)), strings.TrimSpace(domain)) {
			return candidate, requestID, nil
		}
	}
	return nil, requestID, providers.NewDeploymentError("腾讯云 CDN 未找到配置的精确域名", false, requestID, nil)
}

// deployEdgeOneCertificate 校验精确 Zone/Host，绑定 SSL 托管证书，并回读确认。
func (p *Provider) deployEdgeOneCertificate(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	client, err := p.getTEOClient()
	if err != nil {
		return providers.DeploymentResult{}, newTencentDeploymentError("初始化 EdgeOne 客户端", err)
	}
	if _, _, err := describeEdgeOneHost(ctx, client, target.ZoneID, target.Domain); err != nil {
		return providers.DeploymentResult{}, err
	}

	uploaded, err := p.uploadCertificateForDeployment(ctx, certificate, target)
	if err != nil {
		return providers.DeploymentResult{}, err
	}

	request := tencentteo.NewModifyHostsCertificateRequest()
	request.ZoneId = tencentcommon.StringPtr(strings.TrimSpace(target.ZoneID))
	request.Hosts = []*string{tencentcommon.StringPtr(strings.TrimSpace(target.Domain))}
	request.Mode = tencentcommon.StringPtr(tencentEdgeOneMode)
	request.ServerCertInfo = []*tencentteo.ServerCertInfo{
		{CertId: tencentcommon.StringPtr(uploaded.CertificateID)},
	}
	response, err := client.ModifyHostsCertificateWithContext(ctx, request)
	if err != nil {
		return providers.DeploymentResult{}, newTencentDeploymentError("更新 EdgeOne 域名证书", err)
	}
	if response == nil || response.Response == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 EdgeOne 更新响应格式异常", true, "", nil)
	}
	requestID := strings.TrimSpace(stringValue(response.Response.RequestId))

	readBack, _, err := describeEdgeOneHost(ctx, client, target.ZoneID, target.Domain)
	if err != nil {
		return providers.DeploymentResult{}, err
	}
	if !edgeOneHostContainsCertificate(readBack, uploaded.CertificateID) {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 EdgeOne 证书回读尚未生效", true, requestID, nil)
	}
	fingerprintRequestID, err := p.verifyCertificateFingerprint(ctx, uploaded.CertificateID, certificate.CertificatePEM)
	if err != nil {
		return providers.DeploymentResult{}, err
	}

	return providers.DeploymentResult{
		RequestID: firstTencentRequestID(requestID, fingerprintRequestID),
		Message:   "腾讯云 EdgeOne 域名证书部署成功",
	}, nil
}

// describeEdgeOneHost 使用 Zone ID 和精确 Host 过滤并再次校验响应。
func describeEdgeOneHost(ctx context.Context, client teoClient, zoneID, host string) (*tencentteo.DetailHost, string, error) {
	request := tencentteo.NewDescribeHostsSettingRequest()
	request.ZoneId = tencentcommon.StringPtr(strings.TrimSpace(zoneID))
	request.Offset = tencentcommon.Int64Ptr(0)
	request.Limit = tencentcommon.Int64Ptr(20)
	request.Filters = []*tencentteo.Filter{
		{
			Name:   tencentcommon.StringPtr("host"),
			Values: []*string{tencentcommon.StringPtr(strings.TrimSpace(host))},
		},
	}
	response, err := client.DescribeHostsSettingWithContext(ctx, request)
	if err != nil {
		return nil, "", newTencentDeploymentError("查询 EdgeOne 域名配置", err)
	}
	if response == nil || response.Response == nil {
		return nil, "", providers.NewDeploymentError("腾讯云 EdgeOne 查询响应格式异常", true, "", nil)
	}
	requestID := strings.TrimSpace(stringValue(response.Response.RequestId))
	for _, candidate := range response.Response.DetailHosts {
		if candidate == nil || !strings.EqualFold(strings.TrimSpace(stringValue(candidate.Host)), strings.TrimSpace(host)) {
			continue
		}
		candidateZoneID := strings.TrimSpace(stringValue(candidate.ZoneId))
		if candidateZoneID != "" && candidateZoneID != strings.TrimSpace(zoneID) {
			continue
		}
		return candidate, requestID, nil
	}
	return nil, requestID, providers.NewDeploymentError("腾讯云 EdgeOne 未找到配置的精确 Zone/Host", false, requestID, nil)
}

// edgeOneHostContainsCertificate 判断 EdgeOne 回读配置是否包含刚绑定的证书 ID。
func edgeOneHostContainsCertificate(host *tencentteo.DetailHost, certificateID string) bool {
	if host == nil || host.Https == nil {
		return false
	}
	for _, certificate := range host.Https.CertInfo {
		if certificate != nil && strings.TrimSpace(stringValue(certificate.CertId)) == certificateID {
			return true
		}
	}
	return false
}
