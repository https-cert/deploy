package volcengine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	albapi "github.com/volcengine/volcengine-go-sdk/service/alb"
	cdnapi "github.com/volcengine/volcengine-go-sdk/service/cdn"
	clbapi "github.com/volcengine/volcengine-go-sdk/service/clb"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/response"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

const (
	loadBalancerCertificateSource = "cert_center"
	loadBalancerDefaultSlot       = "default"
)

// certificateDomainResult 缓存一次负载均衡证书域名解析结果。
type certificateDomainResult struct {
	domains []string // domains 是证书覆盖的规范化域名集合。
	err     error    // err 是证书目录读取或域名解析错误。
}

// newLoadBalancerClients 为每个配置地域创建 CLB、ALB 和 NLB 官方 SDK 客户端。
func newLoadBalancerClients(accessKey, secretKey string, regions []string) (map[string]clbClient, map[string]albClient, map[string]nlbClient, error) {
	clbClients := make(map[string]clbClient, len(regions))
	albClients := make(map[string]albClient, len(regions))
	nlbClients := make(map[string]nlbClient, len(regions))
	for _, region := range regions {
		config := volcengine.NewConfig().
			WithRegion(region).
			WithCredentials(credentials.NewStaticCredentials(accessKey, secretKey, "")).
			WithHTTPClient(newVolcengineHTTPClient())
		sdkSession, err := session.NewSession(config)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("创建火山引擎负载均衡 SDK 会话失败[%s]: %w", region, err)
		}
		clbSDK := clbapi.New(sdkSession)
		clbClients[region] = clbSDK
		albClients[region] = albapi.New(sdkSession)
		nlbClients[region] = clbSDK
	}
	return clbClients, albClients, nlbClients, nil
}

// newVolcengineHTTPClient 创建带统一超时的火山引擎 OpenAPI HTTP 客户端。
func newVolcengineHTTPClient() *http.Client {
	return &http.Client{Timeout: sdkTimeout}
}

// certificateCenterDomains 读取共享证书中心记录并返回证书覆盖域名。
func (p *Provider) certificateCenterDomains(ctx context.Context, certificateID string) ([]string, error) {
	if p.cdn == nil {
		return nil, providers.NewDeploymentError("火山引擎证书中心客户端未初始化", false, "", nil)
	}
	certificateID = strings.TrimSpace(certificateID)
	if certificateID == "" {
		return nil, providers.NewDeploymentError("火山引擎负载均衡证书 ID 为空", false, "", nil)
	}
	output, err := p.cdn.ListCertInfoWithContext(ctx, &cdnapi.ListCertInfoInput{
		Source:   volcengine.String(certificateSource),
		CertId:   volcengine.String(certificateID),
		PageNum:  volcengine.Int32(1),
		PageSize: volcengine.Int32(2),
	})
	if err != nil {
		return nil, err
	}
	if output == nil {
		return nil, providers.NewDeploymentError("火山引擎证书中心详情响应为空", true, "", nil)
	}
	var matched *cdnapi.CertInfoForListCertInfoOutput
	for _, item := range output.CertInfo {
		if item == nil || stringValue(item.CertId) != certificateID {
			continue
		}
		if matched != nil {
			return nil, providers.NewDeploymentError("火山引擎证书中心详情回读结果不唯一", false, metadataRequestID(output.Metadata), nil)
		}
		matched = item
	}
	if matched == nil {
		return nil, providers.NewDeploymentError("火山引擎证书中心记录已失效", false, metadataRequestID(output.Metadata), nil)
	}
	domains := parseVolcengineCertificateDomains(stringValue(matched.DnsName))
	if len(domains) == 0 {
		return nil, providers.NewDeploymentError("火山引擎证书中心记录缺少可识别域名", false, metadataRequestID(output.Metadata), nil)
	}
	return domains, nil
}

// parseVolcengineCertificateDomains 解析 SDK 返回的 JSON、逗号或空白分隔域名集合。
func parseVolcengineCertificateDomains(values ...string) []string {
	rawDomains := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.HasPrefix(value, "[") {
			var decoded []string
			if json.Unmarshal([]byte(value), &decoded) == nil {
				rawDomains = append(rawDomains, decoded...)
				continue
			}
		}
		for _, part := range strings.FieldsFunc(value, func(character rune) bool {
			return character == ',' || character == ';' || character == '\n' || character == '\r' || character == '\t' || character == ' '
		}) {
			rawDomains = append(rawDomains, strings.Trim(part, `[]"'`))
		}
	}
	return providers.NormalizeDomains(rawDomains...)
}

// loadBalancerLifecycle 组合实例与监听器创建时间，防止同名或同 ID 资源重建后误部署。
func loadBalancerLifecycle(loadBalancerCreatedAt, listenerCreatedAt string) string {
	return strings.TrimSpace(loadBalancerCreatedAt) + "\x00" + strings.TrimSpace(listenerCreatedAt)
}

// loadBalancerReady 判断实例与监听器是否均处于官方可部署终态。
func loadBalancerReady(loadBalancerStatus, businessStatus, listenerStatus, enabled string) bool {
	loadBalancerStatus = strings.ToLower(strings.TrimSpace(loadBalancerStatus))
	businessStatus = strings.ToLower(strings.TrimSpace(businessStatus))
	listenerStatus = strings.ToLower(strings.TrimSpace(listenerStatus))
	enabled = strings.ToLower(strings.TrimSpace(enabled))
	return loadBalancerStatus == "active" &&
		businessStatus == "normal" &&
		listenerStatus == "active" &&
		(enabled == "on" || enabled == "true" || enabled == "enabled")
}

// loadBalancerTransitioning 判断 CLB 或 ALB 实例及监听器是否处于异步过渡状态。
func loadBalancerTransitioning(loadBalancerStatus, listenerStatus string) bool {
	loadBalancerStatus = strings.ToLower(strings.TrimSpace(loadBalancerStatus))
	listenerStatus = strings.ToLower(strings.TrimSpace(listenerStatus))
	return loadBalancerStatus == "creating" || loadBalancerStatus == "provisioning" || loadBalancerStatus == "configuring" ||
		listenerStatus == "creating" || listenerStatus == "configuring" || listenerStatus == "updating"
}

// loadBalancerAvailability 将负载均衡终态转换为统一资源可用性。
func loadBalancerAvailability(ready bool) deployPB.DeploymentResourceAvailability {
	if ready {
		return deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
	}
	return deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
}

// int64Value 安全读取可选整数指针。
func int64Value(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

// outputRequestID 优先读取业务响应中的 RequestId，并回退到 SDK 元数据。
func outputRequestID(requestID *string, metadata *response.ResponseMetadata) string {
	return firstNonEmpty(stringValue(requestID), metadataRequestID(metadata))
}
