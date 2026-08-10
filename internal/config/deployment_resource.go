package config

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/https-cert/deploy/pb/deployPB"
	"golang.org/x/net/idna"
)

const (
	// ProviderAliyun 是阿里云 provider 的配置名称。
	ProviderAliyun = "aliyun"
	// ProviderTencentCloud 是腾讯云 provider 的配置名称。
	ProviderTencentCloud = "cloudTencent"
	// ProviderQiniu 是七牛云 provider 的配置名称。
	ProviderQiniu = "qiniu"
)

var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// CDNConfig 描述一个 CDN 精确域名部署资源。
type CDNConfig struct {
	Label  string `yaml:"label,omitempty"` // Label 控制台展示名称，留空时使用规范化域名
	Domain string `yaml:"domain"`          // Domain CDN 绑定的精确域名
}

// DCDNConfig 描述一个 DCDN 精确域名部署资源。
type DCDNConfig struct {
	Label  string `yaml:"label,omitempty"` // Label 控制台展示名称，留空时使用规范化域名
	Domain string `yaml:"domain"`          // Domain DCDN 绑定的精确域名
}

// ESAConfig 描述一个 ESA Record 部署资源。
type ESAConfig struct {
	Label  string `yaml:"label,omitempty"` // Label 控制台展示名称，留空时使用规范化域名
	Domain string `yaml:"domain"`          // Domain ESA Record 绑定的精确域名
	SiteID string `yaml:"siteId"`          // SiteID ESA 站点 ID
}

// OSSConfig 描述一个 OSS Bucket 自定义域名部署资源。
type OSSConfig struct {
	Label    string `yaml:"label,omitempty"`    // Label 控制台展示名称，留空时使用规范化域名
	Domain   string `yaml:"domain"`             // Domain OSS Bucket 绑定的精确自定义域名
	Region   string `yaml:"region"`             // Region OSS Bucket 所在地域
	Bucket   string `yaml:"bucket"`             // Bucket OSS Bucket 名称
	Endpoint string `yaml:"endpoint,omitempty"` // Endpoint 可选的 OSS HTTPS API Origin
}

// EdgeOneConfig 描述一个 EdgeOne Host 部署资源。
type EdgeOneConfig struct {
	Label  string `yaml:"label,omitempty"` // Label 控制台展示名称，留空时使用规范化域名
	Domain string `yaml:"domain"`          // Domain EdgeOne Host 的精确域名
	ZoneID string `yaml:"zoneId"`          // ZoneID EdgeOne 站点 ID
}

// COSConfig 描述一个 COS Bucket 自定义域名部署资源。
type COSConfig struct {
	Label  string `yaml:"label,omitempty"` // Label 控制台展示名称，留空时使用规范化域名
	Domain string `yaml:"domain"`          // Domain COS Bucket 绑定的精确自定义域名
	Region string `yaml:"region"`          // Region COS Bucket 所在地域
	Bucket string `yaml:"bucket"`          // Bucket 包含 APPID 的完整 COS Bucket 名称
}

// CLBConfig 描述阿里云或腾讯云 CLB 监听器部署资源；字段按 provider 名称使用。
type CLBConfig struct {
	Label          string `yaml:"label,omitempty"` // Label 控制台展示名称，留空时使用规范化域名
	Domain         string `yaml:"domain"`          // Domain 监听器默认或 SNI 扩展绑定的精确域名
	Region         string `yaml:"region"`          // Region CLB 实例所在地域 ID
	LoadBalancerID string `yaml:"loadBalancerId"`  // LoadBalancerID CLB 实例 ID
	ListenerPort   int    `yaml:"listenerPort"`    // ListenerPort 阿里云 CLB HTTPS 监听端口
	ListenerID     string `yaml:"listenerId"`      // ListenerID 腾讯云 CLB 监听器 ID
}

// DeploymentResource 描述从固定业务配置中解析出的精确部署资源。
type DeploymentResource struct {
	TargetRef      string // TargetRef 客户端根据资源身份自动生成的不透明稳定引用
	Label          string // Label 控制台展示名称
	Domain         string // Domain 资源绑定的精确域名
	Region         string // Region 对象存储地域
	Endpoint       string // Endpoint OSS API Origin 覆盖值
	Bucket         string // Bucket 对象存储 Bucket 名称
	SiteID         string // SiteID 阿里云 ESA Site ID
	ZoneID         string // ZoneID 腾讯云 EdgeOne Zone ID
	LoadBalancerID string // LoadBalancerID 负载均衡实例 ID
	ListenerPort   int    // ListenerPort 负载均衡监听端口
	ListenerID     string // ListenerID 腾讯云 CLB 监听器 ID
}

// DeploymentResourceDirectoryEntry 是可上报给后端的脱敏部署资源目录项。
type DeploymentResourceDirectoryEntry struct {
	Provider           string                      // Provider 云服务提供商配置名称
	ExecuteBusinesType deployPB.ExecuteBusinesType // ExecuteBusinesType 明确的产品部署业务
	TargetRef          string                      // TargetRef 客户端自动生成的不透明引用
	Label              string                      // Label 资源展示名称
	Domain             string                      // Domain 资源精确域名
}

// GetDeploymentResource 按 provider、业务类型和 targetRef 精确查询本地部署资源。
func GetDeploymentResource(providerName string, business deployPB.ExecuteBusinesType, targetRef string) (*DeploymentResource, bool) {
	if Config == nil || strings.TrimSpace(targetRef) == "" {
		return nil, false
	}
	provider := GetProvider(providerName)
	if provider == nil {
		return nil, false
	}
	for _, resource := range deploymentResources(provider, business) {
		if resource.TargetRef == targetRef {
			copyResource := resource
			return &copyResource, true
		}
	}
	return nil, false
}

// GetDeploymentResourceDirectory 返回不含凭据和私有资源定位字段的部署资源目录。
func GetDeploymentResourceDirectory() []DeploymentResourceDirectoryEntry {
	if Config == nil {
		return nil
	}

	entries := make([]DeploymentResourceDirectoryEntry, 0)
	for _, provider := range Config.Provider {
		if provider == nil {
			continue
		}
		for _, business := range deploymentBusinesses(provider.Name) {
			for _, resource := range deploymentResources(provider, business) {
				entries = append(entries, DeploymentResourceDirectoryEntry{
					Provider:           provider.Name,
					ExecuteBusinesType: business,
					TargetRef:          resource.TargetRef,
					Label:              resource.Label,
					Domain:             resource.Domain,
				})
			}
		}
	}
	return entries
}

// IsDeploymentResourceBusiness 判断业务是否需要解析一个精确部署资源。
func IsDeploymentResourceBusiness(business deployPB.ExecuteBusinesType) bool {
	switch business {
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN,
		deployPB.ExecuteBusinesType_EXECUTE_BUSINES_DCDN,
		deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ESA,
		deployPB.ExecuteBusinesType_EXECUTE_BUSINES_EDGEONE,
		deployPB.ExecuteBusinesType_EXECUTE_BUSINES_COS,
		deployPB.ExecuteBusinesType_EXECUTE_BUSINES_OSS_CUSTOM_DOMAIN,
		deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CLB:
		return true
	default:
		return false
	}
}

// validateDeploymentResources 校验 provider 的固定业务配置并检测自动引用冲突。
func validateDeploymentResources(provider *Provider, targetRefs map[string]string) error {
	if err := validateProviderBusinessFields(provider); err != nil {
		return err
	}
	for _, business := range deploymentBusinesses(provider.Name) {
		if err := normalizeDeploymentResources(provider, business); err != nil {
			return err
		}
		for _, resource := range deploymentResources(provider, business) {
			identity := fmt.Sprintf("%s/%s/%s", provider.Name, business.String(), resource.Domain)
			if previous, exists := targetRefs[resource.TargetRef]; exists {
				return fmt.Errorf("部署资源重复或自动引用冲突: %s 与 %s", previous, identity)
			}
			targetRefs[resource.TargetRef] = identity
		}
	}
	return nil
}

// validateProviderBusinessFields 拒绝 provider 不支持的固定业务字段。
func validateProviderBusinessFields(provider *Provider) error {
	unsupported := make([]string, 0)
	switch provider.Name {
	case ProviderAliyun:
		if len(provider.EdgeOne) > 0 {
			unsupported = append(unsupported, "edgeOne")
		}
		if len(provider.COS) > 0 {
			unsupported = append(unsupported, "cos")
		}
	case ProviderTencentCloud:
		if len(provider.DCDN) > 0 {
			unsupported = append(unsupported, "dcdn")
		}
		if len(provider.ESA) > 0 {
			unsupported = append(unsupported, "esa")
		}
		if len(provider.OSS) > 0 {
			unsupported = append(unsupported, "oss")
		}
	case ProviderQiniu:
		if len(provider.CLB) > 0 {
			unsupported = append(unsupported, "clb")
		}
		if len(provider.ESA) > 0 {
			unsupported = append(unsupported, "esa")
		}
		if len(provider.OSS) > 0 {
			unsupported = append(unsupported, "oss")
		}
		if len(provider.EdgeOne) > 0 {
			unsupported = append(unsupported, "edgeOne")
		}
		if len(provider.COS) > 0 {
			unsupported = append(unsupported, "cos")
		}
	default:
		if hasDeploymentResources(provider) {
			return fmt.Errorf("provider[%s] 不支持自动部署资源配置", provider.Name)
		}
	}
	if len(unsupported) > 0 {
		return fmt.Errorf("provider[%s] 不支持部署业务字段: %s", provider.Name, strings.Join(unsupported, ", "))
	}
	return nil
}

// validateDeploymentResourceCredentials 校验启用部署资源时所需的 provider 认证字段。
func validateDeploymentResourceCredentials(provider *Provider) error {
	if !hasDeploymentResources(provider) {
		return nil
	}
	if provider.Auth == nil {
		return fmt.Errorf("provider[%s].auth 不能为空：配置自动部署资源时必须提供认证信息", provider.Name)
	}

	missingFields := make([]string, 0)
	switch provider.Name {
	case ProviderAliyun:
		if strings.TrimSpace(provider.Auth.AccessKeyId) == "" {
			missingFields = append(missingFields, "accessKeyId")
		}
		if strings.TrimSpace(provider.Auth.AccessKeySecret) == "" {
			missingFields = append(missingFields, "accessKeySecret")
		}
	case ProviderTencentCloud:
		if strings.TrimSpace(provider.Auth.SecretId) == "" {
			missingFields = append(missingFields, "secretId")
		}
		if strings.TrimSpace(provider.Auth.SecretKey) == "" {
			missingFields = append(missingFields, "secretKey")
		}
	case ProviderQiniu:
		if strings.TrimSpace(provider.Auth.AccessKey) == "" {
			missingFields = append(missingFields, "accessKey")
		}
		if strings.TrimSpace(provider.Auth.AccessSecret) == "" {
			missingFields = append(missingFields, "accessSecret")
		}
	}
	if len(missingFields) > 0 {
		return fmt.Errorf("provider[%s].auth 缺少自动部署资源所需字段: %s", provider.Name, strings.Join(missingFields, ", "))
	}
	return nil
}

// normalizeDeploymentResources 规范化并校验一个固定业务下的全部资源。
func normalizeDeploymentResources(provider *Provider, business deployPB.ExecuteBusinesType) error {
	switch business {
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN:
		for index, resource := range provider.CDN {
			path := fmt.Sprintf("provider[%s].cdn[%d]", provider.Name, index)
			if resource == nil {
				return fmt.Errorf("%s 不能为空", path)
			}
			if err := normalizeResourceLabelAndDomain(&resource.Label, &resource.Domain, path); err != nil {
				return err
			}
		}
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_DCDN:
		for index, resource := range provider.DCDN {
			path := fmt.Sprintf("provider[%s].dcdn[%d]", provider.Name, index)
			if resource == nil {
				return fmt.Errorf("%s 不能为空", path)
			}
			if err := normalizeResourceLabelAndDomain(&resource.Label, &resource.Domain, path); err != nil {
				return err
			}
		}
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ESA:
		for index, resource := range provider.ESA {
			path := fmt.Sprintf("provider[%s].esa[%d]", provider.Name, index)
			if resource == nil {
				return fmt.Errorf("%s 不能为空", path)
			}
			if err := normalizeResourceLabelAndDomain(&resource.Label, &resource.Domain, path); err != nil {
				return err
			}
			resource.SiteID = strings.TrimSpace(resource.SiteID)
			if resource.SiteID == "" {
				return fmt.Errorf("%s.siteId 不能为空", path)
			}
		}
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_OSS_CUSTOM_DOMAIN:
		for index, resource := range provider.OSS {
			path := fmt.Sprintf("provider[%s].oss[%d]", provider.Name, index)
			if resource == nil {
				return fmt.Errorf("%s 不能为空", path)
			}
			if err := normalizeResourceLabelAndDomain(&resource.Label, &resource.Domain, path); err != nil {
				return err
			}
			resource.Region = strings.ToLower(strings.TrimSpace(resource.Region))
			resource.Bucket = strings.TrimSpace(resource.Bucket)
			resource.Endpoint = strings.TrimSpace(resource.Endpoint)
			if resource.Region == "" || resource.Bucket == "" {
				return fmt.Errorf("%s 的 region 和 bucket 不能为空", path)
			}
			if resource.Endpoint != "" {
				if err := validateDeploymentEndpoint(resource.Endpoint); err != nil {
					return fmt.Errorf("%s.endpoint 无效: %w", path, err)
				}
			}
		}
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_EDGEONE:
		for index, resource := range provider.EdgeOne {
			path := fmt.Sprintf("provider[%s].edgeOne[%d]", provider.Name, index)
			if resource == nil {
				return fmt.Errorf("%s 不能为空", path)
			}
			if err := normalizeResourceLabelAndDomain(&resource.Label, &resource.Domain, path); err != nil {
				return err
			}
			resource.ZoneID = strings.TrimSpace(resource.ZoneID)
			if resource.ZoneID == "" {
				return fmt.Errorf("%s.zoneId 不能为空", path)
			}
		}
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_COS:
		for index, resource := range provider.COS {
			path := fmt.Sprintf("provider[%s].cos[%d]", provider.Name, index)
			if resource == nil {
				return fmt.Errorf("%s 不能为空", path)
			}
			if err := normalizeResourceLabelAndDomain(&resource.Label, &resource.Domain, path); err != nil {
				return err
			}
			resource.Region = strings.TrimSpace(resource.Region)
			resource.Bucket = strings.TrimSpace(resource.Bucket)
			if resource.Region == "" || resource.Bucket == "" {
				return fmt.Errorf("%s 的 region 和 bucket-appid 不能为空", path)
			}
			if !isCOSBucketWithAppID(resource.Bucket) {
				return fmt.Errorf("%s.bucket 必须使用完整 bucket-appid 格式", path)
			}
		}
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CLB:
		for index, resource := range provider.CLB {
			path := fmt.Sprintf("provider[%s].clb[%d]", provider.Name, index)
			if resource == nil {
				return fmt.Errorf("%s 不能为空", path)
			}
			if err := normalizeResourceLabelAndDomain(&resource.Label, &resource.Domain, path); err != nil {
				return err
			}
			if strings.HasPrefix(resource.Domain, "*.") {
				return fmt.Errorf("%s.domain 必须是精确域名，不能使用泛域名", path)
			}
			resource.Region = strings.ToLower(strings.TrimSpace(resource.Region))
			resource.LoadBalancerID = strings.TrimSpace(resource.LoadBalancerID)
			if err := validateCLBRegion(resource.Region); err != nil {
				return fmt.Errorf("%s.region 无效: %w", path, err)
			}
			if resource.LoadBalancerID == "" {
				return fmt.Errorf("%s.loadBalancerId 不能为空", path)
			}
			if strings.IndexFunc(resource.LoadBalancerID, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
				return fmt.Errorf("%s.loadBalancerId 不能包含空白或控制字符", path)
			}
			if provider.Name == ProviderTencentCloud {
				resource.ListenerID = strings.TrimSpace(resource.ListenerID)
				if resource.ListenerID == "" {
					return fmt.Errorf("%s.listenerId 不能为空", path)
				}
				if strings.IndexFunc(resource.ListenerID, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
					return fmt.Errorf("%s.listenerId 不能包含空白或控制字符", path)
				}
				continue
			}
			if resource.ListenerPort < minPort || resource.ListenerPort > maxPort {
				return fmt.Errorf("%s.listenerPort 必须在 %d-%d 之间", path, minPort, maxPort)
			}
		}
	}
	return nil
}

// normalizeResourceLabelAndDomain 规范化资源展示名称和精确域名。
func normalizeResourceLabelAndDomain(label, domain *string, path string) error {
	normalizedDomain, err := normalizeDeploymentDomain(*domain)
	if err != nil {
		return fmt.Errorf("%s.domain 无效: %w", path, err)
	}
	*domain = normalizedDomain
	*label = strings.TrimSpace(*label)
	if *label == "" {
		*label = normalizedDomain
	}
	if utf8.RuneCountInString(*label) > 128 {
		return fmt.Errorf("%s.label 长度不能超过 128 个字符", path)
	}
	if strings.IndexFunc(*label, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s.label 不能包含控制字符", path)
	}
	return nil
}

// deploymentBusinesses 返回 provider 支持的明确资源部署业务。
func deploymentBusinesses(providerName string) []deployPB.ExecuteBusinesType {
	switch providerName {
	case ProviderAliyun:
		return []deployPB.ExecuteBusinesType{
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN,
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_DCDN,
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ESA,
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_OSS_CUSTOM_DOMAIN,
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CLB,
		}
	case ProviderTencentCloud:
		return []deployPB.ExecuteBusinesType{
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN,
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_EDGEONE,
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_COS,
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CLB,
		}
	case ProviderQiniu:
		return []deployPB.ExecuteBusinesType{
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN,
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_DCDN,
		}
	default:
		return nil
	}
}

// deploymentResources 将一个明确业务的固定配置转换为统一执行字段。
func deploymentResources(provider *Provider, business deployPB.ExecuteBusinesType) []DeploymentResource {
	resources := make([]DeploymentResource, 0)
	switch business {
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN:
		for _, resource := range provider.CDN {
			if resource != nil {
				resources = append(resources, newDeploymentResource(provider.Name, business, resource.Label, resource.Domain, "", "", "", "", "", "", 0, ""))
			}
		}
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_DCDN:
		for _, resource := range provider.DCDN {
			if resource != nil {
				resources = append(resources, newDeploymentResource(provider.Name, business, resource.Label, resource.Domain, "", "", "", "", "", "", 0, ""))
			}
		}
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ESA:
		for _, resource := range provider.ESA {
			if resource != nil {
				resources = append(resources, newDeploymentResource(provider.Name, business, resource.Label, resource.Domain, "", "", "", resource.SiteID, "", "", 0, ""))
			}
		}
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_OSS_CUSTOM_DOMAIN:
		for _, resource := range provider.OSS {
			if resource != nil {
				resources = append(resources, newDeploymentResource(provider.Name, business, resource.Label, resource.Domain, resource.Region, resource.Endpoint, resource.Bucket, "", "", "", 0, ""))
			}
		}
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_EDGEONE:
		for _, resource := range provider.EdgeOne {
			if resource != nil {
				resources = append(resources, newDeploymentResource(provider.Name, business, resource.Label, resource.Domain, "", "", "", "", resource.ZoneID, "", 0, ""))
			}
		}
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_COS:
		for _, resource := range provider.COS {
			if resource != nil {
				resources = append(resources, newDeploymentResource(provider.Name, business, resource.Label, resource.Domain, resource.Region, "", resource.Bucket, "", "", "", 0, ""))
			}
		}
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CLB:
		for _, resource := range provider.CLB {
			if resource != nil {
				resources = append(resources, newDeploymentResource(provider.Name, business, resource.Label, resource.Domain, resource.Region, "", "", "", "", resource.LoadBalancerID, resource.ListenerPort, resource.ListenerID))
			}
		}
	}
	return resources
}

// newDeploymentResource 创建统一执行资源并根据规范化定位字段生成稳定引用。
func newDeploymentResource(provider string, business deployPB.ExecuteBusinesType, label, domain, region, endpoint, bucket, siteID, zoneID, loadBalancerID string, listenerPort int, listenerID string) DeploymentResource {
	identityParts := []string{provider, business.String()}
	switch business {
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ESA:
		identityParts = append(identityParts, siteID)
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_OSS_CUSTOM_DOMAIN,
		deployPB.ExecuteBusinesType_EXECUTE_BUSINES_COS:
		identityParts = append(identityParts, region, bucket)
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_EDGEONE:
		identityParts = append(identityParts, zoneID)
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CLB:
		if provider == ProviderTencentCloud {
			identityParts = append(identityParts, region, loadBalancerID, listenerID)
		} else {
			identityParts = append(identityParts, region, loadBalancerID, strconv.Itoa(listenerPort))
		}
	}
	identityParts = append(identityParts, domain)
	digest := sha256.Sum256([]byte(strings.ToLower(strings.Join(identityParts, "\x00"))))
	prefix := strings.ToLower(strings.TrimPrefix(business.String(), "EXECUTE_BUSINES_"))
	return DeploymentResource{
		TargetRef:      fmt.Sprintf("%s-%x", prefix, digest[:12]),
		Label:          label,
		Domain:         domain,
		Region:         region,
		Endpoint:       endpoint,
		Bucket:         bucket,
		SiteID:         siteID,
		ZoneID:         zoneID,
		LoadBalancerID: loadBalancerID,
		ListenerPort:   listenerPort,
		ListenerID:     listenerID,
	}
}

// hasDeploymentResources 判断 provider 是否配置了任一明确业务资源。
func hasDeploymentResources(provider *Provider) bool {
	return len(provider.CDN) > 0 || len(provider.DCDN) > 0 || len(provider.ESA) > 0 ||
		len(provider.OSS) > 0 || len(provider.EdgeOne) > 0 || len(provider.COS) > 0 || len(provider.CLB) > 0
}

// validateCLBRegion 校验 CLB 地域为单个安全 DNS 标签，避免将任意文本带入云 API 请求。
func validateCLBRegion(region string) error {
	if region == "" {
		return errors.New("不能为空")
	}
	if len(region) > 63 || !dnsLabelPattern.MatchString(strings.ToLower(region)) {
		return errors.New("必须是小写字母、数字或连字符组成的地域 ID")
	}
	return nil
}

// normalizeDeploymentDomain 将域名规范化为小写且不带末尾点的 DNS 名称。
func normalizeDeploymentDomain(rawDomain string) (string, error) {
	domain := strings.TrimSuffix(strings.TrimSpace(rawDomain), ".")
	if domain == "" {
		return "", errors.New("不能为空")
	}
	if strings.Contains(domain, "://") || strings.ContainsAny(domain, "/?#@:") {
		return "", errors.New("只能填写域名，不能包含协议、端口或路径")
	}
	if strings.IndexFunc(domain, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
		return "", errors.New("不能包含空白或控制字符")
	}

	validationDomain := domain
	wildcard := strings.HasPrefix(validationDomain, "*.")
	if wildcard {
		validationDomain = strings.TrimPrefix(validationDomain, "*.")
	}
	if strings.Contains(validationDomain, "*") {
		return "", errors.New("泛域名只能使用开头的 *. 格式")
	}
	asciiDomain, err := idna.Lookup.ToASCII(validationDomain)
	if err != nil {
		return "", fmt.Errorf("IDNA 规范化失败: %w", err)
	}
	validationDomain = strings.ToLower(asciiDomain)
	if len(validationDomain) > 253 {
		return "", errors.New("长度不能超过 253 个字符")
	}
	labels := strings.Split(validationDomain, ".")
	if len(labels) < 2 {
		return "", errors.New("必须是包含至少两个标签的完整 DNS 名称")
	}
	for _, label := range labels {
		if !dnsLabelPattern.MatchString(label) {
			return "", fmt.Errorf("DNS 标签不合法: %s", label)
		}
	}
	if wildcard {
		return "*." + validationDomain, nil
	}
	return validationDomain, nil
}

// validateDeploymentEndpoint 校验 OSS endpoint 是无附加部分的 HTTPS Origin。
func validateDeploymentEndpoint(rawEndpoint string) error {
	parsed, err := url.Parse(rawEndpoint)
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return errors.New("必须是合法的 HTTPS Origin")
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return errors.New("只允许 HTTPS")
	}
	if parsed.User != nil {
		return errors.New("不能包含用户凭据")
	}
	if parsed.Path != "" || parsed.RawPath != "" || parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("不能包含 path、query 或 fragment")
	}
	return nil
}

// isCOSBucketWithAppID 判断腾讯云 COS Bucket 是否包含末尾数字 APPID。
func isCOSBucketWithAppID(bucket string) bool {
	separator := strings.LastIndexByte(bucket, '-')
	if separator <= 0 || separator == len(bucket)-1 {
		return false
	}
	for _, char := range bucket[separator+1:] {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
