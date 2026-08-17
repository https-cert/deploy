package config

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/https-cert/deploy/pb/deployPB"
)

const (
	// ProviderANSSLCLI 是客户端本地和面板部署配置名称。
	ProviderANSSLCLI = "ansslCli"
	// ProviderAliyun 是阿里云 provider 的配置名称。
	ProviderAliyun = "aliyun"
	// ProviderTencentCloud 是腾讯云 provider 的配置名称。
	ProviderTencentCloud = "cloudTencent"
	// ProviderQiniu 是七牛云 provider 的配置名称。
	ProviderQiniu = "qiniu"
	// ProviderHuaweiCloud 是华为云 provider 的配置名称。
	ProviderHuaweiCloud = "huawei"
	// ProviderVolcengine 是火山引擎 provider 的配置名称。
	ProviderVolcengine = "volcengine"
	// ProviderJDCloud 是京东云 provider 的配置名称。
	ProviderJDCloud = "jdcloud"
	// ProviderBaiduCloud 是百度云 provider 的配置名称。
	ProviderBaiduCloud = "baidu"
	// ProviderDogeCloud 是多吉云 provider 的配置名称。
	ProviderDogeCloud = "dogecloud"
	// ProviderLeCDN 是 LeCDN provider 的配置名称。
	ProviderLeCDN = "lecdn"
)

// DeploymentProviderName 返回 v2 provider 对应的兼容配置键。
func DeploymentProviderName(provider deployPB.Provider) (string, bool) {
	switch provider {
	case deployPB.Provider_PROVIDER_ANSSL_CLI:
		return ProviderANSSLCLI, true
	case deployPB.Provider_PROVIDER_ALIYUN:
		return ProviderAliyun, true
	case deployPB.Provider_PROVIDER_TENCENT_CLOUD:
		return ProviderTencentCloud, true
	case deployPB.Provider_PROVIDER_QINIU:
		return ProviderQiniu, true
	case deployPB.Provider_PROVIDER_HUAWEI_CLOUD:
		return ProviderHuaweiCloud, true
	case deployPB.Provider_PROVIDER_VOLCENGINE:
		return ProviderVolcengine, true
	case deployPB.Provider_PROVIDER_JD_CLOUD:
		return ProviderJDCloud, true
	case deployPB.Provider_PROVIDER_BAIDU_CLOUD:
		return ProviderBaiduCloud, true
	case deployPB.Provider_PROVIDER_DOGE_CLOUD:
		return ProviderDogeCloud, true
	case deployPB.Provider_PROVIDER_LECDN:
		return ProviderLeCDN, true
	default:
		return "", false
	}
}

// DeploymentProviderFromName 将现有 config.yaml provider 键转换成 v2 provider。
func DeploymentProviderFromName(name string) (deployPB.Provider, bool) {
	switch strings.TrimSpace(name) {
	case ProviderANSSLCLI:
		return deployPB.Provider_PROVIDER_ANSSL_CLI, true
	case ProviderAliyun:
		return deployPB.Provider_PROVIDER_ALIYUN, true
	case ProviderTencentCloud:
		return deployPB.Provider_PROVIDER_TENCENT_CLOUD, true
	case ProviderQiniu:
		return deployPB.Provider_PROVIDER_QINIU, true
	case ProviderHuaweiCloud:
		return deployPB.Provider_PROVIDER_HUAWEI_CLOUD, true
	case ProviderVolcengine:
		return deployPB.Provider_PROVIDER_VOLCENGINE, true
	case ProviderJDCloud:
		return deployPB.Provider_PROVIDER_JD_CLOUD, true
	case ProviderBaiduCloud:
		return deployPB.Provider_PROVIDER_BAIDU_CLOUD, true
	case ProviderDogeCloud:
		return deployPB.Provider_PROVIDER_DOGE_CLOUD, true
	case ProviderLeCDN:
		return deployPB.Provider_PROVIDER_LECDN, true
	default:
		return deployPB.Provider_PROVIDER_UNSPECIFIED, false
	}
}

var removedDeploymentResourceFields = []string{
	"cdn",
	"dcdn",
	"esa",
	"oss",
	"edgeone",
	"cos",
	"clb",
	"alb",
	"nlb",
}

// IsDeploymentResourceType 判断 v2 部署类型是否需要实时解析一个精确部署资源。
func IsDeploymentResourceType(deploymentType deployPB.DeploymentType) bool {
	switch deploymentType {
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_EDGEONE,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_COS,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_OSS_CUSTOM_DOMAIN,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_OBS_CUSTOM_DOMAIN,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_TOS_CUSTOM_DOMAIN,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_CLB,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ALB,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_NLB,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ELB,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_WEBSITE_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_BT_PANEL_WEBSITE_CERT:
		return true
	default:
		return false
	}
}

// validateRemovedDeploymentResourceFields 拒绝已经移除的 YAML 云资源数组。
func validateRemovedDeploymentResourceFields(rawProviders any) error {
	providers, ok := rawProviders.([]any)
	if !ok {
		return nil
	}
	for index, rawProvider := range providers {
		provider, ok := rawProvider.(map[string]any)
		if !ok {
			continue
		}
		name := strings.TrimSpace(fmt.Sprint(provider["name"]))
		if name == "" {
			name = fmt.Sprintf("#%d", index+1)
		}
		for _, field := range removedDeploymentResourceFields {
			if _, exists := provider[field]; exists {
				return fmt.Errorf("provider[%s].%s 资源配置已移除，请重新生成配置并在网页中关联资源", name, field)
			}
		}
	}
	return nil
}

// validateProviderCredentials 校验动态资源发现所需的云厂商凭据。
func validateProviderCredentials(provider *Provider) error {
	if provider.Name != ProviderAliyun && provider.Name != ProviderTencentCloud && provider.Name != ProviderQiniu &&
		provider.Name != ProviderHuaweiCloud && provider.Name != ProviderVolcengine && provider.Name != ProviderJDCloud &&
		provider.Name != ProviderBaiduCloud && provider.Name != ProviderDogeCloud && provider.Name != ProviderLeCDN {
		return nil
	}
	if provider.Auth == nil {
		return fmt.Errorf("provider[%s].auth 不能为空", provider.Name)
	}

	missingFields := make([]string, 0, 2)
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
	case ProviderHuaweiCloud, ProviderVolcengine, ProviderJDCloud, ProviderBaiduCloud:
		if strings.TrimSpace(provider.Auth.AccessKeyId) == "" {
			missingFields = append(missingFields, "accessKeyId")
		}
		if strings.TrimSpace(provider.Auth.AccessKeySecret) == "" {
			missingFields = append(missingFields, "accessKeySecret")
		}
	case ProviderDogeCloud:
		if strings.TrimSpace(provider.Auth.AccessKey) == "" {
			missingFields = append(missingFields, "accessKey")
		}
		if strings.TrimSpace(provider.Auth.AccessSecret) == "" {
			missingFields = append(missingFields, "accessSecret")
		}
	case ProviderLeCDN:
		if strings.TrimSpace(provider.Auth.APIBaseURL) == "" {
			missingFields = append(missingFields, "apiBaseUrl")
		}
		if strings.TrimSpace(provider.Auth.APIToken) == "" {
			missingFields = append(missingFields, "apiToken")
		}
	}
	if len(missingFields) > 0 {
		return fmt.Errorf("provider[%s].auth 缺少动态资源发现所需字段: %s", provider.Name, strings.Join(missingFields, ", "))
	}
	if provider.Name == ProviderLeCDN {
		baseURL := strings.TrimRight(strings.TrimSpace(provider.Auth.APIBaseURL), "/")
		parsedURL, err := url.Parse(baseURL)
		if err != nil || parsedURL.Hostname() == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
			return fmt.Errorf("provider[%s].auth.apiBaseUrl 必须是合法的 HTTP 或 HTTPS 地址", provider.Name)
		}
		if parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
			return fmt.Errorf("provider[%s].auth.apiBaseUrl 不能包含用户凭据、查询参数或片段", provider.Name)
		}
		allowLocalHTTP := parsedURL.Scheme == "http" && Config != nil && Config.Server != nil &&
			Config.Server.Env == envLocal && isLoopbackHostname(parsedURL.Hostname())
		if parsedURL.Scheme != "https" && !allowLocalHTTP {
			return fmt.Errorf("provider[%s].auth.apiBaseUrl 只允许 HTTPS，本地环境可使用回环 HTTP", provider.Name)
		}
		provider.Auth.APIBaseURL = baseURL
		provider.Auth.APIToken = strings.TrimSpace(provider.Auth.APIToken)
	}
	return nil
}
