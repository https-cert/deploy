package client

import (
	"fmt"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/internal/client/providers/aliyun"
	"github.com/https-cert/deploy/internal/client/providers/baidu"
	cloud_tencent "github.com/https-cert/deploy/internal/client/providers/cloud_tencent"
	"github.com/https-cert/deploy/internal/client/providers/dogecloud"
	"github.com/https-cert/deploy/internal/client/providers/huawei"
	"github.com/https-cert/deploy/internal/client/providers/jdcloud"
	"github.com/https-cert/deploy/internal/client/providers/lecdn"
	"github.com/https-cert/deploy/internal/client/providers/qiniu"
	"github.com/https-cert/deploy/internal/client/providers/volcengine"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
)

// providerDefinition 描述一个云厂商的完整运行期能力，避免多个 switch 漂移。
type providerDefinition struct {
	// Provider 是 v2 协议中的云厂商枚举。
	Provider deployPB.Provider
	// ConfigName 是 config.yaml 中的 provider.name。
	ConfigName string
	// UploadOnly 表示是否支持证书中心上传。
	UploadOnly bool
	// ResourceTypes 是该厂商支持的动态资源类型，顺序用于稳定能力上报。
	ResourceTypes []deployPB.DeploymentType
	// New 根据一次配置快照构造单次操作使用的 provider 客户端。
	New func(*config.Provider) (any, error)
}

// providerDefinitions 是云厂商的唯一注册表；切勿在运行路径中缓存返回的 SDK 客户端。
var providerDefinitions = []providerDefinition{
	{Provider: deployPB.Provider_PROVIDER_ALIYUN, ConfigName: config.ProviderAliyun, UploadOnly: true, ResourceTypes: []deployPB.DeploymentType{deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN, deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA, deployPB.DeploymentType_DEPLOYMENT_TYPE_OSS_CUSTOM_DOMAIN, deployPB.DeploymentType_DEPLOYMENT_TYPE_CLB, deployPB.DeploymentType_DEPLOYMENT_TYPE_ALB, deployPB.DeploymentType_DEPLOYMENT_TYPE_NLB}, New: newAliyunHandler},
	{Provider: deployPB.Provider_PROVIDER_TENCENT_CLOUD, ConfigName: config.ProviderTencentCloud, UploadOnly: true, ResourceTypes: []deployPB.DeploymentType{deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, deployPB.DeploymentType_DEPLOYMENT_TYPE_EDGEONE, deployPB.DeploymentType_DEPLOYMENT_TYPE_COS, deployPB.DeploymentType_DEPLOYMENT_TYPE_CLB}, New: newTencentHandler},
	{Provider: deployPB.Provider_PROVIDER_QINIU, ConfigName: config.ProviderQiniu, UploadOnly: true, ResourceTypes: []deployPB.DeploymentType{deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN}, New: newQiniuHandler},
	{Provider: deployPB.Provider_PROVIDER_DOGE_CLOUD, ConfigName: config.ProviderDogeCloud, UploadOnly: true, ResourceTypes: []deployPB.DeploymentType{deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN}, New: newDogeCloudHandler},
	{Provider: deployPB.Provider_PROVIDER_BAIDU_CLOUD, ConfigName: config.ProviderBaiduCloud, UploadOnly: true, ResourceTypes: []deployPB.DeploymentType{deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN}, New: newBaiduHandler},
	{Provider: deployPB.Provider_PROVIDER_JD_CLOUD, ConfigName: config.ProviderJDCloud, UploadOnly: true, ResourceTypes: []deployPB.DeploymentType{deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN}, New: newJDCloudHandler},
	{Provider: deployPB.Provider_PROVIDER_VOLCENGINE, ConfigName: config.ProviderVolcengine, UploadOnly: true, ResourceTypes: []deployPB.DeploymentType{deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN, deployPB.DeploymentType_DEPLOYMENT_TYPE_TOS_CUSTOM_DOMAIN, deployPB.DeploymentType_DEPLOYMENT_TYPE_CLB, deployPB.DeploymentType_DEPLOYMENT_TYPE_ALB, deployPB.DeploymentType_DEPLOYMENT_TYPE_NLB}, New: newVolcengineHandler},
	{Provider: deployPB.Provider_PROVIDER_HUAWEI_CLOUD, ConfigName: config.ProviderHuaweiCloud, UploadOnly: true, ResourceTypes: []deployPB.DeploymentType{deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN, deployPB.DeploymentType_DEPLOYMENT_TYPE_OBS_CUSTOM_DOMAIN, deployPB.DeploymentType_DEPLOYMENT_TYPE_ELB}, New: newHuaweiHandler},
	{Provider: deployPB.Provider_PROVIDER_LECDN, ConfigName: config.ProviderLeCDN, UploadOnly: false, ResourceTypes: []deployPB.DeploymentType{deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN}, New: newLeCDNHandler},
}

// findProviderDefinition 按协议枚举查找唯一云厂商定义。
func findProviderDefinition(provider deployPB.Provider) (providerDefinition, bool) {
	for _, definition := range providerDefinitions {
		if definition.Provider == provider {
			return definition, true
		}
	}
	return providerDefinition{}, false
}

// providerSupportsResource 判断云厂商是否声明了指定动态资源类型。
func providerSupportsResource(provider deployPB.Provider, deploymentType deployPB.DeploymentType) bool {
	definition, ok := findProviderDefinition(provider)
	if !ok {
		return false
	}
	for _, supportedType := range definition.ResourceTypes {
		if supportedType == deploymentType {
			return true
		}
	}
	return false
}

// configuredProvider 从运行时快照读取 provider 配置，不依赖全局配置。
func configuredProvider(runtime *config.Runtime, name string) *config.Provider {
	if runtime == nil || runtime.Config == nil {
		return nil
	}
	for _, provider := range runtime.Config.Provider {
		if provider != nil && provider.Name == name {
			return provider
		}
	}
	return nil
}

// newConfiguredProvider 根据注册表和运行时配置构造 provider。
func newConfiguredProvider(runtime *config.Runtime, provider deployPB.Provider) (any, error) {
	definition, ok := findProviderDefinition(provider)
	if !ok {
		return nil, fmt.Errorf("暂不支持部署 provider: %s", provider.String())
	}
	configuration := configuredProvider(runtime, definition.ConfigName)
	if configuration == nil {
		return nil, fmt.Errorf("提供商配置不存在: %s", definition.ConfigName)
	}
	return definition.New(configuration)
}

// newDeploymentResourceProvider 从显式运行时配置创建 v2 动态资源适配器。
func newDeploymentResourceProvider(provider deployPB.Provider, deploymentType deployPB.DeploymentType, runtime *config.Runtime) (providers.DeploymentResourceProvider, error) {
	if !providerSupportsResource(provider, deploymentType) {
		return nil, providers.NewDeploymentError("部署类型与 provider 不匹配", false, "", nil)
	}
	if runtime == nil || runtime.Config == nil {
		return nil, providers.NewDeploymentError("运行时配置未初始化", false, "", nil)
	}
	handler, err := newConfiguredProvider(runtime, provider)
	if err != nil {
		return nil, providers.NewDeploymentError("初始化部署资源 provider 失败", false, "", err)
	}
	resourceProvider, ok := handler.(providers.DeploymentResourceProvider)
	if !ok {
		return nil, providers.NewDeploymentError("provider 不支持动态资源部署", false, "", nil)
	}
	return resourceProvider, nil
}

// providerAuthRequired 校验通用的访问密钥认证字段。
func providerAuthRequired(provider *config.Provider, firstName, secondName string) error {
	if provider == nil || provider.Auth == nil {
		return fmt.Errorf("provider 配置不完整: %s 或 %s 为空", firstName, secondName)
	}
	if providerAuthValue(provider, firstName) == "" || providerAuthValue(provider, secondName) == "" {
		return fmt.Errorf("provider 配置不完整: %s 或 %s 为空", firstName, secondName)
	}
	return nil
}

// providerAuthValue 读取注册表构造器使用的认证字段。
func providerAuthValue(provider *config.Provider, field string) string {
	if provider == nil || provider.Auth == nil {
		return ""
	}
	switch field {
	case "accessKeyId":
		return provider.Auth.AccessKeyId
	case "accessKeySecret":
		return provider.Auth.AccessKeySecret
	case "secretId":
		return provider.Auth.SecretId
	case "secretKey":
		return provider.Auth.SecretKey
	case "accessKey":
		return provider.Auth.AccessKey
	case "accessSecret":
		return provider.Auth.AccessSecret
	case "apiBaseUrl":
		return provider.Auth.APIBaseURL
	case "apiToken":
		return provider.Auth.APIToken
	default:
		return ""
	}
}

// newAliyunHandler 创建阿里云 provider。
func newAliyunHandler(configuration *config.Provider) (any, error) {
	if err := providerAuthRequired(configuration, "accessKeyId", "accessKeySecret"); err != nil {
		return nil, fmt.Errorf("阿里云%s", err)
	}
	return aliyun.New(configuration.GetAccessKeyId(), configuration.GetAccessKeySecret())
}

// newTencentHandler 创建腾讯云 provider。
func newTencentHandler(configuration *config.Provider) (any, error) {
	if err := providerAuthRequired(configuration, "secretId", "secretKey"); err != nil {
		return nil, fmt.Errorf("腾讯云%s", err)
	}
	return cloud_tencent.New(configuration.GetSecretId(), configuration.GetSecretKey()), nil
}

// newQiniuHandler 创建七牛云 provider。
func newQiniuHandler(configuration *config.Provider) (any, error) {
	if err := providerAuthRequired(configuration, "accessKey", "accessSecret"); err != nil {
		return nil, fmt.Errorf("七牛云%s", err)
	}
	return qiniu.New(configuration.GetAccessKey(), configuration.GetAccessSecret()), nil
}

// newDogeCloudHandler 创建多吉云 provider。
func newDogeCloudHandler(configuration *config.Provider) (any, error) {
	if err := providerAuthRequired(configuration, "accessKey", "accessSecret"); err != nil {
		return nil, fmt.Errorf("多吉云%s", err)
	}
	return dogecloud.New(configuration.GetAccessKey(), configuration.GetAccessSecret()), nil
}

// newBaiduHandler 创建百度云 provider。
func newBaiduHandler(configuration *config.Provider) (any, error) {
	if err := providerAuthRequired(configuration, "accessKeyId", "accessKeySecret"); err != nil {
		return nil, fmt.Errorf("百度云%s", err)
	}
	return baidu.New(configuration.GetAccessKeyId(), configuration.GetAccessKeySecret())
}

// newJDCloudHandler 创建京东云 provider。
func newJDCloudHandler(configuration *config.Provider) (any, error) {
	if err := providerAuthRequired(configuration, "accessKeyId", "accessKeySecret"); err != nil {
		return nil, fmt.Errorf("京东云%s", err)
	}
	return jdcloud.New(configuration.GetAccessKeyId(), configuration.GetAccessKeySecret()), nil
}

// newVolcengineHandler 创建火山引擎 provider。
func newVolcengineHandler(configuration *config.Provider) (any, error) {
	if err := providerAuthRequired(configuration, "accessKeyId", "accessKeySecret"); err != nil {
		return nil, fmt.Errorf("火山引擎%s", err)
	}
	return volcengine.NewConfigured(configuration.GetAccessKeyId(), configuration.GetAccessKeySecret(), configuration.Region, configuration.CertificateRegion, configuration.Regions)
}

// newHuaweiHandler 创建华为云 provider。
func newHuaweiHandler(configuration *config.Provider) (any, error) {
	if err := providerAuthRequired(configuration, "accessKeyId", "accessKeySecret"); err != nil {
		return nil, fmt.Errorf("华为云%s", err)
	}
	return huawei.New(configuration.GetAccessKeyId(), configuration.GetAccessKeySecret(), configuration.Region, configuration.CertificateRegion, configuration.Regions)
}

// newLeCDNHandler 创建 LeCDN provider。
func newLeCDNHandler(configuration *config.Provider) (any, error) {
	if err := providerAuthRequired(configuration, "apiBaseUrl", "apiToken"); err != nil {
		return nil, fmt.Errorf("LeCDN%s", err)
	}
	return lecdn.New(configuration.GetAPIBaseURL(), configuration.GetAPIToken()), nil
}
