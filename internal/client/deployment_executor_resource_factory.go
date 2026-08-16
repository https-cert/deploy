package client

import (
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/internal/client/providers/aliyun"
	cloud_tencent "github.com/https-cert/deploy/internal/client/providers/cloud_tencent"
	"github.com/https-cert/deploy/internal/client/providers/qiniu"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
)

// newDeploymentResourceProvider 从现有配置凭据创建 v2 动态资源适配器。
func newDeploymentResourceProvider(provider deployPB.Provider, deploymentType deployPB.DeploymentType) (providers.DeploymentResourceProvider, error) {
	if !providerSupportsDeploymentType(provider, deploymentType) {
		return nil, providers.NewDeploymentError("部署类型与 provider 不匹配", false, "", nil)
	}
	providerName, ok := config.DeploymentProviderName(provider)
	if !ok {
		return nil, providers.NewDeploymentError("暂不支持部署资源 provider: "+provider.String(), false, "", nil)
	}
	providerConfig := config.GetProvider(providerName)
	if providerConfig == nil {
		return nil, providers.NewDeploymentError("部署资源 provider 未配置: "+providerName, false, "", nil)
	}

	switch provider {
	case deployPB.Provider_PROVIDER_ALIYUN:
		accessKeyID := providerConfig.GetAccessKeyId()
		accessKeySecret := providerConfig.GetAccessKeySecret()
		if accessKeyID == "" || accessKeySecret == "" {
			return nil, providers.NewDeploymentError("阿里云配置不完整: accessKeyId 或 accessKeySecret 为空", false, "", nil)
		}
		deployer, err := aliyun.New(accessKeyID, accessKeySecret)
		if err != nil {
			return nil, providers.NewDeploymentError("初始化阿里云部署客户端失败", false, "", err)
		}
		return deployer, nil

	case deployPB.Provider_PROVIDER_TENCENT_CLOUD:
		secretID := providerConfig.GetSecretId()
		secretKey := providerConfig.GetSecretKey()
		if secretID == "" || secretKey == "" {
			return nil, providers.NewDeploymentError("腾讯云配置不完整: secretId 或 secretKey 为空", false, "", nil)
		}
		return cloud_tencent.New(secretID, secretKey), nil

	case deployPB.Provider_PROVIDER_QINIU:
		accessKey := providerConfig.GetAccessKey()
		accessSecret := providerConfig.GetAccessSecret()
		if accessKey == "" || accessSecret == "" {
			return nil, providers.NewDeploymentError("七牛云配置不完整: accessKey 或 accessSecret 为空", false, "", nil)
		}
		return qiniu.New(accessKey, accessSecret), nil

	default:
		return nil, providers.NewDeploymentError("暂不支持部署资源 provider: "+providerName, false, "", nil)
	}
}

// providerSupportsDeploymentType 判断 provider 是否原生实现指定 v2 动态资源类型。
func providerSupportsDeploymentType(provider deployPB.Provider, deploymentType deployPB.DeploymentType) bool {
	switch provider {
	case deployPB.Provider_PROVIDER_ALIYUN:
		return deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN ||
			deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN ||
			deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA ||
			deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_OSS_CUSTOM_DOMAIN ||
			deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_CLB ||
			deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_ALB ||
			deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_NLB
	case deployPB.Provider_PROVIDER_TENCENT_CLOUD:
		return deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN ||
			deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_EDGEONE ||
			deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_COS ||
			deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_CLB
	case deployPB.Provider_PROVIDER_QINIU:
		return deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN ||
			deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN
	default:
		return false
	}
}
