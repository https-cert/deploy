package client

import (
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/internal/client/providers/aliyun"
	cloud_tencent "github.com/https-cert/deploy/internal/client/providers/cloud_tencent"
	"github.com/https-cert/deploy/internal/client/providers/qiniu"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
)

// getDeploymentResourceProvider 构建与 provider 和明确业务对应的动态资源适配器。
func (be *BusinessExecutor) getDeploymentResourceProvider(providerName string, business deployPB.ExecuteBusinesType) (providers.DeploymentResourceProvider, error) {
	_ = be
	return newDeploymentResourceProvider(providerName, business)
}

// newDeploymentResourceProvider 从本地凭据创建动态资源适配器。
func newDeploymentResourceProvider(providerName string, business deployPB.ExecuteBusinesType) (providers.DeploymentResourceProvider, error) {
	if !providerSupportsDeploymentBusiness(providerName, business) {
		return nil, providers.NewDeploymentError("部署业务与 provider 不匹配", false, "", nil)
	}

	providerConfig := config.GetProvider(providerName)
	if providerConfig == nil {
		return nil, providers.NewDeploymentError("部署资源 provider 未配置: "+providerName, false, "", nil)
	}

	switch providerName {
	case config.ProviderAliyun:
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

	case config.ProviderTencentCloud:
		secretID := providerConfig.GetSecretId()
		secretKey := providerConfig.GetSecretKey()
		if secretID == "" || secretKey == "" {
			return nil, providers.NewDeploymentError("腾讯云配置不完整: secretId 或 secretKey 为空", false, "", nil)
		}
		return cloud_tencent.New(secretID, secretKey), nil

	case config.ProviderQiniu:
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

// providerSupportsDeploymentBusiness 判断 provider 是否实现指定的明确部署业务。
func providerSupportsDeploymentBusiness(providerName string, business deployPB.ExecuteBusinesType) bool {
	switch providerName {
	case config.ProviderAliyun:
		return business == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN ||
			business == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_DCDN ||
			business == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ESA ||
			business == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_OSS_CUSTOM_DOMAIN ||
			business == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CLB ||
			business == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ALB ||
			business == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_NLB
	case config.ProviderTencentCloud:
		return business == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN ||
			business == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_EDGEONE ||
			business == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_COS ||
			business == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CLB
	case config.ProviderQiniu:
		return business == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN ||
			business == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_DCDN
	default:
		return false
	}
}
