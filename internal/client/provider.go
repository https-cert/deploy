package client

import (
	"fmt"

	"github.com/https-cert/deploy/internal/client/providers/aliyun"
	"github.com/https-cert/deploy/internal/client/providers/qiniu"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

// ProviderInfo 提供商信息
type ProviderInfo struct {
	Name   string
	Remark string
}

// GetProviderInfo 获取提供商信息列表
func GetProviderInfo() []ProviderInfo {
	cfg := config.GetConfig()
	var providers []ProviderInfo
	for _, p := range cfg.Provider {
		providers = append(providers, ProviderInfo{
			Name:   p.Name,
			Remark: p.Remark,
		})
	}
	return providers
}

// TestProviderConnection 测试提供商连接
func TestProviderConnection(providerName string) (bool, error) {
	switch providerName {
	case "ansslCli":
		return true, nil

	case "aliyun":
		providerConfig := config.GetProvider("aliyun")
		if providerConfig == nil {
			return false, fmt.Errorf("未配置【阿里云】提供商配置")
		}

		provider, err := aliyun.New(providerConfig.GetAccessKeyId(), providerConfig.GetAccessKeySecret())
		if err != nil {
			return false, fmt.Errorf("创建阿里云提供商实例失败: %w", err)
		}
		success, err := provider.TestConnection()
		if err != nil {
			return false, fmt.Errorf("阿里云连接测试失败: %w", err)
		}
		return success, nil

	case "cloudTencent":
		return false, nil

	case "qiniu":
		providerConfig := config.GetProvider("qiniu")
		if providerConfig == nil {
			return false, fmt.Errorf("未配置【七牛云】提供商配置")
		}

		provider := qiniu.New(providerConfig.GetAccessKey(), providerConfig.GetAccessSecret())
		success, err := provider.TestConnection()
		if err != nil {
			return false, fmt.Errorf("七牛云连接测试失败: %w", err)
		}
		return success, nil

	default:
		logger.Warn("未知提供商", "provider", providerName)
		return false, fmt.Errorf("未知提供商: %s", providerName)
	}
}
