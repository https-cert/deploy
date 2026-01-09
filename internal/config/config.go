package config

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/spf13/viper"
)

var (
	Config   *Configuration
	Version  = "v0.5.0"
	URL      = URLProd
	URLProd  = "https://anssl.cn/deploy"
	URLLocal = "http://localhost:9000/deploy"
)

// Configuration 应用配置结构
type Configuration struct {
	Server   *ServerConfig `yaml:"server"`
	SSL      *DeployConfig `yaml:"ssl"`
	Update   *UpdateConfig `yaml:"update"`
	Provider []*Provider   `yaml:"provider"`
}

type (
	ServerConfig struct {
		AccessKey string `yaml:"accessKey"`
		Env       string `yaml:"env"`
		Port      int    `yaml:"port"` // HTTP-01 challenge 服务端口，默认 19000
	}

	DeployConfig struct {
		NginxPath     string          `yaml:"nginxPath"`     // Nginx SSL 证书目录
		ApachePath    string          `yaml:"apachePath"`    // Apache SSL 证书目录
		RustFSPath    string          `yaml:"rustFSPath"`    // RustFS TLS 证书目录
		FeiNiuEnabled bool            `yaml:"feiNiuEnabled"` // 飞牛 TLS 证书部署开关
		OnePanel      *OnePanelConfig `yaml:"onePanel"`      // 1Panel 配置
	}

	// OnePanelConfig 1Panel 配置
	OnePanelConfig struct {
		URL    string `yaml:"url"`    // 1Panel API 地址
		APIKey string `yaml:"apiKey"` // 1Panel API 密钥
	}

	UpdateConfig struct {
		// 镜像源类型: github(默认), ghproxy, fastgit, custom
		Mirror string `yaml:"mirror"`
		// 自定义镜像地址（当 mirror=custom 时使用）
		CustomURL string `yaml:"customUrl"`
		// HTTP 代理地址
		Proxy string `yaml:"proxy"`
	}

	ProviderAuth struct {
		// 阿里云认证字段
		AccessKeyId     string `yaml:"accessKeyId,omitempty"`
		AccessKeySecret string `yaml:"accessKeySecret,omitempty"`
		// 腾讯云认证字段
		SecretId  string `yaml:"secretId,omitempty"`
		SecretKey string `yaml:"secretKey,omitempty"`
		// 七牛云认证字段
		AccessKey    string `yaml:"accessKey,omitempty"`
		AccessSecret string `yaml:"accessSecret,omitempty"`
	}

	Provider struct {
		Name   string        `yaml:"name"`
		Remark string        `yaml:"remark"`
		Auth   *ProviderAuth `yaml:"auth"`
	}
)

// Init 初始化配置
func Init(configFile string) error {
	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		return err
	}

	// 将配置绑定到结构体
	Config = &Configuration{}
	if err := viper.Unmarshal(Config); err != nil {
		return err
	}

	if err := validateConfig(); err != nil {
		return err
	}

	return nil
}

// validateConfig 验证配置
func validateConfig() error {
	// 检查 Server 配置是否存在
	if Config.Server == nil {
		return errors.New("server 配置不能为空")
	}

	if Config.Server.AccessKey == "" {
		return errors.New("accessKey不能为空")
	}

	// 设置 HTTP-01 challenge 服务端口默认值
	if Config.Server.Port == 0 {
		Config.Server.Port = 19000
	}

	// 处理 SSL 配置
	if Config.SSL == nil {
		Config.SSL = &DeployConfig{}
	}

	// 创建证书目录
	if Config.SSL.NginxPath != "" {
		if err := os.MkdirAll(Config.SSL.NginxPath, 0755); err != nil {
			return fmt.Errorf("创建Nginx证书目录失败: %w", err)
		}
	}
	if Config.SSL.ApachePath != "" {
		if err := os.MkdirAll(Config.SSL.ApachePath, 0755); err != nil {
			return fmt.Errorf("创建Apache证书目录失败: %w", err)
		}
	}
	if Config.SSL.RustFSPath != "" {
		if err := os.MkdirAll(Config.SSL.RustFSPath, 0755); err != nil {
			return fmt.Errorf("创建RustFS证书目录失败: %w", err)
		}
	}

	if Config.Server.Env == "local" {
		URL = URLLocal
	}

	// 验证更新配置
	if Config.Update == nil {
		Config.Update = &UpdateConfig{}
	}
	if Config.Update.Mirror != "" {
		validMirrors := []string{"github", "ghproxy", "ghproxy2", "custom"}
		isValid := slices.Contains(validMirrors, Config.Update.Mirror)
		if !isValid {
			return fmt.Errorf("不支持的镜像源类型: %s (支持: github, ghproxy, ghproxy2, custom)", Config.Update.Mirror)
		}

		// 如果使用自定义镜像，检查 customUrl 是否设置
		if Config.Update.Mirror == "custom" && Config.Update.CustomURL == "" {
			return errors.New("使用 custom 镜像源时，customUrl 不能为空")
		}
	} else {
		Config.Update.Mirror = "ghproxy"
	}

	return nil
}

// GetConfig 获取配置
func GetConfig() *Configuration {
	return Config
}

// GetProvider 获取提供商配置
func GetProvider(name string) *Provider {
	for _, p := range Config.Provider {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// Provider Getter 方法
// 提供便捷访问 Auth 嵌套字段的方法

// GetAccessKeyId 获取阿里云 AccessKeyId
func (p *Provider) GetAccessKeyId() string {
	if p.Auth != nil {
		return p.Auth.AccessKeyId
	}
	return ""
}

// GetAccessKeySecret 获取阿里云 AccessKeySecret
func (p *Provider) GetAccessKeySecret() string {
	if p.Auth != nil {
		return p.Auth.AccessKeySecret
	}
	return ""
}

// GetSecretId 获取腾讯云 SecretId
func (p *Provider) GetSecretId() string {
	if p.Auth != nil {
		return p.Auth.SecretId
	}
	return ""
}

// GetSecretKey 获取腾讯云 SecretKey
func (p *Provider) GetSecretKey() string {
	if p.Auth != nil {
		return p.Auth.SecretKey
	}
	return ""
}

// GetAccessKey 获取七牛云 AccessKey
func (p *Provider) GetAccessKey() string {
	if p.Auth != nil {
		return p.Auth.AccessKey
	}
	return ""
}

// GetAccessSecret 获取七牛云 AccessSecret
func (p *Provider) GetAccessSecret() string {
	if p.Auth != nil {
		return p.Auth.AccessSecret
	}
	return ""
}
