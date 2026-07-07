package config

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/viper"
)

var (
	Config   *Configuration
	URL      = URLProd
	URLProd  = "https://anssl.cn/deploy"
	URLLocal = "http://localhost:9000/deploy"
)

const (
	defaultHTTPChallengePort = 19000
	minPort                  = 1
	maxPort                  = 65535
	envLocal                 = "local"
	defaultUpdateMirror      = "ghproxy"
)

// Configuration 应用配置结构
type Configuration struct {
	Server   *ServerConfig `yaml:"server"`   // Server 服务端连接和本地 HTTP-01 配置
	SSL      *DeployConfig `yaml:"ssl"`      // SSL 本地部署目标配置
	Update   *UpdateConfig `yaml:"update"`   // Update 自更新配置
	Provider []*Provider   `yaml:"provider"` // Provider 云服务提供商配置
}

type (
	// ServerConfig 服务端连接和本地 HTTP-01 challenge 配置
	ServerConfig struct {
		AccessKey string `yaml:"accessKey"` // AccessKey 后端鉴权令牌
		Env       string `yaml:"env"`       // Env 服务环境，空值为生产环境，local 为本地开发环境
		Port      int    `yaml:"port"`      // Port HTTP-01 challenge 服务端口，默认 19000
	}

	// DeployConfig 本地证书部署目标配置
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

	// UpdateConfig 自更新下载源和代理配置
	UpdateConfig struct {
		// 镜像源类型: github, ghproxy, ghproxy2, custom
		Mirror string `yaml:"mirror"`
		// 自定义镜像地址（当 mirror=custom 时使用）
		CustomURL string `yaml:"customUrl"`
		// HTTP 代理地址
		Proxy string `yaml:"proxy"`
	}

	// ProviderAuth 云服务提供商认证字段集合
	ProviderAuth struct {
		// 阿里云认证字段
		AccessKeyId     string `yaml:"accessKeyId,omitempty"`
		AccessKeySecret string `yaml:"accessKeySecret,omitempty"`
		ESASiteID       string `yaml:"esaSiteId,omitempty"`
		// 腾讯云认证字段
		SecretId  string `yaml:"secretId,omitempty"`
		SecretKey string `yaml:"secretKey,omitempty"`
		// 七牛云认证字段
		AccessKey    string `yaml:"accessKey,omitempty"`
		AccessSecret string `yaml:"accessSecret,omitempty"`
	}

	// Provider 云服务提供商配置
	Provider struct {
		Name   string        `yaml:"name"`   // Name 提供商内部名称
		Remark string        `yaml:"remark"` // Remark 提供商展示备注
		Auth   *ProviderAuth `yaml:"auth"`   // Auth 提供商认证配置
	}
)

// Init 初始化配置
func Init(configFile string) error {
	viper.Reset()
	URL = URLProd

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
		Config.Server.Port = defaultHTTPChallengePort
	}
	if Config.Server.Port < minPort || Config.Server.Port > maxPort {
		return fmt.Errorf("server.port 必须在 %d-%d 之间", minPort, maxPort)
	}

	// 处理 SSL 配置
	if Config.SSL == nil {
		Config.SSL = &DeployConfig{}
	}

	if Config.Server.Env != "" && Config.Server.Env != envLocal {
		return fmt.Errorf("不支持的服务环境: %s (支持: 空值, local)", Config.Server.Env)
	}
	if Config.Server.Env == envLocal {
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
		Config.Update.Mirror = defaultUpdateMirror
	}

	if err := validateProviders(); err != nil {
		return err
	}

	return nil
}

// PrepareRuntimeDirs 创建启动和部署需要的本地目录
func PrepareRuntimeDirs() error {
	if Config == nil {
		return errors.New("配置未初始化")
	}
	if Config.SSL == nil {
		return nil
	}

	if err := prepareDir("Nginx", Config.SSL.NginxPath); err != nil {
		return err
	}
	if err := prepareDir("Apache", Config.SSL.ApachePath); err != nil {
		return err
	}
	if err := prepareDir("RustFS", Config.SSL.RustFSPath); err != nil {
		return err
	}

	return nil
}

// prepareDir 创建单个运行期目录
func prepareDir(name, path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("创建%s证书目录失败: %w", name, err)
	}
	return nil
}

// validateProviders 验证 provider 列表中不包含空名称或重复名称
func validateProviders() error {
	providerNames := make(map[string]struct{}, len(Config.Provider))
	for _, provider := range Config.Provider {
		if provider == nil {
			return errors.New("provider 配置不能为空")
		}

		name := strings.TrimSpace(provider.Name)
		if name == "" {
			return errors.New("provider.name 不能为空")
		}

		if _, exists := providerNames[name]; exists {
			return fmt.Errorf("provider.name 不能重复: %s", name)
		}
		providerNames[name] = struct{}{}
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

// GetESASiteID 获取阿里云 ESA SiteId
func (p *Provider) GetESASiteID() string {
	if p.Auth != nil {
		return p.Auth.ESASiteID
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
