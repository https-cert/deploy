package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/spf13/viper"
)

var (
	Config           *Configuration
	URL              = URLProd
	URLProd          = "https://anssl.cn/deploy"
	URLLocal         = "http://localhost:9000/deploy"
	loadedConfigFile string
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
	Log      *LogConfig    `yaml:"log"`      // Log 日志轮转配置
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
		NginxPath  string          `yaml:"nginxPath"`  // NginxPath 是 Nginx SSL 证书目录
		ApachePath string          `yaml:"apachePath"` // ApachePath 是 Apache SSL 证书目录
		RustFSPath string          `yaml:"rustFSPath"` // RustFSPath 兼容旧版 RustFS 本机目录配置
		RustFS     *RustFSConfig   `yaml:"rustFS"`     // RustFS 是本机或 SSH 远程部署配置
		FeiNiu     *SSHConfig      `yaml:"feiNiu"`     // FeiNiu 是可选的 SSH 远程配置，空值表示本机部署
		OnePanel   *OnePanelConfig `yaml:"onePanel"`   // OnePanel 是 1Panel API 配置
		SafeLine   *SafeLineConfig `yaml:"safeLine"`   // SafeLine 是雷池 WAF OpenAPI 配置
	}

	// SSHConfig 保存仅供 deploy 客户端本地使用的 SSH 认证配置。
	SSHConfig struct {
		Host                 string `yaml:"host"`                 // Host 是远程主机名或 IP 地址
		Port                 int    `yaml:"port"`                 // Port 是 SSH 端口，默认 22
		Username             string `yaml:"username"`             // Username 是 SSH 登录用户名
		Password             string `yaml:"password"`             // Password 是密码认证及 sudo 使用的密码
		PrivateKeyPath       string `yaml:"privateKeyPath"`       // PrivateKeyPath 是 deploy 客户端本地私钥绝对路径
		PrivateKeyPassphrase string `yaml:"privateKeyPassphrase"` // PrivateKeyPassphrase 是加密私钥的可选口令
	}

	// FeiNiuSSHConfig 兼容已有飞牛 SSH 配置类型名称。
	FeiNiuSSHConfig = SSHConfig

	// RustFSConfig 保存 RustFS 证书目录及可选的 SSH 远程配置。
	RustFSConfig struct {
		Path      string                                  `yaml:"path"` // Path 是 RustFS TLS 证书根目录
		SSHConfig `yaml:",inline" mapstructure:",squash"` // SSHConfig 是可选的 SSH 远程连接配置
	}

	// OnePanelConfig 1Panel 配置
	OnePanelConfig struct {
		URL    string `yaml:"url"`    // 1Panel API 地址
		APIKey string `yaml:"apiKey"` // 1Panel API 密钥
	}

	// SafeLineConfig 雷池 WAF OpenAPI 配置。
	SafeLineConfig struct {
		URL                string `yaml:"url"`                // URL 是雷池管理端地址
		APIToken           string `yaml:"apiToken"`           // APIToken 是通用设置中生成的 API Token
		InsecureSkipVerify bool   `yaml:"insecureSkipVerify"` // InsecureSkipVerify 仅用于显式信任自签名 HTTPS 证书
	}

	// UpdateConfig 自更新下载源和代理配置
	UpdateConfig struct {
		// 镜像源类型: github, ghproxy, custom
		Mirror string `yaml:"mirror"`
		// 自定义镜像地址（当 mirror=custom 时使用）
		CustomURL string `yaml:"customUrl"`
		// HTTP 代理地址
		Proxy string `yaml:"proxy"`
	}

	// LogConfig 日志轮转配置
	LogConfig struct {
		MaxSizeMB  int `yaml:"maxSizeMB"`  // MaxSizeMB 单个日志文件最大体积，单位 MB
		MaxBackups int `yaml:"maxBackups"` // MaxBackups 最多保留的轮转文件数量
		MaxAgeDays int `yaml:"maxAgeDays"` // MaxAgeDays 轮转文件最长保留天数
	}

	// ProviderAuth 云服务提供商认证字段集合
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
	loadedConfigFile = configFile
	if absoluteConfigFile, err := filepath.Abs(configFile); err == nil {
		loadedConfigFile = absoluteConfigFile
	}

	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		return err
	}
	if err := validateRemovedDeploymentResourceFields(viper.AllSettings()["provider"]); err != nil {
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
	if err := validateRustFSConfig(); err != nil {
		return err
	}
	if err := validateFeiNiuConfig(); err != nil {
		return err
	}
	if err := validateSafeLineConfig(); err != nil {
		return err
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
		validMirrors := []string{"github", "ghproxy", "custom"}
		isValid := slices.Contains(validMirrors, Config.Update.Mirror)
		if !isValid {
			return fmt.Errorf("不支持的镜像源类型: %s (支持: github, ghproxy, custom)", Config.Update.Mirror)
		}

		// 如果使用自定义镜像，检查 customUrl 是否设置
		if Config.Update.Mirror == "custom" && Config.Update.CustomURL == "" {
			return errors.New("使用 custom 镜像源时，customUrl 不能为空")
		}
		if Config.Update.Mirror == "custom" {
			if err := validateUpdateURL("update.customUrl", Config.Update.CustomURL, false); err != nil {
				return err
			}
		}
	} else {
		Config.Update.Mirror = defaultUpdateMirror
	}
	if Config.Update.Proxy != "" {
		if err := validateProxyURL(Config.Update.Proxy); err != nil {
			return err
		}
	}

	if err := validateProviders(); err != nil {
		return err
	}
	applyLogDefaults()
	if err := validateLogConfig(); err != nil {
		return err
	}

	return nil
}

// validateFeiNiuConfig 验证可选的飞牛 OS SSH 远程部署配置。
func validateFeiNiuConfig() error {
	if Config.SSL.FeiNiu == nil {
		return nil
	}
	return validateSSHConfig("ssl.feiNiu", Config.SSL.FeiNiu)
}

// validateSafeLineConfig 验证可选的雷池地址和 API Token，并规范化管理端地址。
func validateSafeLineConfig() error {
	if Config.SSL.SafeLine == nil {
		return nil
	}

	safeLine := Config.SSL.SafeLine
	safeLine.URL = strings.TrimRight(strings.TrimSpace(safeLine.URL), "/")
	safeLine.APIToken = strings.TrimSpace(safeLine.APIToken)
	if safeLine.URL == "" && safeLine.APIToken == "" {
		if safeLine.InsecureSkipVerify {
			return errors.New("ssl.safeLine.insecureSkipVerify 只能在配置雷池地址和 API Token 后启用")
		}
		return nil
	}
	if safeLine.URL == "" {
		return errors.New("ssl.safeLine.url 不能为空")
	}
	if safeLine.APIToken == "" {
		return errors.New("ssl.safeLine.apiToken 不能为空")
	}
	if strings.ContainsAny(safeLine.APIToken, "\r\n\x00") {
		return errors.New("ssl.safeLine.apiToken 不能包含换行或 NUL 字符")
	}

	parsedURL, err := url.Parse(safeLine.URL)
	if err != nil || parsedURL.Hostname() == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return errors.New("ssl.safeLine.url 必须是合法的 HTTP 或 HTTPS 地址")
	}
	if parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return errors.New("ssl.safeLine.url 不能包含用户凭据、查询参数或片段")
	}
	if safeLine.InsecureSkipVerify && parsedURL.Scheme != "https" {
		return errors.New("ssl.safeLine.insecureSkipVerify 仅适用于 HTTPS 地址")
	}
	return nil
}

// validateRustFSConfig 归一化 RustFS 新旧配置并验证本机或 SSH 远程模式。
func validateRustFSConfig() error {
	legacyPath := strings.TrimSpace(Config.SSL.RustFSPath)
	if Config.SSL.RustFS == nil {
		if legacyPath == "" {
			return nil
		}
		Config.SSL.RustFS = &RustFSConfig{Path: legacyPath}
		Config.SSL.RustFSPath = ""
		return validateRustFSPath(Config.SSL.RustFS.Path)
	}

	rustFS := Config.SSL.RustFS
	rustFS.Path = strings.TrimSpace(rustFS.Path)
	if legacyPath != "" && rustFS.Path != "" && legacyPath != rustFS.Path {
		return errors.New("ssl.rustFS.path 与旧版 ssl.rustFSPath 不能同时配置为不同目录")
	}
	if rustFS.Path == "" {
		rustFS.Path = legacyPath
	}
	Config.SSL.RustFSPath = ""
	if rustFS.Path == "" {
		return errors.New("ssl.rustFS.path 不能为空")
	}
	if err := validateRustFSPath(rustFS.Path); err != nil {
		return err
	}
	if !IsSSHConfigured(&rustFS.SSHConfig) {
		return nil
	}
	return validateSSHConfig("ssl.rustFS", &rustFS.SSHConfig)
}

// validateRustFSPath 验证 RustFS 证书根目录是安全的 POSIX 绝对路径。
func validateRustFSPath(rustFSPath string) error {
	if !path.IsAbs(rustFSPath) || path.Clean(rustFSPath) != rustFSPath || rustFSPath == "/" {
		return errors.New("ssl.rustFS.path 必须是非根目录的规范 POSIX 绝对路径")
	}
	if strings.ContainsAny(rustFSPath, "\r\n\x00") {
		return errors.New("ssl.rustFS.path 不能包含换行或 NUL 字符")
	}
	return nil
}

// IsSSHConfigured 判断除默认端口外是否已经填写任一 SSH 字段。
func IsSSHConfigured(sshConfig *SSHConfig) bool {
	if sshConfig == nil {
		return false
	}
	return strings.TrimSpace(sshConfig.Host) != "" ||
		strings.TrimSpace(sshConfig.Username) != "" ||
		sshConfig.Password != "" ||
		strings.TrimSpace(sshConfig.PrivateKeyPath) != "" ||
		sshConfig.PrivateKeyPassphrase != "" ||
		(sshConfig.Port != 0 && sshConfig.Port != 22)
}

// validateSSHConfig 验证密码或私钥认证共用的 SSH 连接字段。
func validateSSHConfig(section string, sshConfig *SSHConfig) error {
	sshConfig.Host = strings.TrimSpace(sshConfig.Host)
	if strings.HasPrefix(sshConfig.Host, "[") && strings.HasSuffix(sshConfig.Host, "]") {
		sshConfig.Host = strings.TrimSuffix(strings.TrimPrefix(sshConfig.Host, "["), "]")
	}
	sshConfig.Username = strings.TrimSpace(sshConfig.Username)
	sshConfig.PrivateKeyPath = strings.TrimSpace(sshConfig.PrivateKeyPath)
	if sshConfig.Port == 0 {
		sshConfig.Port = 22
	}
	if sshConfig.Host == "" {
		return fmt.Errorf("%s.host 不能为空", section)
	}
	if strings.Contains(sshConfig.Host, "://") || strings.ContainsAny(sshConfig.Host, "/?#@") || containsSpaceOrControl(sshConfig.Host) {
		return fmt.Errorf("%s.host 必须是主机名或 IP 地址，不能包含协议、路径或空白字符", section)
	}
	if strings.Contains(sshConfig.Host, ":") && net.ParseIP(sshConfig.Host) == nil {
		return fmt.Errorf("%s.host 不能包含端口，端口请单独填写到 %s.port", section, section)
	}
	if sshConfig.Port < minPort || sshConfig.Port > maxPort {
		return fmt.Errorf("%s.port 必须在 %d-%d 之间", section, minPort, maxPort)
	}
	if sshConfig.Username == "" || containsSpaceOrControl(sshConfig.Username) {
		return fmt.Errorf("%s.username 不能为空且不能包含空白或控制字符", section)
	}
	if sshConfig.Password == "" && sshConfig.PrivateKeyPath == "" {
		return fmt.Errorf("%s.password 或 %s.privateKeyPath 必须填写一项", section, section)
	}
	if strings.ContainsAny(sshConfig.Password, "\r\n\x00") {
		return fmt.Errorf("%s.password 不能包含换行或 NUL 字符", section)
	}
	if sshConfig.PrivateKeyPath != "" {
		if !filepath.IsAbs(sshConfig.PrivateKeyPath) || filepath.Clean(sshConfig.PrivateKeyPath) != sshConfig.PrivateKeyPath {
			return fmt.Errorf("%s.privateKeyPath 必须是 deploy 客户端本地的规范绝对路径", section)
		}
		if strings.ContainsAny(sshConfig.PrivateKeyPath, "\r\n\x00") {
			return fmt.Errorf("%s.privateKeyPath 不能包含换行或 NUL 字符", section)
		}
	} else if sshConfig.PrivateKeyPassphrase != "" {
		return fmt.Errorf("%s.privateKeyPassphrase 只能与 privateKeyPath 一起配置", section)
	}
	if strings.ContainsAny(sshConfig.PrivateKeyPassphrase, "\r\n\x00") {
		return fmt.Errorf("%s.privateKeyPassphrase 不能包含换行或 NUL 字符", section)
	}
	return nil
}

// containsSpaceOrControl 判断 SSH 标识字段是否含不可接受的空白或控制字符。
func containsSpaceOrControl(value string) bool {
	return strings.IndexFunc(value, func(character rune) bool {
		return unicode.IsSpace(character) || unicode.IsControl(character)
	}) >= 0
}

// validateUpdateURL validates an update mirror URL and permits local HTTP only in local mode.
func validateUpdateURL(name, rawURL string, allowPath bool) error {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Hostname() == "" || parsed.User != nil {
		return fmt.Errorf("%s 必须是包含主机名且不含用户凭据的合法 URL", name)
	}
	if !allowPath && parsed.RawQuery != "" {
		return fmt.Errorf("%s 不能包含查询参数", name)
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && Config.Server.Env == envLocal && isLoopbackHostname(parsed.Hostname()) {
		return nil
	}
	return fmt.Errorf("%s 只允许 HTTPS，本地环境可使用回环 HTTP", name)
}

// validateProxyURL validates supported HTTP and SOCKS proxy URL forms.
func validateProxyURL(rawURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Hostname() == "" {
		return errors.New("update.proxy 必须是包含主机名的合法 URL")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "socks5", "socks5h":
		return nil
	default:
		return fmt.Errorf("update.proxy 不支持协议: %s", parsed.Scheme)
	}
}

// isLoopbackHostname reports whether a hostname resolves syntactically to a loopback address.
func isLoopbackHostname(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// applyLogDefaults 设置日志轮转默认值。
func applyLogDefaults() {
	if Config.Log == nil {
		Config.Log = &LogConfig{}
	}
	if Config.Log.MaxSizeMB == 0 {
		Config.Log.MaxSizeMB = 20
	}
	if Config.Log.MaxBackups == 0 {
		Config.Log.MaxBackups = 5
	}
	if Config.Log.MaxAgeDays == 0 {
		Config.Log.MaxAgeDays = 30
	}
}

// validateLogConfig 验证日志轮转配置。
func validateLogConfig() error {
	if Config.Log.MaxSizeMB < 0 {
		return errors.New("log.maxSizeMB 不能小于 0")
	}
	if Config.Log.MaxBackups < 0 {
		return errors.New("log.maxBackups 不能小于 0")
	}
	if Config.Log.MaxAgeDays < 0 {
		return errors.New("log.maxAgeDays 不能小于 0")
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
	if Config.SSL.RustFS != nil && !IsSSHConfigured(&Config.SSL.RustFS.SSHConfig) {
		if err := prepareDir("RustFS", Config.SSL.RustFS.Path); err != nil {
			return err
		}
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

		provider.Name = name
		if err := validateProviderCredentials(provider); err != nil {
			return err
		}
	}
	return nil
}

// GetConfig 获取配置
func GetConfig() *Configuration {
	return Config
}

// GetSSHKnownHostsFile 返回与当前配置文件同目录的 SSH 主机密钥记录文件。
func GetSSHKnownHostsFile() string {
	if loadedConfigFile == "" {
		return "known_hosts"
	}
	return filepath.Join(filepath.Dir(loadedConfigFile), "known_hosts")
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
