package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/viper"
)

var (
	Config   *Configuration
	Version  = "v0.1.0"
	URL      = URLProd
	URLProd  = "https://anssl.cn/deploy"
	URLLocal = "http://localhost:9000/deploy"
)

// Configuration 应用配置结构
type Configuration struct {
	Server ServerConfig `yaml:"server"`
	SSL    SSLConfig    `yaml:"ssl"`
	Update UpdateConfig `yaml:"update"`
}

type (
	ServerConfig struct {
		AccessKey string `yaml:"accessKey"`
		Env       string `yaml:"env"`
	}

	SSLConfig struct {
		Path string `yaml:"path"`
	}

	UpdateConfig struct {
		// 镜像源类型: github(默认), ghproxy, fastgit, custom
		Mirror string `yaml:"mirror"`
		// 自定义镜像地址（当 mirror=custom 时使用）
		CustomURL string `yaml:"customUrl"`
		// HTTP 代理地址
		Proxy string `yaml:"proxy"`
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
	if Config.Server.AccessKey == "" {
		return errors.New("accessKey不能为空")
	}

	if Config.SSL.Path != "" {
		// 检查证书存储目录是否存在，不存在则创建
		if err := os.MkdirAll(Config.SSL.Path, 0755); err != nil {
			return fmt.Errorf("创建证书存储目录失败: %w", err)
		}
	}

	if Config.Server.Env == "local" {
		URL = URLLocal
	}

	return nil
}

// GetConfig 获取配置
func GetConfig() *Configuration {
	return Config
}
