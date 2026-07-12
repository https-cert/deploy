package cmd

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"
)

var (
	ConfigFile string
)

const (
	localDefaultConfigFile     = "config.yaml"
	installedDefaultConfigFile = "/opt/anssl/config.yaml"
)

// CreateRootCmd 创建根命令
func CreateRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "anssl",
		Short: "证书自动部署工具",
		Long:  "一个用于自动部署证书并重载nginx的工具",
	}

	// 添加子命令
	rootCmd.AddCommand(CreateDaemonCmd())
	rootCmd.AddCommand(createSupervisorCmd())
	rootCmd.AddCommand(CreateStartCmd())
	rootCmd.AddCommand(CreateStopCmd())
	rootCmd.AddCommand(CreateStatusCmd())
	rootCmd.AddCommand(CreateRestartCmd())
	rootCmd.AddCommand(CreateLogCmd())
	rootCmd.AddCommand(CreateDoctorCmd())
	rootCmd.AddCommand(CreateCheckUpdateCmd())
	rootCmd.AddCommand(CreateUpdateCmd())
	rootCmd.AddCommand(CreateRollbackCmd())
	rootCmd.AddCommand(CreateVersionCmd())

	// 全局标志
	rootCmd.PersistentFlags().StringVarP(&ConfigFile, "config", "c", defaultConfigFile(), "配置文件路径")

	return rootCmd
}

// 辅助函数

// defaultConfigFile 返回默认配置文件路径，本地开发配置优先于安装目录配置。
func defaultConfigFile() string {
	if _, err := os.Stat(localDefaultConfigFile); err == nil {
		return localDefaultConfigFile
	}
	if _, err := os.Stat(installedDefaultConfigFile); err == nil {
		return installedDefaultConfigFile
	}
	return localDefaultConfigFile
}

// GetPIDFile 获取PID文件路径
func GetPIDFile() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// 如果无法获取用户主目录，使用当前目录
		homeDir = "."
	}
	return filepath.Join(homeDir, ".anssl.pid")
}

// GetLogFile 获取日志文件路径（与配置文件同一目录）
func GetLogFile() string {
	configDir := filepath.Dir(ConfigFile)
	return filepath.Join(configDir, "anssl.log")
}

// IsRunning 检查守护进程是否在运行
func IsRunning() bool {
	pidFile := GetPIDFile()
	record, err := readPIDRecord(pidFile)
	if err != nil {
		return false
	}
	return supervisorProcessMatches(record)
}

// GetPID 获取守护进程PID
func GetPID() string {
	pidFile := GetPIDFile()
	record, err := readPIDRecord(pidFile)
	if err != nil {
		return "unknown"
	}
	return strconv.Itoa(record.PID)
}
