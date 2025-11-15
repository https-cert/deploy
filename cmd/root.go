package cmd

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

var (
	ConfigFile string
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
	rootCmd.AddCommand(CreateCheckUpdateCmd())
	rootCmd.AddCommand(CreateUpdateCmd())

	// 全局标志
	rootCmd.PersistentFlags().StringVarP(&ConfigFile, "config", "c", "config.yaml", "配置文件路径")

	return rootCmd
}

// 辅助函数

// GetPIDFile 获取PID文件路径
func GetPIDFile() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// 如果无法获取用户主目录，使用当前目录
		homeDir = "."
	}
	return filepath.Join(homeDir, ".cert-deploy.pid")
}

// GetLogFile 获取日志文件路径（与配置文件同一目录）
func GetLogFile() string {
	configDir := filepath.Dir(ConfigFile)
	return filepath.Join(configDir, "cert-deploy.log")
}

// IsRunning 检查守护进程是否在运行
func IsRunning() bool {
	pidFile := GetPIDFile()
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return false
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// GetPID 获取守护进程PID
func GetPID() string {
	pidFile := GetPIDFile()
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}
