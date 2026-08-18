package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
	"github.com/spf13/cobra"
)

type doctorResult struct {
	// Name 是诊断项名称。
	Name string `json:"name"`
	// OK 表示诊断项是否通过。
	OK bool `json:"ok"`
	// Status 是适合 CLI 和脚本消费的状态文本。
	Status string `json:"status"`
	// Message 是诊断项的详细说明。
	Message string `json:"message"`
}

type doctorOptions struct {
	// provider 是需要额外执行真实连接测试的 provider 名称。
	provider string
	// json 表示是否输出机器可读的 JSON 结果。
	json bool
}

type doctorReport struct {
	// OK 表示全部诊断项是否通过。
	OK bool `json:"ok"`
	// Results 是完整诊断项列表。
	Results []doctorResult `json:"results"`
}

// CreateDoctorCmd 创建运行环境诊断命令。
func CreateDoctorCmd() *cobra.Command {
	options := &doctorOptions{}

	doctorCmd := &cobra.Command{
		Use:           "doctor",
		Short:         "诊断本机运行环境",
		Long:          "检查配置、端口、部署目录、Nginx/Apache 命令和 provider 配置",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Init()
			return runDoctor(options)
		},
	}

	doctorCmd.Flags().StringVar(&options.provider, "provider", "", "指定 provider 并执行连接测试")
	doctorCmd.Flags().BoolVar(&options.json, "json", false, "输出 JSON 格式诊断结果")
	return doctorCmd
}

// runDoctor 执行本机诊断流程。
func runDoctor(options *doctorOptions) error {
	results := make([]doctorResult, 0, 16)

	runtime, err := config.Load(ConfigFile)
	if err != nil {
		results = append(results, failDoctor("配置文件", fmt.Sprintf("初始化配置失败: %v", err)))
		writeDoctorResults(doctorFailureWriter(options), options, results)
		return err
	}

	cfg := runtime.Config
	results = append(results, okDoctor("配置文件", fmt.Sprintf("已加载 %s", ConfigFile)))
	results = append(results, checkAccessKey(cfg.Server.AccessKey))
	results = append(results, checkHTTPPort(cfg.Server.Port))
	results = append(results, checkDeployServerURL(runtime.ServerURL))
	results = append(results, checkDeployDir("Nginx 证书目录", cfg.SSL.NginxPath))
	results = append(results, checkDeployDir("Apache 证书目录", cfg.SSL.ApachePath))
	results = append(results, checkRustFSTarget(cfg.SSL.RustFS))
	results = append(results, checkCommand("Nginx 命令", "nginx", "-t"))
	results = append(results, checkApacheCommand())
	results = append(results, checkProviderConfigs(cfg)...)

	if options.provider != "" {
		results = append(results, checkProviderConnection(context.Background(), runtime, options.provider))
	}

	if hasDoctorFailure(results) {
		writeDoctorResults(doctorFailureWriter(options), options, results)
		return fmt.Errorf("诊断发现异常")
	}
	writeDoctorResults(os.Stdout, options, results)
	return nil
}

// checkRustFSTarget 区分 RustFS 本机目录和 SSH 远程目录，避免拿远端路径检查本机文件系统。
func checkRustFSTarget(rustFS *config.RustFSConfig) doctorResult {
	if rustFS == nil {
		return checkDeployDir("RustFS 证书目录", "")
	}
	if config.IsSSHConfigured(&rustFS.SSHConfig) {
		return okDoctor("RustFS 证书目录", "已配置 SSH 远程部署")
	}
	return checkDeployDir("RustFS 证书目录", rustFS.Path)
}

// okDoctor 创建成功诊断结果。
func okDoctor(name, message string) doctorResult {
	return doctorResult{Name: name, OK: true, Status: "PASS", Message: message}
}

// failDoctor 创建失败诊断结果。
func failDoctor(name, message string) doctorResult {
	return doctorResult{Name: name, OK: false, Status: "FAIL", Message: message}
}

// checkHTTPPort 检查本地 HTTP-01 端口是否可监听。
func checkHTTPPort(port int) doctorResult {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return failDoctor("HTTP-01 端口", fmt.Sprintf("%s 不可监听: %v", addr, err))
	}
	if err := listener.Close(); err != nil {
		return failDoctor("HTTP-01 端口", fmt.Sprintf("%s 关闭监听失败: %v", addr, err))
	}
	return okDoctor("HTTP-01 端口", fmt.Sprintf("%s 可监听", addr))
}

// checkAccessKey 检查服务端鉴权令牌是否明显可用。
func checkAccessKey(accessKey string) doctorResult {
	accessKey = strings.TrimSpace(accessKey)
	if accessKey == "" {
		return failDoctor("AccessKey", "未配置")
	}
	if isPlaceholderSecret(accessKey) {
		return failDoctor("AccessKey", "仍为模板占位值，请替换为真实 accessKey")
	}
	return okDoctor("AccessKey", maskSecret(accessKey))
}

// checkDeployServerURL 检查 deploy 服务地址格式和主机解析能力。
func checkDeployServerURL(serverURL string) doctorResult {
	parsedURL, err := url.Parse(serverURL)
	if err != nil {
		return failDoctor("Deploy 服务地址", fmt.Sprintf("URL 解析失败: %v", err))
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return failDoctor("Deploy 服务地址", fmt.Sprintf("不支持的协议: %s", parsedURL.Scheme))
	}

	host := parsedURL.Hostname()
	if host == "" {
		return failDoctor("Deploy 服务地址", "缺少主机名")
	}

	addresses, err := net.LookupHost(host)
	if err != nil {
		return failDoctor("Deploy 服务地址", fmt.Sprintf("%s 解析失败: %v", host, err))
	}
	return okDoctor("Deploy 服务地址", fmt.Sprintf("%s 可解析为 %s", host, strings.Join(addresses, ", ")))
}

// checkDeployDir 检查部署目录是否已可写，或父目录是否具备创建目标目录的权限。
func checkDeployDir(name, dir string) doctorResult {
	if dir == "" {
		return okDoctor(name, "未配置，跳过")
	}

	cleanDir := filepath.Clean(dir)
	info, err := os.Stat(cleanDir)
	if err == nil {
		if !info.IsDir() {
			return failDoctor(name, fmt.Sprintf("%s 不是目录", cleanDir))
		}
		return probeWritableDir(name, cleanDir)
	}
	if !os.IsNotExist(err) {
		return failDoctor(name, fmt.Sprintf("读取目录状态失败: %v", err))
	}

	parentDir, err := nearestExistingParent(cleanDir)
	if err != nil {
		return failDoctor(name, err.Error())
	}
	if result := probeWritableDir(name, parentDir); !result.OK {
		return failDoctor(name, fmt.Sprintf("目标目录尚未创建，且父目录不可写: %s", result.Message))
	}
	return okDoctor(name, fmt.Sprintf("%s 尚未创建，父目录 %s 可写", cleanDir, parentDir))
}

// probeWritableDir 通过临时探测文件检查目录写权限。
func probeWritableDir(name, dir string) doctorResult {
	probePath := filepath.Join(dir, ".anssl-doctor")
	if err := os.WriteFile(probePath, []byte(time.Now().Format(time.RFC3339)), 0600); err != nil {
		return failDoctor(name, fmt.Sprintf("目录不可写: %v", err))
	}
	if err := os.Remove(probePath); err != nil {
		return failDoctor(name, fmt.Sprintf("清理探测文件失败: %v", err))
	}
	return okDoctor(name, fmt.Sprintf("%s 可写", dir))
}

// nearestExistingParent 返回路径向上追溯后第一个存在且为目录的父目录。
func nearestExistingParent(path string) (string, error) {
	current := filepath.Clean(path)
	for {
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("找不到可用父目录: %s", path)
		}

		info, err := os.Stat(parent)
		if err == nil {
			if !info.IsDir() {
				return "", fmt.Errorf("父路径不是目录: %s", parent)
			}
			return parent, nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("读取父目录状态失败: %v", err)
		}
		current = parent
	}
}

// checkCommand 检查命令是否存在，并可选执行快速测试参数。
func checkCommand(name, command string, args ...string) doctorResult {
	path, err := exec.LookPath(command)
	if err != nil {
		return okDoctor(name, "未安装或不在 PATH 中，跳过")
	}

	if len(args) == 0 {
		return okDoctor(name, fmt.Sprintf("已找到 %s", path))
	}

	cmd := exec.Command(path, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return failDoctor(name, fmt.Sprintf("%s %s 失败: %v\n%s", command, strings.Join(args, " "), err, strings.TrimSpace(string(output))))
	}
	return okDoctor(name, fmt.Sprintf("%s %s 通过", command, strings.Join(args, " ")))
}

// checkApacheCommand 检查 Apache 控制命令和配置。
func checkApacheCommand() doctorResult {
	commands := []string{"apachectl", "apache2ctl", "httpd"}
	for _, command := range commands {
		if path, err := exec.LookPath(command); err == nil {
			cmd := exec.Command(path, "-t")
			output, err := cmd.CombinedOutput()
			if err != nil {
				return failDoctor("Apache 命令", fmt.Sprintf("%s -t 失败: %v\n%s", command, err, strings.TrimSpace(string(output))))
			}
			return okDoctor("Apache 命令", fmt.Sprintf("%s -t 通过", command))
		}
	}
	return okDoctor("Apache 命令", "未安装或不在 PATH 中，跳过")
}

// checkProviderConfigs 检查 provider 配置完整性，不主动发起外部 API 请求。
func checkProviderConfigs(cfg *config.Configuration) []doctorResult {
	if len(cfg.Provider) == 0 {
		return []doctorResult{okDoctor("Provider 配置", "未配置，跳过")}
	}

	results := make([]doctorResult, 0, len(cfg.Provider))
	for _, provider := range cfg.Provider {
		switch provider.Name {
		case "aliyun", "aliyunEsa":
			results = append(results, checkProviderFields("Provider "+provider.Name, map[string]string{
				"accessKeyId":     provider.GetAccessKeyId(),
				"accessKeySecret": provider.GetAccessKeySecret(),
			}))
		case "qiniu":
			results = append(results, checkProviderFields("Provider qiniu", map[string]string{
				"accessKey":    provider.GetAccessKey(),
				"accessSecret": provider.GetAccessSecret(),
			}))
		case "cloudTencent":
			results = append(results, checkProviderFields("Provider cloudTencent", map[string]string{
				"secretId":  provider.GetSecretId(),
				"secretKey": provider.GetSecretKey(),
			}))
		default:
			results = append(results, failDoctor("Provider "+provider.Name, "暂不支持的 provider 名称"))
		}
	}
	return results
}

// checkProviderFields 检查 provider 必填字段是否完整。
func checkProviderFields(name string, fields map[string]string) doctorResult {
	missing := make([]string, 0)
	for field, value := range fields {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, field)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return failDoctor(name, "缺少字段: "+strings.Join(missing, ", "))
	}
	return okDoctor(name, "配置完整")
}

// checkProviderConnection 执行指定 provider 的真实连接测试。
func checkProviderConnection(ctx context.Context, runtime *config.Runtime, provider string) doctorResult {
	success, err := client.TestProviderConnection(ctx, runtime, provider)
	if err != nil {
		return failDoctor("Provider 连接测试", err.Error())
	}
	if !success {
		return failDoctor("Provider 连接测试", provider+" 连接失败")
	}
	return okDoctor("Provider 连接测试", provider+" 连接成功")
}

// maskSecret 对敏感值脱敏展示。
func maskSecret(value string) string {
	if value == "" {
		return "未配置"
	}
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
}

// isPlaceholderSecret 判断敏感配置是否仍是模板占位值。
func isPlaceholderSecret(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(normalized, "your_") || strings.HasPrefix(normalized, "your-")
}

// doctorFailureWriter 返回失败诊断结果应写入的输出流。
func doctorFailureWriter(options *doctorOptions) io.Writer {
	if options != nil && options.json {
		return os.Stdout
	}
	return os.Stderr
}

// writeDoctorResults 按用户选择输出文本或 JSON 诊断结果。
func writeDoctorResults(writer io.Writer, options *doctorOptions, results []doctorResult) {
	if options != nil && options.json {
		writeDoctorJSONResults(writer, results)
		return
	}
	writeDoctorTextResults(writer, results)
}

// writeDoctorTextResults 输出文本诊断结果。
func writeDoctorTextResults(writer io.Writer, results []doctorResult) {
	for _, result := range results {
		fmt.Fprintf(writer, "[%s] %s: %s\n", result.Status, result.Name, result.Message)
	}
}

// writeDoctorJSONResults 输出 JSON 诊断结果。
func writeDoctorJSONResults(writer io.Writer, results []doctorResult) {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doctorReport{OK: !hasDoctorFailure(results), Results: results}); err != nil {
		fmt.Fprintf(writer, `{"ok":false,"results":[],"error":%q}`+"\n", err.Error())
	}
}

// hasDoctorFailure 判断诊断结果中是否存在失败项。
func hasDoctorFailure(results []doctorResult) bool {
	for _, result := range results {
		if !result.OK {
			return true
		}
	}
	return false
}
