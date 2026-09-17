package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxReportedLogMessageBytes = 8 << 10
	minSensitiveValueBytes     = 8
)

var (
	pemBlockPattern            = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9][A-Z0-9 -]{0,64}-----.*?-----END [A-Z0-9][A-Z0-9 -]{0,64}-----`)
	authSchemePattern          = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+`)
	sensitiveAssignmentPattern = regexp.MustCompile(`(?i)(["']?[a-z0-9_-]*(?:access[_-]?key|api[_-]?key|secret|token|password|passwd|passphrase|authorization|credential|signature|private[_-]?key|cookie|username)[a-z0-9_-]*["']?\s*(?::|=)\s*)(?:"[^"]*"|'[^']*'|[^\s,;&]+)`)
	ipv4AddressPattern         = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6CandidatePattern       = regexp.MustCompile(`\[[0-9A-Fa-f:.]+\]|[0-9A-Fa-f]*:[0-9A-Fa-f:.]+`)
	sensitiveValuesMu          sync.RWMutex
	sensitiveValues            []string
)

// LogLevel 日志级别
type LogLevel string

const (
	LevelDebug LogLevel = "DEBUG"
	LevelInfo  LogLevel = "INFO"
	LevelWarn  LogLevel = "WARN"
	LevelError LogLevel = "ERROR"
	LevelFatal LogLevel = "FATAL"
)

// LogReporter 日志上报器（用于上报到服务端）
type LogReporter struct {
	ServerURL string // ServerURL 是日志服务基础地址。
	ClientID  string // ClientID 标识当前部署客户端。
	AccessKey string // AccessKey 用于日志接口认证。

	mu           sync.Mutex // mu 串行化异步请求的失败统计和本机告警。
	failureSince time.Time  // failureSince 记录本轮连续失败的开始时间。
	failures     uint64     // failures 统计本轮恢复前失败的上报请求数。
}

var (
	Logger     *log.Logger
	reporter   *LogReporter
	reporterMu sync.RWMutex // reporterMu 保护上报器替换和异步任务快照读取。
)

// Init 初始化日志
func Init() {
	Logger = log.New(os.Stdout, "", log.LstdFlags)
}

// SetReporter 设置日志上报器
func SetReporter(r *LogReporter) {
	reporterMu.Lock()
	defer reporterMu.Unlock()
	reporter = nil
	if r != nil {
		// 配置切换后独立统计故障；在途请求继续使用原上报器的配置和状态。
		reporter = &LogReporter{ServerURL: r.ServerURL, ClientID: r.ClientID, AccessKey: r.AccessKey}
	}
}

// SetSensitiveValues 设置在线日志必须额外清除的实际配置值，防止第三方 SDK 无字段名回显凭据。
func SetSensitiveValues(values ...string) {
	uniqueValues := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if len(value) < minSensitiveValueBytes {
			continue
		}
		uniqueValues[value] = struct{}{}
	}

	nextValues := make([]string, 0, len(uniqueValues))
	for value := range uniqueValues {
		nextValues = append(nextValues, value)
	}
	sort.Slice(nextValues, func(i, j int) bool {
		if len(nextValues[i]) == len(nextValues[j]) {
			return nextValues[i] < nextValues[j]
		}
		return len(nextValues[i]) > len(nextValues[j])
	})

	sensitiveValuesMu.Lock()
	sensitiveValues = nextValues
	sensitiveValuesMu.Unlock()
}

// configuredSensitiveValues 返回当前在线日志脱敏使用的不可变配置值快照。
func configuredSensitiveValues() []string {
	sensitiveValuesMu.RLock()
	defer sensitiveValuesMu.RUnlock()
	return append([]string(nil), sensitiveValues...)
}

// formatKeyValues 格式化键值对参数
func formatKeyValues(args ...any) string {
	if len(args) == 0 {
		return ""
	}

	var parts []string
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			key := fmt.Sprintf("%v", args[i])
			value := fmt.Sprintf("%v", args[i+1])
			parts = append(parts, fmt.Sprintf("%s=%s", key, value))
		} else {
			// 奇数个参数，最后一个单独处理
			parts = append(parts, fmt.Sprintf("%v", args[i]))
		}
	}

	if len(parts) > 0 {
		return " " + strings.Join(parts, " ")
	}
	return ""
}

// sanitizeLogMessage 在在线上报前移除凭据和证书材料，同时保留云 API 状态码、错误码和请求编号。
func sanitizeLogMessage(message string) string {
	sanitized := pemBlockPattern.ReplaceAllString(message, "[已脱敏 PEM 内容]")
	sanitized = authSchemePattern.ReplaceAllString(sanitized, "$1 [已脱敏]")
	sanitized = sensitiveAssignmentPattern.ReplaceAllString(sanitized, "$1[已脱敏]")
	for _, value := range configuredSensitiveValues() {
		sanitized = strings.ReplaceAll(sanitized, value, "[已脱敏]")
	}
	sanitized = ipv4AddressPattern.ReplaceAllString(sanitized, "[已脱敏 IP]")
	sanitized = ipv6CandidatePattern.ReplaceAllStringFunc(sanitized, func(candidate string) string {
		address := strings.Trim(candidate, "[]")
		if net.ParseIP(address) != nil {
			return "[已脱敏 IP]"
		}
		return candidate
	})
	if len(sanitized) <= maxReportedLogMessageBytes {
		return sanitized
	}

	// 按 rune 截断，避免在多字节中文字符中间截断后生成无效 UTF-8。
	var builder strings.Builder
	for _, char := range sanitized {
		if builder.Len()+len(string(char)) > maxReportedLogMessageBytes {
			break
		}
		builder.WriteRune(char)
	}
	return builder.String()
}

// reportLog 上报日志到服务端
func reportLog(level LogLevel, message string, timestamp int64) {
	reporterMu.RLock()
	r := reporter
	reporterMu.RUnlock()
	if r == nil {
		return
	}

	// 在线日志统一在 deploy 端脱敏；本机 logger 仍保留完整诊断。
	message = sanitizeLogMessage(message)

	go r.report(level, message, timestamp)
}

// report 执行一次日志上报，失败诊断只写本机，避免再次触发上报。
func (r *LogReporter) report(level LogLevel, message string, timestamp int64) {
	// 后端日志存储按毫秒时间戳过滤；微秒会被当成未来时间而丢弃。
	if timestamp > 1e15 {
		timestamp /= 1000
	}
	payload := map[string]any{
		"type":      "deploy",
		"clientId":  r.ClientID,
		"level":     level,
		"message":   message,
		"timestamp": timestamp,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return
	}

	url := r.ServerURL + "/api/logs"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		r.logReportResult(0, err, time.Now())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Access-Key", r.AccessKey)

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		r.logReportResult(0, err, time.Now())
		return
	}
	defer resp.Body.Close()
	r.logReportResult(resp.StatusCode, nil, time.Now())
	// 消费常见的小响应以复用连接；不输出 HTML 或其他未经筛选的响应正文。
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
}

// logReportResult 每轮连续失败只告警一次，实际上报成功后记录恢复并重置状态。
func (r *LogReporter) logReportResult(status int, err error, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if Logger == nil {
		return
	}
	if err == nil && status >= 200 && status < 300 {
		if r.failures > 0 {
			Logger.Printf("[INFO] 在线日志上报已恢复 failures=%d duration=%s", r.failures, now.Sub(r.failureSince).Round(time.Second))
			r.failures = 0
			r.failureSince = time.Time{}
		}
		return
	}

	r.failures++
	if r.failures > 1 {
		return
	}
	r.failureSince = now
	detail := fmt.Sprintf("status=%d reason=%q", status, http.StatusText(status))
	if err != nil {
		// 引号转义保留错误信息，同时确保网络错误中的换行不会破坏日志行。
		detail = fmt.Sprintf("error=%q", err.Error())
	}
	Logger.Printf("[WARN] 在线日志上报失败 %s", detail)
}

// Debug 记录调试日志
func Debug(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	ts := time.Now().UnixMilli() // 毫秒时间戳，与后端日志查询窗口一致
	content := fmt.Sprintf("%s%s", msg, formatKeyValues(args...))
	Logger.Printf("[DEBUG] %s", content)
	reportLog(LevelDebug, content, ts)
}

// Info 记录信息日志
func Info(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	ts := time.Now().UnixMilli() // 毫秒时间戳，与后端日志查询窗口一致
	content := fmt.Sprintf("%s%s", msg, formatKeyValues(args...))
	Logger.Printf("[INFO] %s", content)
	reportLog(LevelInfo, content, ts)
}

// InfoLocal 仅写入 deploy 本机信息日志，不向服务端上报私密运行参数。
func InfoLocal(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	content := fmt.Sprintf("%s%s", msg, formatKeyValues(args...))
	Logger.Printf("[INFO] %s", content)
}

// Warn 记录警告日志
func Warn(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	ts := time.Now().UnixMilli() // 毫秒时间戳，与后端日志查询窗口一致
	content := fmt.Sprintf("%s%s", msg, formatKeyValues(args...))
	Logger.Printf("[WARN] %s", content)
	reportLog(LevelWarn, content, ts)
}

// WarnLocal 仅写入 deploy 本机警告日志，不向服务端上报私密诊断。
func WarnLocal(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	content := fmt.Sprintf("%s%s", msg, formatKeyValues(args...))
	Logger.Printf("[WARN] %s", content)
}

// Error 记录错误日志
func Error(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	ts := time.Now().UnixMilli() // 毫秒时间戳，与后端日志查询窗口一致
	content := fmt.Sprintf("%s%s", msg, formatKeyValues(args...))
	Logger.Printf("[ERROR] %s", content)
	reportLog(LevelError, content, ts)
}

// ErrorLocal 仅写入 deploy 本机日志，不向服务端上报可能包含私密诊断的信息。
func ErrorLocal(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	content := fmt.Sprintf("%s%s", msg, formatKeyValues(args...))
	Logger.Printf("[ERROR] %s", content)
}

// Fatal 记录致命错误日志并退出
func Fatal(msg string, args ...interface{}) {
	if Logger == nil {
		os.Exit(1)
	}
	ts := time.Now().UnixMilli() // 毫秒时间戳，与后端日志查询窗口一致
	content := fmt.Sprintf("%s%s", msg, formatKeyValues(args...))
	Logger.Printf("[FATAL] %s", content)
	reportLog(LevelFatal, content, ts)
	time.Sleep(100 * time.Millisecond) // 等待日志上报
	os.Exit(1)
}
