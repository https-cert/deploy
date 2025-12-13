package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
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
	ServerURL string
	ClientID  string
	AccessKey string
}

var (
	Logger   *log.Logger
	reporter *LogReporter
)

// Init 初始化日志
func Init() {
	Logger = log.New(os.Stdout, "", log.LstdFlags)
}

// SetReporter 设置日志上报器
func SetReporter(r *LogReporter) {
	reporter = r
}

// formatKeyValues 格式化键值对参数
func formatKeyValues(args ...interface{}) string {
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

// reportLog 上报日志到服务端
func reportLog(level LogLevel, message string, timestamp int64) {
	if reporter == nil {
		return
	}

	// 异步上报，不阻塞
	go func() {
		payload := map[string]interface{}{
			"type":      "deploy", // 日志类型
			"clientId":  reporter.ClientID,
			"level":     level,
			"message":   message,
			"timestamp": timestamp,
		}

		jsonData, err := json.Marshal(payload)
		if err != nil {
			return
		}

		url := reporter.ServerURL + "/api/logs"
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			return
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Access-Key", reporter.AccessKey)

		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			// 上报失败时输出到 stderr（仅用于调试，不使用 logger 避免递归）
			fmt.Fprintf(os.Stderr, "[LOG_REPORT_ERROR] url=%s error=%v\n", url, err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "[LOG_REPORT_ERROR] url=%s status=%d\n", url, resp.StatusCode)
		}
	}()
}

// Debug 记录调试日志
func Debug(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	ts := time.Now().UnixMicro() // 微秒时间戳，确保顺序
	content := fmt.Sprintf("%s%s", msg, formatKeyValues(args...))
	Logger.Printf("[DEBUG] %s", content)
	reportLog(LevelDebug, content, ts)
}

// Info 记录信息日志
func Info(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	ts := time.Now().UnixMicro() // 微秒时间戳，确保顺序
	content := fmt.Sprintf("%s%s", msg, formatKeyValues(args...))
	Logger.Printf("[INFO] %s", content)
	reportLog(LevelInfo, content, ts)
}

// Warn 记录警告日志
func Warn(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	ts := time.Now().UnixMicro() // 微秒时间戳，确保顺序
	content := fmt.Sprintf("%s%s", msg, formatKeyValues(args...))
	Logger.Printf("[WARN] %s", content)
	reportLog(LevelWarn, content, ts)
}

// Error 记录错误日志
func Error(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	ts := time.Now().UnixMicro() // 微秒时间戳，确保顺序
	content := fmt.Sprintf("%s%s", msg, formatKeyValues(args...))
	Logger.Printf("[ERROR] %s", content)
	reportLog(LevelError, content, ts)
}

// Fatal 记录致命错误日志并退出
func Fatal(msg string, args ...interface{}) {
	if Logger == nil {
		os.Exit(1)
	}
	ts := time.Now().UnixMicro() // 微秒时间戳，确保顺序
	content := fmt.Sprintf("%s%s", msg, formatKeyValues(args...))
	Logger.Printf("[FATAL] %s", content)
	reportLog(LevelFatal, content, ts)
	time.Sleep(100 * time.Millisecond) // 等待日志上报
	os.Exit(1)
}
