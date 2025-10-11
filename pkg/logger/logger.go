package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
)

var (
	Logger *log.Logger
)

// Init 初始化日志
func Init() {
	Logger = log.New(os.Stdout, "", log.LstdFlags)
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

// Debug 记录调试日志
func Debug(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	Logger.Printf("[DEBUG] %s%s", msg, formatKeyValues(args...))
}

// Info 记录信息日志
func Info(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	Logger.Printf("[INFO] %s%s", msg, formatKeyValues(args...))
}

// Warn 记录警告日志
func Warn(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	Logger.Printf("[WARN] %s%s", msg, formatKeyValues(args...))
}

// Error 记录错误日志
func Error(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	Logger.Printf("[ERROR] %s%s", msg, formatKeyValues(args...))
}

// Fatal 记录致命错误日志并退出
func Fatal(msg string, args ...interface{}) {
	if Logger == nil {
		os.Exit(1)
	}
	Logger.Printf("[FATAL] %s%s", msg, formatKeyValues(args...))
	os.Exit(1)
}
