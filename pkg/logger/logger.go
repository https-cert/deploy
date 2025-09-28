package logger

import (
	"log"
	"os"
)

var (
	Logger *log.Logger
)

// Init 初始化日志
func Init() {
	Logger = log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile)
}

// Debug 记录调试日志
func Debug(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	Logger.Printf("[DEBUG] "+msg, args...)
}

// Info 记录信息日志
func Info(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	Logger.Printf("[INFO] "+msg, args...)
}

// Warn 记录警告日志
func Warn(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	Logger.Printf("[WARN] "+msg, args...)
}

// Error 记录错误日志
func Error(msg string, args ...interface{}) {
	if Logger == nil {
		return
	}
	Logger.Printf("[ERROR] "+msg, args...)
}

// Fatal 记录致命错误日志并退出
func Fatal(msg string, args ...interface{}) {
	if Logger == nil {
		os.Exit(1)
	}
	Logger.Printf("[FATAL] "+msg, args...)
	os.Exit(1)
}
