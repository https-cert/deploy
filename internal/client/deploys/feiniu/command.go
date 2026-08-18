package feiniu

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/https-cert/deploy/pkg/logger"
)

const feiniuCommandTimeout = 30 * time.Second

// changeGroupToRootContext 使用调用方 context 修改目录和文件的组为 root。
func changeGroupToRootContext(ctx context.Context, targetDir string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := runFeiniuCommandContext(ctx, feiniuCommandTimeout, "chgrp", "-R", "root", targetDir); err != nil {
		logger.Warn("普通权限修改组失败，尝试使用 sudo", "error", err)
		if output, err := runFeiniuCommandContext(ctx, feiniuCommandTimeout, "sudo", "chgrp", "-R", "root", targetDir); err != nil {
			return fmt.Errorf("修改组为root失败: %w, output: %s", err, string(output))
		}
	}
	logger.Info("已修改组为root", "path", targetDir)
	return nil
}

// reloadFeiniuServicesContext 使用调用方 context 重启飞牛 OS 相关服务。
func reloadFeiniuServicesContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	services := []string{"webdav.service", "smbftpd.service", "trim_nginx.service"}
	for _, service := range services {
		if output, err := runFeiniuCommandContext(ctx, feiniuCommandTimeout, "systemctl", "restart", service); err != nil {
			logger.Warn("重启服务失败", "service", service, "error", err, "output", string(output))
			if output, err := runFeiniuCommandContext(ctx, feiniuCommandTimeout, "sudo", "systemctl", "restart", service); err != nil {
				logger.Warn("使用sudo重启服务也失败", "service", service, "error", err, "output", string(output))
			}
		} else {
			logger.Info("已重启服务", "service", service)
		}
	}
	return nil
}

// runFeiniuCommandContext 使用调用方 context 执行飞牛系统命令。
func runFeiniuCommandContext(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(commandContext, name, args...)
	output, err := cmd.CombinedOutput()
	if commandContext.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("命令执行超时: %s", name)
	}
	return output, err
}

// isPermissionError 检查错误是否为权限错误。
func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		if errors.Is(pathErr.Err, syscall.EACCES) || errors.Is(pathErr.Err, syscall.EPERM) {
			return true
		}
		errText := pathErr.Err.Error()
		return errText == "permission denied" || errText == "operation not permitted"
	}
	return false
}
