package client

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/https-cert/deploy/internal/updater"
	"github.com/https-cert/deploy/pkg/logger"
)

// handleUpdate 处理版本更新
func (c *Client) handleUpdate() {
	logger.Info("收到版本更新通知")

	updateInfo, err := updater.CheckUpdate(c.ctx)
	if err != nil {
		logger.Error("检查更新失败", "error", err)
		return
	}

	if !updateInfo.HasUpdate {
		return
	}

	logger.Info("发现新版本", "current", updateInfo.CurrentVersion, "latest", updateInfo.LatestVersion)

	if err := updater.PerformUpdate(c.ctx, updateInfo); err != nil {
		logger.Error("更新失败", "error", err)
		return
	}

	logger.Info("更新完成，重启中...")

	// 创建更新标记文件
	execPath, err := os.Executable()
	if err != nil {
		logger.Error("获取可执行文件路径失败", "error", err)
		return
	}
	execDir := filepath.Dir(execPath)
	markerFile := filepath.Join(execDir, ".anssl-updated")
	content := fmt.Sprintf("%s\n%s\n", updateInfo.LatestVersion, time.Now().Format(time.RFC3339))
	if err := os.WriteFile(markerFile, []byte(content), 0600); err != nil {
		logger.Error("创建更新标记文件失败", "error", err)
		return
	}

	time.Sleep(1 * time.Second)
	os.Exit(0)
}
