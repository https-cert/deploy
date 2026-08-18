package updater

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/https-cert/deploy/pkg/logger"
)

// downloadFile 使用显式 HTTP 客户端下载文件。
func downloadFile(ctx context.Context, httpClient *http.Client, downloadURL, filepath string) error {
	var lastErr error

	for attempt := 1; attempt <= downloadRetries; attempt++ {
		if attempt > 1 {
			if !waitWithContext(ctx, time.Duration(attempt-1)*time.Second) {
				return ctx.Err()
			}
			_ = os.Remove(filepath)
		}

		if err := downloadFileOnce(ctx, httpClient, downloadURL, filepath); err != nil {
			lastErr = err
			logger.Warn("下载失败，准备重试", "attempt", attempt, "max", downloadRetries, "error", err)
			continue
		}

		return nil
	}

	return lastErr
}

// downloadFileOnce 执行单次受限更新包下载。
func downloadFileOnce(ctx context.Context, httpClient *http.Client, downloadURL, filePath string) error {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	parsedURL, err := url.Parse(downloadURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Hostname() == "" || parsedURL.User != nil {
		return fmt.Errorf("更新下载 URL 必须是 HTTPS 且包含合法主机")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return err
	}

	if httpClient == nil {
		httpClient = newHTTPClientForRuntime(nil)
	}
	clientCopy := *httpClient
	client := &clientCopy
	originalRedirect := client.CheckRedirect
	client.CheckRedirect = func(nextReq *http.Request, via []*http.Request) error {
		if !strings.EqualFold(parsedURL.Scheme, nextReq.URL.Scheme) || !strings.EqualFold(parsedURL.Host, nextReq.URL.Host) {
			return fmt.Errorf("拒绝跨主机更新下载重定向")
		}
		if originalRedirect != nil {
			return originalRedirect(nextReq, via)
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败，状态码: %d", resp.StatusCode)
	}
	if resp.ContentLength > maxUpdateSize {
		return fmt.Errorf("更新包超过大小限制")
	}

	out, err := os.CreateTemp(filepath.Dir(filePath), ".anssl-update-download-*")
	if err != nil {
		return err
	}
	tempPath := out.Name()
	completed := false
	defer func() {
		_ = out.Close()
		if !completed {
			_ = os.Remove(tempPath)
		}
	}()

	written, err := io.Copy(out, io.LimitReader(resp.Body, maxUpdateSize+1))
	if err != nil {
		return err
	}
	if written > maxUpdateSize {
		return fmt.Errorf("更新包超过大小限制")
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, filePath); err != nil {
		return err
	}
	completed = true

	return nil
}

// waitWithContext waits for a retry delay without blocking shutdown.
func waitWithContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
