package feiniu

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/https-cert/deploy/internal/client/deploys/shared"
	"github.com/https-cert/deploy/pkg/logger"
)

// updateFeiniuNginxConfigContext 使用调用方 context 更新飞牛 OS Nginx 配置。
func updateFeiniuNginxConfigContext(ctx context.Context, domain, certPath string) error {
	if err := shared.OperationContextError(ctx); err != nil {
		return err
	}
	return updateFeiniuNginxConfigFile(feiniuNginxConfigFile, domain, certPath)
}

// updateFeiniuNginxConfigFile 原子更新飞牛网关证书 JSON 文件。
func updateFeiniuNginxConfigFile(configFile, domain, certPath string) error {
	if shared.SanitizeDomain(domain) == "" {
		return fmt.Errorf("飞牛证书域名无效")
	}

	resolvedConfigFile, err := filepath.EvalSymlinks(configFile)
	if err != nil {
		return fmt.Errorf("解析Nginx配置路径失败: %w", err)
	}
	content, err := os.ReadFile(resolvedConfigFile)
	if err != nil {
		return fmt.Errorf("读取Nginx配置失败: %w", err)
	}
	newContent, err := renderFeiniuNginxConfig(content, domain, certPath)
	if err != nil {
		return err
	}

	info, err := os.Stat(resolvedConfigFile)
	if err != nil {
		return fmt.Errorf("读取Nginx配置权限失败: %w", err)
	}
	backupFile := fmt.Sprintf("%s.%d.bak", resolvedConfigFile, time.Now().UnixNano())
	if err := shared.CopyFileWithMode(resolvedConfigFile, backupFile, info.Mode().Perm()); err != nil {
		return fmt.Errorf("备份Nginx配置失败: %w", err)
	}
	if err := writeFileAtomically(resolvedConfigFile, newContent, info.Mode().Perm()); err != nil {
		return fmt.Errorf("写入Nginx配置失败: %w", err)
	}

	logger.Info("已更新飞牛Nginx配置", "domain", domain)
	return nil
}

// renderFeiniuNginxConfig 在内存中更新飞牛网关证书配置，供本机和 SSH 部署复用。
func renderFeiniuNginxConfig(content []byte, domain, certPath string) ([]byte, error) {
	safeDomain := shared.SanitizeDomain(domain)
	if safeDomain == "" {
		return nil, fmt.Errorf("飞牛证书域名无效")
	}
	certFile := path.Join(certPath, safeDomain+".crt")
	keyFile := path.Join(certPath, safeDomain+".key")

	var entries []map[string]any
	if err := json.Unmarshal(content, &entries); err != nil {
		return nil, fmt.Errorf("解析Nginx配置失败，原文件未修改: %w", err)
	}
	replacement := map[string]any{"host": domain, "cert": certFile, "key": keyFile}
	found := false
	for index, entry := range entries {
		if host, ok := entry["host"].(string); ok && host == domain {
			updated := make(map[string]any, len(entry)+3)
			for key, value := range entry {
				updated[key] = value
			}
			updated["host"] = domain
			updated["cert"] = certFile
			updated["key"] = keyFile
			entries[index] = updated
			found = true
		}
	}
	if !found {
		entries = append([]map[string]any{replacement}, entries...)
	}
	newContent, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("序列化Nginx配置失败: %w", err)
	}
	return append(newContent, '\n'), nil
}

// writeFileAtomically 通过同目录临时文件和 rename 原子写入配置。
func writeFileAtomically(path string, data []byte, mode os.FileMode) (err error) {
	tempFile, err := os.CreateTemp(filepath.Dir(path), ".anssl-config-*")
	if err != nil {
		return err
	}
	tempPath := tempFile.Name()
	defer func() {
		_ = tempFile.Close()
		if err != nil {
			_ = os.Remove(tempPath)
		}
	}()
	if err = tempFile.Chmod(mode); err != nil {
		return err
	}
	if _, err = tempFile.Write(data); err != nil {
		return err
	}
	if err = tempFile.Sync(); err != nil {
		return err
	}
	if err = tempFile.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}
