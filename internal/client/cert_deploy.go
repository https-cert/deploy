package client

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/orange-juzipi/cert-deploy/internal/config"
)

const (
	certsDir = "certs"
)

// CertDeployer 证书部署器
type CertDeployer struct {
	client *Client
}

// NewCertDeployer 创建证书部署器
func NewCertDeployer(client *Client) *CertDeployer {
	return &CertDeployer{
		client: client,
	}
}

// DeployCertificate 部署证书
func (cd *CertDeployer) DeployCertificate(domain, url string) error {
	// 创建certs目录
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	// 文件名格式为 {domain}_certificates.zip
	fileName := fmt.Sprintf("%s_certificates.zip", domain)
	zipFile := filepath.Join(certsDir, fileName)

	// 下载zip文件
	if err := cd.client.downloadFile(url, zipFile); err != nil {
		return fmt.Errorf("下载证书失败: %w", err)
	}

	fmt.Printf("证书下载完成: %s\n", zipFile)

	// 确保下载失败时清理
	defer func() {
		if _, err := os.Stat(zipFile); err == nil {
			// 部署成功后删除zip文件
			os.Remove(zipFile)
		}
	}()

	// 检查是否配置了SSL目录
	sslPath := config.GetConfig().SSL.Path
	if sslPath == "" {
		fmt.Println("未配置SSL目录，证书已下载到: ", zipFile)
		return nil
	}

	// 证书文件夹名
	folderName := domain + "_certificates"
	extractDir := filepath.Join(certsDir, folderName)

	// 1. 解压zip文件
	if err := cd.extractZip(zipFile, extractDir); err != nil {
		// 清理失败的解压文件
		os.RemoveAll(extractDir)
		return fmt.Errorf("解压证书失败: %w", err)
	}

	// 2. 移动到配置的SSL目录
	if err := cd.moveCertificates(extractDir, sslPath, folderName); err != nil {
		// 清理失败的解压文件
		os.RemoveAll(extractDir)
		return fmt.Errorf("移动证书失败: %w", err)
	}

	// 3. 检查nginx是否存在，如果存在则测试配置和重新加载
	if cd.isNginxAvailable() {
		// 测试nginx配置
		if err := cd.testNginxConfig(); err != nil {
			return fmt.Errorf("nginx配置测试失败: %w", err)
		}

		// 重新加载nginx
		if err := cd.reloadNginx(); err != nil {
			return fmt.Errorf("nginx重新加载失败: %w", err)
		}
	} else {
		fmt.Println("nginx未安装或不在PATH中，跳过nginx相关操作")
	}

	fmt.Printf("自动部署流程完成: %s\n", domain)
	return nil
}

// extractZip 解压zip文件（修复：资源泄露）
func (cd *CertDeployer) extractZip(zipFile, extractDir string) error {
	// 创建解压目录
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return fmt.Errorf("创建解压目录失败: %w", err)
	}

	// 打开zip文件
	reader, err := zip.OpenReader(zipFile)
	if err != nil {
		return fmt.Errorf("打开zip文件失败: %w", err)
	}
	defer reader.Close()

	// 解压所有文件
	for _, file := range reader.File {
		if err := cd.extractZipFile(file, extractDir); err != nil {
			return err
		}
	}

	return nil
}

// extractZipFile 解压单个zip文件条目
func (cd *CertDeployer) extractZipFile(file *zip.File, extractDir string) error {
	// 使用 filepath.Rel 安全地检查路径
	targetPath := filepath.Join(extractDir, file.Name)
	rel, err := filepath.Rel(extractDir, targetPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("不安全的文件路径: %s", file.Name)
	}

	// 创建目录
	if file.FileInfo().IsDir() {
		return os.MkdirAll(targetPath, file.FileInfo().Mode())
	}

	// 创建文件目录
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return fmt.Errorf("创建文件目录失败: %w", err)
	}

	// 打开zip文件中的文件
	rc, err := file.Open()
	if err != nil {
		return fmt.Errorf("打开zip中的文件失败: %w", err)
	}
	defer rc.Close()

	// 创建目标文件
	outFile, err := os.Create(targetPath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}
	defer outFile.Close()

	// 复制文件内容
	if _, err := io.Copy(outFile, rc); err != nil {
		return fmt.Errorf("复制文件内容失败: %w", err)
	}

	// 设置文件权限
	if err := os.Chmod(targetPath, file.FileInfo().Mode()); err != nil {
		return fmt.Errorf("设置文件权限失败: %w", err)
	}

	return nil
}

// moveCertificates 移动证书文件夹到SSL目录
func (cd *CertDeployer) moveCertificates(sourceDir, sslPath, folderName string) error {
	// 确保SSL目录存在
	if err := os.MkdirAll(sslPath, 0755); err != nil {
		return fmt.Errorf("创建SSL目录失败: %w", err)
	}

	// 构建目标路径
	targetDir := filepath.Join(sslPath, folderName)

	// 如果目标目录已存在，直接删除
	if _, err := os.Stat(targetDir); err == nil {
		if err := os.RemoveAll(targetDir); err != nil {
			return fmt.Errorf("删除现有目录失败: %w", err)
		}
	}

	// 移动新证书到目标位置
	if err := os.Rename(sourceDir, targetDir); err != nil {
		return fmt.Errorf("移动证书文件夹失败: %w", err)
	}

	fmt.Printf("证书文件夹已更新: %s\n", targetDir)
	return nil
}

// isNginxAvailable 检查nginx是否可用
func (cd *CertDeployer) isNginxAvailable() bool {
	_, err := exec.LookPath("nginx")
	return err == nil
}

// testNginxConfig 测试nginx配置
func (cd *CertDeployer) testNginxConfig() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nginx", "-t")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx配置测试失败: %w, 输出: %s", err, string(output))
	}

	return nil
}

// reloadNginx 重新加载nginx
func (cd *CertDeployer) reloadNginx() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nginx", "-s", "reload")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx重新加载失败: %w, 输出: %s", err, string(output))
	}

	fmt.Println("nginx重新加载成功")
	return nil
}
