package client

import (
	"archive/tar"
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
	certsDir := "certs"
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

	// 2. 检查是否配置了SSL目录
	sslPath := config.GetConfig().SSL.Path
	if sslPath != "" {
		// 证书文件夹名
		folderName := domain + "_certificates"

		// 1. 解压zip文件
		extractDir := filepath.Join(certsDir, folderName)
		if err := cd.extractZip(zipFile, extractDir); err != nil {
			return fmt.Errorf("解压证书失败: %w", err)
		}

		// 移动到配置的SSL目录
		if err := cd.moveCertificates(extractDir, sslPath, folderName); err != nil {
			return fmt.Errorf("移动证书失败: %w", err)
		}

		// 3. 测试nginx配置
		if err := cd.testNginxConfig(); err != nil {
			return fmt.Errorf("nginx配置测试失败: %w", err)
		}

		// 4. 重新加载nginx
		if err := cd.reloadNginx(); err != nil {
			return fmt.Errorf("nginx重新加载失败: %w", err)
		}
		fmt.Printf("证书部署完成: %s\n", domain)

	} else {
		fmt.Println("未配置SSL目录，证书已下载到: ", zipFile)
	}

	return nil
}

// extractZip 解压zip文件
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
		// 构建目标文件路径
		targetPath := filepath.Join(extractDir, file.Name)

		// 检查路径安全性
		if !strings.HasPrefix(targetPath, filepath.Clean(extractDir)+string(os.PathSeparator)) {
			return fmt.Errorf("不安全的文件路径: %s", file.Name)
		}

		// 创建目录
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, file.FileInfo().Mode()); err != nil {
				return fmt.Errorf("创建目录失败: %w", err)
			}
			continue
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

		// 创建目标文件
		outFile, err := os.Create(targetPath)
		if err != nil {
			rc.Close()
			return fmt.Errorf("创建文件失败: %w", err)
		}

		// 复制文件内容
		if _, err := io.Copy(outFile, rc); err != nil {
			rc.Close()
			outFile.Close()
			return fmt.Errorf("复制文件内容失败: %w", err)
		}

		rc.Close()
		outFile.Close()

		// 设置文件权限
		if err := os.Chmod(targetPath, file.FileInfo().Mode()); err != nil {
			return fmt.Errorf("设置文件权限失败: %w", err)
		}
	}

	return nil
}

// extractTar 解压tar文件
func (cd *CertDeployer) extractTar(tarFile, extractDir string) error {
	// 创建解压目录
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return fmt.Errorf("创建解压目录失败: %w", err)
	}

	// 打开tar文件
	file, err := os.Open(tarFile)
	if err != nil {
		return fmt.Errorf("打开tar文件失败: %w", err)
	}
	defer file.Close()

	// 创建tar reader
	tr := tar.NewReader(file)

	// 解压所有文件
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取tar文件失败: %w", err)
		}

		// 构建目标文件路径
		targetPath := filepath.Join(extractDir, header.Name)

		// 创建目录
		if header.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("创建目录失败: %w", err)
			}
			continue
		}

		// 创建文件
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return fmt.Errorf("创建文件目录失败: %w", err)
		}

		outFile, err := os.Create(targetPath)
		if err != nil {
			return fmt.Errorf("创建文件失败: %w", err)
		}

		// 复制文件内容
		if _, err := io.Copy(outFile, tr); err != nil {
			outFile.Close()
			return fmt.Errorf("复制文件内容失败: %w", err)
		}
		outFile.Close()

		// 设置文件权限
		if err := os.Chmod(targetPath, os.FileMode(header.Mode)); err != nil {
			return fmt.Errorf("设置文件权限失败: %w", err)
		}
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

	// 如果目标目录已存在，先删除
	if _, err := os.Stat(targetDir); err == nil {
		if err := os.RemoveAll(targetDir); err != nil {
			return fmt.Errorf("删除已存在的目录失败: %w", err)
		}
	}

	// 直接移动整个文件夹
	if err := os.Rename(sourceDir, targetDir); err != nil {
		return fmt.Errorf("移动证书文件夹失败: %w", err)
	}

	fmt.Printf("移动证书文件夹: %s -> %s\n", sourceDir, targetDir)
	return nil
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

	fmt.Println("nginx配置测试通过")
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
