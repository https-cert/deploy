package updater

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// extractBinary 从下载的文件中提取可执行文件。
// 支持 .tar.gz、.zip，如果是普通文件则直接返回原路径。
func extractBinary(downloadPath, tempDir string) (string, error) {
	return extractBinaryNamed(downloadPath, tempDir, getExecutableName())
}

func extractBinaryNamed(downloadPath, tempDir, executableName string) (string, error) {
	if executableName == "" {
		return "", fmt.Errorf("可执行文件名不能为空")
	}

	name := filepath.Base(downloadPath)

	// tar.gz 压缩包
	if strings.HasSuffix(name, ".tar.gz") {
		f, err := os.Open(downloadPath)
		if err != nil {
			return "", err
		}
		defer f.Close()

		gzr, err := gzip.NewReader(f)
		if err != nil {
			return "", err
		}
		defer gzr.Close()

		tr := tar.NewReader(gzr)

		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", err
			}

			if hdr.Typeflag != tar.TypeReg {
				continue
			}

			if filepath.Base(hdr.Name) != executableName {
				continue
			}

			dstPath := filepath.Join(tempDir, executableName)
			if err := writeExtractedBinary(dstPath, tr); err != nil {
				return "", err
			}
			return dstPath, nil
		}

		return "", fmt.Errorf("压缩包中未找到可执行文件: %s", executableName)
	}

	// zip 压缩包
	if strings.HasSuffix(name, ".zip") {
		r, err := zip.OpenReader(downloadPath)
		if err != nil {
			return "", err
		}
		defer r.Close()

		for _, f := range r.File {
			if f.FileInfo().IsDir() {
				continue
			}

			if filepath.Base(f.Name) != executableName {
				continue
			}

			rc, err := f.Open()
			if err != nil {
				return "", err
			}

			dstPath := filepath.Join(tempDir, executableName)
			if err := writeExtractedBinary(dstPath, rc); err != nil {
				rc.Close()
				return "", err
			}

			if err := rc.Close(); err != nil {
				return "", err
			}

			return dstPath, nil
		}

		return "", fmt.Errorf("压缩包中未找到可执行文件: %s", executableName)
	}

	// 普通文件，直接返回
	return downloadPath, nil
}

func writeExtractedBinary(dstPath string, src io.Reader) (err error) {
	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := out.Close(); err == nil {
			err = closeErr
		}
	}()

	_, err = io.Copy(out, src)
	return err
}

// verifyChecksum 验证文件的 SHA256 校验和
func verifyChecksum(binaryPath, checksumPath, binaryName string) error {
	// 读取 checksums.txt
	content, err := os.ReadFile(checksumPath)
	if err != nil {
		return err
	}

	// 解析 checksums.txt，找到对应文件的 checksum
	lines := strings.Split(string(content), "\n")
	var expectedChecksum string
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 2 && strings.TrimPrefix(parts[1], "*") == binaryName {
			expectedChecksum = strings.TrimSpace(parts[0])
			break
		}
	}

	if expectedChecksum == "" {
		return fmt.Errorf("在校验文件中未找到 %s 的校验和", binaryName)
	}
	if len(expectedChecksum) != sha256.Size*2 {
		return fmt.Errorf("校验和格式无效")
	}
	if _, err := hex.DecodeString(expectedChecksum); err != nil {
		return fmt.Errorf("校验和格式无效: %w", err)
	}

	// 计算下载文件的 SHA256
	file, err := os.Open(binaryPath)
	if err != nil {
		return err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}

	actualChecksum := hex.EncodeToString(hash.Sum(nil))

	// 比较
	if !strings.EqualFold(actualChecksum, expectedChecksum) {
		return fmt.Errorf("校验和不匹配\n期望: %s\n实际: %s", expectedChecksum, actualChecksum)
	}

	return nil
}
