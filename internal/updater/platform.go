package updater

import (
	"fmt"
	"runtime"
)

// getBinaryName 根据当前系统获取二进制文件名
func getBinaryName() string {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	var name string
	switch goos {
	case "darwin":
		if goarch == "arm64" {
			name = "anssl-darwin-arm64.tar.gz"
		} else {
			name = "anssl-darwin-amd64.tar.gz"
		}
	case "linux":
		if goarch == "arm64" {
			name = "anssl-linux-arm64.tar.gz"
		} else {
			name = "anssl-linux-amd64.tar.gz"
		}
	case "windows":
		if goarch == "arm64" {
			name = "anssl-windows-arm64.zip"
		} else {
			name = "anssl-windows-amd64.zip"
		}
	default:
		name = fmt.Sprintf("anssl-%s-%s.tar.gz", goos, goarch)
	}

	return name
}

// getExecutableName 根据当前系统获取压缩包内的可执行文件名
func getExecutableName() string {
	if runtime.GOOS == "windows" {
		return "anssl.exe"
	}
	return "anssl"
}
