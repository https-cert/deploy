package cmd

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// CreateLogCmd 创建日志查看命令
func CreateLogCmd() *cobra.Command {
	var follow bool

	cmd := &cobra.Command{
		Use:   "log",
		Short: "查看守护进程日志",
		Long:  "查看证书部署守护进程的日志输出",
		Run: func(cmd *cobra.Command, args []string) {
			logFile := GetLogFile()
			if _, err := os.Stat(logFile); os.IsNotExist(err) {
				fmt.Println("日志文件不存在")
				return
			}

			if follow {
				followLogs(logFile)
			} else {
				content, err := os.ReadFile(logFile)
				if err != nil {
					fmt.Printf("读取日志失败: %v\n", err)
					return
				}
				fmt.Print(string(content))
			}
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "实时跟踪日志")

	return cmd
}

// followLogs 实时跟踪日志文件
func followLogs(logFile string) {
	content, err := os.ReadFile(logFile)
	if err == nil && len(content) > 0 {
		fmt.Print(string(content))
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	file, err := os.Open(logFile)
	if err != nil {
		fmt.Printf("打开日志失败: %v\n", err)
		return
	}
	defer file.Close()

	offset, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		fmt.Printf("定位日志失败: %v\n", err)
		return
	}

	buffer := make([]byte, 1024)

	for {
		select {
		case <-sigChan:
			return
		default:
		}

		n, err := file.Read(buffer)
		if n > 0 {
			fmt.Print(string(buffer[:n]))
			offset += int64(n)
		}
		if err == nil {
			continue
		}
		if err == io.EOF {
			newFile, newOffset, changed, reopenErr := reopenFollowLogIfNeeded(logFile, file, offset)
			if reopenErr != nil {
				fmt.Printf("重新打开日志失败: %v\n", reopenErr)
				return
			}
			if changed {
				file.Close()
				file = newFile
				offset = newOffset
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		fmt.Printf("读取日志失败: %v\n", err)
		return
	}
}

// reopenFollowLogIfNeeded 在日志轮转或截断后重新打开当前日志文件。
func reopenFollowLogIfNeeded(logFile string, currentFile *os.File, offset int64) (*os.File, int64, bool, error) {
	currentInfo, currentErr := currentFile.Stat()
	pathInfo, err := os.Stat(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			return currentFile, offset, false, nil
		}
		return currentFile, offset, false, err
	}

	changed := currentErr != nil || !os.SameFile(currentInfo, pathInfo) || pathInfo.Size() < offset
	if !changed {
		return currentFile, offset, false, nil
	}

	newFile, err := os.Open(logFile)
	if err != nil {
		return currentFile, offset, false, err
	}
	return newFile, 0, true, nil
}
