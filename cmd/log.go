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

	file.Seek(0, 2)

	buffer := make([]byte, 1024)
	done := make(chan bool)

	go func() {
		for {
			select {
			case <-done:
				return
			default:
				n, err := file.Read(buffer)
				if err != nil {
					if err == io.EOF {
						time.Sleep(100 * time.Millisecond)
						continue
					}
					done <- true
					return
				}
				if n > 0 {
					fmt.Print(string(buffer[:n]))
				}
			}
		}
	}()

	<-sigChan
	done <- true
}
