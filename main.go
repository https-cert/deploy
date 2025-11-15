package main

import (
	"fmt"
	"os"

	"github.com/https-cert/deploy/cmd"
	"github.com/https-cert/deploy/pkg/logger"
)

func main() {
	logger.Init()

	rootCmd := cmd.CreateRootCmd()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "执行命令失败: %v\n", err)
		os.Exit(1)
	}
}
