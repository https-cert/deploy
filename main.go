package main

import (
	"fmt"
	"os"

	"github.com/orange-juzipi/cert-deploy/cmd"
)

func main() {
	rootCmd := cmd.CreateRootCmd()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "执行命令失败: %v\n", err)
		os.Exit(1)
	}
}
