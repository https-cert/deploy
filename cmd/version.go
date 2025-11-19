package cmd

import (
	"fmt"

	"github.com/https-cert/deploy/internal/config"
	"github.com/spf13/cobra"
)

// CreateVersionCmd 创建版本命令
func CreateVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "显示当前版本",
		Long:  "显示 anssl CLI 的当前版本号",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("anssl %s\n", config.Version)
		},
	}
}

