package shared

import (
	"context"

	"github.com/https-cert/deploy/internal/config"
)

type runtimeContextKey struct{}

// WithRuntime 将运行时配置附加到一次本地部署 operation context。
func WithRuntime(ctx context.Context, runtime *config.Runtime) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, runtimeContextKey{}, runtime)
}

// RuntimeFromContext 读取 operation context 中的运行时配置。
func RuntimeFromContext(ctx context.Context) *config.Runtime {
	if ctx == nil {
		return nil
	}
	runtime, _ := ctx.Value(runtimeContextKey{}).(*config.Runtime)
	return runtime
}

// ConfigurationFromContext 返回 operation context 中的配置快照。
func ConfigurationFromContext(ctx context.Context) *config.Configuration {
	if runtime := RuntimeFromContext(ctx); runtime != nil {
		return runtime.Config
	}
	return nil
}
