package aliyun

const defaultESAEndpoint = "esa.cn-hangzhou.aliyuncs.com"

// Service 服务类型
const (
	ServiceCAS = "cas"
	ServiceESA = "esa"
)

// Options 阿里云 provider 的可选配置
type Options struct {
	// Service 必填: cas 或 esa
	Service string

	ESASiteID string
}
