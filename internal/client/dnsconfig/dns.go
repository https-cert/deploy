// Package dnsconfig 只创建授权的 CNAME，不修改或删除已有记录。
package dnsconfig

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/baidubce/bce-sdk-go/bce"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/sdkerr"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
)

// Entry 是适配器查询出的精确记录，保留停用和特殊线路状态。
type Entry struct {
	Host        string // Host 是相对主机记录或完整记录名。
	Type        string // Type 是 DNS 类型。
	Value       string // Value 是记录内容。
	Enabled     bool   // Enabled 表示当前记录有效。
	DefaultLine bool   // DefaultLine 表示默认线路。
}

// Backend 是厂商 DNS API 的最小接口，所有查询必须覆盖分页。
type Backend interface {
	// FindZone 精确读取权威托管区，禁止退回祖先区。
	FindZone(context.Context, string) (string, error)
	// List 查询同名全部类型和线路。
	List(context.Context, string, *deployPB.DnsRecord) ([]Entry, error)
	// Create 新增默认线路、TTL 600 的 CNAME。
	Create(context.Context, string, *deployPB.DnsRecord) (string, error)
}

// Definition 描述支持的 DNS 厂商与本地配置名称。
type Definition struct {
	Provider   deployPB.DnsProvider                    // Provider 是协议枚举。
	Name       string                                  // Name 是展示名称。
	ConfigName string                                  // ConfigName 是现有 provider 配置名。
	New        func(*config.Provider) (Backend, error) // New 仅构造 DNS 客户端。
}

// Definitions 是完整支持目录，注册和实际分发使用同一来源。
var Definitions = []Definition{
	{deployPB.DnsProvider_DNS_PROVIDER_ALIYUN, "阿里云 DNS", config.ProviderAliyun, newAliyun},
	{deployPB.DnsProvider_DNS_PROVIDER_TENCENT, "腾讯云 DNSPod", config.ProviderTencentCloud, newTencent},
	{deployPB.DnsProvider_DNS_PROVIDER_HUAWEI, "华为云 DNS", config.ProviderHuaweiCloud, newHuawei},
	{deployPB.DnsProvider_DNS_PROVIDER_BAIDU, "百度智能云 DNS", config.ProviderBaiduCloud, newBaidu},
	{deployPB.DnsProvider_DNS_PROVIDER_JDCLOUD, "京东云 DNS", config.ProviderJDCloud, newJD},
	{deployPB.DnsProvider_DNS_PROVIDER_VOLCENGINE, "火山引擎 DNS", config.ProviderVolcengine, newVolc},
	{deployPB.DnsProvider_DNS_PROVIDER_CLOUDFLARE, "Cloudflare", config.ProviderCloudflare, newCloudflare},
}

// Configuration 从运行期快照读取一项厂商配置。
func Configuration(runtime *config.Runtime, name string) *config.Provider {
	if runtime != nil && runtime.Config != nil {
		for _, p := range runtime.Config.Provider {
			if p != nil && p.Name == name {
				return p
			}
		}
	}
	return nil
}

// Capabilities 返回完整凭据是否存在，不进行云端调用。
func Capabilities(runtime *config.Runtime) []*deployPB.DnsProviderCapability {
	var result []*deployPB.DnsProviderCapability
	for _, d := range Definitions {
		p := Configuration(runtime, d.ConfigName)
		configured := false
		if p != nil && p.Auth != nil {
			if d.Provider == deployPB.DnsProvider_DNS_PROVIDER_CLOUDFLARE {
				configured = strings.TrimSpace(p.GetAPIToken()) != ""
			} else if d.Provider == deployPB.DnsProvider_DNS_PROVIDER_TENCENT {
				configured = strings.TrimSpace(p.GetSecretId()) != "" && strings.TrimSpace(p.GetSecretKey()) != ""
			} else {
				configured = strings.TrimSpace(p.GetAccessKeyId()) != "" && strings.TrimSpace(p.GetAccessKeySecret()) != ""
			}
		}
		result = append(result, &deployPB.DnsProviderCapability{Provider: d.Provider, Name: d.Name, Configured: configured})
	}
	return result
}

// NewBackend 构造与本地凭据对应的 DNS 适配器，不调用其他云产品。
func NewBackend(runtime *config.Runtime, provider deployPB.DnsProvider) (Backend, error) {
	for _, d := range Definitions {
		if d.Provider == provider {
			p := Configuration(runtime, d.ConfigName)
			if p == nil || p.Auth == nil {
				return nil, fmt.Errorf("DNS 密钥未配置")
			}
			return d.New(p)
		}
	}
	return nil, fmt.Errorf("DNS 服务商不支持")
}

// Normalize 将 DNS 名称规范化用于精确比较。
func Normalize(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}

// Classify 在所有同名记录上执行保守冲突判断。
func Classify(entries []Entry, record *deployPB.DnsRecord) deployPB.DnsOperationStatus {
	found := false
	for _, entry := range entries {
		// 未知记录结构不能当成空记录目录，否则可能跳过真实冲突。
		if Normalize(entry.Host) == "" || entry.Type == "" {
			return deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_CONFLICT
		}
		if Normalize(entry.Host) != Normalize(record.Host) && Normalize(entry.Host) != Normalize(record.Fqdn) {
			continue
		}
		found = true
		if !strings.EqualFold(entry.Type, "CNAME") || Normalize(entry.Value) != Normalize(record.Value) || !entry.Enabled || !entry.DefaultLine {
			return deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_CONFLICT
		}
	}
	if found {
		return deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_ALREADY_EXISTS
	}
	return deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_READY
}

// Operate 在写入前重新查询，创建后回读，取消或超时不会触发盲目重试。
func Operate(ctx context.Context, backend Backend, record *deployPB.DnsRecord, write bool) *deployPB.DnsOperationResult {
	result := &deployPB.DnsOperationResult{Record: record}
	if record == nil || record.Zone == "" || !strings.HasPrefix(record.Fqdn, "_acme-challenge.") || !strings.HasSuffix(record.Fqdn, "."+record.Zone) || record.Host != strings.TrimSuffix(record.Fqdn, "."+record.Zone) || record.Value == "" {
		result.Status = deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_FAILED
		result.Message = "授权 DNS 记录无效"
		return result
	}
	zone, err := backend.FindZone(ctx, record.Zone)
	if err != nil {
		return failure(result, err, false)
	}
	entries, err := backend.List(ctx, zone, record)
	if err != nil {
		return failure(result, err, false)
	}
	result.Status = Classify(entries, record)
	if result.Status == deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_CONFLICT {
		result.Message = "同名记录的值、类型、状态或线路冲突，请到 DNS 服务商处理"
		return result
	}
	if result.Status == deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_ALREADY_EXISTS {
		result.Message = "已存在相同且启用的默认线路 CNAME"
		return result
	}
	if !write {
		result.Message = "可配置；已确认托管区可读取，新增权限将在写入时检查"
		return result
	}
	if err = ctx.Err(); err != nil {
		return failure(result, err, false)
	}
	result.ProviderRequestId, err = backend.Create(ctx, zone, record)
	if err != nil {
		return failure(result, err, true)
	}
	// 云控制面可能异步生成记录；回读仅等待控制面，不等待公网传播。
	for attempt := 0; attempt < 5; attempt++ {
		entries, err = backend.List(ctx, zone, record)
		if err == nil && Classify(entries, record) == deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_ALREADY_EXISTS {
			result.Status = deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_CREATED
			result.Message = "CNAME 已写入，正在等待 DNS 验证"
			return result
		}
		if attempt < 4 {
			select {
			case <-ctx.Done():
				return failure(result, ctx.Err(), true)
			case <-time.After(time.Second):
			}
		}
	}
	result.Status = deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_UNCONFIRMED
	result.Message = "创建已提交，回读结果待确认，请重新检查"
	return result
}

// failure 返回脱敏错误分类，原始 SDK 错误不能进入平台或日志。
func failure(result *deployPB.DnsOperationResult, err error, write bool) *deployPB.DnsOperationResult {
	message := strings.ToLower(err.Error())
	if result.ProviderRequestId == "" {
		result.ProviderRequestId = requestIDFromError(err)
	}
	// 阿里云错误的 Error() 已脱敏，读取结构化错误码才能保留权限分类。
	var coded interface{ GetCode() *string }
	if errors.As(err, &coded) {
		message += " " + strings.ToLower(ptrValue(coded.GetCode()))
	}
	var statusCode interface{ GetStatusCode() *int }
	if errors.As(err, &statusCode) && (ptrValue(statusCode.GetStatusCode()) == 401 || ptrValue(statusCode.GetStatusCode()) == 403) {
		message += fmt.Sprintf(" %d", ptrValue(statusCode.GetStatusCode()))
	}
	result.Status = deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_FAILED
	result.Message = "DNS 服务商请求失败，请检查域名访问权限后重试"
	if strings.Contains(message, "permission") || strings.Contains(message, "forbidden") || strings.Contains(message, "unauthorized") || strings.Contains(message, "authfailure") || strings.Contains(message, "accessdenied") || strings.Contains(message, "invalidaccesskey") || strings.Contains(message, "signaturedoesnotmatch") || strings.Contains(message, "401") || strings.Contains(message, "403") {
		result.Status = deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_PERMISSION_DENIED
		result.Message = "密钥无权访问或新增 DNS 记录，请检查 DNS 权限"
	} else if write {
		result.Status = deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_UNCONFIRMED
		result.Message = "写入结果待确认，请先重新检查远端记录"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		result.Message = "客户端操作超时或取消，请重新检查远端记录"
	}
	return result
}

// requestIDFromError 只提取云 SDK 的结构化请求标识，不回传原始错误正文。
func requestIDFromError(err error) string {
	var stringID interface{ GetRequestId() string }
	if errors.As(err, &stringID) {
		return stringID.GetRequestId()
	}
	var pointerID interface{ GetRequestId() *string }
	if errors.As(err, &pointerID) {
		return ptrValue(pointerID.GetRequestId())
	}
	var requestID interface{ RequestID() string }
	if errors.As(err, &requestID) {
		return requestID.RequestID()
	}
	var huaweiError *sdkerr.ServiceResponseError
	if errors.As(err, &huaweiError) {
		return huaweiError.RequestId
	}
	var baiduError *bce.BceServiceError
	if errors.As(err, &baiduError) {
		return baiduError.RequestId
	}
	return ""
}

// ptrValue 安全读取 SDK optional 字段。
func ptrValue[T any](p *T) (v T) {
	if p != nil {
		return *p
	}
	return v
}

// contextCheck 在不支持 context 的 SDK 调用前后检查生命周期。
func contextCheck(ctx context.Context) error { return ctx.Err() }
