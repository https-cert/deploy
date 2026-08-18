package lecdn

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// apiEnvelope 是 LeCDN 统一业务响应外层。
type apiEnvelope struct {
	Code    int             `json:"code"`    // Code 为 0 或 200 时表示业务成功。
	Message string          `json:"message"` // Message 是业务失败诊断信息。
	Data    json.RawMessage `json:"data"`    // Data 保存具体接口响应。
}

// pageResult 是 LeCDN 通用分页响应。
type pageResult[T any] struct {
	Items       []T `json:"items"`        // Items 是当前页记录。
	Total       int `json:"total"`        // Total 是全部记录数。
	CurrentPage int `json:"current_page"` // CurrentPage 是响应页码。
	PageSize    int `json:"page_size"`    // PageSize 是响应每页数量。
}

// siteItem 保存发现域名所需的站点字段。
type siteItem struct {
	ID           flexibleID `json:"id"`            // ID 是站点稳定标识。
	DomainName   any        `json:"domain_name"`   // DomainName 是站点主域名展示值。
	DomainStatus string     `json:"domain_status"` // DomainStatus 是站点运行状态。
}

// siteDomainItem 保存证书引用聚合所需的站点域名字段。
type siteDomainItem struct {
	ID                flexibleID `json:"id"`                 // ID 是站点域名记录标识。
	SiteID            flexibleID `json:"site_id"`            // SiteID 是所属站点标识。
	DomainName        string     `json:"domain_name"`        // DomainName 是证书服务域名。
	CertificateEnable bool       `json:"certificate_enable"` // CertificateEnable 表示该域名启用证书。
	CertificateID     flexibleID `json:"certificate_id"`     // CertificateID 是域名当前引用的证书标识。
}

// syncStatus 保存站点边缘同步状态。
type syncStatus struct {
	Status string     `json:"status"`  // Status 是 wait、running、success 或 fail。
	TaskID flexibleID `json:"task_id"` // TaskID 是可用于诊断的同步任务标识。
}

// certificateResource 是一个 certificate_id 的全部站点和域名引用。
type certificateResource struct {
	CertificateID string              // CertificateID 是被原地更新的证书标识。
	Domains       map[string]struct{} // Domains 保存证书覆盖要求的规范化域名。
	SiteIDs       map[string]struct{} // SiteIDs 保存更新后必须强制同步的站点。
}

// apiError 保存 LeCDN 请求的重试分类和脱敏诊断信息。
type apiError struct {
	Operation string // Operation 是失败的控制面操作。
	Status    int    // Status 是 HTTP 状态码，传输失败时为零。
	Code      int    // Code 是 LeCDN 业务响应码。
	RequestID string // RequestID 是 LeCDN 或网关请求编号。
	Retryable bool   // Retryable 表示重试是否可能恢复。
	Cause     error  // Cause 保存底层网络或解析错误。
}

// Error 返回不包含 Token、证书或完整响应体的本地诊断。
func (e *apiError) Error() string {
	if e == nil {
		return ""
	}
	if e.Status > 0 {
		return fmt.Sprintf("LeCDN %s 失败: HTTP %d, code=%d", e.Operation, e.Status, e.Code)
	}
	return fmt.Sprintf("LeCDN %s 失败", e.Operation)
}

// Unwrap 暴露底层错误供 errors.Is 和 errors.As 使用。
func (e *apiError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// flexibleID 接受 LeCDN 接口中的数字或字符串 ID。
type flexibleID string

// UnmarshalJSON 将数字或字符串 ID 统一归一化为字符串。
func (id *flexibleID) UnmarshalJSON(data []byte) error {
	if id == nil {
		return errors.New("LeCDN ID 接收器不能为空")
	}
	var stringValue string
	if err := json.Unmarshal(data, &stringValue); err == nil {
		*id = flexibleID(strings.TrimSpace(stringValue))
		return nil
	}
	var number json.Number
	if err := json.Unmarshal(data, &number); err != nil {
		return fmt.Errorf("LeCDN ID 格式无效: %w", err)
	}
	*id = flexibleID(number.String())
	return nil
}
