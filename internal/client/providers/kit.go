package providers

import (
	"fmt"
	"strings"

	"github.com/https-cert/deploy/pb/deployPB"
)

// ReadyCatalog 返回非空 READY 资源目录。
func ReadyCatalog(resources []DeploymentResource) ResourceCatalogResult {
	return ResourceCatalogResult{Resources: resources, Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY}
}

// EmptyCatalog 返回 EMPTY 资源目录。
func EmptyCatalog() ResourceCatalogResult {
	return ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY}
}

// CatalogFromResources 按资源数量返回 READY 或 EMPTY 目录。
func CatalogFromResources(resources []DeploymentResource) ResourceCatalogResult {
	if len(resources) == 0 {
		return EmptyCatalog()
	}
	return ReadyCatalog(resources)
}

// PartialCatalog 返回部分成功加载的目录状态。
func PartialCatalog(resources []DeploymentResource) ResourceCatalogResult {
	return ResourceCatalogResult{Resources: resources, Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL}
}

// UnavailableCatalog 返回带诊断错误的 UNAVAILABLE 目录。
func UnavailableCatalog(err error) ResourceCatalogResult {
	return ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE, Error: err}
}

// NotConfiguredCatalog 返回未配置状态目录。
func NotConfiguredCatalog() ResourceCatalogResult {
	return ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED}
}

// EncodeTargetRef 将稳定身份片段编码为不透明 targetRef。
// 片段不得包含空白或分隔符；编码后结果对后端仍是不透明字符串。
func EncodeTargetRef(parts ...string) (string, error) {
	if len(parts) == 0 {
		return "", fmt.Errorf("targetRef 片段不能为空")
	}
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			return "", fmt.Errorf("targetRef 片段不能为空")
		}
		if trimmed != part {
			return "", fmt.Errorf("targetRef 片段不能包含首尾空白")
		}
		if strings.ContainsAny(part, " \x00\n\r\t|") {
			return "", fmt.Errorf("targetRef 片段包含非法字符")
		}
		normalized = append(normalized, part)
	}
	return strings.Join(normalized, "|"), nil
}

// DecodeTargetRef 按固定分隔符解析 targetRef 片段。
func DecodeTargetRef(ref string, expectedParts int) ([]string, error) {
	if strings.TrimSpace(ref) != ref || ref == "" {
		return nil, fmt.Errorf("targetRef 无效")
	}
	parts := strings.Split(ref, "|")
	if expectedParts > 0 && len(parts) != expectedParts {
		return nil, fmt.Errorf("targetRef 片段数量不匹配: got=%d want=%d", len(parts), expectedParts)
	}
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("targetRef 片段不能为空")
		}
	}
	return parts, nil
}
