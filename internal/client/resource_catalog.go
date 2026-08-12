package client

import (
	"context"
	"sort"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pkg/logger"
)

const resourceCatalogTimeout = 50 * time.Second

// providerResourceBusinesses 返回支持实时发现的云厂商业务。
func providerResourceBusinesses(providerName string) []deployPB.ExecuteBusinesType {
	switch providerName {
	case config.ProviderAliyun:
		return []deployPB.ExecuteBusinesType{
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN,
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_DCDN,
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ESA,
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_OSS_CUSTOM_DOMAIN,
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CLB,
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ALB,
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_NLB,
		}
	case config.ProviderTencentCloud:
		return []deployPB.ExecuteBusinesType{
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN,
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_EDGEONE,
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_COS,
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CLB,
		}
	case config.ProviderQiniu:
		return []deployPB.ExecuteBusinesType{
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN,
			deployPB.ExecuteBusinesType_EXECUTE_BUSINES_DCDN,
		}
	default:
		return nil
	}
}

// discoverProviderDirectory 构建能力目录，并按请求只扫描一个明确的云产品。
func discoverProviderDirectory(parent context.Context, providerInfos []ProviderInfo, request *deployPB.GetProviderRequest) []*deployPB.GetProviderResponse_Provider {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, resourceCatalogTimeout)
	defer cancel()

	response := make([]*deployPB.GetProviderResponse_Provider, len(providerInfos))
	for providerIndex, providerInfo := range providerInfos {
		provider := &deployPB.GetProviderResponse_Provider{Name: providerInfo.Name, Remark: providerInfo.Remark}
		response[providerIndex] = provider
		businessTypes := providerResourceBusinesses(providerInfo.Name)
		provider.Businesses = make([]*deployPB.GetProviderResponse_Provider_Business, len(businessTypes))
		for businessIndex, businessType := range businessTypes {
			provider.Businesses[businessIndex] = &deployPB.GetProviderResponse_Provider_Business{
				ExecuteBusinesType: businessType,
			}
			if shouldDiscoverProviderBusiness(request, providerInfo.Name, businessType) {
				provider.Businesses[businessIndex] = discoverProviderBusiness(ctx, providerInfo.Name, businessType)
			}
		}
	}
	return response
}

// shouldDiscoverProviderBusiness 判断请求是否精确指向当前资源业务。
func shouldDiscoverProviderBusiness(request *deployPB.GetProviderRequest, providerName string, businessType deployPB.ExecuteBusinesType) bool {
	return request != nil &&
		request.GetIncludeResources() &&
		request.GetProvider() == providerName &&
		request.GetExecuteBusinesType() == businessType
}

// discoverProviderBusiness 扫描一个产品，失败时只影响当前业务。
func discoverProviderBusiness(ctx context.Context, providerName string, businessType deployPB.ExecuteBusinesType) *deployPB.GetProviderResponse_Provider_Business {
	business := &deployPB.GetProviderResponse_Provider_Business{
		ExecuteBusinesType: businessType,
		ResourceStatus:     deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE,
	}
	adapter, err := newDeploymentResourceProvider(providerName, businessType)
	if err != nil {
		logger.Error("初始化动态资源适配器失败", "error", err, "provider", providerName, "business", businessType.String())
		return business
	}
	catalog := adapter.DiscoverResources(ctx, businessType)
	if catalog.Error != nil {
		logger.Error("读取动态资源目录失败", "error", catalog.Error, "provider", providerName, "business", businessType.String(), "status", catalog.Status.String())
	}
	business.ResourceStatus = catalog.Status
	business.Resources = publicDeployResources(catalog.Resources)
	return business
}

// publicDeployResources 丢弃真实资源定位字段，仅保留 protobuf 公共展示字段。
func publicDeployResources(resources []providers.DeploymentResource) []*deployPB.DeployResource {
	result := make([]*deployPB.DeployResource, 0, len(resources))
	for _, resource := range resources {
		result = append(result, &deployPB.DeployResource{
			TargetRef:    resource.TargetRef,
			Label:        resource.Label,
			Domain:       resource.Domain,
			Domains:      append([]string(nil), resource.Domains...),
			Protocol:     resource.Protocol,
			Status:       resource.Status,
			Group:        resource.Group,
			Region:       resource.Region,
			Port:         uint32(max(resource.ListenerPort, 0)),
			Availability: resource.Availability,
		})
	}
	sort.SliceStable(result, func(left, right int) bool {
		leftReady := result[left].Availability == deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
		rightReady := result[right].Availability == deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
		if leftReady != rightReady {
			return leftReady
		}
		return result[left].Label < result[right].Label
	})
	return result
}
