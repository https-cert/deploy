package btpanel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/idna"
)

// DiscoverBTPanelWebsiteResources 动态读取全部宝塔网站的脱敏目录。
func DiscoverBTPanelWebsiteResources(ctx context.Context) ([]BTPanelWebsiteResource, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	discoveryContext, cancel := context.WithTimeout(ctx, btPanelDiscoveryTimeout)
	defer cancel()

	records, err := loadBTPanelWebsiteRecords(discoveryContext)
	if err != nil {
		return nil, err
	}
	resources := make([]BTPanelWebsiteResource, 0, len(records))
	for _, record := range records {
		resource := record.Resource
		resource.Domains = append([]string(nil), record.Resource.Domains...)
		resources = append(resources, resource)
	}
	return resources, nil
}

// TestBTPanelWebsiteConnection 只读确认 targetRef 对应网站仍存在并能读取 SSL 配置。
func TestBTPanelWebsiteConnection(ctx context.Context, targetRef string) error {
	targetRef = strings.TrimSpace(targetRef)
	if targetRef == "" {
		return fmt.Errorf("宝塔网站 targetRef 不能为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	discoveryContext, cancel := context.WithTimeout(ctx, btPanelDiscoveryTimeout)
	defer cancel()

	apiURL, apiKey, insecureSkipVerify, err := getBTPanelConfig(ctx)
	if err != nil {
		return err
	}
	record, err := findBTPanelWebsiteByTargetRef(discoveryContext, targetRef)
	if err != nil {
		return err
	}
	if record.Resource.Status == btPanelStatusStopped {
		return fmt.Errorf("宝塔网站未运行")
	}
	if _, err := getBTPanelWebsiteSSL(discoveryContext, apiURL, apiKey, insecureSkipVerify, record.SiteName); err != nil {
		return fmt.Errorf("读取宝塔网站 SSL 配置失败: %w", err)
	}
	return nil
}

// listBTPanelWebsiteSummaries 分页读取全部宝塔网站。
func listBTPanelWebsiteSummaries(ctx context.Context, apiURL, apiKey string, insecureSkipVerify bool) ([]btPanelWebsiteSummary, error) {
	websites := make([]btPanelWebsiteSummary, 0)
	for page := 1; page <= btPanelWebsiteMaxPages; page++ {
		var pageData btPanelWebsitePage
		if err := requestBTPanelAPI(ctx, apiURL, apiKey, insecureSkipVerify, btPanelDataPath, url.Values{
			"action": {"getData"},
			"table":  {"sites"},
			"type":   {"-1"},
			"p":      {strconv.Itoa(page)},
			"limit":  {strconv.Itoa(btPanelWebsitePageSize)},
		}, &pageData); err != nil {
			return nil, fmt.Errorf("读取宝塔网站列表失败: %w", err)
		}
		if err := validateBTPanelReadEnvelope(pageData.Status, pageData.Msg, "读取宝塔网站列表"); err != nil {
			return nil, err
		}
		websites = append(websites, pageData.Data...)
		if len(pageData.Data) < btPanelWebsitePageSize {
			return websites, nil
		}
	}
	return nil, fmt.Errorf("宝塔网站分页超过安全上限")
}

// loadBTPanelWebsiteRecords 读取全部宝塔网站及其域名，并用有限并发控制面板压力。
func loadBTPanelWebsiteRecords(ctx context.Context) ([]btPanelWebsiteRecord, error) {
	apiURL, apiKey, insecureSkipVerify, err := getBTPanelConfig(ctx)
	if err != nil {
		return nil, err
	}
	websites, err := listBTPanelWebsiteSummaries(ctx, apiURL, apiKey, insecureSkipVerify)
	if err != nil {
		return nil, err
	}
	if len(websites) == 0 {
		return nil, nil
	}
	for _, website := range websites {
		if website.ID == 0 || strings.TrimSpace(website.Name) == "" || strings.TrimSpace(website.AddTime) == "" {
			return nil, fmt.Errorf("宝塔网站缺少生成稳定引用所需的身份字段")
		}
	}

	workerCount := btPanelWebsiteDomainWorkers
	if len(websites) < workerCount {
		workerCount = len(websites)
	}
	workerContext, cancel := context.WithCancel(ctx)
	defer cancel()
	type websiteJob struct {
		Index   int                   // Index 是结果数组中的稳定位置。
		Website btPanelWebsiteSummary // Website 是待加载域名的网站。
	}
	jobs := make(chan websiteJob)
	records := make([]btPanelWebsiteRecord, len(websites))
	valid := make([]bool, len(websites))
	errorChannel := make(chan error, 1)
	var waitGroup sync.WaitGroup
	for worker := 0; worker < workerCount; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for job := range jobs {
				domains, loadErr := loadBTPanelWebsiteDomains(workerContext, apiURL, apiKey, insecureSkipVerify, job.Website)
				if loadErr != nil {
					select {
					case errorChannel <- loadErr:
						cancel()
					default:
					}
					continue
				}
				if len(domains) == 0 {
					continue
				}
				primaryDomain := normalizeBTPanelDomain(job.Website.Name)
				if primaryDomain == "" {
					primaryDomain = domains[0]
				}
				label := firstBTPanelText(job.Website.Remark, job.Website.Legacy, primaryDomain)
				records[job.Index] = btPanelWebsiteRecord{
					ID:       job.Website.ID,
					SiteName: strings.TrimSpace(job.Website.Name),
					Resource: BTPanelWebsiteResource{
						TargetRef: buildBTPanelWebsiteTargetRef(apiURL, job.Website),
						Label:     label,
						Domain:    primaryDomain,
						Domains:   domains,
						Protocol:  btPanelWebsiteProtocol(job.Website.SSL),
						Status:    btPanelWebsiteStatus(job.Website.Status),
					},
				}
				valid[job.Index] = true
			}
		}()
	}
sendJobs:
	for index, website := range websites {
		select {
		case jobs <- websiteJob{Index: index, Website: website}:
		case <-workerContext.Done():
			break sendJobs
		}
	}
	close(jobs)
	waitGroup.Wait()
	select {
	case loadErr := <-errorChannel:
		return nil, loadErr
	default:
	}

	filtered := make([]btPanelWebsiteRecord, 0, len(records))
	for index, record := range records {
		if valid[index] {
			filtered = append(filtered, record)
		}
	}
	return filtered, nil
}

// loadBTPanelWebsiteDomains 读取一个宝塔网站的域名并规范化、去重和排序。
func loadBTPanelWebsiteDomains(ctx context.Context, apiURL, apiKey string, insecureSkipVerify bool, website btPanelWebsiteSummary) ([]string, error) {
	var response btPanelWebsiteDomains
	if err := requestBTPanelAPI(ctx, apiURL, apiKey, insecureSkipVerify, btPanelSitePath, url.Values{
		"action": {"GetSiteDomains"},
		"id":     {strconv.FormatUint(website.ID, 10)},
	}, &response); err != nil {
		return nil, fmt.Errorf("读取宝塔网站域名失败: %w", err)
	}
	if err := validateBTPanelReadEnvelope(response.Status, response.Msg, "读取宝塔网站域名"); err != nil {
		return nil, err
	}
	domains := make([]string, 0, len(response.Domains)+1)
	seen := make(map[string]struct{}, len(response.Domains)+1)
	appendDomain := func(raw string) {
		domain := normalizeBTPanelDomain(raw)
		if domain == "" {
			return
		}
		if _, exists := seen[domain]; exists {
			return
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	appendDomain(website.Name)
	for _, domain := range response.Domains {
		appendDomain(domain.Name)
	}
	sort.Strings(domains)
	return domains, nil
}

// validateBTPanelReadEnvelope 拒绝只读接口返回的 status=false 错误包络，避免误判为空目录。
func validateBTPanelReadEnvelope(status *bool, message, operation string) error {
	if status == nil || *status {
		return nil
	}
	detail := strings.TrimSpace(message)
	if detail == "" {
		detail = "面板拒绝请求"
	}
	return &btPanelRequestError{Retryable: false, Cause: fmt.Errorf("%s失败: %s", operation, detail)}
}

// getBTPanelWebsiteSSL 读取指定宝塔网站的当前 SSL 状态和证书元数据。
func getBTPanelWebsiteSSL(ctx context.Context, apiURL, apiKey string, insecureSkipVerify bool, siteName string) (*btPanelWebsiteSSL, error) {
	var response btPanelWebsiteSSL
	if err := requestBTPanelAPI(ctx, apiURL, apiKey, insecureSkipVerify, btPanelSitePath, url.Values{
		"action":   {"GetSSL"},
		"siteName": {siteName},
	}, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// findBTPanelWebsiteByTargetRef 重新发现宝塔网站并要求 targetRef 唯一匹配。
func findBTPanelWebsiteByTargetRef(ctx context.Context, targetRef string) (*btPanelWebsiteRecord, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	discoveryContext, cancel := context.WithTimeout(ctx, btPanelDiscoveryTimeout)
	defer cancel()
	records, err := loadBTPanelWebsiteRecords(discoveryContext)
	if err != nil {
		return nil, err
	}
	var matched *btPanelWebsiteRecord
	for index := range records {
		if records[index].Resource.TargetRef != targetRef {
			continue
		}
		if matched != nil {
			return nil, fmt.Errorf("宝塔网站 targetRef 不唯一，请重新配置部署目标")
		}
		record := records[index]
		matched = &record
	}
	if matched == nil {
		return nil, fmt.Errorf("宝塔网站不存在或已重新创建，请重新配置部署目标")
	}
	return matched, nil
}

// buildBTPanelWebsiteTargetRef 根据实例、网站身份和创建时间生成稳定的不透明引用。
func buildBTPanelWebsiteTargetRef(apiURL string, website btPanelWebsiteSummary) string {
	identity := strings.Join([]string{
		"ansslCli",
		"EXECUTE_BUSINES_ANSSL_CLI_BT_PANEL_WEBSITE_CERT",
		normalizeBTPanelOrigin(apiURL),
		strconv.FormatUint(website.ID, 10),
		strings.TrimSpace(website.AddTime),
	}, "\x00")
	digest := sha256.Sum256([]byte(identity))
	return btPanelWebsiteTargetPrefix + hex.EncodeToString(digest[:12])
}

// normalizeBTPanelOrigin 规范化仅用于本地哈希的面板来源，不返回或记录该值。
func normalizeBTPanelOrigin(apiURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(apiURL))
	if err != nil {
		return strings.ToLower(strings.TrimRight(strings.TrimSpace(apiURL), "/"))
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	hostname := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		parsed.Host = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		parsed.Host = "[" + hostname + "]"
	} else {
		parsed.Host = hostname
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/")
}

// normalizeBTPanelDomain 将面板域名规范化为不带端口的小写 ASCII 主机名或 IP。
func normalizeBTPanelDomain(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	wildcard := strings.HasPrefix(value, "*.")
	if wildcard {
		value = strings.TrimPrefix(value, "*.")
	}
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil && parsed.Host != "" {
			value = parsed.Host
		}
	}
	if parsed, err := url.Parse("//" + value); err == nil && parsed.Hostname() != "" {
		value = parsed.Hostname()
	}
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" {
		return ""
	}
	if ip := net.ParseIP(value); ip != nil {
		if wildcard {
			return ""
		}
		return ip.String()
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return ""
	}
	normalized := strings.ToLower(strings.TrimSuffix(ascii, "."))
	if wildcard && normalized != "" {
		return "*." + normalized
	}
	return normalized
}

// btPanelWebsiteStatus 将宝塔数字或字符串状态转换为稳定运行状态。
func btPanelWebsiteStatus(raw json.RawMessage) string {
	value := strings.Trim(strings.TrimSpace(string(raw)), "\"")
	if value == "1" || strings.EqualFold(value, "running") {
		return btPanelStatusRunning
	}
	return btPanelStatusStopped
}

// btPanelWebsiteProtocol 将宝塔网站列表中的 SSL 标记转换为稳定协议名称。
func btPanelWebsiteProtocol(raw json.RawMessage) string {
	value := strings.Trim(strings.TrimSpace(string(raw)), "\"")
	if value != "" && value != "-1" && value != "0" && !strings.EqualFold(value, "false") && value != "null" {
		return btPanelProtocolHTTPS
	}
	return btPanelProtocolHTTP
}

// firstBTPanelText 返回首个非空的宝塔网站展示字段。
func firstBTPanelText(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return "宝塔网站"
}
