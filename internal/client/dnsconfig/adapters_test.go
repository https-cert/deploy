package dnsconfig

import (
	"context"
	"fmt"
	"testing"

	bd "github.com/baidubce/bce-sdk-go/services/dns"
	"github.com/https-cert/deploy/pb/deployPB"
	hw "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2/model"
	jd "github.com/jdcloud-api/jdcloud-sdk-go/services/domainservice/apis"
	jm "github.com/jdcloud-api/jdcloud-sdk-go/services/domainservice/models"
	tx "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
	vc "github.com/volcengine/volcengine-go-sdk/service/dns"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/request"
)

// mockCloud 保存模拟云状态，首个分页总有 100 条无关记录，目标位于次页。
type mockCloud struct {
	t        *testing.T // t 用于断言真实请求参数。
	created  bool       // created 表示远端已完成写入。
	creates  int        // creates 统计写入次数，验证幂等性。
	conflict bool       // conflict 在次页放入特殊线路冲突。
	readErr  error      // readErr 模拟查询权限、限流和超时。
	writeErr error      // writeErr 模拟新增权限或响应丢失。
}

// testRecord 使用单独委派的子区，防止实现误删主机记录中的标签。
func testRecord() *deployPB.DnsRecord {
	return &deployPB.DnsRecord{Zone: "api.example.com", Fqdn: "_acme-challenge.api.example.com", Host: "_acme-challenge", Value: "target.example.net", Fingerprint: "snapshot"}
}

// rows 在第二页才返回目标，证明适配器没有漏读分页冲突。
func (m *mockCloud) rows(page int) []Entry {
	if page == 1 {
		entries := make([]Entry, 100)
		for i := range entries {
			entries[i] = Entry{Host: fmt.Sprintf("unrelated%d", i), Type: "TXT", Value: "unrelated", Enabled: true, DefaultLine: true}
		}
		return entries
	}
	if m.created || m.conflict {
		return []Entry{{Host: "_acme-challenge", Type: "CNAME", Value: "target.example.net", Enabled: true, DefaultLine: !m.conflict}}
	}
	return []Entry{}
}

// create 验证所有厂商都传递 TTL 600 和精确值，保存远端写入状态。
func (m *mockCloud) create(host, value, kind string, ttl int) error {
	m.t.Helper()
	if host != "_acme-challenge" || Normalize(value) != "target.example.net" || kind != "CNAME" || ttl != 600 {
		m.t.Fatalf("写入请求错误：%s %s %s %d", host, value, kind, ttl)
	}
	m.creates++
	if m.writeErr != nil {
		return m.writeErr
	}
	m.created = true
	return nil
}

// mockAli 模拟 AliDNS RPC 响应。
type mockAli struct {
	m *mockCloud /* m 保存远端状态。 */
}

// Call 校验精确查询与默认线路。
func (a mockAli) Call(_ context.Context, action string, params map[string]string) (map[string]any, string, error) {
	if params["DomainName"] != "api.example.com" {
		a.m.t.Fatal("托管区错误")
	}
	if action == "AddDomainRecord" {
		if params["Line"] != "default" {
			a.m.t.Fatal("非默认线路")
		}
		err := a.m.create(params["RR"], params["Value"], params["Type"], 600)
		if params["TTL"] != "600" {
			a.m.t.Fatal("TTL 错误")
		}
		return map[string]any{}, "ali-request", err
	}
	if a.m.readErr != nil {
		return nil, "", a.m.readErr
	}
	if action == "DescribeDomainInfo" {
		return map[string]any{"DomainName": "API.EXAMPLE.COM."}, "", nil
	}
	if params["RRKeyWord"] != "_acme-challenge" || params["Type"] != "" || params["Line"] != "" {
		a.m.t.Fatal("漏查全部记录类型或线路")
	}
	page := 1
	if params["PageNumber"] == "2" {
		page = 2
	}
	records := []any{}
	for _, e := range a.m.rows(page) {
		line := "default"
		if !e.DefaultLine {
			line = "telecom"
		}
		records = append(records, map[string]any{"RR": e.Host, "Value": e.Value, "Type": e.Type, "Status": "ENABLE", "Line": line})
	}
	return map[string]any{"DomainRecords": map[string]any{"Record": records}}, "", nil
}

// mockBaidu 模拟 marker 分页和百度启用状态。
type mockBaidu struct {
	m *mockCloud /* m 保存远端状态。 */
}

// ListZone 模拟下一页才出现精确区。
func (a mockBaidu) ListZone(r *bd.ListZoneRequest) (*bd.ListZoneResponse, error) {
	if a.m.readErr != nil {
		return nil, a.m.readErr
	}
	if r.Marker == "" {
		return &bd.ListZoneResponse{IsTruncated: true, NextMarker: "next"}, nil
	}
	return &bd.ListZoneResponse{Zones: []bd.Zone{{Name: "api.example.com"}}}, nil
}

// ListRecord 模拟所有线路的查询。
func (a mockBaidu) ListRecord(zone string, r *bd.ListRecordRequest) (*bd.ListRecordResponse, error) {
	if a.m.readErr != nil {
		return nil, a.m.readErr
	}
	if zone != "api.example.com" || r.Rr != "_acme-challenge" {
		a.m.t.Fatal("区或记录错误")
	}
	page := 1
	if r.Marker != "" {
		page = 2
	}
	reply := &bd.ListRecordResponse{IsTruncated: page == 1, NextMarker: "next"}
	for _, e := range a.m.rows(page) {
		line := "default"
		if !e.DefaultLine {
			line = "telecom"
		}
		reply.Records = append(reply.Records, bd.Record{Rr: e.Host, Type: e.Type, Value: e.Value, Status: "enable", Line: line})
	}
	return reply, nil
}

// CreateRecord 验证百度幂等 token 和默认线路。
func (a mockBaidu) CreateRecord(zone string, r *bd.CreateRecordRequest, token string) (string, error) {
	if zone != "api.example.com" || token != "snapshot" || r.Line != nil {
		a.m.t.Fatal("百度写入参数错误")
	}
	return "baidu-request", a.m.create(r.Rr, r.Value, r.Type, int(ptrValue(r.Ttl)))
}

// mockTencent 模拟 DNSPod 官方 SDK。
type mockTencent struct {
	m *mockCloud /* m 保存远端状态。 */
}

// DescribeDomainWithContext 校验委派区访问。
func (a mockTencent) DescribeDomainWithContext(_ context.Context, r *tx.DescribeDomainRequest) (*tx.DescribeDomainResponse, error) {
	if a.m.readErr != nil {
		return nil, a.m.readErr
	}
	if ptrValue(r.Domain) != "api.example.com" {
		a.m.t.Fatal("腾讯域名错误")
	}
	return &tx.DescribeDomainResponse{Response: &tx.DescribeDomainResponseParams{DomainInfo: &tx.DomainInfo{Domain: new("api.example.com")}}}, nil
}

// DescribeRecordListWithContext 返回第二页的目标，保留线路 ID。
func (a mockTencent) DescribeRecordListWithContext(_ context.Context, r *tx.DescribeRecordListRequest) (*tx.DescribeRecordListResponse, error) {
	if a.m.readErr != nil {
		return nil, a.m.readErr
	}
	if ptrValue(r.Subdomain) != "_acme-challenge" || r.RecordType != nil || r.RecordLine != nil {
		a.m.t.Fatal("腾讯查询过滤错误")
	}
	reply := &tx.DescribeRecordListResponse{Response: &tx.DescribeRecordListResponseParams{}}
	for _, e := range a.m.rows(int(ptrValue(r.Offset)/100) + 1) {
		line := "0"
		if !e.DefaultLine {
			line = "10"
		}
		reply.Response.RecordList = append(reply.Response.RecordList, &tx.RecordListItem{Name: new(e.Host), Type: new(e.Type), Value: new(e.Value), Status: new("ENABLE"), LineId: new(line)})
	}
	return reply, nil
}

// CreateRecordWithContext 验证 DNSPod 默认线路和 TTL。
func (a mockTencent) CreateRecordWithContext(_ context.Context, r *tx.CreateRecordRequest) (*tx.CreateRecordResponse, error) {
	if ptrValue(r.RecordLine) != "默认" {
		a.m.t.Fatal("腾讯默认线路错误")
	}
	err := a.m.create(ptrValue(r.SubDomain), ptrValue(r.Value), ptrValue(r.RecordType), int(ptrValue(r.TTL)))
	return &tx.CreateRecordResponse{Response: &tx.CreateRecordResponseParams{RequestId: new("tx-request")}}, err
}

// mockHuawei 模拟公网 Zone 和含线路 RecordSet 查询。
type mockHuawei struct {
	m *mockCloud /* m 保存远端状态。 */
}

// ListPublicZones 验证分页后的精确区。
func (a mockHuawei) ListPublicZones(r *hw.ListPublicZonesRequest) (*hw.ListPublicZonesResponse, error) {
	if a.m.readErr != nil {
		return nil, a.m.readErr
	}
	zones := []hw.PublicZoneResp{}
	if ptrValue(r.Offset) == 0 {
		zones = make([]hw.PublicZoneResp, 100)
	} else {
		zones = []hw.PublicZoneResp{{Name: new("api.example.com."), Id: new("zone-id"), Status: new("ACTIVE")}}
	}
	return &hw.ListPublicZonesResponse{Zones: &zones}, nil
}

// ListRecordSetsWithLine 保留特殊线路而不过滤默认线路。
func (a mockHuawei) ListRecordSetsWithLine(r *hw.ListRecordSetsWithLineRequest) (*hw.ListRecordSetsWithLineResponse, error) {
	if a.m.readErr != nil {
		return nil, a.m.readErr
	}
	if ptrValue(r.ZoneId) != "zone-id" || ptrValue(r.Name) != "_acme-challenge.api.example.com." {
		a.m.t.Fatal("华为区或记录错误")
	}
	records := []hw.QueryRecordSetWithLineAndTagsResp{}
	for _, e := range a.m.rows(int(ptrValue(r.Offset)/100) + 1) {
		line := "default"
		if !e.DefaultLine {
			line = "telecom"
		}
		values := []string{e.Value}
		host := e.Host
		if host == "_acme-challenge" {
			host += ".api.example.com."
		}
		records = append(records, hw.QueryRecordSetWithLineAndTagsResp{Name: new(host), Type: new(e.Type), Records: &values, Status: new("ACTIVE"), Line: new(line)})
	}
	return &hw.ListRecordSetsWithLineResponse{Recordsets: &records}, nil
}

// CreateRecordSet 验证完整 DNS 名和末尾点。
func (a mockHuawei) CreateRecordSet(r *hw.CreateRecordSetRequest) (*hw.CreateRecordSetResponse, error) {
	if r.ZoneId != "zone-id" || r.Body.Name != "_acme-challenge.api.example.com." || r.Body.Records[0] != "target.example.net." {
		a.m.t.Fatal("华为写入参数错误")
	}
	err := a.m.create("_acme-challenge", r.Body.Records[0], r.Body.Type, int(ptrValue(r.Body.Ttl)))
	return &hw.CreateRecordSetResponse{}, err
}

// mockJD 模拟 Domainservice 分页。
type mockJD struct {
	m *mockCloud /* m 保存远端状态。 */
}

// DescribeDomains 只有第二页包含精确区。
func (a mockJD) DescribeDomains(r *jd.DescribeDomainsRequest) (*jd.DescribeDomainsResponse, error) {
	if a.m.readErr != nil {
		return nil, a.m.readErr
	}
	reply := &jd.DescribeDomainsResponse{Result: jd.DescribeDomainsResult{TotalPage: 2}}
	if r.PageNumber == 2 {
		reply.Result.DataList = []jm.DomainInfo{{Id: 42, DomainName: "api.example.com"}}
	}
	return reply, nil
}

// DescribeResourceRecord 返回所有线路与状态。
func (a mockJD) DescribeResourceRecord(r *jd.DescribeResourceRecordRequest) (*jd.DescribeResourceRecordResponse, error) {
	if a.m.readErr != nil {
		return nil, a.m.readErr
	}
	if r.DomainId != "42" || ptrValue(r.Search) != "_acme-challenge" {
		a.m.t.Fatal("京东查询参数错误")
	}
	reply := &jd.DescribeResourceRecordResponse{Result: jd.DescribeResourceRecordResult{TotalPage: 2}}
	for _, e := range a.m.rows(ptrValue(r.PageNumber)) {
		view := -1
		if !e.DefaultLine {
			view = 1
		}
		reply.Result.DataList = append(reply.Result.DataList, jm.RRInfo{HostRecord: e.Host, HostValue: e.Value, Type: e.Type, ViewValue: []int{view}, ResolvingStatus: "2"})
	}
	return reply, nil
}

// CreateResourceRecord 验证默认线路和 TTL。
func (a mockJD) CreateResourceRecord(r *jd.CreateResourceRecordRequest) (*jd.CreateResourceRecordResponse, error) {
	if r.DomainId != "42" || r.Req.ViewValue != -1 {
		a.m.t.Fatal("京东新增参数错误")
	}
	err := a.m.create(r.Req.HostRecord, r.Req.HostValue, r.Req.Type, r.Req.Ttl)
	return &jd.CreateResourceRecordResponse{RequestID: "jd-request"}, err
}

// mockVolc 模拟上下文感知 DNS SDK。
type mockVolc struct {
	m *mockCloud /* m 保存远端状态。 */
}

// ListZonesWithContext 只有次页有精确域名。
func (a mockVolc) ListZonesWithContext(_ volcengine.Context, r *vc.ListZonesInput, _ ...request.Option) (*vc.ListZonesOutput, error) {
	if a.m.readErr != nil {
		return nil, a.m.readErr
	}
	reply := &vc.ListZonesOutput{}
	if ptrValue(r.PageNumber) == 1 {
		reply.Zones = make([]*vc.ZoneForListZonesOutput, 100)
	} else {
		reply.Zones = []*vc.ZoneForListZonesOutput{{ZoneName: new("api.example.com"), ZID: new(int32(42))}}
	}
	return reply, nil
}

// ListRecordsWithContext 保留启用和线路字段。
func (a mockVolc) ListRecordsWithContext(_ volcengine.Context, r *vc.ListRecordsInput, _ ...request.Option) (*vc.ListRecordsOutput, error) {
	if a.m.readErr != nil {
		return nil, a.m.readErr
	}
	if ptrValue(r.ZID) != 42 || ptrValue(r.Host) != "_acme-challenge" {
		a.m.t.Fatal("火山查询参数错误")
	}
	reply := &vc.ListRecordsOutput{}
	for _, e := range a.m.rows(int(ptrValue(r.PageNumber))) {
		line := "default"
		if !e.DefaultLine {
			line = "telecom"
		}
		reply.Records = append(reply.Records, &vc.RecordForListRecordsOutput{Host: new(e.Host), Type: new(e.Type), Value: new(e.Value), Enable: new(true), Line: new(line)})
	}
	return reply, nil
}

// CreateRecordWithContext 验证默认线路和 TTL。
func (a mockVolc) CreateRecordWithContext(_ volcengine.Context, r *vc.CreateRecordInput, _ ...request.Option) (*vc.CreateRecordOutput, error) {
	if ptrValue(r.ZID) != 42 || ptrValue(r.Line) != "default" {
		a.m.t.Fatal("火山新增参数错误")
	}
	err := a.m.create(ptrValue(r.Host), ptrValue(r.Value), ptrValue(r.Type), int(ptrValue(r.TTL)))
	return &vc.CreateRecordOutput{}, err
}

// mockBackendFactory 使用相同场景验证六家厂商映射，不触碰真实账户。
func mockBackendFactory(name string, m *mockCloud) Backend {
	switch name {
	case "aliyun":
		return &aliyunBackend{mockAli{m}}
	case "tencent":
		return &tencentBackend{mockTencent{m}}
	case "huawei":
		return &huaweiBackend{api: mockHuawei{m}}
	case "baidu":
		return &baiduBackend{mockBaidu{m}}
	case "jdcloud":
		return &jdBackend{mockJD{m}, "cn-north-1"}
	default:
		return &volcBackend{mockVolc{m}}
	}
}

// TestProviderFlows 覆盖六家托管区、分页、创建回读和重复点击。
func TestProviderFlows(t *testing.T) {
	for _, name := range []string{"aliyun", "tencent", "huawei", "baidu", "jdcloud", "volcengine"} {
		t.Run(name, func(t *testing.T) {
			m := &mockCloud{t: t}
			backend := mockBackendFactory(name, m)
			r := testRecord()
			checked := Operate(context.Background(), backend, r, false)
			if checked.Status != deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_READY || m.creates != 0 {
				t.Fatal("只读检查产生写入", checked)
			}
			created := Operate(context.Background(), backend, r, true)
			if created.Status != deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_CREATED || m.creates != 1 {
				t.Fatal("创建或回读失败", created)
			}
			again := Operate(context.Background(), backend, r, true)
			if again.Status != deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_ALREADY_EXISTS || m.creates != 1 {
				t.Fatal("重复创建", again)
			}
			m.created = false
			m.conflict = true
			conflict := Operate(context.Background(), backend, r, true)
			if conflict.Status != deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_CONFLICT || m.creates != 1 {
				t.Fatal("漏读次页线路冲突", conflict)
			}
		})
	}
}

// TestProviderErrors 验证无读取权限、无新增权限、限流和超时均保守返回且脱敏。
func TestProviderErrors(t *testing.T) {
	for _, name := range []string{"aliyun", "tencent", "huawei", "baidu", "jdcloud", "volcengine"} {
		t.Run(name, func(t *testing.T) {
			m := &mockCloud{t: t, readErr: fmt.Errorf("403 forbidden secret-value")}
			backend := mockBackendFactory(name, m)
			if got := Operate(context.Background(), backend, testRecord(), true); got.Status != deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_PERMISSION_DENIED || m.creates != 0 {
				t.Fatal(got)
			}
			m.readErr = nil
			m.writeErr = fmt.Errorf("403 forbidden secret-value")
			if got := Operate(context.Background(), backend, testRecord(), true); got.Status != deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_PERMISSION_DENIED {
				t.Fatal(got)
			}
			m.writeErr = context.DeadlineExceeded
			if got := Operate(context.Background(), backend, testRecord(), true); got.Status != deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_UNCONFIRMED {
				t.Fatal(got)
			}
			m.readErr = fmt.Errorf("throttled secret-value")
			m.writeErr = nil
			if got := Operate(context.Background(), backend, testRecord(), false); got.Status != deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_FAILED || got.Message == m.readErr.Error() {
				t.Fatal("限流或脱敏错误", got)
			}
		})
	}
}
