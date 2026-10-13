package dnsconfig

import (
	"context"
	"testing"

	deployPB "github.com/https-cert/deploy/pb/deployPB"
)

// TestRecordConflicts 对同名不同类型、值、停用和线路做严格冲突判定。
func TestRecordConflicts(t *testing.T) {
	record := testRecord()
	identical := Entry{Host: "_ACME-CHALLENGE.", Type: "cname", Value: "TARGET.EXAMPLE.NET.", Enabled: true, DefaultLine: true}
	if Classify([]Entry{identical}, record) != deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_ALREADY_EXISTS {
		t.Fatal("规范化相同记录未识别")
	}
	changes := []Entry{identical, identical, identical, identical}
	changes[0].Type = "TXT"
	changes[1].Value = "other.net"
	changes[2].Enabled = false
	changes[3].DefaultLine = false
	for _, entry := range changes {
		if Classify([]Entry{identical, entry}, record) != deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_CONFLICT {
			t.Fatal("漏判冲突", entry)
		}
	}
	record.Zone = "ample.com"
	backend := mockBackendFactory("aliyun", &mockCloud{t: t})
	if Operate(context.Background(), backend, record, true).Status != deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_FAILED {
		t.Fatal("允许越过托管区边界")
	}
}

// lostReplyBackend 模拟创建成功后 HTTP 响应丢失。
type lostReplyBackend struct {
	Backend            /* Backend 提供实际模拟云查询。 */
	cloud   *mockCloud /* cloud 保留已写入的远端状态。 */
}

// Create 写入已生效，但向调用方返回超时。
func (b lostReplyBackend) Create(ctx context.Context, zone string, record *deployPB.DnsRecord) (string, error) {
	if _, err := b.Backend.Create(ctx, zone, record); err != nil {
		return "", err
	}
	return "lost-request", context.DeadlineExceeded
}

// TestLostWriteReplyRetriedByRead 验证未知结果重试先查远端，无重复新增。
func TestLostWriteReplyRetriedByRead(t *testing.T) {
	m := &mockCloud{t: t}
	backend := lostReplyBackend{mockBackendFactory("aliyun", m), m}
	first := Operate(context.Background(), backend, testRecord(), true)
	if first.Status != deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_UNCONFIRMED || m.creates != 1 {
		t.Fatal(first)
	}
	second := Operate(context.Background(), backend, testRecord(), true)
	if second.Status != deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_ALREADY_EXISTS || m.creates != 1 {
		t.Fatal("重试重复写入", second)
	}
}

// TestAliyunMalformedReply 验证缺失记录数组不会被误认为空区并执行新增。
func TestAliyunMalformedReply(t *testing.T) {
	backend := &aliyunBackend{invalidAliReply{}}
	if _, err := backend.List(context.Background(), "api.example.com", testRecord()); err == nil {
		t.Fatal("格式异常被当作空解析")
	}
}

// invalidAliReply 模拟缺失记录容器的响应。
type invalidAliReply struct{}

// Call 返回不可用于冲突判断的正文。
func (invalidAliReply) Call(context.Context, string, map[string]string) (map[string]any, string, error) {
	return map[string]any{}, "", nil
}
