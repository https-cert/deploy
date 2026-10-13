package client

import (
	"context"
	"testing"
	"time"

	"github.com/https-cert/deploy/internal/client/dnsconfig"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
)

// blockingDNS 模拟写入已发出而 SDK 暂时不响应取消的情况。
type blockingDNS struct {
	started chan struct{} // started 通知新增请求已经进入云 SDK。
	release chan struct{} // release 控制 SDK 完成的时刻。
}

// FindZone 返回精确托管区，不依赖证书绑定。
func (b *blockingDNS) FindZone(context.Context, string) (string, error) {
	return "zone-id", nil
}

// List 返回空记录目录，确保测试进入新增路径。
func (b *blockingDNS) List(context.Context, string, *deployPB.DnsRecord) ([]dnsconfig.Entry, error) {
	return nil, nil
}

// Create 保持阻塞直到 SDK 自行收敛，故意忽略取消信号。
func (b *blockingDNS) Create(context.Context, string, *deployPB.DnsRecord) (string, error) {
	close(b.started)
	<-b.release
	return "create-id", nil
}

// TestDNSTimeoutRetainsLocksAndSlot 验证超时只回包一次，底层写入结束前不释放锁和并发槽。
func TestDNSTimeoutRetainsLocksAndSlot(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner := newOperationRunner(1)
	backend := &blockingDNS{started: make(chan struct{}), release: make(chan struct{})}
	defer close(backend.release)
	replies := make(chan *deployPB.DeploymentRequest, 4)
	service := &deploymentService{
		client: &WSClient{ops: runner}, ops: runner, parent: parent, clientID: "dns-client",
		sendEnvelope:  func(reply *deployPB.DeploymentRequest) { replies <- reply },
		newDNSBackend: func(*config.Runtime, deployPB.DnsProvider) (dnsconfig.Backend, error) { return backend, nil },
	}
	record := &deployPB.DnsRecord{Zone: "example.com", Fqdn: "_acme-challenge.example.com", Host: "_acme-challenge", Value: "target.example.net"}
	service.runDNS("first", &deployPB.DnsOperationRequest{Record: record}, true)
	select {
	case <-backend.started:
	case <-time.After(time.Second):
		t.Fatal("新增没有启动")
	}
	cancel()
	select {
	case reply := <-replies:
		if reply.ClientId != "dns-client" || reply.RequestId != "first" || reply.GetDnsConfigureResponse().GetStatus() != deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_UNCONFIRMED {
			t.Fatal("超时响应关联或状态错误", reply)
		}
	case <-time.After(time.Second):
		t.Fatal("取消后没有及时回包")
	}
	lockCtx, lockCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer lockCancel()
	if release, err := runner.LockResource(lockCtx, "dns\x00example.com\x00_acme-challenge.example.com"); err == nil {
		release()
		t.Fatal("未收敛写入的串行锁被提前释放")
	}
	service.runDNS("second", &deployPB.DnsOperationRequest{Record: record}, true)
	if reply := <-replies; reply.RequestId != "second" || reply.GetDnsConfigureResponse().GetStatus() != deployPB.DnsOperationStatus_DNS_OPERATION_STATUS_FAILED {
		t.Fatal("未收敛写入的并发槽被提前释放", reply)
	}
	backend.release <- struct{}{}
	runner.Wait()
	select {
	case reply := <-replies:
		t.Fatal("已超时的任务再次回包", reply)
	default:
	}
	if len(runner.sem) != 0 {
		t.Fatal("SDK 收敛后未释放并发槽")
	}
}
