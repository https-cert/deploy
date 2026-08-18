package client

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/internal/system"
	"github.com/https-cert/deploy/pb/deployPB"
	"google.golang.org/protobuf/encoding/protojson"
)

// TestWSClientConstructionAndLifecycle 验证显式依赖构造、缓存、并发限制和生命周期辅助方法。
func TestWSClientConstructionAndLifecycle(t *testing.T) {
	if _, err := NewWSClient(context.Background(), nil); err == nil {
		t.Fatal("空 runtime 应返回错误")
	}
	runtime := testWSRuntime("https://deploy.example.com/base")
	wantIDError := errors.New("client id failed")
	if _, err := newWSClientWithDependencies(context.Background(), runtime, wsClientDependencies{
		uniqueClientID: func(context.Context) (string, error) { return "", wantIDError },
	}); !errors.Is(err, wantIDError) {
		t.Fatalf("客户端 ID 错误未传播: %v", err)
	}
	if _, err := newWSClientWithDependencies(context.Background(), runtime, wsClientDependencies{
		uniqueClientID: func(context.Context) (string, error) { return "client-id", nil },
		newHandlerRegistry: func(*WSClient) (*DeploymentHandlerRegistry, error) {
			return nil, errors.New("registry failed")
		},
	}); err == nil || !strings.Contains(err.Error(), "registry") {
		t.Fatalf("registry 错误未传播: %v", err)
	}

	var systemInfoCalls atomic.Int32
	// nilContext 刻意使用 context.Context 零值，以覆盖构造器的兼容防御分支。
	var nilContext context.Context
	client, err := newWSClientWithDependencies(nilContext, runtime, wsClientDependencies{
		uniqueClientID: func(context.Context) (string, error) { return "client-id", nil },
		loadSystemInfo: func() (*system.SystemInfo, error) {
			systemInfoCalls.Add(1)
			return &system.SystemInfo{OS: "linux", Arch: "arm64", Hostname: "host", IP: "127.0.0.1"}, nil
		},
	})
	if err != nil {
		t.Fatalf("构造 WebSocket 客户端失败: %v", err)
	}
	if client.GetServerURL() != runtime.ServerURL || client.GetClientID() != "client-id" || client.GetAccessKey() != "access-key" {
		t.Fatal("客户端 getter 返回值不匹配")
	}
	client.SetHTTPServer(nil)
	if err := client.Wait(context.Background()); err != nil {
		t.Fatalf("未启动客户端 Wait 应立即成功: %v", err)
	}
	first, err := client.getSystemInfo()
	if err != nil {
		t.Fatalf("读取系统信息失败: %v", err)
	}
	second, err := client.getSystemInfo()
	if err != nil || first != second || systemInfoCalls.Load() != 1 {
		t.Fatalf("系统信息未缓存: first=%p second=%p calls=%d err=%v", first, second, systemInfoCalls.Load(), err)
	}
	registration := client.buildDeploymentRegistration(first)
	if registration.GetProtocolVersion() != 2 || registration.GetOs() != "linux" || len(registration.GetCapabilities()) == 0 {
		t.Fatalf("注册摘要不完整: %+v", registration)
	}
	if client.buildDeploymentRegistration(nil).GetHostname() != "" {
		t.Fatal("nil 系统信息不应填充主机名")
	}
	if got := client.buildWSURL(); got != "wss://deploy.example.com/base/v2/ws?accessKey=access-key&clientId=client-id" {
		t.Fatalf("WebSocket URL 不匹配: %s", got)
	}

	completed := make(chan struct{})
	client.runOperation("success", nil, func() { close(completed) })
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("异步业务未执行")
	}
	client.operationSem = make(chan struct{}, 1)
	client.operationSem <- struct{}{}
	busy := make(chan struct{})
	client.runOperation("busy", func() { close(busy) }, func() { t.Error("并发满载时不应执行业务") })
	select {
	case <-busy:
	case <-time.After(time.Second):
		t.Fatal("并发满载回调未执行")
	}
	<-client.operationSem

	downloadClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Query().Get("accessKey") != "access-key" {
			t.Fatalf("下载缺少 accessKey: %s", request.URL.String())
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}, nil
	})}
	client.httpClient = downloadClient
	target := filepath.Join(t.TempDir(), "archive")
	if err := client.downloadFile(context.Background(), "https://example.com/archive", target); err != nil {
		t.Fatalf("客户端下载失败: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("下载目标不存在: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("关闭空连接失败: %v", err)
	}

	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()
	canceledClient, err := newWSClientWithDependencies(canceledContext, testWSRuntime("http://127.0.0.1:1"), wsClientDependencies{
		uniqueClientID: func(context.Context) (string, error) { return "client-id", nil },
	})
	if err != nil {
		t.Fatalf("构造已取消客户端失败: %v", err)
	}
	canceledClient.Start()
	canceledClient.Start()
	waitContext, waitCancel := context.WithTimeout(context.Background(), time.Second)
	defer waitCancel()
	if err := canceledClient.Wait(waitContext); err != nil {
		t.Fatalf("客户端循环未按取消退出: %v", err)
	}
}

// TestWSConnectionHelpers 验证临时错误识别、URL 规范化和重连标记。
func TestWSConnectionHelpers(t *testing.T) {
	if isTemporaryError(nil) || isTemporaryError(errors.New("permanent")) {
		t.Fatal("永久错误分类不匹配")
	}
	if !isTemporaryError(&net.DNSError{IsTimeout: true}) || !isTemporaryError(errors.New("connection refused")) || !isTemporaryError(errors.New("websocket closed")) {
		t.Fatal("临时网络错误未被识别")
	}
	client := &WSClient{serverURL: "http://example.com", accessKey: "key", clientId: "id"}
	if got := client.buildWSURL(); got != "ws://example.com/deploy/v2/ws?accessKey=key&clientId=id" {
		t.Fatalf("根路径 WebSocket URL 不匹配: %s", got)
	}
	client.markReconnectPending()
	if client.reconnectPending.Load() {
		t.Fatal("从未连接时不应标记重连")
	}
	client.connectionLogged.Store(true)
	client.markReconnectPending()
	if !client.reconnectPending.Load() {
		t.Fatal("历史连接断开后应标记重连")
	}
}

// TestWSClientConnectAndSend 验证本地 WebSocket 握手、注册信封和响应信封。
func TestWSClientConnectAndSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverConnection := make(chan *websocket.Conn, 1)
	handlerDone := make(chan struct{})
	requestURL := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requestURL <- request.URL.String()
		connection, err := websocket.Accept(response, request, nil)
		if err != nil {
			return
		}
		serverConnection <- connection
		<-handlerDone
	}))
	defer server.Close()

	client, err := newWSClientWithDependencies(ctx, testWSRuntime(server.URL+"/deploy"), wsClientDependencies{
		uniqueClientID: func(context.Context) (string, error) { return "client-id", nil },
		loadSystemInfo: func() (*system.SystemInfo, error) {
			return &system.SystemInfo{OS: "darwin", Arch: "arm64"}, nil
		},
	})
	if err != nil {
		t.Fatalf("构造客户端失败: %v", err)
	}
	if err := client.connect(); err != nil {
		t.Fatalf("连接本地 WebSocket 失败: %v", err)
	}
	connection := <-serverConnection
	defer func() {
		_ = connection.Close(websocket.StatusNormalClosure, "test complete")
		close(handlerDone)
	}()
	if got := <-requestURL; got != "/deploy/v2/ws?accessKey=access-key&clientId=client-id" {
		t.Fatalf("握手 URL 不匹配: %s", got)
	}
	register := readDeploymentRequest(t, connection)
	if register.GetRegister().GetProtocolVersion() != 2 || register.GetAccessKey() != "access-key" || register.GetClientId() != "client-id" {
		t.Fatalf("注册信封不匹配: %+v", register)
	}

	selector := &deployPB.DeploymentSelector{Provider: deployPB.Provider_PROVIDER_ALIYUN, DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, TargetRef: "target"}
	client.sendDeploymentDiscoverResponse("discover", &deployPB.DeploymentCapability{Provider: selector.Provider})
	if got := readDeploymentRequest(t, connection); got.GetDiscoverResponse() == nil || got.GetRequestId() != "discover" {
		t.Fatalf("discover 响应不匹配: %+v", got)
	}
	client.sendDeploymentTestResponse("test", selector, successfulDeploymentResult("ok", ""))
	if got := readDeploymentRequest(t, connection); got.GetTestResponse().GetResult().GetStatus() != deployPB.DeploymentExecutionResult_STATUS_SUCCESS {
		t.Fatalf("test 响应不匹配: %+v", got)
	}
	client.sendDeploymentExecuteResponse("execute", selector, failedDeploymentResult("failed", true))
	if got := readDeploymentRequest(t, connection); got.GetExecuteResponse().GetResult().GetStatus() != deployPB.DeploymentExecutionResult_STATUS_FAILED {
		t.Fatalf("execute 响应不匹配: %+v", got)
	}
	challenge := &deployPB.DeploymentChallengeRequest{OperationId: 1, CertId: 2, Domain: "example.com", Token: "token"}
	client.sendDeploymentChallengeResponse("challenge", challenge, successfulDeploymentResult("ok", ""))
	if got := readDeploymentRequest(t, connection); got.GetChallengeResponse().GetToken() != "token" {
		t.Fatalf("challenge 响应不匹配: %+v", got)
	}
	client.sendDeploymentChallengeResponse("challenge-nil", nil, failedDeploymentResult("failed", false))
	if got := readDeploymentRequest(t, connection); got.GetChallengeResponse().GetOperationId() != 0 {
		t.Fatalf("nil challenge 响应不匹配: %+v", got)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("关闭连接失败: %v", err)
	}
	if err := client.sendRegister(); err == nil {
		t.Fatal("关闭连接后注册应失败")
	}
	if err := client.sendDeploymentRequest(&deployPB.DeploymentRequest{}); err == nil {
		t.Fatal("关闭连接后发送应失败")
	}
	client.sendDeploymentEnvelope(&deployPB.DeploymentRequest{RequestId: "closed"})
}

// TestDeploymentMessageRouting 验证 discover、test、execute 和 challenge 的 v2 分发结果。
func TestDeploymentMessageRouting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientConnection, serverConnection := openWebSocketPair(t, ctx)
	defer clientConnection.Close(websocket.StatusNormalClosure, "test complete")
	defer serverConnection.Close(websocket.StatusNormalClosure, "test complete")

	key := DeploymentHandlerKey{Provider: deployPB.Provider_PROVIDER_ALIYUN, DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN}
	handler := &fakeDeploymentHandler{
		key:          key,
		capability:   &deployPB.DeploymentCapability{Provider: key.Provider, DeploymentType: key.DeploymentType},
		catalog:      providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY, Resources: []providers.DeploymentResource{{TargetRef: "target", Domain: "example.com"}}},
		deployResult: providers.DeploymentResult{Message: "deployed", RequestID: "provider-request"},
	}
	registry, err := newDeploymentHandlerRegistry([]DeploymentHandler{handler})
	if err != nil {
		t.Fatalf("构造 fake registry 失败: %v", err)
	}
	client := &WSClient{
		ctx:                ctx,
		accessKey:          "access-key",
		clientId:           "client-id",
		conn:               clientConnection,
		deploymentHandlers: registry,
		operationSem:       make(chan struct{}, maxConcurrentOps),
		operationLocks:     make(map[string]*resourceOperationLock),
		protojsonMarshaler: protojson.MarshalOptions{},
	}
	selector := &deployPB.DeploymentSelector{Provider: key.Provider, DeploymentType: key.DeploymentType, TargetRef: "target"}

	client.handleDeploymentResponse(&deployPB.DeploymentResponse{Data: &deployPB.DeploymentResponse_Register{Register: &deployPB.DeploymentRegisterV2{ProtocolVersion: 2}}})
	if !client.registrationLogged.Load() {
		t.Fatal("注册确认未记录")
	}
	client.handleDeploymentResponse(&deployPB.DeploymentResponse{RequestId: "discover", Data: &deployPB.DeploymentResponse_DiscoverRequest{DiscoverRequest: &deployPB.DeploymentDiscoverRequest{Selector: selector, IncludeResources: true}}})
	if response := readDeploymentRequest(t, serverConnection); response.GetDiscoverResponse().GetCapability().GetResources()[0].GetTargetRef() != "target" {
		t.Fatalf("discover 分发响应不匹配: %+v", response)
	}
	client.handleDeploymentResponse(&deployPB.DeploymentResponse{RequestId: "test-envelope", Data: &deployPB.DeploymentResponse_TestRequest{TestRequest: &deployPB.DeploymentTestRequest{RequestId: "test", Selector: selector}}})
	if response := readDeploymentRequest(t, serverConnection); response.GetTestResponse().GetResult().GetStatus() != deployPB.DeploymentExecutionResult_STATUS_SUCCESS || handler.lastTarget != "target" {
		t.Fatalf("test 分发响应不匹配: response=%+v target=%q", response, handler.lastTarget)
	}
	client.handleDeploymentResponse(&deployPB.DeploymentResponse{Data: &deployPB.DeploymentResponse_ExecuteRequest{ExecuteRequest: &deployPB.DeploymentExecuteRequest{RequestId: "execute", Selector: selector, Domain: "example.com", Cert: "cert", Key: "key"}}})
	if response := readDeploymentRequest(t, serverConnection); response.GetExecuteResponse().GetResult().GetProviderRequestId() != "provider-request" || handler.lastRequest.Domain != "example.com" {
		t.Fatalf("execute 分发响应不匹配: response=%+v request=%+v", response, handler.lastRequest)
	}
	challengeServer := &fakeChallengeServer{}
	client.httpServer = challengeServer
	challenge := &deployPB.DeploymentChallengeRequest{RequestId: "challenge", OperationId: 1, CertId: 2, Domain: "example.com", Token: "token", KeyAuth: "key-auth", Action: deployPB.DeploymentChallengeRequest_ACTION_SET}
	client.handleDeploymentResponse(&deployPB.DeploymentResponse{Data: &deployPB.DeploymentResponse_ChallengeRequest{ChallengeRequest: challenge}})
	if response := readDeploymentRequest(t, serverConnection); response.GetChallengeResponse().GetResult().GetStatus() != deployPB.DeploymentExecutionResult_STATUS_SUCCESS || challengeServer.setToken != "token" {
		t.Fatalf("challenge 分发响应不匹配: response=%+v server=%+v", response, challengeServer)
	}

	handler.testErr = providers.NewDeploymentError("denied", false, "request-denied", nil)
	client.handleDeploymentTestRequest("test-failed", &deployPB.DeploymentTestRequest{Selector: selector})
	if response := readDeploymentRequest(t, serverConnection); response.GetTestResponse().GetResult().GetProviderRequestId() != "request-denied" {
		t.Fatalf("test 错误分类不匹配: %+v", response)
	}
	handler.deployErr = providers.NewDeploymentError("deploy failed", true, "request-failed", nil)
	client.handleDeploymentExecuteRequest("execute-failed", &deployPB.DeploymentExecuteRequest{Selector: selector, Domain: "example.com"})
	if response := readDeploymentRequest(t, serverConnection); response.GetExecuteResponse().GetResult().GetProviderRequestId() != "request-failed" {
		t.Fatalf("execute 错误分类不匹配: %+v", response)
	}
	unknown := &deployPB.DeploymentSelector{Provider: deployPB.Provider_PROVIDER_QINIU, DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN}
	client.handleDeploymentDiscoverRequest("discover-unsupported", &deployPB.DeploymentDiscoverRequest{Selector: unknown})
	if response := readDeploymentRequest(t, serverConnection); response.GetDiscoverResponse().GetCapability().GetResourceStatus() != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE {
		t.Fatalf("未知 discover 响应不匹配: %+v", response)
	}
	client.handleDeploymentTestRequest("test-unsupported", &deployPB.DeploymentTestRequest{Selector: unknown})
	if response := readDeploymentRequest(t, serverConnection); response.GetTestResponse().GetResult().GetStatus() != deployPB.DeploymentExecutionResult_STATUS_NOT_SUPPORTED {
		t.Fatalf("未知 test 响应不匹配: %+v", response)
	}
	client.handleDeploymentExecuteRequest("execute-unsupported", &deployPB.DeploymentExecuteRequest{Selector: unknown})
	if response := readDeploymentRequest(t, serverConnection); response.GetExecuteResponse().GetResult().GetStatus() != deployPB.DeploymentExecutionResult_STATUS_NOT_SUPPORTED {
		t.Fatalf("未知 execute 响应不匹配: %+v", response)
	}
	client.handleDeploymentUpdateRequest(nil)
	client.handleDeploymentResponse(nil)
	client.handleDeploymentResponse(&deployPB.DeploymentResponse{RequestId: "unknown"})
	if _, ok := client.deploymentHandler(nil); ok {
		t.Fatal("nil selector 不应找到 handler")
	}
	if _, ok := (*WSClient)(nil).deploymentHandler(selector); ok {
		t.Fatal("nil client 不应找到 handler")
	}

	client.operationSem = make(chan struct{}, 1)
	client.operationSem <- struct{}{}
	client.handleDeploymentResponse(&deployPB.DeploymentResponse{Data: &deployPB.DeploymentResponse_TestRequest{TestRequest: &deployPB.DeploymentTestRequest{RequestId: "busy", Selector: selector}}})
	if response := readDeploymentRequest(t, serverConnection); !response.GetTestResponse().GetResult().GetRetryable() {
		t.Fatalf("并发满载结果应可重试: %+v", response)
	}
	<-client.operationSem
}

// TestHandleWSMessages 验证无效消息、空信封、有效注册和正常关闭的读取循环。
func TestHandleWSMessages(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientConnection, serverConnection := openWebSocketPair(t, ctx)
	client := &WSClient{
		ctx:                  ctx,
		conn:                 clientConnection,
		deploymentHandlers:   &DeploymentHandlerRegistry{},
		protojsonUnmarshaler: protojson.UnmarshalOptions{DiscardUnknown: true},
		reconnectPending:     atomic.Bool{},
		registrationLogged:   atomic.Bool{},
		connected:            atomic.Bool{},
		protojsonMarshaler:   protojson.MarshalOptions{},
		operationSem:         make(chan struct{}, maxConcurrentOps),
		operationLocks:       make(map[string]*resourceOperationLock),
	}
	client.reconnectPending.Store(true)
	result := make(chan error, 1)
	go func() { result <- client.handleWSMessages() }()
	writeRawWebSocketMessage(t, serverConnection, []byte("not-json"))
	writeDeploymentResponse(t, serverConnection, &deployPB.DeploymentResponse{RequestId: "empty"})
	writeDeploymentResponse(t, serverConnection, &deployPB.DeploymentResponse{Data: &deployPB.DeploymentResponse_Register{Register: &deployPB.DeploymentRegisterV2{ProtocolVersion: 2}}})
	deadline := time.Now().Add(time.Second)
	for !client.registrationLogged.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !client.registrationLogged.Load() {
		t.Fatal("消息循环未处理注册确认")
	}
	if err := serverConnection.Close(websocket.StatusNormalClosure, "done"); err != nil {
		t.Fatalf("关闭服务端连接失败: %v", err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("正常关闭消息循环返回错误: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("消息循环未退出")
	}
	if client.connected.Load() || client.conn != nil {
		t.Fatal("消息循环退出后应清理连接状态")
	}
}

// testWSRuntime 创建 WebSocket 单元测试使用的最小运行时快照。
func testWSRuntime(serverURL string) *config.Runtime {
	return &config.Runtime{
		Config:    &config.Configuration{Server: &config.ServerConfig{AccessKey: "access-key"}, SSL: &config.DeployConfig{}},
		ServerURL: serverURL,
	}
}

// openWebSocketPair 创建仅在当前进程内通信的 WebSocket 连接对。
func openWebSocketPair(t *testing.T, ctx context.Context) (*websocket.Conn, *websocket.Conn) {
	t.Helper()
	connectionChannel := make(chan *websocket.Conn, 1)
	handlerDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(response, request, nil)
		if err != nil {
			return
		}
		connectionChannel <- connection
		<-handlerDone
	}))
	clientConnection, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		close(handlerDone)
		server.Close()
		t.Fatalf("创建 WebSocket 测试连接失败: %v", err)
	}
	serverConnection := <-connectionChannel
	t.Cleanup(func() {
		_ = clientConnection.CloseNow()
		_ = serverConnection.CloseNow()
		close(handlerDone)
		server.Close()
	})
	return clientConnection, serverConnection
}

// readDeploymentRequest 从 WebSocket 读取并解析一条客户端 v2 信封。
func readDeploymentRequest(t *testing.T, connection *websocket.Conn) *deployPB.DeploymentRequest {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, data, err := connection.Read(ctx)
	if err != nil {
		t.Fatalf("读取 deployment 请求失败: %v", err)
	}
	request := &deployPB.DeploymentRequest{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, request); err != nil {
		t.Fatalf("解析 deployment 请求失败: %v body=%s", err, data)
	}
	return request
}

// writeDeploymentResponse 序列化并发送一条服务端 v2 信封。
func writeDeploymentResponse(t *testing.T, connection *websocket.Conn, response *deployPB.DeploymentResponse) {
	t.Helper()
	data, err := protojson.Marshal(response)
	if err != nil {
		t.Fatalf("序列化 deployment 响应失败: %v", err)
	}
	writeRawWebSocketMessage(t, connection, data)
}

// writeRawWebSocketMessage 向测试客户端发送一条原始文本消息。
func writeRawWebSocketMessage(t *testing.T, connection *websocket.Conn, data []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := connection.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatalf("写入 WebSocket 测试消息失败: %v", err)
	}
}
