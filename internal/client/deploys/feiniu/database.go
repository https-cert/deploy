package feiniu

import (
	"context"
	"fmt"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/deploys/shared"
	"github.com/https-cert/deploy/pkg/logger"
)

// updateFeiniuDatabaseContext 使用调用方 context 更新飞牛 OS 数据库证书信息。
func updateFeiniuDatabaseContext(ctx context.Context, domain, certPath string, validFrom, validTo int64) error {
	if ctx == nil {
		ctx = context.Background()
	}
	safeDomain := shared.SanitizeDomain(domain)
	if safeDomain == "" {
		return fmt.Errorf("飞牛证书域名无效")
	}
	certFile := path.Join(certPath, safeDomain+".crt")
	keyFile := path.Join(certPath, safeDomain+".key")
	issuerFile := ""
	currentTime := time.Now().UnixMilli()

	encryptType := "RSA"
	issuedBy := "Let's Encrypt"
	output, opensslErr := runFeiniuCommandContext(ctx, feiniuCommandTimeout, "openssl", "x509", "-in", certFile, "-noout", "-text")
	if opensslErr == nil {
		outputStr := string(output)
		if strings.Contains(outputStr, "ECDSA") || strings.Contains(outputStr, "ECC") {
			encryptType = "ECDSA"
		}
		if issuerOutput, err := runFeiniuCommandContext(ctx, feiniuCommandTimeout, "openssl", "x509", "-in", certFile, "-noout", "-issuer"); err == nil {
			parts := strings.Split(string(issuerOutput), "=")
			if len(parts) > 0 {
				issuedBy = strings.TrimSpace(parts[len(parts)-1])
			}
		}
	}

	variables := map[string]string{
		"domain":       domain,
		"valid_from":   strconv.FormatInt(validFrom, 10),
		"valid_to":     strconv.FormatInt(validTo, 10),
		"encrypt_type": encryptType,
		"issued_by":    issuedBy,
		"current_time": strconv.FormatInt(currentTime, 10),
		"private_key":  keyFile,
		"certificate":  certFile,
		"issuer":       issuerFile,
	}
	output, err := runFeiniuPSQLContext(ctx, variables, feiniuUpsertSQL)
	if err != nil {
		return fmt.Errorf("更新飞牛数据库失败: %w, output: %s", err, strings.TrimSpace(string(output)))
	}
	logger.Info("已更新飞牛数据库证书信息", "domain", domain)
	return nil
}

const feiniuUpsertSQL = `
BEGIN;
LOCK TABLE cert IN EXCLUSIVE MODE;
SELECT EXISTS(SELECT 1 FROM cert WHERE domain = :'domain') AS cert_exists \gset
\if :cert_exists
UPDATE cert SET
    valid_from = :'valid_from'::bigint,
    valid_to = :'valid_to'::bigint,
    encrypt_type = :'encrypt_type',
    issued_by = :'issued_by',
    last_renew_time = :'current_time'::bigint,
    des = '由anssl自动部署的证书',
    private_key = :'private_key',
    certificate = :'certificate',
    issuer_certificate = :'issuer',
    status = 'suc',
    updated_time = :'current_time'::bigint
WHERE domain = :'domain';
\else
INSERT INTO cert VALUES (
    (SELECT COALESCE(MAX(id), 0) + 1 FROM cert),
    :'domain', '*' || :'domain' || ',' || :'domain',
    :'valid_from'::bigint, :'valid_to'::bigint, :'encrypt_type', :'issued_by', :'current_time'::bigint,
    '由anssl自动部署的证书', 0, null, 'upload', null,
    :'private_key', :'certificate', :'issuer', 'suc', :'current_time'::bigint, :'current_time'::bigint
);
\endif
COMMIT;
`

// runFeiniuPSQLContext 使用调用方 context 执行参数化 psql 脚本。
func runFeiniuPSQLContext(ctx context.Context, variables map[string]string, script string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	args := buildFeiniuPSQLArgs(variables)

	commandContext, cancel := context.WithTimeout(ctx, feiniuCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(commandContext, "psql", args...)
	cmd.Stdin = strings.NewReader(script)
	output, err := cmd.CombinedOutput()
	if commandContext.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("psql 执行超时")
	}
	return output, err
}

// buildFeiniuPSQLArgs 将不受信任的 SQL 值作为 psql 变量传入。
func buildFeiniuPSQLArgs(variables map[string]string) []string {
	args := []string{"-X", "--set=ON_ERROR_STOP=1", "-U", "postgres", "-d", "trim_connect"}
	keys := make([]string, 0, len(variables))
	for key := range variables {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--set="+key+"="+variables[key])
	}
	return args
}
