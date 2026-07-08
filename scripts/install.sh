#!/usr/bin/env sh
set -eu

# anssl 一键安装脚本。
# 默认安装 GitHub Release 最新版本，可通过 VERSION 固定版本。

REPO="${REPO:-https-cert/deploy}"
BIN_NAME="${BIN_NAME:-anssl}"
VERSION="${VERSION:-latest}"
MIRROR="${MIRROR:-ghproxy}"
APP_DIR="${APP_DIR:-/opt/anssl}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-$APP_DIR}"
ACTION="install"
PURGE="false"

# log_info 输出普通安装日志。
log_info() {
	printf '%s\n' "==> $*"
}

# log_warn 输出不阻断安装流程的警告。
log_warn() {
	printf '%s\n' "WARN: $*" >&2
}

# log_error 输出错误并结束脚本。
log_error() {
	printf '%s\n' "ERROR: $*" >&2
	exit 1
}

# need_cmd 检查安装流程必需的命令是否存在。
need_cmd() {
	command -v "$1" >/dev/null 2>&1 || log_error "缺少命令: $1"
}

# usage 输出安装脚本支持的参数和环境变量。
usage() {
	cat <<EOF
用法:
  install.sh [--uninstall] [--purge] [--help]

环境变量:
  VERSION      安装版本，默认 latest，例如 v0.6.0
  MIRROR       下载源，可选 ghproxy、github，默认 ghproxy
  APP_DIR      程序目录，默认 /opt/anssl
  INSTALL_DIR  命令链接目录，默认 /usr/local/bin
  CONFIG_DIR   配置目录，默认等于 APP_DIR
EOF
}

# parse_args 解析安装、卸载和清理参数。
parse_args() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
			--uninstall)
				ACTION="uninstall"
				;;
			--purge)
				PURGE="true"
				;;
			--help | -h)
				usage
				exit 0
				;;
			*)
				log_error "未知参数: $1"
				;;
		esac
		shift
	done

	if [ "$PURGE" = "true" ] && [ "$ACTION" != "uninstall" ]; then
		log_error "--purge 只能和 --uninstall 一起使用"
	fi
}

# run_privileged 在需要写系统目录时自动使用 sudo。
run_privileged() {
	if "$@" 2>/dev/null; then
		return
	fi

	if [ "$(id -u)" -eq 0 ]; then
		log_error "命令执行失败: $*"
	fi

	if command -v sudo >/dev/null 2>&1; then
		sudo "$@"
		return
	fi

	log_error "当前用户没有写入权限且未安装 sudo，请使用 root 执行"
}

# detect_platform 识别 release 包使用的系统和架构名。
detect_platform() {
	os="$(uname -s | tr '[:upper:]' '[:lower:]')"
	arch="$(uname -m)"

	case "$os" in
		linux)
			asset_os="linux"
			;;
		darwin)
			asset_os="darwin"
			;;
		*)
			log_error "不支持的系统: $os"
			;;
	esac

	case "$arch" in
		x86_64 | amd64)
			asset_arch="amd64"
			;;
		arm64 | aarch64)
			asset_arch="arm64"
			;;
		*)
			log_error "不支持的架构: $arch"
			;;
	esac
}

# build_release_urls 根据版本和镜像源生成下载地址。
build_release_urls() {
	if [ "$VERSION" = "latest" ]; then
		base_url="https://github.com/${REPO}/releases/latest/download"
	else
		base_url="https://github.com/${REPO}/releases/download/${VERSION}"
	fi

	asset_name="${BIN_NAME}-${asset_os}-${asset_arch}.tar.gz"
	asset_url="${base_url}/${asset_name}"
	checksum_url="${base_url}/checksums.txt"

	case "$MIRROR" in
		github)
			;;
		ghproxy)
			asset_url="https://gh-proxy.com/${asset_url}"
			checksum_url="https://gh-proxy.com/${checksum_url}"
			;;
		*)
			log_error "不支持的下载源: ${MIRROR}，可选值: ghproxy, github"
			;;
	esac
}

# verify_checksum 使用 checksums.txt 校验下载的 release 包。
verify_checksum() {
	if ! grep "  ${asset_name}$" checksums.txt >/dev/null 2>&1 && ! grep " ${asset_name}$" checksums.txt >/dev/null 2>&1; then
		log_warn "checksums.txt 中未找到 ${asset_name}，跳过校验"
		return
	fi

	if command -v sha256sum >/dev/null 2>&1; then
		grep " ${asset_name}$" checksums.txt | sha256sum -c -
		return
	fi

	if command -v shasum >/dev/null 2>&1; then
		expected="$(grep " ${asset_name}$" checksums.txt | awk '{print $1}')"
		actual="$(shasum -a 256 "$asset_name" | awk '{print $1}')"
		[ "$expected" = "$actual" ] || log_error "校验失败: ${asset_name}"
		log_info "校验通过: ${asset_name}"
		return
	fi

	log_warn "未找到 sha256sum 或 shasum，跳过校验"
}

# install_binary 安装 anssl 可执行文件。
install_binary() {
	[ -f "$BIN_NAME" ] || log_error "发布包中未找到 ${BIN_NAME}"

	run_privileged mkdir -p "$APP_DIR"
	run_privileged mkdir -p "$INSTALL_DIR"
	run_privileged install -m 0755 "$BIN_NAME" "${APP_DIR}/${BIN_NAME}"

	if [ -e "${INSTALL_DIR}/${BIN_NAME}" ] && [ ! -L "${INSTALL_DIR}/${BIN_NAME}" ]; then
		log_warn "${INSTALL_DIR}/${BIN_NAME} 已存在且不是软链接，已跳过命令链接"
		return
	fi

	run_privileged ln -sfn "${APP_DIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
}

# install_config 首次安装时复制默认配置，已有配置永不覆盖。
install_config() {
	run_privileged mkdir -p "$CONFIG_DIR"

	if [ -f "${CONFIG_DIR}/config.yaml" ]; then
		log_info "配置已存在，未覆盖: ${CONFIG_DIR}/config.yaml"
		return
	fi

	if [ ! -f config.yaml ]; then
		log_warn "发布包中未找到 config.yaml，跳过配置初始化"
		return
	fi

	run_privileged install -m 0600 config.yaml "${CONFIG_DIR}/config.yaml"
	log_info "已生成默认配置: ${CONFIG_DIR}/config.yaml"
}

# uninstall_anssl 卸载程序；默认保留配置，--purge 才删除配置目录。
uninstall_anssl() {
	log_info "卸载 ${BIN_NAME}"

	if [ -L "${INSTALL_DIR}/${BIN_NAME}" ]; then
		run_privileged rm -f "${INSTALL_DIR}/${BIN_NAME}"
	elif [ -e "${INSTALL_DIR}/${BIN_NAME}" ]; then
		log_warn "${INSTALL_DIR}/${BIN_NAME} 不是软链接，未自动删除"
	fi

	if [ -f "${APP_DIR}/${BIN_NAME}" ]; then
		run_privileged rm -f "${APP_DIR}/${BIN_NAME}"
	fi

	if [ "$PURGE" = "true" ]; then
		if [ "$APP_DIR" = "/" ] || [ "$CONFIG_DIR" = "/" ]; then
			log_error "拒绝删除根目录"
		fi

		if [ "$CONFIG_DIR" = "$APP_DIR" ]; then
			run_privileged rm -rf "$APP_DIR"
		else
			run_privileged rm -rf "$CONFIG_DIR"
			rmdir "$APP_DIR" 2>/dev/null || true
		fi
		log_info "已删除配置目录"
	else
		log_info "已保留配置: ${CONFIG_DIR}/config.yaml"
		rmdir "$APP_DIR" 2>/dev/null || true
	fi

	log_info "卸载完成"
}

# print_success_banner 输出安装完成后的摘要信息。
print_success_banner() {
	version_output="$("${INSTALL_DIR}/${BIN_NAME}" version 2>/dev/null || true)"
	if [ "$version_output" = "" ]; then
		version_output="${BIN_NAME} version unknown"
	fi

	cat <<EOF

------------------------------------------------------------
     ___    _   _ ____ ____  _
    / _ \  | \ | / ___/ ___|| |
   / /_\ \ |  \| \___ \___ \| |
  / ___  \ | |\ | ___) |__) | |___
 /_/   \_\|_| \_||____/____/|_____|

  anssl 安装成功

  版本: ${version_output}
  程序: ${APP_DIR}/${BIN_NAME}
  命令: ${INSTALL_DIR}/${BIN_NAME}
  配置: ${CONFIG_DIR}/config.yaml

  卸载:
    curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/https-cert/deploy/main/scripts/install.sh | sh -s -- --uninstall

  卸载并删除配置:
    curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/https-cert/deploy/main/scripts/install.sh | sh -s -- --uninstall --purge
------------------------------------------------------------

EOF
}

# main 执行下载、校验、解压和安装流程。
main() {
	parse_args "$@"

	if [ "$ACTION" = "uninstall" ]; then
		uninstall_anssl
		return
	fi

	need_cmd curl
	need_cmd tar
	need_cmd grep
	need_cmd awk
	need_cmd uname
	need_cmd tr
	need_cmd id
	need_cmd install
	need_cmd mktemp

	detect_platform
	build_release_urls

	tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/anssl.XXXXXX")"
	trap 'rm -rf "$tmp_dir"' EXIT INT TERM

	log_info "下载 ${asset_name}"
	curl -fL "$asset_url" -o "${tmp_dir}/${asset_name}"

	log_info "下载 checksums.txt"
	curl -fL "$checksum_url" -o "${tmp_dir}/checksums.txt"

	cd "$tmp_dir"
	verify_checksum

	log_info "解压 ${asset_name}"
	tar -xzf "$asset_name"

	log_info "安装 ${BIN_NAME} 到 ${APP_DIR}"
	install_binary

	log_info "准备配置目录 ${CONFIG_DIR}"
	install_config

	print_success_banner
	printf '%s\n' "下一步：编辑 ${CONFIG_DIR}/config.yaml，填写 server.accessKey 后运行："
	printf '%s\n' "${INSTALL_DIR}/${BIN_NAME} daemon -c ${CONFIG_DIR}/config.yaml"
}

main "$@"
