#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "请使用 sudo 运行此脚本" >&2
  exit 1
fi

service_name="${MESHLAN_NODE_SERVICE:-meshlan-node.service}"
binary_path="/usr/local/bin/meshlan-nebula"
state_path="/etc/meshlan-node/node-state.json"
config_path="/etc/meshlan-node/node.yml"
release_base_url="${MESHLAN_RELEASE_BASE_URL:-https://your-meshlan.example}"

if [[ ! -f "$state_path" ]]; then
  echo "未找到 $state_path；这台机器不是已安装的 MeshLAN 子节点" >&2
  exit 1
fi
if ! systemctl cat "$service_name" >/dev/null 2>&1; then
  echo "未找到 systemd 服务 $service_name" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) node_arch="amd64" ;;
  aarch64|arm64) node_arch="arm64" ;;
  *) echo "仅支持 Linux AMD64 和 ARM64" >&2; exit 2 ;;
esac

temporary_root="$(mktemp -d)"
trap 'rm -rf -- "$temporary_root"' EXIT
package="$temporary_root/meshlan-node"
headers="$temporary_root/node.headers"

echo "[1/5] 下载 Linux $node_arch 更新包..."
curl --fail --silent --show-error --location --retry 5 --retry-delay 2 \
  -D "$headers" "$release_base_url/download/node/linux-$node_arch" -o "$package"
expected_hash="$(awk 'tolower($1)=="x-content-sha256:" {gsub("\r", "", $2); print tolower($2)}' "$headers" | tail -1)"
actual_hash="$(sha256sum "$package" | awk '{print $1}')"
if [[ -z "$expected_hash" || "$expected_hash" != "$actual_hash" ]]; then
  echo "更新包 SHA-256 校验失败" >&2
  exit 1
fi
chmod 0755 "$package"

echo "[2/5] 备份当前程序..."
backup_path="$binary_path.previous"
if [[ -f "$binary_path" ]]; then
  install -m 0755 "$binary_path" "$backup_path"
fi
install -m 0755 "$package" "$binary_path.new"
mv -f "$binary_path.new" "$binary_path"

echo "[3/5] 重启子节点服务..."
if ! systemctl restart "$service_name"; then
  echo "新版本启动失败，正在回滚..." >&2
  if [[ -f "$backup_path" ]]; then
    install -m 0755 "$backup_path" "$binary_path"
    systemctl restart "$service_name" || true
  fi
  exit 1
fi

echo "[4/5] 等待健康检查..."
healthy=false
for _ in $(seq 1 30); do
  if systemctl is-active --quiet "$service_name"; then
    healthy=true
    break
  fi
  sleep 1
done
if [[ "$healthy" != true ]]; then
  echo "新版本30秒内未进入运行状态，正在回滚..." >&2
  if [[ -f "$backup_path" ]]; then
    install -m 0755 "$backup_path" "$binary_path"
    systemctl restart "$service_name" || true
  fi
  exit 1
fi

echo "[5/5] 等待主控同步 Relay 配置..."
relay_ready=false
for _ in $(seq 1 60); do
  if [[ -f "$config_path" ]] && grep -Eq '^  am_relay: true$' "$config_path" && systemctl is-active --quiet "$service_name"; then
    relay_ready=true
    break
  fi
  sleep 1
done

echo
echo "MeshLAN 子节点升级完成"
echo "SHA-256: $actual_hash"
echo "服务状态: $(systemctl is-active "$service_name")"
if [[ "$relay_ready" == true ]]; then
  echo "Relay 状态: 已启用"
else
  echo "Relay 状态: 等待主控下一轮健康同步（程序升级已成功）"
fi
