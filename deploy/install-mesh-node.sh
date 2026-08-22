#!/usr/bin/env bash
set -euo pipefail

endpoint=""
name=""
binary=""
nebula_bin="$(command -v nebula || true)"
nebula_cert_bin="$(command -v nebula-cert || true)"
control_port="8090"
nebula_port="4242"
release_base_url="${MESHLAN_RELEASE_BASE_URL:-https://your-meshlan.example}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoint) endpoint="$2"; shift 2 ;;
    --name) name="$2"; shift 2 ;;
    --binary) binary="$2"; shift 2 ;;
    --nebula) nebula_bin="$2"; shift 2 ;;
    --nebula-cert) nebula_cert_bin="$2"; shift 2 ;;
    --control-port) control_port="$2"; shift 2 ;;
    --nebula-port) nebula_port="$2"; shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "请使用 sudo 运行此脚本" >&2
  exit 1
fi
if [[ -z "$endpoint" ]]; then
  echo "用法: sudo bash install-mesh-node.sh --endpoint <公网IP> [--name hk-02] [--control-port 8090] [--nebula-port 4242]" >&2
  exit 2
fi

case "$(uname -m)" in
  x86_64|amd64) node_arch="amd64" ;;
  aarch64|arm64) node_arch="arm64" ;;
  *) echo "仅支持 Linux AMD64 和 ARM64" >&2; exit 2 ;;
esac

temporary_root="$(mktemp -d)"
trap 'rm -rf -- "$temporary_root"' EXIT

if [[ -z "$binary" ]]; then
  binary="$temporary_root/meshlan-node"
  headers="$temporary_root/node.headers"
  curl -fsSL -D "$headers" "$release_base_url/download/node/linux-$node_arch" -o "$binary"
  expected_hash="$(awk 'tolower($1)=="x-content-sha256:" {gsub("\r", "", $2); print tolower($2)}' "$headers" | tail -1)"
  actual_hash="$(sha256sum "$binary" | awk '{print $1}')"
  if [[ -z "$expected_hash" || "$expected_hash" != "$actual_hash" ]]; then
    echo "MeshLAN 子节点程序 SHA-256 校验失败" >&2
    exit 1
  fi
  chmod 0755 "$binary"
fi

if [[ -z "$nebula_bin" || ! -x "$nebula_bin" || -z "$nebula_cert_bin" || ! -x "$nebula_cert_bin" ]]; then
  nebula_version="1.11.0"
  archive="nebula-linux-$node_arch.tar.gz"
  curl -fsSL "https://github.com/slackhq/nebula/releases/download/v$nebula_version/$archive" -o "$temporary_root/$archive"
  curl -fsSL "https://github.com/slackhq/nebula/releases/download/v$nebula_version/SHASUM256.txt" -o "$temporary_root/SHASUM256.txt"
  (cd "$temporary_root" && grep "  $archive\$" SHASUM256.txt | sha256sum -c -)
  tar -xzf "$temporary_root/$archive" -C "$temporary_root"
  nebula_bin="$temporary_root/nebula"
  nebula_cert_bin="$temporary_root/nebula-cert"
fi

state_dir="/etc/meshlan-node"
state_path="$state_dir/node-state.json"
install -d -m 0700 "$state_dir"
install -m 0755 "$binary" /usr/local/bin/meshlan-nebula
install -m 0755 "$nebula_bin" /usr/local/bin/nebula
install -m 0755 "$nebula_cert_bin" /usr/local/bin/nebula-cert
nebula_bin="/usr/local/bin/nebula"
nebula_cert_bin="/usr/local/bin/nebula-cert"

init_args=(server node-init -state "$state_path" -endpoint "$endpoint" -control-port "$control_port" -nebula-port "$nebula_port" -nebula "$nebula_bin" -nebula-cert "$nebula_cert_bin")
if [[ -n "$name" ]]; then init_args+=(-name "$name"); fi
/usr/local/bin/meshlan-nebula "${init_args[@]}"

cat >/etc/systemd/system/meshlan-node.service <<EOF
[Unit]
Description=MeshLAN Secondary Lighthouse Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/meshlan-nebula server node-serve -state $state_path -bind 0.0.0.0
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$state_dir

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now meshlan-node.service
echo
echo "子节点服务已启动。请在防火墙放行 TCP/$control_port 与 UDP/$nebula_port。"
