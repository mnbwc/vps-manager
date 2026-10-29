#!/usr/bin/env bash
# VPS Manager 方案 A：窄权限 helper + sudoers 白名单（T-34）
# 由 install.sh 以 root 调用。面板 PHP-FPM 以 root 运行的部署模型下本文件为纵深防御；
# 若未来 FPM 改为非 root，此处 sudoers 白名单即为唯一特权执行通道。
set -euo pipefail

HELPER=/usr/local/sbin/vpsmgr-helper
cat > "$HELPER" <<'EOF'
#!/usr/bin/env bash
# vpsmgr-helper：白名单特权操作入口。用法: vpsmgr-helper <op> [args...]
# 只允许固定操作，禁止任意参数/路径/命令；全部记录审计日志。
set -euo pipefail
LOG=/var/log/vpsmgr-helper.log
log() { echo "$(date -Is) user=$(id -un) op=$*" >> "$LOG" 2>/dev/null || true; }
op="${1:-}"; shift || true
finish() { rc=$?; [ $rc -ne 0 ] && log "DENIED rc=$rc op=$op $*"; exit $rc; }
trap finish EXIT
case "$op" in
  nginx-test)    log "$@"; exec /usr/sbin/nginx -t ;;
  nginx-reload)  log "$@"; /usr/sbin/nginx -t; exec systemctl reload nginx ;;
  svc-status)    [ $# -eq 1 ] && [[ "$1" =~ ^[a-zA-Z0-9.@_-]+$ ]] || exit 2; log "$@"; exec systemctl is-active "$1" ;;
  svc-start)     [ $# -eq 1 ] && [[ "$1" =~ ^[a-zA-Z0-9.@_-]+$ ]] || exit 2; log "$@"; exec systemctl start "$1" ;;
  svc-stop)      [ $# -eq 1 ] && [[ "$1" =~ ^[a-zA-Z0-9.@_-]+$ ]] || exit 2; log "$@"; exec systemctl stop "$1" ;;
  svc-restart)   [ $# -eq 1 ] && [[ "$1" =~ ^[a-zA-Z0-9.@_-]+$ ]] || exit 2; log "$@"; exec systemctl restart "$1" ;;
  svc-reload)    [ $# -eq 1 ] && [[ "$1" =~ ^[a-zA-Z0-9.@_-]+$ ]] || exit 2; log "$@"; exec systemctl reload "$1" ;;
  crontab-load)  [ $# -eq 1 ] && [ -f "$1" ] || exit 2; log "$@"; exec /usr/bin/crontab "$1" ;;
  apply-file)    [ $# -eq 2 ] && [ -f "$1" ] || exit 2; case "$2" in /etc/nginx/sites-available/*|/etc/nginx/sites-enabled/*|/etc/nginx/conf.d/*) log "$@"; install -m 0644 "$1" "$2"; exit 0;; *) exit 2;; esac ;;
  unlink-path)   [ $# -eq 1 ] || exit 2; case "$1" in /etc/nginx/sites-enabled/*|/etc/nginx/sites-available/*) log "$@"; rm -f "$1"; exit 0;; *) exit 2;; esac ;;
  mkdir-www)     [ $# -eq 1 ] || exit 2; case "$1" in /var/www/*) log "$@"; mkdir -p "$1"; chown www-data:www-data "$1" 2>/dev/null || chown nginx:nginx "$1" 2>/dev/null || true; exit 0;; *) exit 2;; esac ;;
  chown-www)     [ $# -eq 1 ] || exit 2; case "$1" in /var/www/*) log "$@"; chown -R www-data:www-data "$1" 2>/dev/null || chown -R nginx:nginx "$1"; exit 0;; *) exit 2;; esac ;;
  rm-www)        [ $# -eq 1 ] || exit 2; case "$1" in /var/www/*) [ "$1" != "/var/www" ] && [ "$1" != "/var/www/" ] || exit 2; log "$@"; rm -rf "$1"; exit 0;; *) exit 2;; esac ;;
  reload-nginx)  log "$@"; /usr/sbin/nginx -t && (systemctl reload nginx 2>/dev/null || nginx -s reload); exit 0 ;;
  backup-dir-ok) log "$@"; mkdir -p /var/lib/vps-manager/backups/migration; chown -R www-data:www-data /var/lib/vps-manager 2>/dev/null || chown -R nginx:nginx /var/lib/vps-manager; exit 0 ;;
  *) log "DENIED op=$op $*"; echo "unknown op" >&2; exit 2 ;;
esac
EOF
chmod 0750 "$HELPER"

# sudoers：www-data 仅允许该 helper（若面板以 root 运行则无需 NOPASSWD 条目，仅装 helper 备用）
if id www-data >/dev/null 2>&1; then
  # 默认启用 sudoers 白名单（安装时 FPM 尚未启动是常见时序；宁可白名单多装，也不让面板裸奔）
  cat > /etc/sudoers.d/vpsmgr <<EOF
www-data ALL=(root) NOPASSWD: $HELPER
EOF
  chmod 0440 /etc/sudoers.d/vpsmgr
  visudo -c -f /etc/sudoers.d/vpsmgr
  echo "✓ sudoers 白名单已启用（仅限 $HELPER 固定操作）"
else
  echo "ℹ 无 www-data 用户（Alpine 等），helper 已安装作为纵深防御"
fi
touch /var/log/vpsmgr-helper.log && chmod 0640 /var/log/vpsmgr-helper.log
echo "✓ vpsmgr-helper 安装完成: $HELPER"
