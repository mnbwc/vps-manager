# 🖥️ VPS Manager（中文版）

**单文件 PHP VPS 管理面板** — SQLite 存储、低占用、三发行版真机实测，替代宝塔的轻量选择。

![Version](https://img.shields.io/badge/version-3.1-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![PHP](https://img.shields.io/badge/PHP-8.2%2B-purple)

## ✨ 特性（v3.1）

- **网站管理** — 建站/删站、Nginx 虚拟主机自动配置、5 种伪静态预设（WordPress/ThinkPHP/Laravel/Typecho/自写）、按站点缓存开关
- **PHP 管理** — 8.2/8.3/8.4/8.5 多版本并存安装/卸载、按站点切换 PHP 版本、扩展开关、默认版本设置
- **数据库** — SQLite 模式零依赖（默认）/ MySQL 按需安装、站点↔数据库绑定管理
- **文件管理** — 浏览/上传/编辑/解压/新建目录/删除（防路径穿越）
- **备份恢复** — 站点一键备份（zip 0600）、备份列表/删除/恢复、rclone 云备份（Google Drive / MEGA / S3 兼容）
- **整机迁移** — 一键打包迁移（自动排除机密文件）、导入恢复
- **SSL 证书** — Let's Encrypt HTTP-01/DNS-01(Cloudflare)、泛域名证书、自动续期
- **定时任务** — Cron 表达式校验 + 落系统 crontab
- **进程守护** — 自定义常驻进程监控 + 自动拉起
- **防火墙** — iptables 封禁/解封 IP、Fail2ban 一键安装（sshd/nginx 防爆破）
- **监控** — CPU/内存/磁盘/网络 实时曲线（/dev/shm 滚动采样，不落盘）
- **终端** — Web 终端（命令白名单 + 30 秒超时保护）
- **多用户** — admin/user 角色、细粒度操作权限（ADMIN_ONLY 白名单）
- **Docker 管理** — 容器列表/启停/安装（可选）

## 🚀 一键安装

```bash
bash <(curl -sSL https://raw.githubusercontent.com/mnbwc/vps-manager/main/install.sh)
```

安装过程中会提示设置管理员密码；通过 SSH 管道等非交互方式安装时，会自动生成密码并写入安装日志。

## 🧩 架构（生产形态）

| 组件 | 端口 | 说明 |
|:-----|:-----|:-----|
| 面板 | **127.0.0.1:9001** | root `php -S` 常驻（systemd/OpenRC 服务 `vpsmgr-panel`） |
| Nginx | **0.0.0.0:8080** | 纯 HTTP 反代到面板（用户网站用 80/443 不冲突） |

- 面板必须 root 运行（管理 nginx 配置/系统服务/多 PHP 版本），不对公网直开，由 nginx 反代隔离。
- 数据库文件 `.panel.db`（0600）、密码哈希 `.passwd`（0600）等机密文件均在 `/var/www/manager/`，nginx `location ~ /\.` 已 deny 防外泄。

## 📦 系统要求与兼容性（三真机实测）

| 系统 | 状态 |
|:-----|:-----|
| **Debian 12** | ✅ systemd + php8.3-fpm |
| **Ubuntu 20.04/22.04/24.04** | ✅ 同 Debian 分支 |
| **CentOS Stream 9 / Rocky / Alma** | ✅ dnf + Remi PHP 8.3（conf.d 目录自适应） |
| **Alpine 3.20+** | ✅ apk + OpenRC（需 bash） |

最低 **512MB 内存**即可流畅运行（实测三服务全开 used ≈ 60-70MB）。

## 🔐 安全特性

- 登录 SVG 验证码（一次性 + 300s 过期 + `hash_equals` 恒时比较，免 GD 依赖）
- 登录节流：5 次失败锁 15 分钟（按真实 IP 计数，反代下用 X-Real-IP）
- 全站 CSRF token（所有 POST 动作统一校验）
- XSS 输出转义（`sanitize`/`js_str` + 表单 lint 工具 `tests/lint_forms.py`）
- bcrypt 密码哈希、登录后 `session_regenerate_id`
- 命令执行白名单、shell 参数转义、30 秒超时
- 机密文件 0600 / 目录 0700、nginx 配置原子替换 + 校验回滚（`nginx -t` 失败自动回滚）
- 迁移包自动排除机密（.panel.db/.passwd/.cf_token 等）

## 📝 使用说明

详见 [使用说明.md](./使用说明.md) · 升级与回滚见 [UPGRADE_AND_ROLLBACK.md](./UPGRADE_AND_ROLLBACK.md) · 开发/交接见 [PROJECT_HANDOVER.md](./PROJECT_HANDOVER.md)

## ⚠️ 安全提醒

面板是 **root 级工具**：建议仅通过内网 / SSH 隧道访问，或用防火墙限源，不要直接暴露公网 8080 端口。

## 📝 License

MIT
