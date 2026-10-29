# VPS-Manager（中文 SQLite 单文件面板）项目说明与交接文档

> 更新日期：2026-10-28 ｜ 交接基线：commit **2443394**（HEAD）
> 交付包：`/home/agentuser/downloads/vps-manager-zh-sqlite-v3.0.tar.gz`（299KB，12 个文件，不含 .git/PROJECT_CONTEXT.md，已逐文件 md5 校验与工作副本一致）

---

## 1. 项目是什么

单文件 PHP 的 root 级 VPS 管理面板（fork 改造自 panelboss/vps-manager），中文界面、SQLite 单管理员、无 composer/npm 依赖。功能：网站建站（nginx+PHP 多版本）、伪静态一键预设、数据库、SSL（含 Cloudflare DNS-01 通配符）、备份/迁移、Docker、进程托管、云备份（rclone）、防火墙、监控、文件管理器、Cron、反向代理、缓存、面板自身 HTTPS 等 20+ 页面。

- **主文件**：`index.php`（5660 行 / 335,869 字节 / md5 `54acdca75a28ee17a7e131e305d44f41`）
- **安装方式**：`VP_MANAGER_ADMIN_PASS='***' bash install.sh`（Debian/Ubuntu apt 或 Alpine apk，自动判断）
- **运行形态（生产，v3.0 起）**：root `php -S 127.0.0.1:9001` 常驻服务（Alpine OpenRC `vpsmgr-panel` / Debian systemd `vpsmgr-panel.service`）+ nginx :8080 **纯 HTTP 反代**到 9001。原因：仅 root 模型下 FPM worker POST 全 403——**绝不能让 nginx 直接 fastcgi 到 FPM 跑面板**。80 端口网站照常走 FPM（站点 conf 用 sock）。测试 = root `php -S :PORT index.php`

## 2. 仓库与关键文件

| 文件 | 作用 |
|---|---|
| `index.php` | 全部功能（面板+API+进度端点），单文件部署 |
| `install.sh` / `install-core.sh` | 入口安装器 / 核心（内嵌 gzip+base64 的 index.php、nginx conf、consolidate.php） |
| `build.py` | **把当前 index.php 重新内嵌进 install-core.sh 并生成 install.sh** |
| `install-privilege.sh` | sudo helper 安装器（仅 root 模型下实际上不再被面板使用，保留向后兼容） |
| `consolidate.php` | CLI：多用户收敛到单管理员（`--keep USER` / `--dry-run`），77 行 |
| `tests/lint_forms.py` | 静态门禁：检查 CSRF 字段、on* 属性、confirm 转义（每次改动后必须 0 违规） |
| `CHANGELOG.md` | 全部迭代的中文记录（任务 ID/锚点/验收），回溯第一入口 |
| `PROJECT_CONTEXT.md` | **绝对禁止分发**（真实生产凭据）。不进 tar、不进公开仓库 |
| `index_7f7997.php.baseline` | 3c8bacaa 施工单基线快照（.gitignore 忽略，仅本地回溯用） |

**Git**：本地仓库 `~/vps-manager`，无远程。完整链 30+ commit 从 `ddb3460`（首修）到 `2443394`（HEAD），详见 CHANGELOG.md。

## 3. 架构要点（改代码前必读）

- **动作注册表**：所有 POST `action` 必须同时登记在 `$KNOWN_ACTS`（68 个）和 `$ADMIN_ONLY_ACTS`（42 个）数组中，并带 `csrf_field()`。漏登记 → 400/403。
- **仅 root 模型（T07b）**：非 root 进程 POST → 403 + 红色横幅（仅 `logout` 豁免）。`is_root_process()` = `posix_geteuid()` 回退 `id -u`。**这意味着 FPM worker（www-data/nginx 用户）下所有 POST 都会 403——这是设计行为，不是 bug**。真机功能验收必须 root 起 `php -S`。
- **特权操作**：全部走 `priv_*` 系列函数（priv_apply_file/priv_symlink/priv_unlink/priv_reload_nginx/nginx_verify_or_rollback 等），内部有 is_root_process 分支（sudo helper 通道已删，仅剩 root 直行）。
- **nginx 配置纪律（R1）**：临时文件（tempnam + 0600）→ 写入 sites-available → enabled 用 **软链接**（priv_symlink，不是二次写文件）→ `nginx -t` → 失败自动删除本次产物回滚 → 成功才 reload（reload 结果要检查，R6）。
- **Alpine 兼容**：`is_alpine()` 分支 + `php_bin()`/`php_fpm_svc()`/`alpine_php_sfx()`（php83 无点命名）+ `alpine_fix_fpm_sock()`（新装 PHP-FPM 后初始化 /run/php-fpmNN/ sock 与属主）+ ensure_dirs 顶层自愈（sites-enabled 目录缺失时自动创建并注入 include）。Alpine nginx 默认 include 是 `/etc/nginx/http.d/*.conf`，面板统一改造为 sites-available/enabled。
- **站点→数据库映射**：`/var/www/manager/.site_db_map.json`（0600，flock+原子写），`map[domain] = [数据库名数组]`。备份是否含库、删站/删库清理都依赖它。
- **机密文件清单**（全部 0600）：`.passwd`、`.panel.db`（SQLite）、`.api_token`、`.cf_token`（Cloudflare，读统一走 `cf_token_load()`）、`.notify.json`。**迁移备份排除以上全部 + uptime.log**。
- **进度端点**：`?progress=<task_id>` 轮询 `/tmp/progress_<task_id>.log`（任务日志以 `___COMPLETE___` 结尾）。
- **REST API**：token 经 `X-API-Token`/`Authorization` 头（GET token 参数仅为兼容过渡）。

## 4. 全局编码规则（历轮审计沉淀，改动必须遵守）

- **R1** nginx conf：临时文件→原子替换→`nginx -t`→失败恢复+重载；成功才 reload。
- **R2** 用户输入进 shell/配置/路径前必过 validate_domain/白名单/cmdv argv，禁字符串拼 shell。
- **R3** HTML 输出 sanitize、JS 字符串经 `js_str()`/`confirm_attr()`、CSRF 禁放 on* 属性。
- **R4** 机密 0600、目录 0700、临时文件 tempnam/random_bytes，禁固定 /tmp 路径。
- **R5** `cmd($c, false)` 为静默通道；cmd() 默认追加 2>&1，禁在命令里再写非管道 `2>/dev/null`。
- **R6** 成功提示必须基于退出码/结果检查（reload/install 类尤其如此，参考 priv_reload_nginx 用法）。
- **preg_replace 陷阱**：replacement 字符串中 `$1` 会被当反向引用。preset 类固定文本一律用 `preg_replace_callback`（见 save_rewrite）。
- **每次改完 index.php 必须**：`php -l` → `python3 tests/lint_forms.py` → **`python3 build.py`**（否则 install.sh 内嵌旧版！）→ 重打 tar → CHANGELOG 记录。

## 5. 打包与交付纪律

```bash
cd ~/vps-manager
php -l index.php && python3 tests/lint_forms.py index.php   # 门禁
python3 build.py                                            # 重建 install.sh（内嵌最新 index.php）
tar czf /home/agentuser/downloads/vps-manager-zh-sqlite-v3.0.tar.gz \
  build.py index.php 使用说明.md UPGRADE_AND_ROLLBACK.md install-privilege.sh \
  README.md install-core.sh consolidate.php index.html install.sh CHANGELOG.md tests/lint_forms.py
```
- **绝不**把 `.git`、`PROJECT_CONTEXT.md`、`index_7f7997.php.baseline` 打进包。
- 凭据一律写 `[REDACTED]`，任何日志/文档不落真实密码/token。
- 一切产出默认输出到 `/home/agentuser/downloads/`。

## 6. 测试环境与配方（当前仍存活）

| 环境 | 用途 | 要点 |
|---|---|---|
| Docker `vpsmgr-test`（ubuntu:24.04） | Debian 线验收 | root `php -S 127.0.0.1:8090`（/tmp/panel_root），nginx+fpm 8080 为安装形态 |
| Docker `vpsmgr-alpine`（alpine:3.20） | Alpine 线验收 | 已装 openrc+sysvinit（容器特殊）；FPM worker POST 403=预期；root `php -S 127.0.0.1:8091` 验收 |
| 本机 `/tmp/vpspanel2` | 快速回归 | `sudo -n php -S 127.0.0.1:8898 index.php`；登录 admin / [REDACTED]（/tmp/fixdb.php 可重置 hash） |

**容器更新三步**：改代码 → build.py → tar → `docker cp` → **容器内必须重新 tar xzf**（docker cp 直接覆盖文件不生效于解压场景）→ 重装/重启。
**容器后台进程必须 `docker exec -d`**，否则 exec 退出即被杀；pkill php-fpm 与后续命令分开跑（pkill 会波及自身会话）。

**已完成的真机验收项**（可复跑）：建站/软链/nginx -t/二次建站拒绝/删站拦截/备份 0600/迁移包无机密/伪静态 $1 保留/穿越 conf 名拒绝/php_ext_scan 只列已装版本/consolidate --keep --dry-run/XSS 文件名转义/20+ 页面 200。

## 7. 已知残余问题（接手者优先级清单）

1. **ttyd :8081 明文 http 无认证**——ttyd 不随包安装；部署文档须要求 SSH 隧道/反代加认证（已记录，未改代码）。
2. **helper apply-file src 不校验来源**——低风险（仅 root 可调），纵深防御可选修。
3. **docker-compose-v2 包名**：Debian 12/Ubuntu 22.04 官方源无此包，已做降级尝试（v2→plugin→跳过），**未在 Debian 12 实测**。
4. **Alpine 真机（裸机）未实测**——容器验收已过，OpenRC 在真实主机行为应一致。
5. **U12 打磨项**：全文 13 处 `cmd('nginx -t 2>&1')` 可收敛进 helper（纯重构，无功能影响）。
6. 面板是 root 级 web shell——每次交付都提醒：仅内网/SSH 隧道/HTTPS 反代部署。

## 8. 回溯入口（按序读）

1. 本文件 → 2. `CHANGELOG.md`（30+ commit 全记录）→ 3. `git log`（每 commit 一主题）→ 4. `UPGRADE_AND_ROLLBACK.md`（升级/回滚操作）→ 5. `使用说明.md`（终端用户视角）。
施工单/审计报告原件存于 `/home/agentuser/.hermes/opencraft-attachments/`（3c8bacaa=T01-T24 施工单、594f58e9=终极收尾单、b54f1a71=外部审计报告）。

## 9. 版本指纹（交接时快照）

- index.php：5660 行 / 335,869 B / md5 见 git（真机部署后未再改）
- 真机已部署：Alpine NAT VPS 154.222.30.52（65397→22/18080→8080/20080→80/11443→443），形态即上述 root 服务+反代
- KNOWN_ACTS 68 ｜ ADMIN_ONLY_ACTS 42 ｜ 顶层函数 74 个
- git HEAD：`2443394`（build: 重跑 build.py 内嵌最新 index.php + Alpine 验收记录）
- 近期 commit 链：`3718088`(终极收尾) → `30dd74d`(四轮自审) → `064c4f7`(外部审计整改) → `4c6b84c`(五轮自审) → `2443394`(HEAD)
- Docker 测试容器：vpsmgr-test（ubuntu:24.04）、vpsmgr-alpine（alpine:3.20）均 Up
