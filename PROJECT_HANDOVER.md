# PROJECT_HANDOVER — vps-manager（汉化 SQLite 版 v3.1+）

> 交接文档：接手者读完即可继续开发/部署/排障。最后更新：2026-10-31。
> 仓库：https://github.com/mnbwc/vps-manager（main 分支）
> ⚠️ 本文档**绝不**打进交付 tar 包、**绝不**提交到公开仓库之外的任何压缩包；仓库里已有的历史快照不要更新（敏感信息隔离原则）。

---

## 1. 项目是什么

单文件 PHP VPS 管理面板（`index.php`，约 5943 行，中文界面），单用户 + SQLite 存储（`.panel.db`），面向 Debian/Ubuntu、Alpine、**CentOS/RHEL 系（重点实测 CentOS Stream 9）**。

核心能力：
- 网站管理（PHP 多版本建站 / Node.js 站点 / 反向代理）
- SSL（Let's Encrypt + Cloudflare DNS-01 通配符）
- 数据库（MySQL 可选，默认 SQLite 面板库）
- 文件管理器、定时任务、防火墙、进程托管（systemd/OpenRC）
- Docker 管理、Nginx 在线编辑、伪静态预设、监控图表、Webhook 通知
- REST API Token、云备份（rclone）、迁移打包

## 2. 目录与关键文件

```
index.php            # 全部面板逻辑（唯一源码）
build.py             # 把 index.php gzip+base64 内嵌进 install-core.sh；python3 build.py 产出 install.sh
install.sh           # 顶层安装脚本（sh 兼容），内含 install-core.sh 的 base64 payload
install-core.sh      # 安装主体：包安装、nginx/fpm 配置、面板落位 /var/www/manager
install-privilege.sh # 特权 helper（sudo 白名单 shim），非 root 模式用
consolidate.php      # 备份整理脚本
tests/lint_forms.py  # 表单规范 lint（0 违规为通过门槛）
使用说明.md / UPGRADE_AND_ROLLBACK.md / README.md / CHANGELOG.md
```

**铁律**：
- 改完 `index.php` / `install-core.sh` / `build.py` 必须 `python3 build.py` 重跑并真机实测；build.py 模板里换行必须用 `{chr(10)}`（曾因字面 `\n` 导致 install.sh 单行静默空跑）。
- `php -l index.php` + `python3 tests/lint_forms.py`（0 违规）是提交门槛。
- 交付 tar **必须排除**：`.git/`、`PROJECT_CONTEXT.md`、`index_7f7997.php`（历史残留含敏感内容）。
- GitHub PAT 用后即删本地副本；绝不明文入库。

## 3. 架构铁律（违反必出事故）

1. **root 模型 + nginx 反代**：面板以 root 跑 `php -S 127.0.0.1:9001`（systemd unit `vpsmgr-panel`），nginx 反代 9001。**绝不可 fpm 直连**——非 root 警告 + POST 403（CSRF/session 属主问题全由此而来）。
2. **RHEL conf.d 单目录**：`NGINX_AVAILABLE == NGINX_ENABLED == /etc/nginx/conf.d`，且站点 conf 必须带 `.conf` 后缀（`cfg_filename()`）。任何按 sites-available/sites-enabled 写的逻辑都要过 `is_rhel()` 分支。
3. **新增 POST action 三件套**：`$KNOWN_ACTS` 白名单 + `$ADMIN_ONLY_ACTS`（高危动作）+ 表单内 `csrf_field()`。界面文案一律中文。
4. **nginx 变更必须校验回滚**：写 conf 后跑 `nginx -t`，失败回滚（`nginx_verify_or_rollback`）。坏 conf 会**挡住面板所有建站操作**（nginx -t 全局失败）。
5. **会话/验证码**：登录字段名是 `user`/`pass`（不是 username/password）；SVG 验证码是逐字符 `<text>` 节点，解析须按 x 排序拼接；登录限流文件 `/var/www/manager/.login_guard`（测试时清空它）。RHEL 下 session 目录与 `.panel.db` 必须 `chown nginx`。

## 4. 真机环境（CentOS Stream 9 实测机）

- IP `154.222.30.52`，NAT 端口：65397→22、18080→8080、20080→80、11443→443
- 面板：https://154.222.30.52:18080/（HTTPS mode=on，自签证书含 IP SAN）
- 部署形态：nginx 8080(ssl) → 127.0.0.1:9001 root `php -S`（vpsmgr-panel systemd）
- 站点目录 `/etc/nginx/conf.d/*.conf`；面板库 `/var/www/manager/.panel.db`（0600, nginx 属主）
- 同机还跑着 Kaetram 游戏服（4100 + GM 面板 9003），与面板共存但无关
- ⚠️ 该机 conf.d 里的 `game.kaetram.local.conf` 有特殊 WS 反代写法，改 nginx 全局配置时勿动

## 5. 近期修复史（踩坑索引，按主题归档）

### 5.1 RHEL 兼容
- `create_site` 曾用 Debian 专属 `include snippets/fastcgi-php.conf;` → RHEL nginx -t 失败回滚。修复：`is_alpine()||is_rhel()` 改用 `fastcgi_index index.php;`（~792 / ~1144 两处）；fpm sock RHEL 用 `/run/php-fpm/www.sock`。
- `?page=node` 建站同理，`cfg_path` 已统一走 `.conf` 后缀。
- php-fpm 服务名 / php 二进制无版本号（RHEL 无 `php8.3` 裸名）→ `php_fpm_svc()` / `php_bin()` 已自适应。

### 5.2 幻影站点 / 列表噪音
- 扫描 `conf.d` 会捞到非站点 conf → 过滤规则：跳过无 `server {`、`_`、无点域名、`.bak.`、面板自身 conf（vps-manager.conf / php-fpm.conf）。出现在 ssl/uptime/phpsite 三处扫描 + websites 列表。

### 5.3 siteconf「配置不存在」（最新修复 5cdd0c4）
- websites 列表传 `cfg=test.com`（无后缀），siteconf 页拼 `/etc/nginx/conf.d/test.com` 找不到 → 报「❌ 配置不存在」。修复：原路径不存在时自动补 `.conf`。

### 5.4 删除站点是改名不是删除
- `delete_site` 把 conf rename 成 `<domain>_blocked_<hash>`（防误删）。这些文件不会被 nginx 加载，但会残留在 conf.d。可接受；若要真删需改 index.php 的 delete 分支。

### 5.5 登录/CSRF 系列
- CSRF 死循环：session 目录属主不是 root php 进程可写（RHEL 需 `/var/lib/php/session` chown nginx 或对应配置）。
- 验证码 v3：一次性、300s 过期、hash_equals、失败计节流（`client_ip()`，反代下 REMOTE_ADDR=127.0.0.1 曾致共享桶 DoS，已修）。

### 5.6 HTTPS
- `panel_https_toggle`：mode=on 走 8080 ssl 反代 9001；证书自签含 IP SAN；RHEL conf.d 路径适配。**不可绕过反代直连 fpm**。

## 6. 开发工作流

1. 改 `index.php` → `php -l` → `tests/lint_forms.py` → 本机（或 Docker）冒烟 → 真机 scp `/var/www/manager/index.php` → `systemctl restart vpsmgr-panel` → 浏览器/curl 验证。
2. 通过后：`python3 build.py` → `git add -A`（注意别把 PROJECT_CONTEXT.md / index_7f7997.php 加进来）→ commit + push → 重打交付 tar 到 `/home/agentuser/downloads/`。
3. tar 内容清单（固定）：`build.py index.php 使用说明.md UPGRADE_AND_ROLLBACK.md install-privilege.sh README.md install-core.sh consolidate.php index.html install.sh CHANGELOG.md tests/lint_forms.py`。

### 真机验证登录（脚本/curl 流程）
```
curl -sk -c jar https://127.0.0.1:8080/          # 取 csrf + SVG 验证码（<text> 按 x 排序拼）
POST action=pub-login&user=admin&pass=***&csrf=...&captcha=...   # 302 = 成功
```
测试临时改密码：用 python sqlite3 直接 UPDATE users 表（`sqlite3` CLI 会把 `$2y$10$` 里的 `$` 做 shell 展开，**必须用参数绑定或转义**）；测完恢复原 hash，并清空 `.login_guard`（否则 127.0.0.1 被限流 15 分钟，表象是「尝试次数过多」）。

## 7. 已知残留 / 待办

- [ ] PHP 站「删除」残留 `<domain>_blocked_*` conf 文件（功能正常，仅整洁问题）
- [ ] 仓库 git 历史早期含已删 PROJECT_CONTEXT.md 旧内容（如需彻底清除要 filter-repo + force push）
- [ ] `index_7f7997.php` 历史残留在工作区（已加 tar 排除，可删）
- [ ] GitHub PAT 建议轮换/revoke（本地副本已按纪律删除）
- [ ] 11443→443 NAT 端口未实测过面板 HTTPS
- [ ] 真机 /var/www 残留失败尝试目录（testphp88/99、777r 系列）可清理

## 8. 联系上下文

- 历史会话：session_id `20261027_185829_ce8f00`（session_search 可查每条修复的完整命令与输出）
- 同期关联项目：Kaetram 汉化改版部署于同机（见该项目自己的交接文档），面板为其建过 node 站点/反代，排查面板问题时注意区分。
