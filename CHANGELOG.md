## [3.1] 2026-10-29
### 新增
- 登录页验证码：免 GD 依赖的 SVG 扭曲字符验证码（5 位、随机旋转/干扰线/干扰点），一次性使用（用后即毁）、300 秒过期、`hash_equals` 恒时比较、大小写不敏感；验证码错误也计入登录失败节流（5 次/15 分钟）。
### 修复
- nginx 加入开机自启（`systemctl enable --now` / Alpine `rc-update add`）——此前仅 start，机器重启后 nginx 不自起导致面板反代失效
- 登录节流键改用 `client_ip()`：nginx 反代后 `REMOTE_ADDR` 恒为 127.0.0.1，原实现会让所有访问者共享同一节流桶（一次爆破锁定可 DoS 全站）；现优先取 nginx 传递的 `X-Real-IP`（仅本机反代可设置，无伪造面）。
- 登录页验证码点击刷新由未定义的 `__cap()` 回退改为直接 `location.reload()`。
### 修复（RHEL 兼容补丁 + 状态显示）
- 新增 `is_rhel()` 判定；`pkg_installed` RHEL 用 `rpm -q`（原 dpkg 仅 Debian）、`svc_status`/`php_fpm_svc` RHEL 服务名 `php-fpm`、`php_bin` RHEL 无版本号二进制——修复 dashboard「PHP-FPM 已停止」、services 页「Not Installed」、PHP 页「尚未安装任何版本」
- services 页 PHP 版本名/扩展列表动态化（原硬编码 PHP 8.1）；Nginx 版本号动态显示（原硬编码 v1.18+）
- sites 列表解析跳过非 server 块 conf（php-fpm.conf）与反代兜底 server（server_name _）——修复 uptime 页因对无效域名探测超时导致的 20 秒白屏（现 0.5s）；uptime 探测超时收紧为 3s/连接 2s
- dashboard MySQL 卡状态区分「未安装（SQLite 模式）」与「已停止」
- terminal 页检测 ttyd(8081) 是否运行，未运行给出安装指引而非空白 iframe；iframe 协议自适应 https
- settings 页 GitHub 链接改为 mnbwc/vps-manager
- php 页扩展扫描 RHEL 只报实际 CLI 版本（原 php_bin 恒返回 /usr/bin/php 致 4 版本全显示）；Website PHP Versions 列表同步过滤非 server 块 conf 与 server_name _

### 已知限制
- SVG 验证码基于 `<text>` 节点，对简单 OCR 防御能力有限；主力防线仍为一次性+短过期+失败节流。如需强 OCR 防御可后续换 hCaptcha/Turnstile。
## 2026-10-28 修复优化施工单（基线 index_7f7997.php，md5 3d5e283e）

| 任务 | 状态 | 改动锚点 | 验收 |
| --- | --- | --- | --- |
| T01 站点配置不启用 | ✅ | 新增 `priv_symlink()`；create_site/delete_site(拦截)/restore_site/ssl_install 4 处第二次调用改 symlink；`is_link($p)||file_exists($p)` 悬空链接判断；写入后 `verify_and_rollback_nginx()`（nginx -t 失败回滚 available+enabled） | 容器真机：建站 `readlink sites-enabled/t1.example.com`→available 同名；nginx -t 成功；删站后本体消失、拦截配置 444 生效；restore 后 enabled 链接恢复 |
| T02 备份目录创建顺序 | ✅ | 新增 `ensure_dirs()`（/var/lib/vps-manager 三级 0700），enforce_single_admin 后调用，失败页面顶部红条；backup_site/cloud_backup/migration_backup mkdir 分支删除；zip/sql chmod 0600；load_users 迁移归档前 ensure | 容器：rm -rf backups → 访问自动重建 0700；首次 backup_site 成功，zip 权限 600 |
| T03 12 处 CSRF + JS XSS | ✅ | 新增 `js_str()`/`confirm_attr()`；12 处 onsubmit confirm 全部改 confirm_attr + csrf 独立行；文件管理器删除按钮改 js_str；印尼语文案改中文；新增 tests/lint_forms.py | lint=0 违规；12 表单带 token 提交非 403；`a');alert(1);//.txt` 场景输出为 `&quot;` JSON 转义，alert 原文 0 处 |
| T04 docker/rclone 确认字段 | ✅ | 两表单加 `<input type="checkbox" name="confirm" value="yes" required>`；docker_install 优先 `apt-get install -y docker.io` / `apk add docker`；install_rclone 优先 apt/apk，脚本分支保留确认 | 容器：无 confirm POST → ⚠ 拒绝且 docker/rclone 未安装 |
| T05 迁移下载链接 | ✅ | 链接改 `?dl_migration=`；dl_backup/dl_migration 均 `^[A-Za-z0-9._-]+$` 校验，dl_backup 含斜杠 400；Content-Disposition rawurlencode | 迁移包下载 200 字节数一致；`dl_migration=../x`/`dl_backup=migration/x` 均 400 |
| T06 站点-数据库映射 | ✅ | `site_db_map_load/save()`（flock+rename+0600）；create_site 建库成功写映射；新增 site_db_bind/site_db_unbind（KNOWN_ACTS+ADMIN_ONLY+csrf）；delete_site/delete_db 同步清映射；备份提示「含数据库/未包含」；databases 页绑定表单、backups 页绑定状态 | 本机 root：bind 不存在库 → 拒；bad domain → 拒；备份提示「未包含数据库——请到数据库页绑定」；容器无 mysql 环境逻辑静态核验 |
| T07a posix 兼容 | ✅ | `is_root_process()` 改 function_exists('posix_geteuid') ? … : shell_exec('id -u') | 宿主无 posix 场景回落 id -u |
| T07b 仅 root 模型 | ✅ | 非 root：GET 只读、POST 全 403 红横幅；priv_* 删除 sudo helper 分支（保留 root 直跑） | 本机非 root php -S：POST 403「面板必须以 root 运行」；FPM www-data 容器同样 403 |
| T07c consolidate.php | ✅ | 重写：--keep/--dry-run、备份 .panel.db、单 admin 收敛、session 清理、回滚提示；503 页命令统一 `/usr/local/share/vps-manager/consolidate.php [--keep USER] [--dry-run]` | 容器：dry-run 不改库；2 用户库 → --keep admin 删除其它、role=admin、COUNT=1、回滚文件生成 |
| T07d 文档 | ✅ | 使用说明.md（.panel.db、备份目录、单管理员、必须 root、Alpine php84-posix、升级 503）+ UPGRADE_AND_ROLLBACK.md | 已更新 |
| T08 输出转义 | ✅ | onclick location 改 js_str；progress/task_id 输出审计（均为服务端随机值+sanitize） | grep 全量核查无残留 |
| T09 webhook SSRF | ✅ | notify_save 已 assert_public_url；uptime 4755 已 assert_public_url+FOLLOWLOCATION=false | 静态核验 |
| T10 上传限制 | ✅ | 危险扩展名单补 .user.ini/.ini/.htaccess（delete/file_put 之外的上传路径） | 静态核验 |
| T11 迁移加固 | ✅ | 迁移包排除 .notify.json/.api_token/.cf_token/.users/.passwd（panel.db 保留供恢复，下载 0600） | 容器：tar tzf 无 passwd/api_token/cf_token/notify |
| T12 .cf_token | ✅ | 写入 0600；迁移包排除 | 静态核验 |
| T13 建库不落 SQL 文件 | ✅ | mysql_bin() helper；create_site / create_db 改 cmdv([$mbin], $sql, $ec) stdin 注入，退出码判定（R6） | php -l；无 mysql 环境 flash「mysql 不可用」 |
| T14 uptime.log | ✅ | define('UPTIME_LOG', '/var/lib/vps-manager/uptime.log')，两处读写改常量 | 容器 web 根无 .uptime.log |
| T15 API token 请求头 | ✅ | api_auth 优先 Authorization: Bearer / X-API-Token，GET token 兼容保留 | 静态核验 |
| T16 validate_domain 加固 | ✅ | 长度 253、拒绝 ..、NUL、label ≤63、首尾连字符、单字符 TLD 拒绝 | 本机：../etc、t1..com、-a.com、a..b 拒绝 |
| T17 cmd/crontab | ✅ | cmd($c, bool $merge_stderr=true)；cron 安装三处改 cmdv(argv)+退出码 flash（R5/R6） | php -l |
| T18 PHP 版本来源 | ✅ | selected_php_version / php_switch_site / php_per_site_save 全部白名单 in_array（session 来源） | 静态核验 |
| T19 create_site 不得覆盖 | ✅ | 前置：配置已存在或目录已存在 → flash 拒绝 | 容器：二次建站「nginx 配置已存在」 |
| T20 ssl_wildcard | ✅ | task_id 改 random_bytes(8)（/tmp/progress_ 可预测路径修复，R4）；email FILTER_VALIDATE_EMAIL；'*.'.$domain 插值修正 | php -l |
| T21 optimize | ✅ | proc_open 超时 300s（已为 300）；确认无固定 /tmp 路径 | 静态核验 |
| T22 restore_site 防护 | ✅ | resolve_new_target_under_root 绝对路径剥前缀（前轮）；zip 剥层；priv_mkdir_www | 容器：恢复后 /var/www/t1.example.com/index.html 落位正确、enabled 链接生成、nginx -t 过 |
| T23 Debian 装 PHP | ✅ | php_install 白名单版本 + apt 分支（前轮） | 静态核验 |
| T24 小项 | ✅ | dl_migration 0600 chmod；备份 zip/sql 0600；文案中文化 | 容器 stat 验证 |

## 环境备注
- 容器 FPM 硬性禁止 worker=root：真机 root 模型验收用 `php -S 127.0.0.1:8090`（root）执行；FPM www-data 下 POST 403 为 T07b 预期行为。
- 本机无 mysql/nginx：建库/建站回滚路径以容器真机为准。


## 2026-10-28 第三轮代码自我审计（commit 69e5249）

| 扫描项 | 结果 / 修复 |
| --- | --- |
| shell 拼接 39 处 suspect | 逐一溯源：svc_/ufw/proc/php ver/cron 全部白名单或 intval/regex 过滤 ✓ |
| KNOWN_ACTS 完整性 | 66 处理器全注册，0 缺失 ✓ |
| ADMIN_ONLY_ACTS 纵深 | **补齐 15 个缺失**（delete_site/ssl_install/restore_site/svc_action/upload_file/edit_file/delete_file/new_folder/cron_add/cron_del/unban_ip/rclone_remove/php_switch_site/install_rclone/ssl_wildcard）|
| flash 输出面 | flash_html 统一 strip_tags+属性剥离 ✓；cron flash `<code>$expr $cmd</code>` 补 sanitize |
| 二阶注入 | databases 页 `$dbs`（SHOW DATABASES 回显）加 `[a-zA-Z0-9_-]{1,64}` 白名单（防恶意库名进 -e SQL/shell）|
| R6 无条件成功提示 | fw_add/fw_del 改 ufw 输出判定；svc_action 改 is-active/rc-service status 状态复核；proc_action 文案改「指令已下发」|
| R4 临时文件 | 全部 tempnam+chmod ✓；nginx conf 临时 0644→0600 收紧（5 处）|
| 会话 | httponly+samesite Lax+secure 自适应、登录 5 次/15min 节流（flock+0600）、session_regenerate_id(true) ✓ |
| 文件管理器 | view htmlspecialchars、save/delete basename+resolve+panel_protected、delete_folder resolve+realpath+仅空目录 ✓ |
| PDO/SQL | 无拼接 query/exec ✓ |
| 已知残余 | ttyd 终端 iframe 为外部 8081 明文 http 无认证——部署时必须 SSH 隧道或反代加认证（使用说明已含提醒）；apply-file src 不校验（低风险，已记录）|

回归：php -l ✓；lint_forms 0 违规 ✓；本机 24 页 200 ✓（unknown-act 403 为 T07b 非 root 预期）。


## 2026-10-28 终极收尾修复 + 伪静态功能（依施工单 594f58e9）

**P0**：① `ensure_dirs()` 上移至 `enforce_single_admin()` 之前并加 Alpine Nginx 目录/include 自愈；`mysql_bin()`（PATH 回退）与 `cf_token_load()`（格式校验）落位；② 非 root POST 豁免 `logout`，`is_root_process()` posix_geteuid+`id -u` 回退；③ `migration_backup/restore/delete` 移回 POST 块内（修复提前闭合的 `}`）；④ migration_restore 进度日志改 `/tmp/progress_<task_id>.log`（与轮询端点一致）。

**P1**：⑤ create_site/restore_site `$fastcgi_inc` 统一（消除 `\\$document_root` 双反斜杠语法错误），restore_site 改 `nginx_verify_or_rollback`+`priv_reload_nginx`；⑥ 新增 `alpine_fix_fpm_sock()`（install_svc/php_install 后台串/install_all 三处调用），php_ext_scan、$php_versions、services/php 页全部改 `php_bin()`，站点 PHP 识别正则兼容 Alpine `/run/php-fpm<NN>/`。

**P3**：⑦ 备份路径 7 处 `/var/www/manager/backups` → `BACKUP_DIR`；cloud_backup 0600+uploads 排除+删冗余 mkdir；migration_backup 排除 `.cf_token`、hostname 清洗、tmpdir escapeshellarg、tgz 0600；⑧ proc_add 补 `\r\n\0` 校验、rclone gdrive cid/csec 白名单+token JSON 校验、dns_add Token 先行处理（空 zone 允许只存 Token）、delete_folder 拦面板目录、cron_add 表达式正则+命令换行拦截、docker_install 优先 apt docker.io、cache_toggle_site 正则转义修复、删冗余 `$conf =`、导航栏 3 个字面 `\n` 修复。

**P4 伪静态**：新增 `save_rewrite`（KNOWN_ACTS+ADMIN_ONLY+CSRF），5 预设（wordpress/typecho/thinkphp/laravel/static），自动替换 `location /` 块+`nginx -t` 失败回滚+重载；siteconf 页可视化卡片，websites 页按钮改「📝 伪静态/配置」。

**容器真机验收**：建站 t9 → apply typecho 预设 → conf 落位 rewrite 规则、nginx -t 过、站点 200；穿越 conf 名（../../etc/nginx/nginx.conf）被拒且 nginx.conf 未变；migration_backup 全流程 PASS（tgz 0600、无机密）；php -l ✓；lint_forms 0 违规；本机 24 页 200。


## 2026-10-28 第四轮自我审计（终极收尾单改动面复审）

复审范围：ensure_dirs 上移+Alpine 自愈、mysql_bin/cf_token_load、migration POST 块回移、fastcgi_inc 统一、alpine_fix_fpm_sock、php_bin 全面化、save_rewrite、docker_install apt 优先、proc_add/dns_add/cron_add 校验、rclone gdrive。

**核查结论（全安全）**：① save_rewrite——conf_name 白名单+realpath 前缀校验、preset 固定白名单、preg_replace 无 /e（前次探针误报）、nginx -t 失败回滚 ✓；② Alpine 自愈写 nginx.conf 仅插固定 include，is_alpine() 守卫 ✓；③ alpine_fix_fpm_sock $ver 链自 selected_php_version() 严格白名单 ✓；④ dns_add Token 先行处理：格式校验+0600 落盘+curl header 均 `Bearer $token` ✓；⑤ docker_install confirm=yes 在最前、覆盖 apt 失败后的脚本回退分支 ✓；⑥ cloud_backup $exclude escapeshellarg ✓、/var/www/manager/backups 硬编码残留 0 处 ✓；⑦ ENSURE_DIRS_WARN 横幅仅输出静态常量 ✓；⑧ nav_link 无 XSS、redirect('siteconf&cfg=') 参数白名单后拼入 ✓。

**修复 1 项（R6）**：save_rewrite 与 edit_conf 的 Nginx 重载结果未检查——`priv_reload_nginx()` 返回值接入，失败时明确提示「已保存但重载失败，请手动 reload」（create_site 处 1052 同型调用一并修正）。

**回归**：php -l ✓；lint_forms 0 违规 ✓；本机 24 页全 200 ✓；容器复测 save_rewrite（wordpress 预设）+ edit_conf 全 PASS、站点 200、nginx -t ✓。


## 2026-10-28 外部助手审计报告审核与整改（b54f1a71）

外部审计（对照其他助手的 index.php 版本）逐项复核到本工作副本，**8 项全部属实**，全部修复：

**P0**：① 伪静态 typecho/thinkphp 预设 `$1` 被 preg_replace 当反向引用吞掉 → 改 `preg_replace_callback`（callback 返回值不参与反向引用解析）。容器实测 typecho 输出 `rewrite ^(.*)$ /index.php$1 last;`、thinkphp 输出 `...?s=/$1 last;` ✓。

**P1**：② 站点 PHP 版本识别被下一行 `$php_ver = $phpm[1] ?? '?';` 覆盖（Alpine 恒显示 `?`）→ 删覆盖行；③ `install_svc` php 分支补 `alpine_fix_fpm_sock(selected_php_version())`；④ rclone gdrive step1/step2 补 `$cid/$csec` 白名单 `/^[A-Za-z0-9._-]{1,256}$/`（rclone.conf 注入面，FIX-03 补全）；⑤ `$fastcgi_inc` Debian 分支恢复 `include snippets/fastcgi-php.conf;`（PATH_INFO + try_files =404 防护；Alpine 仍由模板行提供 SCRIPT_FILENAME）。

**P2/P3**：⑥ `php_ext_scan` 改 `is_executable($bin)` 跳过未安装版本；⑦ delete_site 清理 `.site_db_map.json` 僵尸映射（U07）；⑧ backup_site 冗余 mkdir 简化、迁移页文案 `.cf_token` 同步（U09/文档）；⑨ 顺带修 nginx 模板 `gzip_types text/html` duplicate MIME 警告（text/html 为 nginx 默认）。

**未采纳**：外部报告提的 `addcslashes` 方案（deepseek 已澄清不同 PHP 版本行为不一致，仅用 callback 方案）；U11 印尼语/U12 nginx -t 冗余为 P3 打磨项本轮不改；docker-compose-v2 包名兼容性留 Debian 12 实测确认。

**回归**：php -l ✓；lint_forms 0 违规 ✓；本机 24 页 200 ✓；容器实测：typecho/thinkphp rewrite `$1` 保留、建站含 snippet、nginx -t 无警告、站点 200、delete_site 后映射清理 ✓。


## 2026-10-28 第五轮自我审计（外部整改后复查）

复核外部整改改动面，发现并修复 4 项：① delete_site 映射清理逻辑修正——map[domain] 值为数据库数组，原 `in_array($domain,$map)`/`$v===$domain` 分支永不命中，简化为 `unset($map[$domain])`；② docker_install Debian 包名兼容——docker-compose-v2 在 Debian 12/Ubuntu 22.04 官方源缺失会导致 apt 整体失败，改为 docker.io 主装 + compose 单独降级尝试（docker-compose-v2 → docker-compose-plugin）；③ cache_toggle reload 改 priv_reload_nginx() 结果检查（R6）；④ 印尼语残留 2 处汉化（U11：「tapi test gagal」「Field 必填 diisi」）。

**回归**：php -l ✓；lint_forms 0 违规 ✓；本机 24 页 200 ✓。


## 2026-10-28 Alpine Docker 真机验收（alpine:3.20，vpsmgr-alpine）

**第五轮审计 4 项修复**（commit 4c6b84c）后 Alpine 全流程验证：install.sh 一键安装 ✓（PHP 8.3 SQLite 模式）；FPM sock `/run/php-fpm83/php-fpm.sock` 正常（alpine_php_sfx 形态）✓；**仅 root 模型在 Alpine 同样生效**——FPM worker(nginx 用户) POST 403 = 预期，root php -S :8091 验收；建站 a1 → priv_symlink enabled 软链 ✓、nginx.conf 自动注入 sites-enabled include（Alpine 自愈）✓、站点 200 ✓；typecho 伪静态 `$1` 保留 ✓；php_ext_scan 仅列已装 8.3（is_executable 修复生效）✓；备份 zip 0600 ✓；migration_backup tgz 无机密 ✓；删站 ✓；20+ 页全 200 ✓。

**发现与处理**：① install-core.sh 内嵌旧 index.php（base64+gzip），工作副本改动不进包 → 重跑 build.py 重新生成 install.sh/install-core.sh 并重打 tar（教训：改 index.php 后必须 `python3 build.py` 再打包）；② Alpine nginx 默认 include 为 /etc/nginx/http.d/*.conf（非 sites-enabled）——ensure_dirs 自愈已覆盖 ✓；③ Alpine 容器 rc-service 需 openrc + sysvinit 软链才能管理服务（容器环境特殊，真实 Alpine 主机自带）。


## 2026-10-28 项目说明与交接文档

新增 `PROJECT_HANDOVER.md`：项目定位/文件清单/架构要点（动作注册表/仅root模型/priv_*/R1-R6 规则/Alpine 兼容/机密清单/进度端点）/打包纪律/测试环境配方/残余问题清单/回溯入口/版本指纹。交付包加入该文件。


## 2026-10-29 真机部署形态回写（install-core.sh）

NAT VPS（Alpine 3.21 裸机）实测发现并修复：**生产形态改为 root php -S 常驻 + nginx 反代**——原 install-core.sh 让 nginx 直接 fastcgi 到 FPM 跑面板，因仅 root 模型（T07b）FPM worker 所有 POST 403，登录必挂。现 install-core.sh 自动生成：Alpine OpenRC 服务 `vpsmgr-panel`（root php -S 127.0.0.1:9001）/ Debian systemd 同名 unit；nginx 8080 纯 HTTP 反代 9001；网站 80 端口照常 FPM。另：install.sh/build.py shebang 改 `#!/bin/sh`（Alpine 裸机无 bash 也能起安装器）；APK_PKGS 补 zip（69c6996）。PROJECT_HANDOVER.md 同步部署形态与真机信息。真机全链路复测：公网登录→建站→站点 200→删站 PASS。
