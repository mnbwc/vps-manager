# 升级与回滚指南（UPGRADE_AND_ROLLBACK）

## 单用户收敛（T-02）

### 升级窗口
面板在账号数 ≠ 1 时返回 503 并提示执行收敛。升级期间面板不可用，通常 < 1 分钟。

### 步骤
```bash
# 1. 上传新版后，以 root 执行收敛 CLI（位于 DocumentRoot 外）
VP_MANAGER_ADMIN_PASS='你的管理密码' php /usr/local/share/vps-manager/consolidate.php
# 库中已唯一 admin 且不想改密码：省略环境变量直接跑（幂等，仅归档遗留文件+校验+清 session）

# 2. 安装特权 helper（方案 A，可选但推荐）
bash install-privilege.sh

# 3. 重启 php-fpm / 重载面板
```

### 备份位置
- 收敛前自动备份到 `/var/lib/vps-manager/`（0700）：`panel.db.pre-consolidate.<时间戳>`、`.users.bak.<时间戳>`、`.passwd.bak.<时间戳>`

### 收敛 CLI 做了什么
1. 私有备份旧库与遗留文件（Web 根外 0700）
2. 确定唯一 admin：
   - 库中恰 1 个 admin → 保留（可选重置密码）
   - 空库 → 从 legacy `.users` 取唯一 admin 凭据，否则要求显式 `VP_MANAGER_ADMIN_PASS`（绝不静默挑账号、绝不静默重置）
   - 多账号 → 必须显式 `VP_MANAGER_ADMIN_PASS`，收敛为唯一 `admin`
3. 归档 `.users` / `.passwd` 到 `/var/lib/vps-manager/`（改名，防再次导入）
4. 校验 `SELECT COUNT(*) FROM users == 1`
5. 清空全部 PHP session 文件——**所有用户必须重新登录**（旧 `role=user` 快照失效）

### 回滚
```bash
cp /var/lib/vps-manager/panel.db.pre-consolidate.<时间戳> /var/www/manager/.panel.db
# 如需恢复遗留文件：
cp /var/lib/vps-manager/.users.bak.<时间戳> /var/www/manager/.users
```

### 遗留文件处理
`.users` 导入后重命名为 `.users.migrated.<时间戳>` 存放于 `/var/lib/vps-manager/`，`load_users()` 只在**库空且仅一个 admin** 时才读取它，不会复发多账号。

### 运行级门
每个请求（`enforce_single_admin()`）校验登录会话 user 必须等于库中唯一 admin；不匹配（旧 session/role 残留）立即销毁会话并跳转登录页。

---

## 特权执行方案 A（T-34）

面板 PHP-FPM 以 root 运行的部署模型下，`install-privilege.sh` 安装的 `/usr/local/sbin/vpsmgr-helper` 是**纵深防御**：固定白名单操作（nginx -t / nginx reload / systemctl is-active|start|stop|restart|reload / crontab <file>），禁止任意参数路径命令，全部操作写审计日志 `/var/log/vpsmgr-helper.log`。
若未来把 FPM 改为非 root：sudoers 白名单自动启用（仅允许该 helper），届时面板的特权写操作经 helper 通道执行，**不授予 sudo ALL**。

---

## 残余风险（发布判定）

| 项 | 状态 |
|---|---|
| rclone/docker 远程脚本安装 | 已禁管道默认执行 + 二次确认 + 下载到私有文件 + sha256 记录；**仍属残余高风险**，推荐发行版包 |
| API token GET 传参 | 内网工具定位，hash_equals 校验；建议内网/隧道部署 |
| Alpine 真机行为 | 建议一次性 VM 验证后再上生产 |
| CSP | DEFERRED（DEF-1） |
| 备份 manifest HMAC | DEFERRED（DEF-3） |
