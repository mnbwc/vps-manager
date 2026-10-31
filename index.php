<?php
session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax', 'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'), 'path' => '/']);
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
session_start();
define('PASSWD_FILE', '/var/www/manager/.passwd');
define('USERS_FILE', '/var/www/manager/.users');
define('BACKUP_DIR', '/var/lib/vps-manager/backups');
define('MIGRATION_DIR', '/var/lib/vps-manager/backups/migration');
// RHEL 系（CentOS/Rocky/Alma）站点配置目录是 /etc/nginx/conf.d
function is_rhel(): bool { // RHEL 系判定（CentOS/Rocky/Alma/Fedora）
    static $c = null;
    if ($c === null) {
        $c = file_exists('/etc/redhat-release')
            || (is_readable('/etc/os-release') && preg_match('/^(ID_LIKE|ID)=.*(rhel|centos|fedora|rocky|alma)/mi', file_get_contents('/etc/os-release')));
    }
    return $c;
}
if (is_rhel()) {
    define('NGINX_AVAILABLE', '/etc/nginx/conf.d');
    define('NGINX_ENABLED', '/etc/nginx/conf.d');
} else {
    define('NGINX_AVAILABLE', '/etc/nginx/sites-available');
    define('NGINX_ENABLED', '/etc/nginx/sites-enabled');
}
define('WWW_ROOT', '/var/www');

// RHEL 系 NGINX_AVAILABLE == NGINX_ENABLED（/etc/nginx/conf.d），软链自指会产生 E_LOOP
// RHEL conf.d 要求 .conf 后缀：站点配置文件名统一走此 helper
function cfg_filename(string $domain): string { return is_rhel() ? $domain . '.conf' : $domain; }
function cfg_path(string $domain, string $which = 'available'): string {
    $base = $which === 'enabled' ? NGINX_ENABLED : NGINX_AVAILABLE;
    return $base . '/' . cfg_filename($domain);
}
function priv_nginx_link_site(string $src, string $dst): void {
    if (realpath(dirname($src)) === realpath(dirname($dst))) return; // RHEL conf.d 单目录：无需软链
    @symlink($src, $dst);
}
define('DB_FILE', '/var/www/manager/.panel.db'); // 点前缀：配合 nginx location ~ /\. deny 防外泄

// ===== SQLITE =====
function db(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $dir = dirname(DB_FILE);
        if (!is_dir($dir)) { @mkdir($dir, 0700, true); }
        if (is_file(DB_FILE) && !is_writable(DB_FILE) && function_exists('posix_getuid') && posix_getuid() === 0) { @chmod(DB_FILE, 0660); }
        try { $pdo = new PDO('sqlite:' . DB_FILE); }
        catch (Throwable $e) { http_response_code(500); exit('⛔ 无法打开面板数据库 ' . basename(DB_FILE) . '：请检查文件属主与运行用户一致（如 chown ' . get_current_user() . ' ' . DB_FILE . '）。'); }
        @chmod(DB_FILE, 0600);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec('CREATE TABLE IF NOT EXISTS users (user TEXT PRIMARY KEY, pass TEXT NOT NULL, role TEXT NOT NULL DEFAULT "user")');
    }
    return $pdo;
}

// Load users
function load_users() {
    static $cache = null;
    if ($cache !== null && empty($GLOBALS['_users_cache_stale'])) return $cache;
    $rows = db()->query('SELECT user, pass, role FROM users')->fetchAll(PDO::FETCH_ASSOC);
    if (empty($rows)) {
        // 首次启动：种入默认管理员（密码取旧 .passwd 明文，否则 admin123），立即 bcrypt 化
        $env_pass = getenv('VP_MANAGER_ADMIN_PASS') ?: '';
        if (file_exists(PASSWD_FILE)) $init = trim(file_get_contents(PASSWD_FILE));
        elseif ($env_pass) $init = $env_pass;
        else {
            // 无任何初始密码来源：写入引导文件，管理员须手动创建后重试
            $bootstrap = dirname(DB_FILE) . '/.bootstrap_required';
            if (!file_exists($bootstrap)) file_put_contents($bootstrap, date('c') . " 首次启动：请在服务器上执行  echo -n '你的管理密码' > " . PASSWD_FILE . "  (chmod 600) 后刷新本页\n");
            http_response_code(503); exit('<h2 style="font-family:sans-serif">首次初始化</h2><p style="font-family:sans-serif">未检测到初始管理密码。请在服务器上执行：<br><code>echo -n \'你的密码\' &gt; ' . PASSWD_FILE . ' &amp;&amp; chmod 600 ' . PASSWD_FILE . '</code><br>然后刷新本页。</p>');
        }
        if ($init === '') { http_response_code(503); exit('初始密码为空，请在 ' . PASSWD_FILE . ' 写入非空密码'); }
        db()->prepare('INSERT INTO users (user, pass, role) VALUES (?, ?, ?)')
            ->execute(['admin', password_hash($init, PASSWORD_BCRYPT), 'admin']);
        $bootstrap = dirname(DB_FILE) . '/.bootstrap_required';
        if (file_exists($bootstrap)) @unlink($bootstrap);
        if (file_exists(PASSWD_FILE)) @unlink(PASSWD_FILE);
        $rows = db()->query('SELECT user, pass, role FROM users')->fetchAll(PDO::FETCH_ASSOC);
    }
    // 兼容迁移（T-02 重写）：只允许「库空 + 仅 .users」场景导入唯一 admin 账号；
    // 多账号一律 503，指向 CLI 收敛工具（vpsmgr-consolidate），不再自动导入多账号、不再静默重置密码
    $legacy = '/var/www/manager/.users';
    if (file_exists($legacy) && empty($rows)) {
        $arr = json_decode(@file_get_contents($legacy), true);
        if (is_array($arr)) {
            $admins = array_values(array_filter($arr, fn($u) => ($u['role'] ?? 'user') === 'admin'));
            if (count($admins) === 1) {
                $u = $admins[0];
                if (!empty($u['user']) && !empty($u['pass'])) {
                    db()->prepare('INSERT INTO users (user, pass, role) VALUES (?, ?, ?)')
                        ->execute([$u['user'], strlen($u['pass']) >= 20 ? $u['pass'] : password_hash($u['pass'], PASSWORD_BCRYPT), 'admin']);
                    // 归档 .users（移出 Web 根可执行路径，改名防重导入）
                    if (!is_dir('/var/lib/vps-manager')) @mkdir('/var/lib/vps-manager', 0700, true);
                    @rename($legacy, '/var/lib/vps-manager/.users.migrated.' . date('YmdHis'));
                    $rows = db()->query('SELECT user, pass, role FROM users')->fetchAll(PDO::FETCH_ASSOC);
                }
            }
        }
    }
    // 单用户不变式：非 1 行 → 永久 503，提示 CLI 收敛（每请求都到这里的调用方都会被拦）
    if (count($rows) !== 1) {
        http_response_code(503);
        exit('<h2 style="font-family:sans-serif">需要单用户收敛</h2><p style="font-family:sans-serif">检测到账号数异常（当前 ' . count($rows) . ' 个，要求恰好 1 个 admin）。请在服务器上以 root 执行收敛工具：<br><code>php /usr/local/share/vps-manager/consolidate.php [--keep USER] [--dry-run]</code><br>详见 UPGRADE_AND_ROLLBACK.md。</p>');
    }
    $cache = $rows;
    $GLOBALS['_users_cache_stale'] = false;
    return $rows;
}
function save_users($users) {
    $st = db()->prepare('INSERT INTO users (user, pass, role) VALUES (?, ?, ?) ON CONFLICT(user) DO UPDATE SET pass = excluded.pass, role = excluded.role');
    db()->beginTransaction();
    foreach ($users as $u) { $st->execute([$u['user'], $u['pass'], $u['role'] ?? 'user']); }
    db()->commit();
    $GLOBALS['_users_cache_stale'] = true;
}
function check_user($u, $p) {
    foreach (load_users() as $user) {
        if ($user['user'] === $u) {
            $stored = $user['pass'];
            // 兼容迁移：旧明文密码首次登录后自动升级为 bcrypt
            if (strlen($stored) < 20 && hash_equals($stored, $p)) {
                $user['pass'] = password_hash($p, PASSWORD_BCRYPT);
                if (!db()->prepare('UPDATE users SET pass = ? WHERE user = ?')->execute([$user['pass'], $u])) return null;
                $GLOBALS['_users_cache_stale'] = true;
                if (file_exists(PASSWD_FILE)) @unlink(PASSWD_FILE);
            } elseif (!password_verify($p, $stored)) {
                return null;
            }
            return $user;
        }
    }
    return null;
}
function current_user() { if (isset($_SESSION['user'])) return $_SESSION['user']; return null; }

// ===== 平台检测与抽象（Debian/Ubuntu vs Alpine）=====
function is_alpine() { return file_exists('/etc/alpine-release'); }
function web_user() { return is_alpine() ? 'nginx' : 'www-data'; }
function uptime_str() { $u = (float)(@file_get_contents('/proc/uptime') ?: 0); $d = floor($u/86400); $h = floor(($u%86400)/3600); return $d > 0 ? "{$d} days {$h}h up" : "{$h}h up"; }
function proc_top($n = 10) {
    $rows = explode("\n", trim(cmd("ps -o %cpu,%mem,comm -A 2>/dev/null") ?: ''));
    $list = [];
    foreach (array_slice($rows, 1) as $r) {
        $f = preg_split('/\s+/', trim($r));
        if (count($f) >= 3 && is_numeric($f[0])) $list[] = $f;
    }
    usort($list, fn($a,$b) => ($b[1] ?: 0) <=> ($a[1] ?: 0));
    $out = [];
    foreach (array_slice($list, 0, $n) as $f) $out[] = "{$f[0]} {$f[1]} {$f[2]}";
    return implode("\n", $out);
}
define('NOTIFY_FILE', '/var/www/manager/.notify.json');
// T14：uptime 历史移出 web 根（避免未鉴权读取站点域名与状态）
define('UPTIME_LOG', '/var/lib/vps-manager/uptime.log');
define('API_TOKEN_FILE', '/var/www/manager/.api_token');
function is_mysql_available() {
    // 小内存 VPS / 未安装时：仅 SQLite 可用
    if (is_alpine()) return extension_loaded('mysqli') || is_executable('/usr/bin/mariadb') || is_executable('/usr/bin/mysql');
    return is_executable('/usr/bin/mysql') || is_executable('/usr/bin/mariadb') || pkg_installed('mariadb-server') || pkg_installed('default-mysql-server');
}
// MySQL/None CLI 包装：未安装时优雅报错而不是裸崩
// P0：mysql 二进制定位（含 PATH 回退）；Cloudflare Token 读取（含格式校验）
function mysql_bin(): ?string {
    if (!is_mysql_available()) return null;
    foreach (['/usr/bin/mariadb', '/usr/bin/mysql'] as $bin) {
        if (is_executable($bin)) return $bin;
    }
    foreach (['mariadb', 'mysql'] as $name) {
        $p = trim((string)@shell_exec('command -v ' . escapeshellarg($name) . ' 2>/dev/null'));
        if ($p !== '') return $p;
    }
    return null;
}
function cf_token_load(): string {
    $f = '/var/www/manager/.cf_token';
    if (!file_exists($f)) return '';
    $t = trim((string)@file_get_contents($f));
    if ($t === '' || strlen($t) > 200 || preg_match('/[\r\n"\']/', $t)) return '';
    return $t;
}
function mysql_cli($args) {
    if (!is_mysql_available()) return 'echo "MySQL/MariaDB 未安装（本机使用 SQLite 模式）"';
    foreach (['/usr/bin/mariadb', '/usr/bin/mysql'] as $bin) if (is_executable($bin)) return escapeshellarg($bin) . ' ' . $args;
    return 'mariadb ' . $args;
}
function mysqldump_cli($args) {
    if (!is_mysql_available()) return 'echo "MySQL/MariaDB 未安装（本机使用 SQLite 模式）"';
    foreach (['/usr/bin/mariadb-dump', '/usr/bin/mysqldump'] as $bin) if (is_executable($bin)) return escapeshellarg($bin) . ' ' . $args;
    return 'mariadb-dump ' . $args;
}
// init 服务管理器
function svc_restart($name) { return is_alpine() ? cmd("rc-service $name restart 2>&1") : cmd("systemctl restart $name 2>&1"); }
function svc_reload($name) { return is_alpine() ? cmd("rc-service $name reload 2>&1 || rc-service $name restart 2>&1") : cmd("systemctl reload $name 2>&1"); }
function svc_start_enable($name) { return is_alpine() ? cmd("rc-update add $name default 2>/dev/null; rc-service $name start 2>&1") : cmd("systemctl enable --now $name 2>&1"); }
// PHP 版本选择（会话级，默认 8.3）：8.2 / 8.3 / 8.4 / 8.5
function selected_php_version() {
    $v = $_SESSION['phpver'] ?? '8.3';
    return in_array($v, ['8.2','8.3','8.4','8.5'], true) ? $v : '8.3';
}
function alpine_php_sfx($v = null) { return str_replace('.', '', $v ?? selected_php_version()); }
function php_bin($v) { return is_alpine() ? '/usr/bin/php' . str_replace('.', '', $v) : (is_rhel() ? '/usr/bin/php' : '/usr/bin/php' . $v); }
function php_fpm_svc() { return is_alpine() ? 'php-fpm' . alpine_php_sfx() : (is_rhel() ? 'php-fpm' : 'php' . selected_php_version() . '-fpm'); }
// P1：Alpine 新装 PHP-FPM 的 socket 自动初始化（目录+listen+属主）
function alpine_fix_fpm_sock(string $ver): void {
    if (!is_alpine()) return;
    $pv = str_replace('.', '', $ver);
    $conf = "/etc/php$pv/php-fpm.d/www.conf";
    if (!is_file($conf)) return;
    @mkdir("/run/php-fpm$pv", 0755, true);
    $c = file_get_contents($conf);
    $c = preg_replace('/^listen\s*=\s*.+$/m', "listen = /run/php-fpm$pv/php-fpm.sock", $c);
    $c = preg_replace('/^;?listen\.owner\s*=\s*.+$/m', 'listen.owner = nginx', $c);
    $c = preg_replace('/^;?listen\.group\s*=\s*.+$/m', 'listen.group = nginx', $c);
    $c = preg_replace('/^user\s*=\s*.+$/m', 'user = nginx', $c);
    $c = preg_replace('/^group\s*=\s*.+$/m', 'group = nginx', $c);
    file_put_contents($conf, $c);
}
function php_pkg_list() {
    if (is_alpine()) {
        $v = str_replace('.', '', selected_php_version());
        return "php$v php$v-fpm php$v-common php$v-mysqli php$v-curl php$v-gd php$v-mbstring php$v-xml php$v-zip php$v-opcache php$v-pecl-apcu";
    }
    $v = selected_php_version();
    return "php$v-fpm php$v-cli php$v-mysql php$v-curl php$v-gd php$v-mbstring php$v-xml php$v-zip php$v-common php$v-opcache php$v-apcu";
}
// 当前运行的 php-fpm 版本（供 nginx 配置与状态显示）
function php_fpm_bin_test($v) {
    if (is_alpine()) return '/usr/sbin/php-fpm' . str_replace('.','',$v) . ' --test';
    return '/usr/sbin/php-fpm' . $v . ' --test';
}
function active_php_fpm() {
    // T-27：仅 CLI 二进制存在不足以证明 FPM 可用——必须验证 FPM socket/service 真实存在
    foreach (['8.5','8.4','8.3','8.2'] as $v) {
        $sock = is_alpine() ? '/run/php-fpm' . str_replace('.','',$v) . '/php-fpm.sock' : '/var/run/php/php' . $v . '-fpm.sock';
        $svc = is_alpine() ? 'php-fpm' . str_replace('.','',$v) : 'php' . $v . '-fpm';
        $svc_ok = is_alpine()
            ? trim(cmd('rc-service ' . escapeshellarg($svc) . ' status 2>/dev/null')) === 'started'
            : trim(cmd('systemctl is-active ' . escapeshellarg($svc) . ' 2>/dev/null')) === 'active';
        if (file_exists($sock) || $svc_ok) return $v;
    }
    // Alpine: php 与 php-fpm83 命名
    if (is_alpine()) { $o = trim(cmd('php -r "echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;" 2>/dev/null')); if ($o) return $o; }
    $o = trim(cmd('php -r "echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;" 2>/dev/null'));
    return $o ?: '8.3';
}
    // ===== NODE.JS 支持 =====
function node_sites_file(): string { return '/var/www/manager/.node_sites.json'; }
function node_sites_all(): array {
    if (!is_file(node_sites_file())) return [];
    $d = json_decode(file_get_contents(node_sites_file()), true);
    return is_array($d) ? $d : [];
}
function node_sites_save(array $d): void {
    file_put_contents(node_sites_file(), json_encode($d, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE));
    @chmod(node_sites_file(), 0600);
}
function node_installed(): bool { return is_executable('/usr/bin/node') || is_executable('/usr/local/bin/node'); }
function node_version(): string { return trim(cmd('node -v 2>/dev/null') ?: ''); }

function enforce_single_admin() {
    // T-02：每请求校验登录会话对应库中唯一 admin（旧 session / role=user 残留一律作废）
    if (empty($_SESSION['auth'])) return;
    $rows = load_users();
    if (count($rows) !== 1) { return; } // 多账号时由 load_users 的 503 门兜底
    $only = $rows[0];
    $cu = current_user();
    if (!$cu || ($cu['user'] ?? '') !== $only['user'] || ($cu['role'] ?? '') !== 'admin') {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) { $pp = session_get_cookie_params(); setcookie(session_name(), '', time()-42000, $pp['path'], $pp['domain'], $pp['secure'], $pp['httponly']); }
        session_destroy();
        header('Location: ?'); exit;
    }
}
// T02/P0：运行前置——备份目录树缺失自动重建 + Alpine Nginx 目录/include 自愈（页面加载即执行）
function ensure_dirs(): bool {
    $ok = true;
    foreach (['/var/lib/vps-manager', '/var/lib/vps-manager/backups', '/var/lib/vps-manager/backups/migration'] as $dir) {
        if (!is_dir($dir)) { if (!@mkdir($dir, 0700, true) && !is_dir($dir)) { $ok = false; continue; } }
        @chmod($dir, 0700);
    }
    if (is_alpine()) {
        foreach ([NGINX_AVAILABLE, NGINX_ENABLED, '/etc/nginx/conf.d'] as $nd) {
            if (!is_dir($nd)) @mkdir($nd, 0755, true);
        }
        $nc = '/etc/nginx/nginx.conf';
        if (is_file($nc)) {
            $nbody = file_get_contents($nc);
            if (strpos($nbody, 'sites-enabled') === false && preg_match('/http\s*\{/', $nbody)) {
                $nbody = preg_replace('/(http\s*\{)/', "$1\n    include /etc/nginx/conf.d/*.conf;\n    include /etc/nginx/sites-enabled/*;", $nbody, 1);
                file_put_contents($nc, $nbody);
            }
        }
    }
    return $ok;
}
enforce_single_admin();
// T02：运行前置——备份目录树缺失时自动重建（失败页面顶部提示）
$GLOBALS['ENSURE_DIRS_WARN'] = !ensure_dirs();
function is_admin() { $u = current_user(); return $u && ($u['role'] ?? '') === 'admin'; }

$page = $_GET['page'] ?? 'dashboard';

// ===== PROGRESS ENDPOINT =====
if (($_GET['progress'] ?? '') !== '') {
    if (empty($_SESSION['auth'])) { http_response_code(403); exit('Forbidden'); }
    $pf = '/tmp/progress_' . basename($_GET['progress']) . '.log';
    if (file_exists($pf) && preg_match('/^[A-Za-z0-9_.-]+$/', basename($_GET['progress']))) {
        header('Content-Type: text/plain');
        $log = file_get_contents($pf);
        echo $log;
        if (strpos($log, '___COMPLETE___') !== false) {
            echo "\n___DONE___\n";
            unlink($pf);
        }
        exit;
    }
    echo "等待中...\n";
    exit;
}

// 预发 CSRF token（匿名会话也有，登录表单使用）
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
// ===== 早期 API GATE（在登录墙之前：metrics 需会话，其余需 token）=====
    if (isset($_GET['cleanup_scan'])) { if (!current_user()) { http_response_code(401); echo json_encode(['error'=>'unauthorized']); exit; }
        header('Content-Type: application/json');
        $items = [];
        $add = function($k, $label, $cmd_sz) use (&$items) { $items[$k] = ['label' => $label, 'size' => trim(cmd($cmd_sz))]; };
        $add('aptcache', 'APT/APK 包缓存', "sh -c 'du -sh /var/cache/apt/archives 2>/dev/null || du -sh /var/cache/apk 2>/dev/null' | cut -f1");
        $add('journal', '系统日志 journal', "journalctl --disk-usage 2>/dev/null | grep -oE '[0-9.]+[KMG]' | head -1");
        $add('varlog', '/var/log 压缩与 7 天前旧日志', "du -sh /var/log 2>/dev/null | cut -f1");
        $add('tmp', '/tmp 3 天前临时文件', "sh -c 'find /tmp -type f -atime +3 -not -name vpsmgr* 2>/dev/null | xargs du -ch 2>/dev/null | tail -1' | cut -f1");
        $add('backups', '面板旧备份（30 天前）', "sh -c 'find /var/lib/vps-manager/backups -mtime +30 -type f 2>/dev/null | xargs du -ch 2>/dev/null | tail -1' | cut -f1");
        echo json_encode($items);
        exit;
    }

if (isset($_GET['php_ext_scan'])) { if (!current_user()) { http_response_code(401); echo json_encode(['error'=>'unauthorized']); exit; }
    header('Content-Type: application/json; charset=utf-8');
    $exts = ['opcache','apcu','redis','igbinary','imagick','memcached','swoole','xdebug','ssh2','zstd','yaml','grpc'];
    $out = [];
    foreach (['8.2','8.3','8.4','8.5'] as $v) {
        $bin = php_bin($v);
        if (is_rhel() && $v !== trim(cmd("php -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;' 2>/dev/null") ?: '')) continue; // RHEL 单二进制：只报实际 CLI 版本
        if (!is_executable($bin)) continue; // 审计修复：未安装版本跳过（php_bin 恒返回非空）
        $mods = explode("\n", trim(cmd(escapeshellarg($bin) . " -m 2>/dev/null") ?: ''));
        $mods = array_map('trim', $mods);
        $have = [];
        foreach ($exts as $e) {
            $key = $e === 'opcache' ? 'Zend OPcache' : ($e === 'apcu' ? 'apcu' : $e);
            $have[$e] = in_array($key, $mods, true) || in_array(ucfirst($e), $mods, true);
        }
        $out[$v] = $have;
    }
    echo json_encode($out);
    exit;
}

if (isset($_GET['dl_backup'])) { if (!current_user()) { http_response_code(401); exit('unauthorized'); }
    $fn = basename($_GET['dl_backup']);
    if (!preg_match('/^[A-Za-z0-9._-]+$/', $fn) || str_contains($_GET['dl_backup'], '/') || str_contains($_GET['dl_backup'], chr(92))) { http_response_code(400); exit('bad filename'); }
    $path = realpath(BACKUP_DIR . '/' . $fn);
    $base = realpath(BACKUP_DIR);
    if ($path && $base && strpos($path . '/', $base . '/') === 0 && is_file($path)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . rawurlencode($fn) . '"');
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: no-store');
        header('Content-Length: ' . filesize($path));
        readfile($path);
    } else { http_response_code(404); echo 'not found'; }
    exit;
}
// T-19：迁移备份独立下载端点（原 basename() 会把 migration/xxx.tar.gz 截成 xxx.tar.gz → 一律 404）
if (isset($_GET['dl_migration'])) { if (!current_user()) { http_response_code(401); exit('unauthorized'); }
    $fn = basename($_GET['dl_migration']);
    if (!preg_match('/^[A-Za-z0-9._-]+$/', $fn) || str_contains($_GET['dl_migration'], '/') || str_contains($_GET['dl_migration'], chr(92))) { http_response_code(400); exit('bad filename'); }
    $mdir = defined('MIGRATION_DIR') ? MIGRATION_DIR : BACKUP_DIR . '/migration';
    $path = realpath($mdir . '/' . $fn);
    $base = realpath($mdir);
    if ($path && $base && strpos($path . '/', $base . '/') === 0 && is_file($path)) {
        @chmod($path, 0600);
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . rawurlencode($fn) . '"');
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: no-store');
        header('Content-Length: ' . filesize($path));
        @chmod($path, 0600);
        readfile($path);
    } else { http_response_code(404); echo 'not found'; }
    exit;
}
if (isset($_GET['api'])) {
    header('Content-Type: application/json');
    if ($_GET['api'] === 'metrics') {
        if (!current_user()) { http_response_code(401); echo json_encode(['error' => 'unauthorized']); exit; }
        $cpu = round(floatval(trim(cmd("top -bn1 | grep 'Cpu(s)' | awk '{print \$2+\$4}' 2>/dev/null") ?: '0')), 1);
        $mem_total = intval(trim(cmd("free -m | grep Mem | awk '{print \$2}'")) ?: 0);
        $mem_used = intval(trim(cmd("free -m | grep Mem | awk '{print \$3}'")) ?: 0);
        $load = sys_getloadavg();
        $net = trim(cmd("cat /proc/net/dev 2>/dev/null | awk 'NR>2 && \$1 !~ /lo:/ {gsub(\":\",\"\",\$1); rx+=\$2; tx+=\$10} END {print rx+0, tx+0}'") ?: '0 0');
        list($net_rx, $net_tx) = array_pad(explode(' ', $net), 2, 0);
        $sample = ['t' => time(), 'cpu' => $cpu, 'mem' => $mem_total > 0 ? round($mem_used / $mem_total * 100, 1) : 0, 'load' => round($load[0], 2), 'rx' => intval($net_rx), 'tx' => intval($net_tx)];
        $buf_file = '/dev/shm/vpsmgr_metrics.json';
        $fp = fopen($buf_file, 'c+');
        if ($fp) {
            flock($fp, LOCK_EX);
            $raw = stream_get_contents($fp);
            $buf = $raw ? (json_decode($raw, true) ?: []) : [];
            $buf[] = $sample;
            if (count($buf) > 720) $buf = array_slice($buf, -720);
            ftruncate($fp, 0); rewind($fp);
            fwrite($fp, json_encode($buf));
            flock($fp, LOCK_UN); fclose($fp);
        }
        echo json_encode(['now' => $sample, 'hist' => array_values($buf)]);
        exit;
    } else {
        $endpoint = preg_replace('/[^a-z_]/', '', $_GET['api']);
        // T15：Token 走请求头（避免进访问日志）；GET 兼容但记录告警
        $token = $_SERVER['HTTP_X_API_TOKEN'] ?? '';
        if ($token === '' && preg_match('/^Bearer\s+(.+)$/i', $_SERVER['HTTP_AUTHORIZATION'] ?? '', $_am)) $token = trim($_am[1]);
        if ($token === '') $token = $_GET['token'] ?? '';
        $saved = is_file(API_TOKEN_FILE) ? trim(file_get_contents(API_TOKEN_FILE)) : '';
        if (empty($saved) || empty($token) || !hash_equals($saved, $token)) { http_response_code(401); echo json_encode(['error' => 'unauthorized']); exit; }
        switch ($endpoint) {
            case 'status':
                $out = [
                    'hostname' => gethostname(),
                    'uptime' => uptime_str(),
                    'cpu_pct' => round(floatval(trim(cmd("top -bn1 | grep 'Cpu(s)' | awk '{print \$2+\$4}' 2>/dev/null") ?: '0')), 1),
                    'mem' => ['total_m' => intval(trim(cmd("free -m | grep Mem | awk '{print \$2}'"))), 'used_m' => intval(trim(cmd("free -m | grep Mem | awk '{print \$3}'")))],
                    'disk' => ['free_g' => disk_free(), 'total_g' => disk_total()],
                    'load' => sys_getloadavg()[0],
                ];
                break;
            case 'sites':
                $out = [];
                foreach (glob(NGINX_ENABLED . '/*') ?: [] as $f) {
                    $cfg = @file_get_contents($f);
                    if ($cfg === false) continue;
                    preg_match('/server_name\s+([^;]+);/', $cfg, $m2);
                    $out[] = ['domain' => trim($m2[1] ?? basename($f)), 'ssl' => strpos($cfg, 'ssl_certificate') !== false];
                }
                break;
            case 'services':
                $out = [];
                foreach (['nginx', php_fpm_svc(), 'mariadb'] as $sv) $out[$sv] = svc_status($sv);
                break;
            case 'docker':
                $docker = is_executable('/usr/bin/docker') ? '/usr/bin/docker' : (is_executable('/usr/local/bin/docker') ? '/usr/local/bin/docker' : '');
                $out = [];
                if ($docker) {
                    $raw = cmd($docker . " ps --format '{{.Names}}|{{.Status}}' 2>/dev/null");
                    foreach (explode("\n", trim($raw)) as $l) { $f2 = explode('|', $l, 2); if (count($f2) === 2) $out[] = ['name' => $f2[0], 'status' => $f2[1]]; }
                }
                break;
            case 'backups':
                $out = [];
                foreach (array_merge(glob(BACKUP_DIR . '/*.zip') ?: [], glob(BACKUP_DIR . '/*.tar.gz') ?: []) as $f3)
                    $out[] = ['file' => basename($f3), 'size_kb' => round(filesize($f3) / 1024, 1), 'time' => date('Y-m-d H:i', filemtime($f3))];
                break;
            default:
                http_response_code(404); $out = ['error' => 'unknown endpoint', 'endpoints' => ['status','sites','services','docker','backups']];
        }
        echo json_encode($out);
        exit;
    }
}

// ===== AUTH ===== (登录限速：5次失败锁15分钟)
define('LOGIN_GUARD_FILE', '/var/www/manager/.login_guard');
function guard_read() {
    $fp = @fopen(LOGIN_GUARD_FILE, 'c+');
    if (!$fp) return [];
    flock($fp, LOCK_SH);
    $d = json_decode(stream_get_contents($fp), true) ?: [];
    flock($fp, LOCK_UN); fclose($fp);
    return $d;
}
function guard_write($d) {
    $fp = @fopen(LOGIN_GUARD_FILE, 'c+');
    if (!$fp) return;
    flock($fp, LOCK_EX); ftruncate($fp, 0); rewind($fp);
    fwrite($fp, json_encode($d)); fflush($fp);
    flock($fp, LOCK_UN); fclose($fp);
    @chmod(LOGIN_GUARD_FILE, 0600);
}
function client_ip(): string { // 反代后 REMOTE_ADDR=127.0.0.1，节流键用 nginx 传的 X-Real-IP（仅本机 nginx 可设置，无伪造面）
    return $_SERVER['HTTP_X_REAL_IP'] ?? ($_SERVER['REMOTE_ADDR'] ?? '');
}
function login_throttled() {
    $rec = guard_read()[client_ip()] ?? null;
    return $rec && $rec['fails'] >= 5 && (time() - $rec['last']) < 900;
}
// ===== LOGIN CAPTCHA（免 GD：SVG 数字/字母扭曲验证码）=====
function captcha_code(): string {
    $chars = 'abcdefghjkmnpqrstuvwxyz23456789';
    $c = '';
    for ($i = 0; $i < 5; $i++) $c .= $chars[random_int(0, strlen($chars) - 1)];
    return $c;
}
function captcha_render(): string {
    if (empty($_SESSION['captcha']) || ($_SESSION['captcha_expire'] ?? 0) < time()) {
        $_SESSION['captcha'] = captcha_code();
        $_SESSION['captcha_expire'] = time() + 300;
    }
    $code = $_SESSION['captcha'];
    $w = 150; $h = 44;
    $svg = '<svg xmlns="http://www.w3.org/2000/svg" width="'.$w.'" height="'.$h.'" viewBox="0 0 '.$w.' '.$h.'">';
    $svg .= '<rect width="'.$w.'" height="'.$h.'" fill="#f5f0e8" rx="8"/>';
    // 干扰线
    for ($i = 0; $i < 5; $i++) {
        $x1 = random_int(0, $w); $y1 = random_int(0, $h); $x2 = random_int(0, $w); $y2 = random_int(0, $h);
        $col = sprintf('#%02x%02x%02x', random_int(120,200), random_int(120,200), random_int(120,200));
        $svg .= '<line x1="'.$x1.'" y1="'.$y1.'" x2="'.$x2.'" y2="'.$y2.'" stroke="'.$col.'" stroke-width="1" opacity="0.6"/>';
    }
    // 干扰点
    for ($i = 0; $i < 40; $i++) {
        $col = sprintf('#%02x%02x%02x', random_int(100,220), random_int(100,220), random_int(100,220));
        $svg .= '<circle cx="'.random_int(0,$w).'" cy="'.random_int(0,$h).'" r="1.2" fill="'.$col.'" opacity="0.7"/>';
    }
    // 字符（随机旋转/偏移/颜色）
    for ($i = 0; $i < strlen($code); $i++) {
        $x = 14 + $i * 27 + random_int(-3, 3);
        $y = 30 + random_int(-4, 4);
        $rot = random_int(-22, 22);
        $col = sprintf('#%02x%02x%02x', random_int(20,90), random_int(20,90), random_int(20,90));
        $svg .= '<text x="'.$x.'" y="'.$y.'" font-family="Georgia,serif" font-size="26" font-weight="bold" fill="'.$col.'" transform="rotate('.$rot.' '.($x+8).' '.($y-8).')">'.htmlspecialchars($code[$i]).'</text>';
    }
    $svg .= '</svg>';
    return $svg;
}
function captcha_check(string $input): bool {
    $ok = !empty($_SESSION['captcha']) && ($_SESSION['captcha_expire'] ?? 0) >= time()
        && hash_equals($_SESSION['captcha'], strtolower(trim($input)));
    unset($_SESSION['captcha'], $_SESSION['captcha_expire']); // 一次性
    return $ok;
}
function login_fail() {
    $ip = client_ip();
    $fp = @fopen(LOGIN_GUARD_FILE, 'c+');
    if (!$fp) return;
    flock($fp, LOCK_EX);
    $d = json_decode(stream_get_contents($fp), true) ?: [];
    if (!isset($d[$ip]) || (time() - ($d[$ip]['last'] ?? 0)) > 900) $d[$ip] = ['fails' => 0, 'last' => 0];
    $d[$ip]['fails']++; $d[$ip]['last'] = time();
    ftruncate($fp, 0); rewind($fp); fwrite($fp, json_encode($d)); fflush($fp);
    flock($fp, LOCK_UN); fclose($fp);
    @chmod(LOGIN_GUARD_FILE, 0600);
}
if (isset($_POST['user']) && isset($_POST['pass'])) {
    if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) { http_response_code(403); exit('CSRF token 无效，请刷新页面重试。'); }
    if (!captcha_check($_POST['captcha'] ?? '')) {
        login_fail(); // 验证码错误也计入失败节流，防脚本刷验证码
        $login_error = login_throttled() ? '尝试次数过多，请 15 分钟后再试。' : '❌ 验证码错误或已过期，请重试。';
    } elseif (login_throttled()) {
        $login_error = '尝试次数过多，请 15 分钟后再试。';
    } else {
    $u = check_user($_POST['user'], $_POST['pass']);
    if ($u) { session_regenerate_id(true); $_SESSION['auth'] = true; $_SESSION['user'] = ['user' => $u['user'], 'role' => $u['role']]; $_SESSION['csrf'] = bin2hex(random_bytes(16)); header('Location: ?'); exit; }
    login_fail();
    $login_error = '用户名或密码错误！';
    }
}
// 全局 CSRF 校验（所有 POST 动作）
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 登录与已登录操作统一校验 CSRF（匿名会话在上方已预发 token）
    if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) { http_response_code(403); exit('CSRF token 无效，请刷新页面重试。'); }
}
if (isset($_GET['logout'])) { http_response_code(405); exit('登出请使用 POST'); }
if (($_POST['action'] ?? '') === 'logout') { $_SESSION = []; if (ini_get('session.use_cookies')) { $pp = session_get_cookie_params(); setcookie(session_name(), '', time()-42000, $pp['path'], $pp['domain'], $pp['secure'], $pp['httponly']); } session_destroy(); header('Location: ?'); exit; }
if (empty($_SESSION['auth'])) {
    ?><!DOCTYPE html><html lang="id"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>VPS Manager</title>
    <style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:linear-gradient(160deg,#dfd9cf 0%,#ebe5d9 40%,#f5f0e8 100%);color:#2d3748;display:flex;align-items:center;justify-content:center;min-height:100vh}.box{background:#fafaf7;padding:44px 40px;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.1),0 1px 3px rgba(0,0,0,.06);width:400px;max-width:92%;border-top:4px solid #1e3a5f}.box h1{text-align:center;color:#1a365d;margin-bottom:4px;font-size:24px;font-weight:800}.box p{text-align:center;color:#718096;font-size:13px;margin-bottom:28px}input[type=text],input[type=password]{width:100%;padding:14px 16px;border-radius:10px;border:2px solid #e2ddd5;background:#fdfcfb;color:#2d3748;font-size:15px;outline:none;margin-bottom:14px;transition:all .2s}input:focus{border-color:#2c5282;box-shadow:0 0 0 3px rgba(44,82,130,.12)}.btn{width:100%;padding:14px;border-radius:10px;background:linear-gradient(135deg,#1e3a5f,#2c5282);color:#fff;border:none;font-size:15px;font-weight:600;cursor:pointer;transition:all .2s;box-shadow:0 2px 8px rgba(30,58,95,.25)}.btn:hover{transform:translateY(-1px);box-shadow:0 4px 16px rgba(30,58,95,.35)}.btn:active{transform:translateY(0)}</style>
    </head><body><div class="box"><h1>🖥️ VPS Manager</h1><p>服务器管理面板</p><form method="POST"><?= csrf_field() ?><input type="text" name="user" placeholder="用户名" style="margin-bottom:10px;border-radius:10px;padding:14px 16px;width:100%;border:2px solid #e2ddd5;background:#fdfcfb;color:#2d3748;font-size:15px;outline:none;transition:all .2s" autofocus><input type="password" name="pass" placeholder="密码"><div style="display:flex;gap:8px;align-items:center;margin:10px 0 0"><div style="flex-shrink:0;border-radius:8px;overflow:hidden;cursor:pointer" title="点击刷新验证码" onclick="location.reload();" title="看不清？刷新页面换一张"><?= captcha_render() ?></div><input type="text" name="captcha" placeholder="验证码" maxlength="5" autocomplete="off" required style="flex:1;margin:0"></div><button class="btn" style="margin-top:12px">🔑 登录</button></form><?= isset($login_error) ? '<p style="color:#c53030;text-align:center;margin-top:14px;font-size:13px">'.$login_error.'</p>' : '' ?></div></body></html><?php exit;
}

// ===== HELPERS =====
function cmd($cmd, bool $merge_stderr = true) { // @deprecated 高危用户输入场景请用 cmdv()；R5：字符串里不要再写 2>/dev/null（会被 2>&1 覆盖），需要静默用 cmd($c, false)
    return shell_exec($merge_stderr ? ($cmd . ' 2>&1') : $cmd);
}

function cmdv(array $argv, ?string $stdin = null, ?int &$exitCode = null): string {
    if (!count($argv)) { $exitCode = 1; return ''; }
    $spec = [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];
    $proc = proc_open($argv, $spec, $pipes);
    if (!is_resource($proc)) { $exitCode = 127; return ''; }
    if ($stdin !== null) fwrite($pipes[0], $stdin);
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    $exitCode = proc_close($proc);
    return rtrim((string)$out . ($err !== '' ? "\n" . $err : ''), "\n");
}

// ===== 特权执行 shim（方案 A：root 直跑；非 root 经 sudo vpsmgr-helper 白名单）=====
// T06：站点→数据库显式映射（.site_db_map.json，0600，flock+原子写）
function site_db_map_load(): array {
    $f = '/var/www/manager/.site_db_map.json';
    if (!is_file($f)) return [];
    $j = json_decode((string)@file_get_contents($f), true);
    return is_array($j) ? $j : [];
}
function site_db_map_save(array $map): bool {
    $f = '/var/www/manager/.site_db_map.json';
    $tmp = tempnam(dirname($f), '.map_'); chmod($tmp, 0600);
    $fp = fopen($tmp, 'w');
    if (!$fp) { @unlink($tmp); return false; }
    flock($fp, LOCK_EX);
    fwrite($fp, json_encode($map, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
    flock($fp, LOCK_UN);
    fclose($fp);
    return @rename($tmp, $f);
}
function is_root_process(): bool {
    if (function_exists('posix_geteuid')) return posix_geteuid() === 0;
    return trim((string)@shell_exec('id -u 2>/dev/null')) === '0';
}
function priv_apply_file(string $tmp, string $dest): bool {
    if (is_root_process()) { $d = dirname($dest); if (!is_dir($d)) @mkdir($d, 0755, true); return rename($tmp, $dest) || (copy($tmp, $dest) && unlink($tmp)); }
    return false; // T07b: 仅支持 root 运行（helper 通道已移除）
}
// R1：nginx 配置写入后校验，失败回滚本次变更
function nginx_verify_or_rollback(array $written_available = [], array $written_enabled = []): bool {
    $t = cmd('nginx -t 2>&1');
    if (strpos($t, 'successful') !== false) return true;
    foreach ($written_enabled as $p) { if (is_link($p) || file_exists($p)) @unlink($p); }
    foreach ($written_available as $p) { if (file_exists($p)) @unlink($p); }
    cmd('nginx -t 2>/dev/null');
    return false;
}
function priv_symlink(string $target, string $link): bool {
    if (is_root_process()) {
        $d = dirname($link);
        if (!is_dir($d)) @mkdir($d, 0755, true);
        if (is_link($link) || file_exists($link)) @unlink($link);
        return @symlink($target, $link);
    }
    return @symlink($target, $link);
}
function priv_unlink(string $dest): bool {
    if (is_root_process()) return @unlink($dest);
    return false; // T07b: 仅支持 root 运行（helper 通道已移除）
}
function priv_mkdir_www(string $dir): bool {
    if (is_root_process()) { if (!is_dir($dir)) @mkdir($dir, 0755, true); return @chown($dir, web_user()) || true; }
    return false; // T07b: 仅支持 root 运行（helper 通道已移除）
}
function priv_chown_www(string $dir): bool {
    if (is_root_process()) { @chown($dir, web_user()); @chgrp($dir, web_user()); return true; }
    return false; // T07b: 仅支持 root 运行（helper 通道已移除）
}
function priv_rm_www(string $dir): bool {
    if (is_root_process()) { shell_exec('rm -rf ' . escapeshellarg($dir)); return true; }
    return false; // T07b: 仅支持 root 运行（helper 通道已移除）
}
function priv_reload_nginx(): bool {
    if (is_root_process()) { $t = cmd('nginx -t 2>&1'); if (strpos($t, 'successful') === false) return false; cmd(is_alpine() ? 'rc-service nginx reload 2>/dev/null || nginx -s reload 2>/dev/null' : 'systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null'); return true; }
    return false; // T07b: 仅支持 root 运行（helper 通道已移除）
}
function priv_backup_dir(): void { ensure_dirs(); }
// T02：ensure_dirs() 已上移至 enforce_single_admin() 之前（见顶部），并增加 Alpine Nginx 目录/include 自愈

function validate_domain(string $d): bool {
    // T16：长度、字符集、逐 label 校验（拒空 label、首尾连字符、连续点、超长 label）
    if ($d === '' || strlen($d) > 253 || str_contains($d, '..') || str_contains($d, chr(0))) return false;
    if (!preg_match('/^[a-z0-9][a-z0-9.-]{0,252}\.[a-z]{2,}$/', $d)) return false;
    foreach (explode('.', $d) as $label) {
        if ($label === '' || strlen($label) > 63) return false;
        if ($label[0] === '-' || $label[strlen($label) - 1] === '-') return false;
    }
    return true;
}
function assert_public_url(string $url): bool {
    // T-21：解析全部 A/AAAA，拒绝环回/RFC1918/link-local/保留/IPv4-mapped/ULA
    $h = parse_url($url, PHP_URL_HOST);
    if (!$h) return false;
    $records = @dns_get_record($h, DNS_A + DNS_AAAA);
    $ips = [];
    if ($records) foreach ($records as $r) { if (!empty($r['ip'])) $ips[] = $r['ip']; if (!empty($r['ipv6'])) $ips[] = $r['ipv6']; }
    if (!$ips) $ips[] = gethostbyname($h);
    foreach ($ips as $ip) {
        $n = filter_var($ip, FILTER_VALIDATE_IP);
        if ($n === false) return false;
        if (!filter_var($n, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return false;
        if (str_contains($n, ':')) { // IPv6: 拒 ULA fc00::/7、link-local fe80::/10、IPv4-mapped ::ffff:
            $up = strtolower($n);
            if (str_starts_with($up, 'fc') || str_starts_with($up, 'fd') || str_starts_with($up, 'fe80') || str_contains($up, '::ffff:')) return false;
        }
    }
    return true;
}
function canonical_root(string $root): string {
    $r = rtrim(str_replace(chr(92), '/', $root), '/');
    if ($r === '' || $r[0] !== '/') return '';
    return $r;
}
function resolve_existing_under_root(string $path, string $root): ?string {
    $root = canonical_root($root);
    if ($root === '' || $path === '' || str_contains($path, chr(0))) return null;
    $real = realpath($path);
    if ($real === false || $real === '/') return null;
    if ($real !== $root && !str_starts_with($real, $root . '/')) return null;
    return $real;
}
function resolve_new_target_under_root(string $path, string $root): ?string {
    $root = canonical_root($root);
    if ($root === '' || $path === '' || str_contains($path, chr(0))) return null;
    $norm = str_replace(chr(92), '/', $path);
    // 绝对路径：必须位于 root 之下，剥去 root 前缀后再归一化（防止 root 前缀重复拼接）
    if ($norm[0] === '/') {
        $rtrim = rtrim($root, '/');
        if ($norm === $rtrim) return $root;
        if (!str_starts_with($norm, $rtrim . '/')) return null;
        $norm = substr($norm, strlen($rtrim) + 1);
    }
    $parts = [];
    foreach (explode('/', $norm) as $seg) {
        if ($seg === '' || $seg === '.') continue;
        if ($seg === '..') { if (!count($parts)) return null; array_pop($parts); continue; }
        $parts[] = $seg;
    }
    $abs = $root . (count($parts) ? '/' . implode('/', $parts) : '');
    if (file_exists($abs)) return resolve_existing_under_root($abs, $root);
    return $abs;
}
function js_str(string $s): string {
    // T03：返回可安全放进 HTML 属性的 JS 字符串字面量（含两端引号）
    return htmlspecialchars(json_encode($s, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT), ENT_QUOTES, 'UTF-8');
}
function confirm_attr(string $msg): string {
    return 'onsubmit="return confirm(' . js_str($msg) . ')"';
}
function sanitize($s) { return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8'); }
function flash_html($s) {
    // 加固（渗透审计 #4）：先整体 HTML 转义再恢复白名单标签——尖括号/引号/&,<,> 一律不再裸输出
    $s = htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $s = preg_replace('/&lt;(\/?)(b|i|em|strong|code|small|span|br|pre|details|summary)\s*&gt;/i', '<$1$2>', $s);
    return $s;
}
function flash($m, $t = 'ok') { $_SESSION['flash'] = ['msg' => $m, 'type' => $t]; }
function get_flash() { $f = $_SESSION['flash'] ?? null; unset($_SESSION['flash']); return $f; }
function redirect($p = '') { header('Location: ?page=' . $p); exit; }
// 给所有 POST 表单自动注入 CSRF token
function csrf_field() { return '<input type="hidden" name="csrf" value="' . htmlspecialchars($_SESSION['csrf'] ?? '') . '">'; }
function svc_status($name) {
    if (is_alpine()) { $o = cmd("rc-service $name status 2>/dev/null"); return stripos($o ?? '', 'started') !== false; }
    $o = cmd("systemctl is-active $name 2>/dev/null"); return trim($o ?? '') === 'active';
}
function pkg_installed($pkg) {
    if (is_alpine()) { $o = cmd("apk info -e $pkg 2>/dev/null"); return trim($o ?? '') === $pkg || trim($o ?? '') === 'true'; }
    if (is_rhel()) { $o = cmd("rpm -q $pkg 2>/dev/null"); return stripos($o ?? '', 'not installed') === false && !empty(trim($o ?? '')); }
    $o = cmd("dpkg -l $pkg 2>/dev/null | grep '^ii'"); return !empty(trim($o ?? ''));
}
function disk_free() { return round(disk_free_space('/') / 1073741824, 1); }
function disk_total() { return round(disk_total_space('/') / 1073741824, 1); }

// ===== ACTIONS =====
$msg = null;

$KNOWN_ACTS = ['node_install','node_site_add','node_site_del','node_app_action','add_redirect','api_token_gen','api_token_revoke','backup_site','cache_toggle_site','change_pass','cleanup_run','clear_uptime','cloud_backup','cloud_target_save','create_db','create_site','cron_add','cron_del','delete_backup','delete_db','delete_folder','delete_redirect','delete_site','dns_add','dns_del','docker_ctl','docker_install','edit_conf','fw_add','fw_del','fw_toggle','install_all','install_certbot','install_f2b','install_rclone','install_svc','logout','migration_backup','migration_delete','migration_restore','new_folder','notify_save','optimize','panel_https_toggle','php_default','php_ext_toggle','php_install','php_per_site_save','php_remove','php_switch_site','proc_action','proc_add','proc_del','proxy_add','proxy_del','purge_cache','rclone_gdrive_step1','rclone_gdrive_step2','rclone_mega_connect','rclone_remove','restore_site','site_db_bind','site_db_unbind','ssl_autorenew','ssl_install','ssl_renew','ssl_wildcard','svc_action','unban_ip','upload_file','uptime_check','save_rewrite'];
$act = $_POST['action'] ?? '';

// T07b：本版本仅支持 PHP-FPM 以 root 运行
if (!is_root_process()) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') !== 'logout') { http_response_code(403); exit('⛔ 面板必须以 root 运行 PHP-FPM（检测到非 root）——请按部署文档配置后重试'); }
    $GLOBALS['NOT_ROOT_WARN'] = true;
}
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($act !== '' && $act !== 'logout' && !in_array($act, $KNOWN_ACTS, true)) { http_response_code(400); exit('未知操作'); }

    // 高危操作仅管理员（admin 角色门）
    $ADMIN_ONLY_ACTS = ['node_install','node_site_add','node_site_del','node_app_action','site_db_bind','site_db_unbind','php_remove','php_install','php_default','php_ext_toggle','php_switch_site','proc_add','proc_del','proc_action',
        'cleanup_run','edit_conf','edit_file','delete_file','new_folder','upload_file','migration_restore','migration_backup','migration_delete','panel_https_toggle',
        'proxy_add','proxy_del','cloud_target_save','api_token_gen','api_token_revoke','docker_install','install_svc','install_rclone',
        'fw_toggle','fw_add','fw_del','install_f2b','svc_action','delete_site','ssl_install','ssl_wildcard','restore_site','rclone_remove','unban_ip','cron_add','cron_del','save_rewrite'];
    if (in_array($act, $ADMIN_ONLY_ACTS, true) && !is_admin()) { http_response_code(403); exit('⛔ 此操作仅管理员可执行'); }

    // --- CREATE WEBSITE ---
    if ($act === 'create_site') {
        $domain = strtolower(trim($_POST['domain'] ?? ''));
        $dbname = strtolower(trim($_POST['dbname'] ?? ''));
        $dbuser = strtolower(trim($_POST['dbuser'] ?? ''));
        $dbpass = $_POST['dbpass'] ?? '';
        $create_db = isset($_POST['create_db']);
        $install_wp = isset($_POST['install_wp']);
        $php_ver = $_POST['php_ver'] ?? selected_php_version();
        $fpm_sock = is_alpine() ? '/run/php-fpm' . str_replace('.','',$php_ver) . '/php-fpm.sock' : (is_rhel() ? '/run/php-fpm/www.sock' : '/var/run/php/php' . $php_ver . '-fpm.sock');
        // RHEL 无 snippets/fastcgi-php.conf（且版本化 sock 不适用 www.sock）；RHEL/Alpine 由模板行提供 SCRIPT_FILENAME
        $fastcgi_inc = is_alpine() || is_rhel() ? 'fastcgi_index index.php;' : 'include snippets/fastcgi-php.conf;';
        if (!in_array($php_ver, ['8.2','8.3','8.4','8.5'], true)) { flash('PHP 版本无效！', 'err'); redirect('sites'); }

        if (!validate_domain($domain)) {
            flash('域名无效!', 'err'); redirect('websites');
        }

        // T19：create_site 不得覆盖——已有 nginx 配置或站点目录时报错退出
        if (is_link(cfg_path($domain, 'enabled')) || file_exists(cfg_path($domain, 'enabled')) || file_exists(cfg_path($domain))) { flash('❌ 站点 ' . $domain . ' 的 nginx 配置已存在（如需重建请先删除）', 'err'); redirect('websites'); }
        if (is_dir(WWW_ROOT . '/' . $domain)) { flash('❌ 目录 ' . WWW_ROOT . '/' . $domain . ' 已存在——如需接管请先删除', 'err'); redirect('websites'); }

        $root = WWW_ROOT . '/' . $domain;
        priv_mkdir_www($root);

        // 数据库参数校验（防 SQL 注入）
        if ($dbname !== '' && !preg_match('/^[a-zA-Z0-9_]{1,64}$/', $dbname)) { flash('数据库名不合法！', 'err'); redirect('websites'); }
        if ($dbuser !== '' && !preg_match('/^[a-zA-Z0-9_]{1,32}$/', $dbuser)) { flash('数据库用户名不合法！', 'err'); redirect('websites'); }
        if ($dbpass !== '' && (strlen($dbpass) > 64 || str_contains($dbpass, "'") || str_contains($dbpass, chr(92)))) { flash('数据库密码含非法字符！', 'err'); redirect('websites'); }

        // 删除该域名的旧 block 配置
        foreach ((array)glob(NGINX_ENABLED . "/*_blocked_*") as $bf) {
            if (strpos(file_get_contents($bf), "server_name " . $domain) !== false) {
                $ba = NGINX_AVAILABLE . "/" . basename($bf);
                priv_unlink($bf); if (file_exists($ba)) priv_unlink($ba);
            }
        }

        // Nginx config
        $nginx_conf = "server {\n    listen 80;\n    server_name $domain www.$domain;\n    root $root;\n    index index.php index.html index.htm;\n\n    client_max_body_size 100M;\n\n    location / {\n        try_files \$uri \$uri/ /index.php?\$query_string;\n    }\n\n    location ~ \\.php\$ {\n        $fastcgi_inc\n        fastcgi_pass unix:$fpm_sock;\n        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;\n        include fastcgi_params;\n    }\n\n    location ~ /\\. { deny all; }\n    gzip on;\n    gzip_types text/css application/javascript;\n    gzip_min_length 256;\n}\n";
        $ntmp = tempnam('/tmp', 'ngx_cs_'); chmod($ntmp, 0600);
        file_put_contents($ntmp, $nginx_conf);
        priv_apply_file($ntmp, cfg_path($domain));
        priv_nginx_link_site(cfg_path($domain), cfg_path($domain, 'enabled'));
        @unlink($ntmp);
        if (!nginx_verify_or_rollback([cfg_path($domain)], [cfg_path($domain, 'enabled')])) { flash('❌ nginx 配置校验失败，建站已回滚', 'err'); redirect('websites'); }
        
        // Create index.html placeholder
        if (!is_dir($root)) priv_mkdir_www($root);
        @file_put_contents("$root/index.html", "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>$domain</title><style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8fafc;color:#1e293b}div{text-align:center}h1{color:#1e3a5f}</style></head><body><div><h1>🚀 $domain</h1><p>网站就绪！请把文件上传到目录 <code>/var/www/$domain</code></p></div></body></html>");
        @chown("$root/index.html", web_user()); @chgrp("$root/index.html", web_user());

        // Create database
        $db_created = false;
        if ($create_db) {
            $dn = $dbname ?: preg_replace('/[.-]/', '_', $domain);
            $du = $dbuser ?: substr($dn, 0, 16);
            $dp = $dbpass ?: substr(bin2hex(random_bytes(8)), 0, 16);
            $sql = "CREATE DATABASE IF NOT EXISTS $dn CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n";
            $sql .= "CREATE USER IF NOT EXISTS '$du'@'localhost' IDENTIFIED BY '$dp';\n";
            $sql .= "GRANT ALL PRIVILEGES ON $dn.* TO '$du'@'localhost';\n";
            $sql .= "FLUSH PRIVILEGES;\n";
            $mbin = mysql_bin();
            if ($mbin) { $ec2 = 0; cmdv([$mbin], $sql, $ec2); if ($ec2 !== 0) { flash('❌ 建库失败（退出码 ' . $ec2 . '）', 'err'); redirect('websites'); } }
            $db_created = true;
            // T06：写入站点→数据库映射（备份据此导出 DB）
            $map = site_db_map_load();
            $map[$domain] = array_values(array_unique(array_merge((array)($map[$domain] ?? []), [$dn])));
            site_db_map_save($map);
        }

        // Install WordPress
        if ($install_wp && $db_created) {
            $dn = $dbname ?: preg_replace('/[.-]/', '_', $domain);
            $du = $dbuser ?: substr($dn, 0, 16);
            $dp = $dbpass ?: substr(bin2hex(random_bytes(8)), 0, 16);
            cmd("cd /tmp && rm -rf latest.tar.gz wordpress && wget -q https://wordpress.org/latest.tar.gz && tar xzf latest.tar.gz && cp -r wordpress/* " . escapeshellarg($root) . "/ && chown -R " . escapeshellarg(web_user() . ":" . web_user()) . " " . escapeshellarg($root) . " && rm -rf wordpress latest.tar.gz");
            $wp_salt = file_get_contents('https://api.wordpress.org/secret-key/1.1/salt/');
            $wp_config = file_get_contents("$root/wp-config-sample.php");
            $wp_config = str_replace("define( 'DB_NAME', 'database_name_here' );", "define( 'DB_NAME', '$dn' );", $wp_config);
            $wp_config = str_replace("define( 'DB_USER', 'username_here' );", "define( 'DB_USER', '$du' );", $wp_config);
            $wp_config = str_replace("define( 'DB_PASSWORD', 'password_here' );", "define( 'DB_PASSWORD', '$dp' );", $wp_config);
            $wp_config = str_replace("define( 'AUTH_KEY',         'put your unique phrase here' );", $wp_salt, $wp_config);
            file_put_contents("$root/wp-config.php", $wp_config);
        }

        cmd("nginx -t 2>/dev/null; " . (is_alpine() ? "rc-service nginx reload 2>/dev/null || nginx -s reload 2>/dev/null" : "systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null"));
        $info = "Domain: $domain | Root: $root";
        if ($db_created) {
            $dn2 = $dbname ?: preg_replace('/[.-]/', '_', $domain);
            $du2 = $dbuser ?: substr($dn2, 0, 16);
            $dp2 = $dbpass ?: substr(bin2hex(random_bytes(8)), 0, 16);
            $info .= " | DB: $dn2 | User: $du2 | Pass: $dp2";
        }
        flash("✅ Website 创建成功! $info"); redirect('websites');
    }

    // --- DELETE WEBSITE ---
    if ($act === 'delete_site') {
        $domain = $_POST['domain'] ?? '';
        if (!validate_domain($domain)) { flash('域名无效', 'err'); redirect('websites'); }
        // cfg_name 服务端推导（不接受客户端自由指定）
        $cfg_name = null;
        foreach ((glob(NGINX_AVAILABLE . '/*') ?: []) as $f) {
            if (!is_file($f)) continue;
            $body = @file_get_contents($f) ?: '';
            if (preg_match('/server_name\s+([^;]+);/', $body, $mm)) {
                $names = preg_split('/\s+/', trim($mm[1]));
                if (in_array($domain, $names, true)) { $cfg_name = preg_replace('/\.conf$/', '', basename($f)); break; }
            }
        }
        if ($cfg_name === null) $cfg_name = $domain;
        if (str_contains($cfg_name, '/') || str_contains($cfg_name, chr(92)) || str_contains($cfg_name, '..')) { flash('配置名无效', 'err'); redirect('websites'); }

        // Check shared config warning
        $shared_warning = '';
        $cfg_path = cfg_path($cfg_name);
        if (file_exists($cfg_path)) {
            preg_match_all('/server_name\s+([^;]+);/', file_get_contents($cfg_path), $m);
            $all_domains = preg_split('/\s+/', trim(implode(' ', $m[1] ?? [])));
            $other_domains = array_filter($all_domains, function($d) use ($domain) { return $d !== $domain && strpos($d, 'www.') === false; });
            if (!empty($other_domains)) {
                $shared_warning = ' ⚠️ Config ' . $cfg_name . ' 同时也服务于：' . implode(', ', $other_domains) . '. 如需请手动删除。';
            }
        }

        // 1. Delete Nginx config
        $nginx_del = false;
        if (is_link(cfg_path($cfg_name, 'enabled')) || file_exists(cfg_path($cfg_name, 'enabled'))) { priv_unlink(cfg_path($cfg_name, 'enabled')); $nginx_del = !(is_link(cfg_path($cfg_name, 'enabled')) || file_exists(cfg_path($cfg_name, 'enabled'))); }
        if (file_exists(cfg_path($cfg_name))) { priv_unlink(cfg_path($cfg_name)); $nginx_del = !file_exists(cfg_path($cfg_name)); }

        // 2. Delete website files
        $www_dir = resolve_existing_under_root(WWW_ROOT . '/' . $domain, WWW_ROOT);
        $files_del = false;
        if ($www_dir !== null && strlen($www_dir) > strlen(rtrim(WWW_ROOT, '/')) && is_dir($www_dir)) {
            priv_rm_www($www_dir); $files_del = !is_dir($www_dir);
        }

        // 3. Delete SSL cert
        $ssl_del = false;
        $cd = "/etc/letsencrypt/live/$domain";
        if (is_dir($cd)) { cmd("certbot delete --cert-name " . escapeshellarg($domain) . " --non-interactive 2>/dev/null"); $ssl_del = !is_dir($cd); }

                // 4. Block domain from nginx (return 444 — close connection)
        $block_conf = "server { listen 80; server_name $domain www.$domain; return 444; }";
        $block_file = '/etc/nginx/sites-available/' . $cfg_name . '_blocked_' . substr(md5($domain), 0, 6);
        $btmp = tempnam('/tmp', 'ngx_bl_'); chmod($btmp, 0600);
        file_put_contents($btmp, $block_conf);
        priv_apply_file($btmp, $block_file);
        priv_nginx_link_site($block_file, NGINX_ENABLED . '/' . basename($block_file));
        @unlink($btmp);
        $nt = cmd('nginx -t 2>&1');
        if (strpos($nt, 'successful') === false) { @unlink(NGINX_ENABLED . '/' . basename($block_file)); @unlink($block_file); cmd('nginx -t 2>&1'); flash('⚠️ 拦截配置校验失败已回滚', 'err'); }
        // 5. Reload nginx
        cmd("nginx -t 2>/dev/null; " . (is_alpine() ? "rc-service nginx reload 2>/dev/null || nginx -s reload 2>/dev/null" : "systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null"));

        // Summary
        $msg = "✅ Site $domain 删除!";
        $parts = [];
        if ($nginx_del) $parts[] = 'Nginx config';
        if ($files_del) $parts[] = 'File /var/www/'.$domain;
        if ($ssl_del) $parts[] = 'SSL certificate';
        if ($parts) $msg .= ' (' . implode(', ', $parts) . ')';
        if ($shared_warning) $msg .= $shared_warning;
        $msg .= ' | ℹ️ 数据库未删除（请到「数据库」菜单手动删除）';
        flash($msg);
        // 审计修复（U07）：删除站点时清理 .site_db_map.json 僵尸映射（map[domain] = 数据库数组）
        $map = site_db_map_load();
        if (isset($map[$domain])) { unset($map[$domain]); site_db_map_save($map); }
        redirect('websites');
    }

    // --- T06: SITE-DB BIND/UNBIND ---
    if ($act === 'site_db_bind' || $act === 'site_db_unbind') {
        $domain = strtolower(trim($_POST['domain'] ?? ''));
        $dbname = trim($_POST['dbname'] ?? '');
        if (!validate_domain($domain)) { flash('域名无效！', 'err'); redirect('databases'); }
        $map = site_db_map_load();
        if ($act === 'site_db_unbind') {
            if (isset($map[$domain])) {
                $map[$domain] = array_values(array_filter((array)$map[$domain], fn($d) => $d !== $dbname));
                if (!count($map[$domain])) unset($map[$domain]);
                site_db_map_save($map);
                flash('✅ 已解绑 ' . $domain . ' ← ' . $dbname);
            }
            redirect('databases');
        }
        if (!preg_match('/^[a-zA-Z0-9_]{1,64}$/', $dbname)) { flash('数据库名无效！', 'err'); redirect('databases'); }
        $sys = ['information_schema','mysql','performance_schema','sys'];
        if (in_array(strtolower($dbname), $sys, true)) { flash('不能绑定系统数据库！', 'err'); redirect('databases'); }
        $chk = trim(cmd(mysql_cli("-e " . escapeshellarg("SHOW DATABASES LIKE " . "'" . $dbname . "'"))));
        if (strpos($chk, $dbname) === false) { flash('数据库 ' . $dbname . ' 不存在！', 'err'); redirect('databases'); }
        $map[$domain] = array_values(array_unique(array_merge((array)($map[$domain] ?? []), [$dbname])));
        site_db_map_save($map);
        flash('✅ 已绑定 ' . $domain . ' → ' . $dbname . '（该站点备份将包含此数据库）');
        redirect('databases');
    }

    // --- CREATE DATABASE ---
    if ($act === 'create_db') {
        $dbname = trim($_POST['dbname'] ?? '');
        $dbuser = trim($_POST['dbuser'] ?? '');
        $dbpass = $_POST['dbpass'] ?? '';
        if (empty($dbname) || !preg_match('/^[a-zA-Z0-9_]{1,64}$/', $dbname)) { flash('数据库名无效！', 'err'); redirect('databases'); }
        if ($dbuser !== '' && !preg_match('/^[a-zA-Z0-9_]{1,32}$/', $dbuser)) { flash('数据库用户名无效！', 'err'); redirect('databases'); }
        if ($dbpass !== '' && (strlen($dbpass) > 64 || str_contains($dbpass, "'") || str_contains($dbpass, chr(92)))) { flash('数据库密码含非法字符！', 'err'); redirect('databases'); }
        $du = $dbuser ?: $dbname . '_user';
        $dp = $dbpass ?: substr(bin2hex(random_bytes(8)), 0, 16);
        $sql = "CREATE DATABASE IF NOT EXISTS $dbname CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n";
        $sql .= "CREATE USER IF NOT EXISTS '$du'@'localhost' IDENTIFIED BY '$dp';\n";
        $sql .= "GRANT ALL PRIVILEGES ON $dbname.* TO '$du'@'localhost';\n";
        $sql .= "FLUSH PRIVILEGES;\n";
        $mbin = mysql_bin();
        if ($mbin) { $ec2 = 0; cmdv([$mbin], $sql, $ec2); if ($ec2 !== 0) { flash('❌ 建库失败（退出码 ' . $ec2 . '）', 'err'); redirect('databases'); } }
        flash("✅ Database dibuat! DB: $dbname | User: $du | Pass: $dp"); redirect('databases');
    }

    // --- DELETE DATABASE ---
    if ($act === 'delete_db') {
        $dbname = $_POST['dbname'] ?? '';
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $dbname)) { flash('数据库名不合法！', 'err'); redirect('databases'); }
        cmd(mysql_cli("-e " . escapeshellarg("DROP DATABASE IF EXISTS `" . $dbname . "`")));
        // T06：从所有映射中移除该库
        $map = site_db_map_load();
        $changed = false;
        foreach ($map as $dm => $dbs) {
            $nd = array_values(array_filter((array)$dbs, fn($d) => $d !== $dbname));
            if (count($nd) !== count((array)$dbs)) { if (count($nd)) $map[$dm] = $nd; else unset($map[$dm]); $changed = true; }
        }
        if ($changed) site_db_map_save($map);
        flash("✅ Database $dbname 删除!"); redirect('databases');
    }

    // --- BACKUP SITE ---
    if ($act === 'backup_site') {
        $domain = $_POST['domain'] ?? '';
        if (!validate_domain($domain)) { flash('域名无效', 'err'); redirect('backups'); }
        $ts = date('Ymd_His');
        $bf = BACKUP_DIR . "/{$domain}_$ts.zip";
        if (resolve_existing_under_root(dirname($bf), BACKUP_DIR) === null) { flash('备份路径无效', 'err'); redirect('backups'); }
        if (!is_dir(BACKUP_DIR)) { flash('❌ 备份目录 ' . BACKUP_DIR . ' 不存在且自动重建失败（ensure_dirs 已尝试）——请检查磁盘权限后重试', 'err'); redirect('backups'); } // 审计修复（U09）：目录重建统一由 ensure_dirs 兜底
        
        // Find actual root by scanning nginx configs (domain may differ from folder name)
        $root = null; $cfg_file = null;
        foreach (glob(NGINX_AVAILABLE . '/*') as $f) {
            $cfg = file_get_contents($f);
            if (preg_match('/server_name\s+([^;]+);/', $cfg, $m)) {
                $names = preg_split('/\s+/', trim($m[1]));
                if (in_array($domain, $names)) {
                    preg_match('/root\s+([^;]+);/', $cfg, $rm);
                    $root = $rm[1] ?? null;
                    $cfg_file = $f;
                    break;
                }
            }
        }
        if (!$root) $root = WWW_ROOT . '/' . $domain; // fallback
        $root = resolve_existing_under_root($root, WWW_ROOT);
        if ($root === null) { flash('网站根目录无效', 'err'); redirect('backups'); }
        if (!is_dir($root)) { flash("目录 $root 未找到", 'err'); redirect('backups'); }
        $exclude = '';
        if (is_dir("$root/uploads")) $exclude = '-x ' . escapeshellarg($root . '/uploads/*');
        cmd("cd " . escapeshellarg(dirname($root)) . " && zip -rq " . escapeshellarg($bf) . " " . escapeshellarg(basename($root)) . " $exclude 2>&1");
        
        // Also backup DB if we can find it in nginx config
        $ngx = $cfg_file;
        $db_file = '';
        $db_names = [];
        // 站点→数据库服务端显式映射（.site_db_map.json），无映射不导出数据库（防全库 dump）
        $db_map = site_db_map_load();
        if (!empty($db_map[$domain])) {
            foreach ((array)$db_map[$domain] as $db) {
                $db = trim((string)$db);
                if ($db !== '' && preg_match('/^[a-zA-Z0-9_-]+$/', $db)) $db_names[] = $db;
            }
        }
        if (!empty($db_names)) {
            $db_file = BACKUP_DIR . "/{$domain}_$ts.sql";
            cmd(mysqldump_cli("--databases " . implode(' ', array_map('escapeshellarg', $db_names)) . " > " . escapeshellarg($db_file) . " 2>&1"));
        }
        if (file_exists($bf)) @chmod($bf, 0600);
        if (!empty($db_names) && file_exists($db_file)) @chmod($db_file, 0600);
        $sz = file_exists($bf) ? round(filesize($bf) / 1024, 1) : 0;
        $msg2 = !empty($db_names) ? '（含数据库：' . implode(', ', $db_names) . '）' : '（未包含数据库——请到「数据库」页绑定站点）';
        flash("✅ 备份成功！{$sz}KB" . $msg2); redirect('backups');
    }

    // --- RESTORE SITE ---
    if ($act === 'restore_site') {
        $domain = trim($_POST['restore_domain'] ?? '');
        if (!validate_domain($domain)) { flash('域名无效!', 'err'); redirect('backups'); }
        
        $zip_uploaded = !empty($_FILES['zipfile']['tmp_name']);
        $sql_uploaded = !empty($_FILES['sqlfile']['tmp_name']);
        
        if ($zip_uploaded) {
            $root = resolve_new_target_under_root(WWW_ROOT . '/' . $domain, WWW_ROOT);
            if ($root === null) { flash('站点目录无效', 'err'); redirect('backups'); }
            if (!is_dir($root)) priv_mkdir_www($root);
            // T-30：随机私有临时目录 0700，禁共享 /tmp/restore_extract；解包前校验
            if ($_FILES['zipfile']['error'] !== UPLOAD_ERR_OK) { flash('❌ 上传失败', 'err'); redirect('backups'); }
            if ($_FILES['zipfile']['size'] > 2 * 1024 * 1024 * 1024) { flash('❌ 文件过大（上限 2GB）', 'err'); redirect('backups'); }
            $workdir = '/tmp/vpsmgr_restore_' . bin2hex(random_bytes(8));
            mkdir($workdir, 0700, true);
            $tmp = $workdir . '/restore.zip';
            if (!move_uploaded_file($_FILES['zipfile']['tmp_name'], $tmp)) { @rmdir($workdir); flash('❌ 保存上传失败', 'err'); redirect('backups'); }
            chmod($tmp, 0600);
            // 先试解包到私有目录（unzip 拒绝路径穿越条目会非零退出，并检查绝对路径/..条目）
            exec('unzip -o ' . escapeshellarg($tmp) . ' -d ' . escapeshellarg($workdir . '/x') . ' 2>&1', $out, $ec);
            $bad = false;
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($workdir . '/x', FilesystemIterator::SKIP_DOTS));
            $total = 0;
            foreach ($it as $f) {
                $total++;
                if ($total > 50000) { $bad = true; break; } // 文件数超限
                $rp = realpath($f->getPathname());
                if ($rp === false || !str_starts_with($rp, $workdir . '/x')) { $bad = true; break; } // symlink 逃逸
                if ($f->isLink()) { $bad = true; break; } // 拒绝符号链接
            }
            if ($ec !== 0 || $bad) {
                shell_exec('rm -rf ' . escapeshellarg($workdir));
                flash('❌ 归档校验失败（可能含路径穿越/符号链接/超限），已拒绝', 'err'); redirect('backups');
            }
            // 复制前先备份现状（可回滚）
            $bak = '/tmp/vpsmgr_pre_restore_' . bin2hex(random_bytes(8)) . '.tar.gz';
            shell_exec('tar czf ' . escapeshellarg($bak) . ' -C ' . escapeshellarg(dirname($root)) . ' ' . escapeshellarg(basename($root)) . ' 2>/dev/null');
            // zip 若含顶层目录前缀（backup 时 cd dirname(root) 打包了 basename(root)/...）则剥掉这一层
            $xentries = (array)@scandir($workdir . '/x');
            $xentries = array_values(array_filter($xentries, fn($e) => $e !== '.' && $e !== '..'));
            $srcc = $workdir . '/x';
            if (count($xentries) === 1 && is_dir($workdir . '/x/' . $xentries[0])) $srcc = $workdir . '/x/' . $xentries[0];
            exec('cp -rf ' . escapeshellarg($srcc) . '/. ' . escapeshellarg($root) . '/ 2>&1', $o2, $ec2);
            exec('chown -R ' . escapeshellarg(web_user() . ':' . web_user()) . ' ' . escapeshellarg($root) . ' 2>&1', $o3, $ec3);
            if ($ec2 !== 0 || $ec3 !== 0) {
                shell_exec('rm -rf ' . escapeshellarg($root) . ' && tar xzf ' . escapeshellarg($bak) . ' -C ' . escapeshellarg(dirname($root)) . ' 2>/dev/null; rm -rf ' . escapeshellarg($workdir) . ' ' . escapeshellarg($bak));
                flash('❌ 恢复失败，已回滚到恢复前状态', 'err'); redirect('backups');
            }
            shell_exec('rm -rf ' . escapeshellarg($workdir) . ' ' . escapeshellarg($bak));
        }
        
        if ($sql_uploaded) {
            if ($_FILES['sqlfile']['error'] !== UPLOAD_ERR_OK) { flash('❌ SQL 上传失败', 'err'); redirect('backups'); }
            $workdir = '/tmp/vpsmgr_sql_' . bin2hex(random_bytes(8));
            mkdir($workdir, 0700, true);
            $tmp_sql = $workdir . '/restore.sql';
            if (!move_uploaded_file($_FILES['sqlfile']['tmp_name'], $tmp_sql)) { @rmdir($workdir); flash('❌ 保存 SQL 失败', 'err'); redirect('backups'); }
            chmod($tmp_sql, 0600);
            // 用 stdin 管道而非 shell '<' 重定向
            $bin = null;
            foreach (['/usr/bin/mariadb', '/usr/bin/mysql'] as $b) if (is_executable($b)) { $bin = $b; break; }
            if ($bin === null) { @unlink($tmp_sql); @rmdir($workdir); flash('❌ MySQL 未安装，无法导入 SQL', 'err'); redirect('backups'); }
            if (filesize($tmp_sql) > 512*1024*1024) { shell_exec('rm -rf ' . escapeshellarg($workdir)); flash('❌ SQL 文件过大（上限 512MB）', 'err'); redirect('backups'); }
            $ec = 0;
            cmdv([$bin], file_get_contents($tmp_sql), $ec);
            shell_exec('rm -rf ' . escapeshellarg($workdir));
            if ($ec !== 0) { flash('❌ SQL 导入失败（退出码 ' . $ec . '）', 'err'); redirect('backups'); }
        }
        
        // Create nginx config if not exists
        if (!file_exists(cfg_path($domain))) {
            $root = WWW_ROOT . '/' . $domain;
            $php_ver = selected_php_version();
            $fpm_sock = is_alpine() ? '/run/php-fpm' . str_replace('.','',$php_ver) . '/php-fpm.sock' : (is_rhel() ? '/run/php-fpm/www.sock' : '/var/run/php/php' . $php_ver . '-fpm.sock');
            $fastcgi_inc = is_alpine() || is_rhel() ? 'fastcgi_index index.php;' : 'include snippets/fastcgi-php.conf;';
            $nginx_conf = "server {\n    listen 80;\n    server_name $domain www.$domain;\n    root $root;\n    index index.php index.html;\n    client_max_body_size 100M;\n    location / { try_files \$uri \$uri/ /index.php?\$query_string; }\n    location ~ \\.php\$ { $fastcgi_inc fastcgi_pass unix:$fpm_sock; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; include fastcgi_params; }\n    location ~ /\\. { deny all; }\n}\n";
            $ntmp = tempnam('/tmp', 'ngx_site_'); chmod($ntmp, 0600);
            file_put_contents($ntmp, $nginx_conf);
            priv_apply_file($ntmp, cfg_path($domain));
            priv_nginx_link_site(cfg_path($domain), cfg_path($domain, 'enabled'));
            @unlink($ntmp);
            if (!nginx_verify_or_rollback([cfg_path($domain)], [cfg_path($domain, 'enabled')])) {
                flash('⚠️ 站点文件已恢复，但 Nginx 配置校验失败未启用', 'err'); redirect('backups');
            }
            priv_reload_nginx();
        }
        flash("✅ 网站 $domain 恢复成功！"); redirect('backups');
    }

    // --- INSTALL SERVICE ---

if ($act === 'node_install') {
        if (node_installed()) { flash('Node.js 已安装（' . node_version() . '）', 'err'); redirect('node'); }
        if (is_alpine()) {
            cmd('apk update 2>&1 && apk add nodejs npm 2>&1');
        } elseif (is_rhel()) {
            cmd('curl -fsSL https://rpm.nodesource.com/setup_20.x | bash - 2>&1 && dnf install -y nodejs 2>&1');
        } else {
            cmd('curl -fsSL https://deb.nodesource.com/setup_20.x | bash - 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs 2>&1');
        }
        if (node_installed()) { flash('✅ Node.js ' . node_version() . ' + npm 安装成功'); }
        else { flash('❌ Node.js 安装失败，请查看系统日志', 'err'); }
        redirect('node');
    }

    if ($act === 'node_site_add') {
        $domain = strtolower(trim($_POST['ndomain'] ?? ''));
        $port = intval($_POST['nport'] ?? 0);
        $entry = trim($_POST['nentry'] ?? 'app.js');
        $npm_install = isset($_POST['nnpm']);
        if (!validate_domain($domain)) { flash('域名无效!', 'err'); redirect('node'); }
        if ($port < 1024 || $port > 65535) { flash('端口须在 1024-65535', 'err'); redirect('node'); }
        if (!preg_match('#^[a-zA-Z0-9._/-]{1,100}$#', $entry) || str_contains($entry, '..')) { flash('入口文件路径无效', 'err'); redirect('node'); }
        $all = node_sites_all();
        if (isset($all[$domain])) { flash('❌ Node 站点 ' . $domain . ' 已存在', 'err'); redirect('node'); }
        if (is_link(cfg_path($domain, 'enabled')) || file_exists(cfg_path($domain))) { flash('❌ nginx 配置已存在（如需重建请先删除）', 'err'); redirect('node'); }
        if (is_dir(WWW_ROOT . '/' . $domain)) { flash('❌ 目录已存在', 'err'); redirect('node'); }

        $root = WWW_ROOT . '/' . $domain;
        priv_mkdir_www($root);
        @file_put_contents("$root/package.json", json_encode(['name'=>$domain,'version'=>'1.0.0','main'=>$entry,'scripts'=>['start'=>'node '.$entry]], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
        @file_put_contents("$root/$entry", "// Node.js app\nconst http = require('http');\nhttp.createServer((req,res)=>{res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});res.end('<h1>Node.js 站点 $domain 运行中</h1>');}).listen($port, '127.0.0.1');\nconsole.log('listening on $port');\n");
        $root_esc = escapeshellarg($root);
        $entry_esc = escapeshellarg($entry);
        if ($npm_install) cmd("cd $root_esc && npm install --production 2>&1");
        // systemd/OpenRC 守护（复用 proc_add 模式）
        $name = 'node-' . preg_replace('/[^a-z0-9-]/', '-', $domain);
        $user = 'root';
        $bin = node_installed() ? trim(cmd('command -v node 2>/dev/null') ?: 'node') : 'node';
        if (is_alpine()) {
            $rc = "/etc/init.d/vpsmgr-$name";
            $sv = <<<SV
#!/sbin/openrc-run
name="vpsmgr-$name"
command="$bin"
command_args="$entry"
command_user="$user"
command_background="yes"
pidfile="/run/vpsmgr-$name.pid"
directory="$root"
output_log="/var/log/vpsmgr-$name.log"
error_log="/var/log/vpsmgr-$name.log"
depend() {
    need net
}
SV;
            file_put_contents($rc, $sv); chmod($rc, 0755);
            cmd("rc-update add vpsmgr-$name default 2>&1; rc-service vpsmgr-$name start 2>&1");
        } else {
            $unit = "/etc/systemd/system/vpsmgr-$name.service";
            $uc = "[Unit]\nDescription=VPS Manager Node: $domain\nAfter=network.target\n\n[Service]\nType=simple\nUser=$user\nWorkingDirectory=$root\nExecStart=$bin $entry_esc\nRestart=on-failure\nRestartSec=5\nEnvironment=PORT=$port\nStandardOutput=append:/var/log/vpsmgr-$name.log\nStandardError=append:/var/log/vpsmgr-$name.log\n\n[Install]\nWantedBy=multi-user.target\n";
            file_put_contents($unit, $uc);
            cmd("systemctl daemon-reload 2>&1 && systemctl enable --now vpsmgr-$name 2>&1");
        }
        // nginx 反代 conf
        $nginx_conf = "server {\n    listen 80;\n    server_name $domain www.$domain;\n    root $root;\n    index index.html;\n\n    client_max_body_size 100M;\n\n    location / {\n        proxy_pass http://127.0.0.1:$port;\n        proxy_http_version 1.1;\n        proxy_set_header Upgrade \$http_upgrade;\n        proxy_set_header Connection \"upgrade\";\n        proxy_set_header Host \$host;\n        proxy_set_header X-Real-IP \$remote_addr;\n        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto \$scheme;\n        proxy_read_timeout 300s;\n    }\n\n    location ~ /\\. { deny all; }\n}\n";
        $ntmp = tempnam('/tmp', 'ngx_nd_'); chmod($ntmp, 0600);
        file_put_contents($ntmp, $nginx_conf);
        priv_apply_file($ntmp, cfg_path($domain));
        priv_nginx_link_site(cfg_path($domain), cfg_path($domain, 'enabled'));
        @unlink($ntmp);
        if (!nginx_verify_or_rollback([cfg_path($domain)], [cfg_path($domain, 'enabled')])) {
            flash('❌ nginx 配置校验失败，Node 站点已回滚', 'err'); redirect('node');
        }
        cmd('nginx -s reload 2>&1');
        $all[$domain] = ['domain'=>$domain, 'port'=>$port, 'entry'=>$entry, 'created'=>date('Y-m-d H:i')];
        node_sites_save($all);
        flash("✅ Node 站点 <b>$domain</b> 已创建（守护 vpsmgr-$name，nginx 反代 :$port）");
        redirect('node');
    }

    if ($act === 'node_app_action') {
        $domain = strtolower(trim($_POST['ndomain'] ?? ''));
        $op = $_POST['op'] ?? '';
        $all = node_sites_all();
        if (!isset($all[$domain])) { flash('Node 站点不存在', 'err'); redirect('node'); }
        $name = 'node-' . preg_replace('/[^a-z0-9-]/', '-', $domain);
        $allowed = ['start','stop','restart','npm_install','npm_build'];
        if (!in_array($op, $allowed, true)) { flash('操作无效', 'err'); redirect('node'); }
        $root_esc = escapeshellarg(WWW_ROOT . '/' . $domain);
        if ($op === 'npm_install') { cmd("cd $root_esc && npm install 2>&1"); flash('✅ npm install 已执行'); }
        elseif ($op === 'npm_build') { cmd("cd $root_esc && npm run build 2>&1"); flash('✅ npm run build 已执行'); }
        else {
            $svc = "vpsmgr-$name";
            if (is_alpine()) {
                $map = ['start'=>'start','stop'=>'stop','restart'=>'restart'];
                cmd('rc-service ' . $svc . ' ' . $map[$op] . ' 2>&1');
            } else {
                cmd('systemctl ' . $op . ' ' . $svc . ' 2>&1');
            }
            flash('✅ ' . sanitize($op) . ' 已执行');
        }
        redirect('node');
    }

    if ($act === 'node_site_del') {
        $domain = strtolower(trim($_POST['ndomain'] ?? ''));
        if (!isset(node_sites_all()[$domain])) { flash('Node 站点不存在', 'err'); redirect('node'); }
        $name = 'node-' . preg_replace('/[^a-z0-9-]/', '-', $domain);
        if (is_alpine()) { cmd("rc-service vpsmgr-$name stop 2>&1; rc-update del vpsmgr-$name default 2>&1"); @unlink("/etc/init.d/vpsmgr-$name"); }
        else { cmd("systemctl stop vpsmgr-$name 2>&1; systemctl disable vpsmgr-$name 2>&1"); @unlink("/etc/systemd/system/vpsmgr-$name.service"); cmd('systemctl daemon-reload 2>&1'); }
        foreach ([cfg_path($domain), cfg_path($domain, 'enabled')] as $p) { if (is_link($p) || file_exists($p)) priv_unlink($p); }
        cmd('rm -rf ' . escapeshellarg(WWW_ROOT . "/$domain")); // 整目录删除（含 node_modules）
        $all = node_sites_all(); unset($all[$domain]); node_sites_save($all);
        cmd('nginx -s reload 2>&1');
        flash("🗑️ Node 站点 $domain 已删除"); redirect('node');
    }

    if ($act === 'install_svc') {
        $svc = $_POST['svc'] ?? '';
        $pkgs = [
            'nginx' => 'nginx',
            'php' => php_pkg_list(),
            'mysql' => is_alpine() ? 'mariadb mariadb-client' : 'mariadb-server mariadb-client',
            'phpmyadmin' => 'phpmyadmin',
            'certbot' => is_alpine() ? 'certbot certbot-nginx' : 'certbot python3-certbot-nginx'
        ];
        if (is_alpine() && $svc === 'phpmyadmin') { flash('❌ Alpine 无 phpMyAdmin 包，请使用 Adminer 或直接用 SQLite 模式', 'err'); redirect('services'); }
        if (isset($pkgs[$svc])) {
            if ($svc === 'mysql' && is_alpine()) $pkgs['mysql'] = 'mariadb mariadb-client';
            if (is_alpine()) {
                cmd("apk update 2>&1 && apk add " . $pkgs[$svc] . " 2>&1");
                if ($svc === 'nginx') svc_start_enable('nginx');
                if ($svc === 'php') { alpine_fix_fpm_sock(selected_php_version()); svc_start_enable(php_fpm_svc()); } // 审计修复：Alpine FPM sock 初始化
                if ($svc === 'mysql') svc_start_enable('mariadb');
            } else {
            cmd("DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq " . $pkgs[$svc] . " 2>&1");
            if ($svc === 'nginx') cmd("systemctl enable --now nginx");
            if ($svc === 'php') svc_start_enable(php_fpm_svc());
            if ($svc === 'mysql') cmd("systemctl enable --now mariadb");
            }
            flash("✅ $svc 已安装并启动！"); redirect('services');
        }
        flash('❌ 未知服务', 'err'); redirect('services');
    }

    // --- PHP: INSTALL VERSION ---
    if ($act === 'php_install') {
        $ver = $_POST['version'] ?? '';
        if (!in_array($ver, ['8.2','8.3','8.4','8.5'], true)) { flash('版本无效！仅支持 8.2 / 8.3 / 8.4 / 8.5', 'err'); redirect('php'); }
        $_SESSION['phpver'] = $ver;
        
        $task_id = 'phpinstall_' . bin2hex(random_bytes(8));
        $logfile = '/tmp/progress_' . $task_id . '.log';
        file_put_contents($logfile, "🐘 开始安装 PHP $ver...\n📦 准备软件源...\n");
        if (is_alpine()) {
            $pv = str_replace('.', '', $ver);
            $pkgs = php_pkg_list();
            $fixsock = "mkdir -p /run/php-fpm$pv; sed -i -E \"s|^listen\\s*=.*|listen = /run/php-fpm$pv/php-fpm.sock|; s|^;?listen\\.owner\\s*=.*|listen.owner = nginx|; s|^;?listen\\.group\\s*=.*|listen.group = nginx|; s|^user\\s*=.*|user = nginx|; s|^group\\s*=.*|group = nginx|\" /etc/php$pv/php-fpm.d/www.conf 2>> $logfile; ";
            $cmd = "(apk add $pkgs >> $logfile 2>&1; ";
            $cmd .= $fixsock;
            $cmd .= "rc-update add php-fpm$pv default >> $logfile 2>&1; ";
            $cmd .= "rc-service php-fpm$pv start >> $logfile 2>&1; ";
            $cmd .= "echo '___COMPLETE___' >> $logfile) > /dev/null 2>&1 &";
        } else {
            $pkgs = "php$ver-fpm php$ver-cli php$ver-mysql php$ver-curl php$ver-gd php$ver-mbstring php$ver-xml php$ver-zip php$ver-intl php$ver-bcmath";
            $cmd = "(apt-get install -y -qq software-properties-common >> $logfile 2>&1; ";
            $cmd .= "add-apt-repository -y ppa:ondrej/php >> $logfile 2>&1; ";
            $cmd .= "apt-get update -qq >> $logfile 2>&1; ";
            $cmd .= "echo '📦 正在安装软件包...' >> $logfile; ";
            $cmd .= "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $pkgs >> $logfile 2>&1; ";
            $cmd .= "systemctl enable --now php$ver-fpm >> $logfile 2>&1; ";
            $cmd .= "echo '___COMPLETE___' >> $logfile) > /dev/null 2>&1 &";
        }
        exec($cmd);
        
        ?><!DOCTYPE html><html lang="id"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>正在安装 PHP <?= $ver ?>...</title>
        <style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:linear-gradient(160deg,#dfd9cf,#f5f0e8);color:#2d3748;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}.box{background:#fafaf7;padding:44px;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,.1);width:90%;max-width:650px;text-align:center;border-top:4px solid #1e3a5f}.spinner{width:48px;height:48px;border:4px solid #e2ddd5;border-top:4px solid #1e3a5f;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 20px}@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}h2{color:#1a365d;margin-bottom:8px;font-weight:700}pre{background:#fdfcfb;padding:16px;border-radius:8px;text-align:left;max-height:350px;overflow:auto;font-family:monospace;font-size:12px;color:#5a6170;line-height:1.6;margin-top:20px;border:1px solid #e2ddd5}.done{display:none;margin-top:16px}.btn-green{background:linear-gradient(135deg,#1e3a5f,#2c5282);color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block;box-shadow:0 2px 8px rgba(30,58,95,.25)}.btn-green:hover{box-shadow:0 4px 14px rgba(30,58,95,.35)}</style></head><body>
        <div class="box"><div class="spinner" id="spinner"></div>
        <h2 id="title">🐘 正在安装 PHP <?= $ver ?>...</h2>
        <p style="color:#64748b;font-size:14px">这大约需要 2-5 分钟，请耐心等待 ☕</p>
        <pre id="log">准备中...</pre>
        <div class="done" id="done"><a href="?page=php" class="btn-green">✅ 返回 PHP Manager</a></div></div>
        <script>
        var tid='<?= $task_id ?>',check=0;
        function poll(){fetch('?progress='+tid).then(r=>r.text()).then(t=>{document.getElementById('log').textContent=t;if(t.indexOf('___COMPLETE___')>-1){document.getElementById('spinner').style.display='none';document.getElementById('title').textContent='✅ PHP <?= $ver ?> 已安装！';document.getElementById('done').style.display='block'}else{check++;var m=Math.floor(check*1.5/60),s=Math.ceil(check*1.5)%60;document.getElementById('title').textContent='🐘 正在安装 PHP <?= $ver ?>... ('+m+'m '+s+'s)';setTimeout(poll,1500)}})}poll();
        </script></body></html><?php exit;
    }

    // --- PHP: SET DEFAULT CLI ---
    if ($act === 'php_default') {
        $ver = $_POST['version'] ?? '';
        if (!in_array($ver, ['8.2','8.3','8.4','8.5'], true)) { flash('版本无效！', 'err'); redirect('php'); }
        $_SESSION['phpver'] = $ver;
        if (is_alpine()) { $psfx = str_replace('.','',$ver); cmd("apk add php$psfx 2>&1 || true; ln -sf /usr/bin/php$psfx /usr/bin/php 2>&1"); }
        else cmd("update-alternatives --set php /usr/bin/php$ver 2>&1");
        flash("✅ PHP CLI 默认版本已改为 $ver！"); redirect('php');
    }

    // --- PHP: REMOVE VERSION ---
    if ($act === 'php_remove') {
        $ver = $_POST['version'] ?? '';
        if (!in_array($ver, ['8.2','8.3','8.4','8.5'], true)) { flash('版本无效！', 'err'); redirect('php'); }
        if (is_alpine()) cmd("rc-service php-fpm" . str_replace('.','',$ver) . " stop 2>&1; apk del php" . str_replace('.','',$ver) . "-fpm 2>&1");
        else cmd("systemctl stop php$ver-fpm 2>&1; systemctl disable php$ver-fpm 2>&1; apt-get remove -y -qq php$ver-* 2>&1");
        flash("✅ PHP $ver 删除!"); redirect('php');
    }

    // --- PHP: SWITCH PER SITE ---
    if ($act === 'php_switch_site') {
        $domain = $_POST['domain'] ?? '';
        $ver = $_POST['version'] ?? '';
        if (empty($domain) || !in_array($ver, ['8.2','8.3','8.4','8.5'], true)) { flash('输入无效!', 'err'); redirect('php'); }
        // Validate PHP version is actually installed and socket exists
        $pv2 = str_replace('.','',$ver);
        if (is_alpine()) { if (!is_executable(php_bin($ver))) { flash("❌ PHP $ver 尚未安装!", 'err'); redirect('php'); } }
        elseif (!file_exists(php_bin($ver))) { flash("❌ PHP $ver 尚未安装!", 'err'); redirect('php'); }
        $sock = is_alpine() ? "/run/php-fpm$pv2/php-fpm.sock" : "/var/run/php/php$ver-fpm.sock";
        if (!file_exists($sock)) $sock = "/run/php/php$ver-fpm.sock";
        if (!file_exists($sock) && is_alpine()) $sock = "/run/php-fpm$pv2/php-fpm.sock";
        if (!file_exists($sock)) { flash("❌ 未找到 PHP $ver FPM socket！请运行: systemctl start php$ver-fpm", 'err'); redirect('php'); }
        // Ensure FPM is running
        $fsvc = is_alpine() ? 'php-fpm' . str_replace('.','',$ver) : "php$ver-fpm";
        if (!svc_status($fsvc)) {
            is_alpine() ? cmd("rc-service $fsvc start 2>&1") : cmd("systemctl start $fsvc 2>&1");
            sleep(1);
        }
        // Find the nginx config file for this domain
        $cfg_file = null;
        foreach (glob(NGINX_AVAILABLE . '/*') as $f) {
            $cfg = file_get_contents($f);
            if (preg_match('/server_name\s+([^;]+);/', $cfg, $m)) {
                $names = preg_split('/\s+/', trim($m[1]));
                if (in_array($domain, $names)) { $cfg_file = $f; break; }
            }
        }
        if (!$cfg_file) { flash("未找到 $domain 的配置！", 'err'); redirect('php'); }
        // Backup config before change
        $cfg_original = file_get_contents($cfg_file);
        $cfg = $cfg_original;
        // Replace any PHP socket with the new version
        $cfg = preg_replace(
            '/unix:(\/var\/run\/php\/php[\d.]+-fpm\.sock|\/run\/php-fpm\d+\/php-fpm\.sock)/',
            "unix:$sock",
            $cfg
        );
        $cfg = preg_replace(
            '/fastcgi_pass\s+127\.0\.0\.1:\d+/',
            "fastcgi_pass unix:$sock",
            $cfg
        );
        file_put_contents($cfg_file, $cfg);
        // Test nginx config - rollback if fails
        $test = cmd("nginx -t 2>&1");
        if (strpos($test, 'successful') === false) {
            file_put_contents($cfg_file, $cfg_original);
            flash("❌ Nginx 配置错误！已回滚到原配置。<br><small>" . nl2br(sanitize(substr($test, 0, 300))) . "</small>", 'err');
            redirect('php');
        }
        svc_reload('nginx');
        flash("✅ <b>$domain</b> 现在使用 <b>PHP $ver</b>！🔄"); redirect('php');
    }

    // --- INSTALL ALL (Full LEMP Stack) ---
    if ($act === 'install_all') {
        $log = '';
        $want_mysql = ($_POST['with_mysql'] ?? '') === '1';
        $v = selected_php_version();
        if (is_alpine()) {
            $pv = str_replace('.', '', $v);
            $steps = [
                ['name' => 'Nginx', 'pkgs' => 'nginx'],
                ['name' => "PHP $v", 'pkgs' => php_pkg_list()],
                ($want_mysql ? ['name' => 'MariaDB', 'pkgs' => 'mariadb mariadb-client'] : null),
                ['name' => 'Certbot (SSL)', 'pkgs' => 'certbot certbot-nginx'],
            ];
        } else {
            $steps = [
                ['name' => 'Nginx', 'pkgs' => 'nginx'],
                ['name' => "PHP $v", 'pkgs' => php_pkg_list() . " php$v-intl php$v-bcmath"],
                ($want_mysql ? ['name' => 'MariaDB', 'pkgs' => 'mariadb-server mariadb-client'] : null),
                ($want_mysql ? ['name' => 'phpMyAdmin', 'pkgs' => 'phpmyadmin'] : null),
                ['name' => 'Certbot (SSL)', 'pkgs' => 'certbot python3-certbot-nginx'],
            ];
        }
        $steps = array_filter($steps);
        if (is_alpine()) {
            cmd("apk update 2>&1");
            foreach ($steps as $step) {
                cmd("apk add " . $step['pkgs'] . " 2>&1");
                $log .= "✅ {$step['name']}: 已安装\n";
            }
            svc_start_enable('nginx');
            alpine_fix_fpm_sock($v);
            svc_start_enable(php_fpm_svc());
            if ($want_mysql) svc_start_enable('mariadb');
        } else {
            cmd("DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>&1");
            foreach ($steps as $step) {
                $r = cmd("DEBIAN_FRONTEND=noninteractive apt-get install -y -qq " . $step['pkgs'] . " 2>&1");
                $log .= "✅ {$step['name']}: 已安装\n";
            }
            svc_start_enable('nginx');
            svc_start_enable(php_fpm_svc());
            if ($want_mysql) svc_start_enable('mariadb');
            svc_start_enable('certbot.timer');
        }
        
        // Link phpMyAdmin to manager panel if panel exists
        if ($want_mysql && is_dir('/usr/share/phpmyadmin') && is_dir('/var/www/manager')) {
            @symlink('/usr/share/phpmyadmin', '/var/www/manager/pma');
        }
        
        flash("🚀 Full LEMP Stack 已安装!\n$log"); redirect('services');
    }

    // --- SSL: INSTALL CERTBOT ---
    if ($act === 'install_certbot') {
        if (is_alpine()) cmd("apk update 2>&1 && apk add certbot certbot-nginx 2>&1");
        else cmd("DEBIAN_FRONTEND=noninteractive apt-get update -qq && apt-get install -y -qq certbot python3-certbot-nginx 2>&1");
        flash('✅ Certbot 已安装!'); redirect('ssl');
    }

    // --- SSL: INSTALL FOR DOMAIN ---
    if ($act === 'ssl_install') {
        $domain = $_POST['domain'] ?? '';
        $email = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL) ?: ('admin@' . $domain);
        if (!validate_domain($domain)) { flash('域名无效!', 'err'); redirect('ssl'); }
        
        // 1. Check DNS
        $a = dns_get_record($domain, DNS_A);
        $dns = $a[0]['ip'] ?? '';
        $server_ip = trim(cmd("curl -s4 ifconfig.me 2>/dev/null"));
        if (empty($dns) || $dns !== $server_ip) {
            flash("❌ 域名 <b>$domain</b> 尚未解析到本 VPS ($server_ip)。<br>请先把 A 记录指到 $server_ip，等解析生效后重试。", 'err');
            redirect('ssl');
        }
        
        // 2. Ensure nginx HTTP config exists + has acme-challenge access
        $cfg_path = cfg_path($domain);
        if (!file_exists($cfg_path)) {
            $root = WWW_ROOT . '/' . $domain;
            priv_mkdir_www($root);
            if (!is_dir("$root/.well-known/acme-challenge")) @mkdir("$root/.well-known/acme-challenge", 0755, true);
            $nginx_conf = "server {\n    listen 80;\n    server_name $domain www.$domain;\n    root $root;\n    index index.html;\n    location ^~ /.well-known/acme-challenge/ { root $root; }\n    location / { try_files \$uri \$uri/ =404; }\n}\n";
            $ntmp = tempnam('/tmp', 'ngx_ssl_'); chmod($ntmp, 0600);
            file_put_contents($ntmp, $nginx_conf);
            priv_apply_file($ntmp, $cfg_path);
            priv_nginx_link_site(cfg_path($domain), cfg_path($domain, 'enabled'));
            @unlink($ntmp);
            if (!nginx_verify_or_rollback([$cfg_path], [cfg_path($domain, 'enabled')])) { flash('❌ nginx 配置校验失败，SSL 前置配置已回滚', 'err'); redirect('ssl'); }
        }
        // 手动 ACME challenge 插入已移除：certbot --nginx 自行处理 HTTP-01（旧插入有 $1 反向引用 bug）
        cmd('nginx -t 2>&1 && ' . (is_alpine() ? 'rc-service nginx reload' : 'systemctl reload nginx'));
        sleep(2);
        
        // 3. Run certbot with live progress
        $task_id = 'ssl_' . bin2hex(random_bytes(8));
        $logfile = '/tmp/progress_' . $task_id . '.log';
        file_put_contents($logfile, "🔒 Memulai install SSL untuk $domain...\n📡 Menghubungi Let's Encrypt...\n");
        $cmd = "certbot --nginx -d " . escapeshellarg($domain) . " -d " . escapeshellarg('www.' . $domain) . " --non-interactive --agree-tos -m " . escapeshellarg($email) . " --redirect >> $logfile 2>&1; echo '___COMPLETE___' >> $logfile";
        exec("$cmd > /dev/null 2>&1 &");
        
        ?><!DOCTYPE html><html lang="id"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Installing SSL...</title>
        <style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:linear-gradient(160deg,#dfd9cf,#f5f0e8);color:#2d3748;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}.box{background:#fafaf7;padding:44px;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,.1);width:90%;max-width:650px;text-align:center;border-top:4px solid #1e3a5f}.spinner{width:48px;height:48px;border:4px solid #e2ddd5;border-top:4px solid #1e3a5f;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 20px}@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}h2{color:#1a365d;margin-bottom:8px;font-weight:700}pre{background:#fdfcfb;padding:16px;border-radius:8px;text-align:left;max-height:350px;overflow:auto;font-family:monospace;font-size:12px;color:#5a6170;line-height:1.6;margin-top:20px;border:1px solid #e2ddd5}.done{display:none;margin-top:16px}.btn-green{background:linear-gradient(135deg,#1e3a5f,#2c5282);color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block;box-shadow:0 2px 8px rgba(30,58,95,.25)}.btn-green:hover{box-shadow:0 4px 14px rgba(30,58,95,.35)}</style></head><body>
        <div class="box"><div class="spinner" id="spinner"></div>
        <h2 id="title">🔒 正在安装 SSL...</h2>
        <p style="color:#64748b;font-size:14px">Domain: <b><?= sanitize($domain) ?></b></p>
        <pre id="log">准备中...</pre>
        <div class="done" id="done"><a href="?page=ssl" class="btn-green">✅ 返回 SSL</a></div></div>
        <script>
        var tid='<?= $task_id ?>',check=0;
        function poll(){fetch('?progress='+tid).then(r=>r.text()).then(t=>{document.getElementById('log').textContent=t;if(t.indexOf('___COMPLETE___')>-1){document.getElementById('spinner').style.display='none';var ok=t.indexOf('Congratulations')>-1||t.indexOf('Successfully')>-1;document.getElementById('title').textContent=ok?'✅ SSL 安装成功！':'❌ SSL 失败';document.getElementById('title').style.color=ok?'#10b981':'#ef4444';document.getElementById('done').style.display='block'}else{check++;document.getElementById('title').textContent='🔒 正在安装 SSL... ('+Math.ceil(check*1.5)+'s)';setTimeout(poll,1500)}})}poll();
        </script></body></html><?php exit;
    }

    // --- SSL: RENEW MANUAL ---
    // --- WILDCARD SSL (DNS-01 via Cloudflare) ---
    if ($act === 'ssl_wildcard') {
        $domain = trim($_POST['wdomain'] ?? '');
        $cf_token = trim($_POST['wtoken'] ?? '');
        $email = trim($_POST['wemail'] ?? ('admin@' . $domain));
        if (!validate_domain($domain) || substr_count($domain, '.') < 2) { flash('请填主域名（如 example.com，将签发 *.example.com）', 'err'); redirect('ssl'); }
        if (empty($cf_token) || strlen($cf_token) > 200 || preg_match('/[\r\n"\']/', $cf_token)) { flash('Cloudflare API Token 无效', 'err'); redirect('ssl'); }
        // 检测 DNS 插件
        $plugin_dir = is_alpine() ? '/usr/lib/python3.*/site-packages/certbot_dns_cloudflare' : '/usr/lib/python3/dist-packages/certbot_dns_cloudflare';
        $has_plugin = !empty(glob($plugin_dir)) || is_executable('/usr/bin/certbot') && trim(cmd('certbot plugins 2>/dev/null | grep -c dns-cloudflare')) !== '0';
        if (!$has_plugin) {
            if (is_alpine()) cmd('apk add certbot-dns-cloudflare 2>&1 || pip3 install certbot-dns-cloudflare 2>&1');
            else cmd('apt-get install -y -qq python3-certbot-dns-cloudflare 2>&1 || pip3 install certbot-dns-cloudflare 2>&1');
            $has_plugin = trim(cmd('certbot plugins 2>/dev/null | grep -c dns-cloudflare')) !== '0' || !empty(glob($plugin_dir));
            if (!$has_plugin) { flash('❌ dns-cloudflare 插件安装失败，请手动安装', 'err'); redirect('ssl'); }
        }
        $cred = '/etc/letsencrypt/.cloudflare.ini';
        $cred_tmp = tempnam(dirname($cred), 'cf_');
        chmod($cred_tmp, 0600);
        file_put_contents($cred_tmp, "dns_cloudflare_api_token = $cf_token\n");
        rename($cred_tmp, $cred); chmod($cred, 0600);
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) { flash('邮箱格式无效', 'err'); redirect('ssl'); }
        $task_id = 'wc_' . bin2hex(random_bytes(8));
        $logfile = '/tmp/progress_' . $task_id . '.log'; // task_id 随机不可预测（R4）
        file_put_contents($logfile, "🔒 开始签发通配符证书 *.$domain...\n📡 DNS-01 验证中（约 1-2 分钟）...\n");
        $cmd = "(certbot certonly --dns-cloudflare --dns-cloudflare-credentials " . escapeshellarg($cred) .
               " -d " . escapeshellarg($domain) . " -d " . escapeshellarg('*.' . $domain) .
               " --non-interactive --agree-tos -m " . escapeshellarg($email) .
               " >> $logfile 2>&1; " .
               "echo '___COMPLETE___' >> $logfile) > /dev/null 2>&1 &";
        exec($cmd);
        ?><!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><meta http-equiv="refresh" content="2;url=?page=progress&task=<?= $task_id ?>&back=ssl"><title>正在签发通配符证书...</title></head><body style="font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh">🔒 正在签发 *.<?= sanitize($domain) ?> 通配符证书（DNS-01），约 1-2 分钟...（2 秒后自动跳转进度页）</body></html><?php
        exit;
    }

    if ($act === 'ssl_renew') {
        $out = cmd("certbot renew --non-interactive 2>&1");
        if (strpos($out, 'No renewals') !== false) {
            flash('ℹ️ 所有证书均有效. 暂无需 renew.');
        } else {
            cmd("nginx -s reload 2>&1");
            flash('✅ SSL renewed!');
        }
        redirect('ssl');
    }

    // --- SSL: ENABLE AUTO-RENEW ---
    if ($act === 'ssl_autorenew') {
        svc_start_enable('certbot.timer');
        flash('✅ Auto-renew SSL 启用! (检查 setiap 12 jam)');
        redirect('ssl');
    }

    // --- FIREWALL: ENABLE/DISABLE ---
    if ($act === 'fw_toggle') {
        $enable = $_POST['enable'] ?? '0';
        if ($enable === '1') {
            cmd("ufw --force enable 2>&1");
            cmd("ufw default deny incoming 2>&1");
            cmd("ufw default allow outgoing 2>&1");
            flash('✅ Firewall 启用! (Default: deny incoming, allow outgoing)');
        } else {
            cmd("ufw disable 2>&1");
            flash('⚠️ Firewall 停用!');
        }
        redirect('firewall');
    }

    // --- FIREWALL: ADD RULE ---
    if ($act === 'fw_add') {
        $port = intval($_POST['port'] ?? 0);
        $proto = ($_POST['proto'] ?? 'tcp') === 'udp' ? 'udp' : 'tcp';
        $action = ($_POST['fw_action'] ?? 'allow') === 'deny' ? 'deny' : 'allow';
        if ($port < 1 || $port > 65535) { flash('Port 无效!', 'err'); redirect('firewall'); }
        $out = cmd("ufw $action $port/$proto 2>&1");
        flash(strpos($out, 'Rule added') !== false || strpos($out, 'Rule updated') !== false ? "✅ Rule: $action $port/$proto 添加!" : ('❌ 规则添加失败: ' . sanitize(substr($out, 0, 200))), strpos($out, 'Rule added') !== false || strpos($out, 'Rule updated') !== false ? 'ok' : 'err');
        redirect('firewall');
    }

    // --- FIREWALL: DELETE RULE ---
    if ($act === 'fw_del') {
        $num = intval($_POST['num'] ?? 0);
        if ($num > 0) {
            $out = cmd("yes | ufw delete $num 2>&1");
            flash(strpos($out, 'Could not delete') === false ? '✅ Rule 删除!' : ('❌ 删除失败: ' . sanitize(substr($out, 0, 200))), strpos($out, 'Could not delete') === false ? 'ok' : 'err');
        }
        redirect('firewall');
    }

    // --- CRON: ADD JOB ---
    if ($act === 'cron_add') {
        $expr = $_POST['expr'] ?? '';
        $cmd = $_POST['cmd'] ?? '';
        if (empty($expr) || empty($cmd)) { flash('Cron 表达式和命令必填！', 'err'); redirect('cron'); }
        if (!preg_match('/^(?:@(?:reboot|yearly|annually|monthly|weekly|daily|hourly)|[\d*,\/-]+(?:\s+[\d*,\/-]+){4})$/', $expr)) { flash('❌ Cron 表达式格式无效', 'err'); redirect('cron'); }
        if (preg_match('/[\r\n\0]/', $cmd)) { flash('❌ 命令含非法换行/空字节', 'err'); redirect('cron'); }
        $current = cmd('crontab -l', false) ?: '';
        $new = $current . "$expr $cmd\n";
        $ct = tempnam('/tmp', 'ctab_'); chmod($ct, 0600);
        file_put_contents($ct, $new);
        $ec = 0; cmdv(['crontab', $ct], null, $ec); @unlink($ct);
        if ($ec !== 0) { flash('❌ crontab 安装失败（退出码 ' . $ec . '）', 'err'); redirect('cron'); }
        flash("✅ Cron job 添加!<br><code>" . sanitize($expr . " " . $cmd) . "</code>");
        redirect('cron');
    }

    // --- CRON: DELETE JOB ---
    if ($act === 'cron_del') {
        $num = intval($_POST['num'] ?? 0);
        $current = cmd('crontab -l', false) ?: '';
        $lines = explode("\n", trim($current));
        // T-26：UI 编号只计非空非注释行 → 映射回原始行数组
            $jobs_idx = [];
            foreach ($lines as $idx => $ln) { $t = trim($ln); if ($t !== '' && $t[0] !== '#') $jobs_idx[] = $idx; }
            if (isset($jobs_idx[$num - 1])) {
            unset($lines[$jobs_idx[$num - 1]]);
            $new = implode("\n", $lines) . "\n";
            $ct = tempnam('/tmp', 'ctab_'); chmod($ct, 0600);
            file_put_contents($ct, $new);
            $ec = 0; cmdv(['crontab', $ct], null, $ec); @unlink($ct);
        if ($ec !== 0) { flash('❌ crontab 安装失败（退出码 ' . $ec . '）', 'err'); redirect('cron'); }
            flash('✅ Cron job 删除!');
        }
        redirect('cron');
    }

    // --- CHANGE PASSWORD (multi-user) ---
    if ($act === 'change_pass') {
        $old = $_POST['old_pass'] ?? '';
        $new = $_POST['new_pass'] ?? '';
        $confirm = $_POST['confirm_pass'] ?? '';
        $cu = current_user();
        if (!$cu || $old === '' || !check_user($cu['user'], $old)) { flash('❌ 旧密码错误！', 'err'); redirect('settings'); }
        if (strlen($new) < 6) { flash('❌ Password baru 至少 6 karakter!', 'err'); redirect('settings'); }
        if ($new !== $confirm) { flash('❌ 两次输入的密码不一致！', 'err'); redirect('settings'); }
        $users = load_users();
        foreach ($users as &$u) { if ($u['user'] === $cu['user']) { $u['pass'] = password_hash($new, PASSWORD_BCRYPT); break; } }
        save_users($users);
        // 密码已 bcrypt 存入 SQLite，不再写明文文件 chmod(PASSWD_FILE, 0600);
        flash('✅ Password 已修改!');
        redirect('settings');
    }

    // --- OPTIMIZE ---
    if ($act === 'optimize') {
        $target = $_POST['target'] ?? '';
        $ram_mb = intval(trim(cmd("free -m | grep Mem | awk '{print \$2}'")));
        $cpu_cores = intval(trim(cmd('nproc')));
        $backup_dir = BACKUP_DIR . '/optimize/' . date('Ymd_His');
        mkdir($backup_dir, 0755, true);
        
        $optimized = [];
        
        if ($target === 'nginx' || $target === 'all') {
            // Backup nginx config
            copy('/etc/nginx/nginx.conf', "$backup_dir/nginx.conf.bak");
            $nconf = file_get_contents('/etc/nginx/nginx.conf');
            $wconn = $ram_mb >= 2048 ? 4096 : ($ram_mb >= 1024 ? 4096 : 2048);
            $nconf = preg_replace('/worker_connections\s+\d+;/', "worker_connections $wconn;", $nconf);
            if (strpos($nconf, 'worker_processes auto;') === false) {
                $nconf = preg_replace('/worker_processes\s+\d+;/', 'worker_processes auto;', $nconf);
            }
            // Add gzip if missing
            if (strpos($nconf, 'gzip on;') === false) {
                $nconf .= "\n# Gzip compression\ngzip on;\ngzip_vary on;\ngzip_comp_level 5;\ngzip_types text/css application/javascript application/json text/html text/xml image/svg+xml;\ngzip_min_length 256;\n";
            }
            // Add fastcgi cache inside http block
            if (strpos($nconf, 'fastcgi_cache_path') === false) {
                $cache_section = "\tfastcgi_cache_path /var/cache/nginx levels=1:2 keys_zone=WORDPRESS:32m max_size=64m inactive=60m;\n\tfastcgi_cache_key \"\$scheme\$request_method\$host\$request_uri\";\n\tfastcgi_cache_use_stale error timeout invalid_header http_500;\n\tfastcgi_ignore_headers Cache-Control Expires Set-Cookie;\n";
                $nconf = preg_replace('/(http\s*\{)/', "\$1\n$cache_section", $nconf);
                if (!is_dir('/var/cache/nginx')) { mkdir('/var/cache/nginx', 0755, true); chown('/var/cache/nginx', web_user()); chgrp('/var/cache/nginx', web_user()); }
            }
            // T-25：事务化——临时文件 → 覆盖 → nginx -t → 失败恢复备份
            $ntmp = tempnam('/etc/nginx', 'ngx_opt_'); chmod($ntmp, 0644);
            file_put_contents($ntmp, $nconf);
            copy('/etc/nginx/nginx.conf', '/etc/nginx/nginx.conf.pre-opt');
            rename($ntmp, '/etc/nginx/nginx.conf');
            $nt = cmd('nginx -t 2>&1');
            if (strpos($nt, 'successful') === false) {
                copy('/etc/nginx/nginx.conf.pre-opt', '/etc/nginx/nginx.conf');
                flash('❌ nginx 优化失败已回滚: ' . sanitize(substr($nt, 0, 200)), 'err'); redirect('optimize');
            }
            @unlink('/etc/nginx/nginx.conf.pre-opt');
            $optimized[] = 'Nginx';
        }
        
        if ($target === 'php' || $target === 'all') {
            $php_ver = trim(cmd("php -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;'"));
            $pool_file = glob(is_alpine() ? "/etc/php" . str_replace('.','',$php_ver) . "/php-fpm.d/www.conf" : "/etc/php/$php_ver/fpm/pool.d/www.conf")[0] ?? '';
            if ($pool_file) {
                copy($pool_file, "$backup_dir/www.conf.bak");
                $pconf = file_get_contents($pool_file);
                $max_children = $ram_mb >= 4096 ? 50 : ($ram_mb >= 2048 ? 35 : ($ram_mb >= 1024 ? 25 : 12));
                $start = max(2, intval($max_children / 4));
                $min_spare = max(1, intval($max_children / 6));
                $max_spare = max(2, intval($max_children / 3));
                $pconf = preg_replace('/^pm\s*=\s*\w+/m', 'pm = ondemand', $pconf);
                $pconf = preg_replace('/^pm\.max_children\s*=\s*\d+/m', "pm.max_children = $max_children", $pconf);
                $pconf = preg_replace('/^pm\.start_servers\s*=\s*\d+/m', "pm.start_servers = $start", $pconf);
                $pconf = preg_replace('/^pm\.min_spare_servers\s*=\s*\d+/m', "pm.min_spare_servers = $min_spare", $pconf);
                $pconf = preg_replace('/^pm\.max_spare_servers\s*=\s*\d+/m', "pm.max_spare_servers = $max_spare", $pconf);
                // T-25：pool 改动事务化（php-fpm -t 校验，失败恢复）
                $ptmp = tempnam(dirname($pool_file), 'pool_'); chmod($ptmp, 0644);
                file_put_contents($ptmp, $pconf);
                copy($pool_file, $pool_file . '.pre-opt');
                rename($ptmp, $pool_file);
                $ft = cmd(php_fpm_bin_test($php_ver) . ' 2>&1');
                if (strpos($ft, 'successful') !== false || strpos($ft, 'done') !== false || $ft === '') {
                    @unlink($pool_file . '.pre-opt');
                } else {
                    copy($pool_file . '.pre-opt', $pool_file); @unlink($pool_file . '.pre-opt');
                    flash('⚠ PHP-FPM pool 优化失败已回滚: ' . sanitize(substr($ft, 0, 200)), 'err');
                }
            }
            // PHP ini - opcache
            $ini_file = is_alpine() ? "/etc/php" . str_replace('.','',$php_ver) . "/php.ini" : "/etc/php/$php_ver/fpm/php.ini";
            copy($ini_file, "$backup_dir/php.ini.bak");
            $ini = file_get_contents($ini_file);
            $ini = preg_replace('/^opcache\.enable\s*=\s*\d/m', 'opcache.enable = 1', $ini);
            if (strpos($ini, 'opcache.enable = 1') === false) $ini .= "\nopcache.enable = 1\n";
            $opcache_mem = $ram_mb >= 2048 ? 256 : ($ram_mb >= 1024 ? 128 : 64);
            $ini = preg_replace('/^opcache\.memory_consumption\s*=\s*\d+/m', "opcache.memory_consumption = $opcache_mem", $ini);
            $ini = preg_replace('/^opcache\.max_accelerated_files\s*=\s*\d+/m', 'opcache.max_accelerated_files = 10000', $ini);
            $ini = preg_replace('/^opcache\.validate_timestamps\s*=\s*\d/m', 'opcache.validate_timestamps = 0', $ini);
            file_put_contents($ini_file, $ini);
            // Also optimize CLI php.ini
            $cli_ini = "/etc/php/$php_ver/cli/php.ini";
            if (file_exists($cli_ini)) {
                copy($cli_ini, "$backup_dir/php-cli.ini.bak");
                $cini = file_get_contents($cli_ini);
                $cini = preg_replace('/memory_limit\s*=\s*\d+M/', 'memory_limit = 256M', $cini);
                file_put_contents($cli_ini, $cini);
            }
            $optimized[] = 'PHP-FPM + OPCache';
        }
        
        $mconf_skip = false;
        $mconf_file = '';
        if (($target === 'mysql' || $target === 'all') && is_mysql_available()) {
            $mconf_file = '/etc/mysql/mariadb.conf.d/50-server.cnf';
            if (!file_exists($mconf_file)) $mconf_file = is_alpine() ? '/etc/my.cnf' : '/etc/mysql/my.cnf';
            if (!file_exists($mconf_file)) { $optimized[] = 'MySQL（未找到配置文件，跳过）'; $mconf_skip = true; }
        }
        if (($target === 'mysql' || $target === 'all') && (!$mconf_skip && $mconf_file !== '')) {
            copy($mconf_file, "$backup_dir/" . basename($mconf_file) . '.bak');
            $mconf = file_get_contents($mconf_file);
            $innodb_bp = $ram_mb >= 4096 ? '2048M' : ($ram_mb >= 2048 ? '1024M' : ($ram_mb >= 1024 ? '256M' : '128M'));
            $max_conn = $ram_mb >= 2048 ? 150 : ($ram_mb >= 1024 ? 80 : 40);
            $tuning = "\n# === VPS Manager Tuning ===\ninnodb_buffer_pool_size = $innodb_bp\ninnodb_log_file_size = 64M\ninnodb_flush_method = O_DIRECT\ninnodb_flush_log_at_trx_commit = 2\nmax_connections = $max_conn\nquery_cache_type = 0\ntmp_table_size = 32M\nmax_heap_table_size = 32M\ntable_open_cache = 2000\n";
            if (strpos($mconf, 'VPS Manager Tuning') === false) {
                $mconf .= $tuning;
            }
            file_put_contents($mconf_file, $mconf);
            $optimized[] = 'MySQL';
        }
        
        if ($target === 'system' || $target === 'all') {
            // Sysctl - swappiness, file limits
            copy('/etc/sysctl.conf', "$backup_dir/sysctl.conf.bak");
            $sysctl = file_get_contents('/etc/sysctl.conf');
            $sys_tuning = "\n# === VPS Manager Tuning ===\nvm.swappiness = 10\nvm.vfs_cache_pressure = 50\nnet.core.somaxconn = 1024\nnet.ipv4.tcp_fastopen = 3\nfs.file-max = 65535\n";
            if (strpos($sysctl, 'VPS Manager Tuning') === false) {
                $sysctl .= $sys_tuning;
            }
            file_put_contents('/etc/sysctl.conf', $sysctl);
            cmd('sysctl -p 2>&1');
            // Limits
            $limits = "/etc/security/limits.conf";
            copy($limits, "$backup_dir/limits.conf.bak");
            $lim = file_get_contents($limits);
            $_wu = web_user(); if (strpos($lim, "$_wu soft nofile 65535") === false) {
                $lim .= "\n$_wu soft nofile 65535\n$_wu hard nofile 65535\n";
                file_put_contents($limits, $lim);
            }
            $optimized[] = 'System Kernel + Limits';
        }
        
        // Reload services
        cmd('nginx -t 2>&1' . (is_alpine() ? ' && rc-service nginx reload 2>&1' : ' && systemctl reload nginx 2>&1'));
        svc_restart(php_fpm_svc());
        if (is_mysql_available()) svc_restart('mariadb');
        
        if (empty($optimized)) { flash('❌ 选择 target optimasi!', 'err'); redirect('optimize'); }
        flash('✅ Optimized: ' . implode(', ', $optimized) . '!<br><small>备份已保存于 ' . $backup_dir . '</small>');
        redirect('optimize');
    }

    // --- SERVICE ACTION ---
    if ($act === 'svc_action') {
        $svc = $_POST['svc'] ?? '';
        $action = $_POST['svc_action'] ?? '';
        $map = ['nginx' => 'nginx', 'php' => php_fpm_svc(), 'mysql' => 'mariadb'];
        if (!isset($map[$svc]) || !in_array($action, ['start', 'stop', 'restart', 'reload'])) redirect('services');
        $real = $map[$svc];
        if (in_array($action, ['start', 'stop', 'restart', 'reload'])) {
            cmd(is_alpine() ? "rc-service $real $action" : "systemctl $action $real");
            $st = is_alpine() ? cmd("rc-service $real status 2>/dev/null") : cmd("systemctl is-active $real 2>/dev/null");
            $ok2 = ($action === 'stop') ? stripos(trim($st), 'active') === false : stripos(trim($st), 'active') !== false || stripos(trim($st), 'started') !== false;
            flash($ok2 ? "✅ $svc: $action 执行成功！" : "⚠ $svc: $action 已下发，但当前状态异常（" . sanitize(trim($st)) . "）", $ok2 ? 'ok' : 'err'); redirect('services');
        }
    }

    // --- DELETE BACKUP ---
    if ($act === 'delete_backup') {
        $f = $_POST['file'] ?? '';
        $fp = BACKUP_DIR . '/' . basename($f);
        if (file_exists($fp)) { unlink($fp); flash('✅ Backup 删除!'); }
        redirect('backups');
    }

    // --- FILE UPLOAD ---
    if ($act === 'upload_file') {
        $up_dir = $_POST['up_dir'] ?? '';
        $upload_dir = resolve_existing_under_root(WWW_ROOT . '/' . ltrim($up_dir, '/'), WWW_ROOT);
        if ($upload_dir && str_starts_with($upload_dir . '/', '/var/www/manager/')) { flash('❌ 不能上传到面板目录', 'err'); redirect('files'); }
        if (!$upload_dir) $upload_dir = canonical_root(WWW_ROOT);
        if (!empty($_FILES['upfile']['tmp_name']) && $_FILES['upfile']['error'] === UPLOAD_ERR_OK) {
            $name = preg_replace('/[^a-zA-Z0-9._-]/', '_', $_FILES['upfile']['name']);
            if (str_contains($name, '..') || $name === '' ) { flash('❌ 文件名非法', 'err'); redirect('files'); }
            $lower = strtolower($name);
            foreach (['.php','.php3','.php4','.php5','.php7','.php8','.phtml','.phar','.phps','.phpz','.pht','.cgi','.pl','.sh','.py','.htaccess','.htpasswd','.user.ini','.ini','.bashrc','.profile'] as $de) {
                if (str_ends_with($lower, $de)) { flash('❌ 禁止上传可执行脚本文件', 'err'); redirect('files'); }
            }
            if (preg_match('/\.(php|phtml|phar|cgi|pl|sh)\.[a-z0-9]+$/i', $lower)) { flash('❌ 禁止双扩展名脚本文件', 'err'); redirect('files'); }
            $dest = $upload_dir . '/' . $name;
            if (move_uploaded_file($_FILES['upfile']['tmp_name'], $dest)) {
                chown($dest, web_user()); chgrp($dest, web_user());
                flash("✅ 文件 <b>$name</b> 上传成功！");
            } else { flash('❌ 文件上传失败！', 'err'); }
        } else { flash('❌ 请先选择文件！', 'err'); }
        $d = urlencode($up_dir); redirect("files&dir=$d");
    }

    // --- NEW FOLDER ---
    if ($act === 'new_folder') {
        $fd = $_POST['fd_dir'] ?? '';
        $target_dir = resolve_existing_under_root(WWW_ROOT . '/' . ltrim($fd, '/'), WWW_ROOT);
        if ($target_dir && str_starts_with($target_dir . '/', '/var/www/manager/')) { flash('❌ 不能在面板目录创建', 'err'); redirect('files'); }
        if (!$target_dir) $target_dir = canonical_root(WWW_ROOT);
        $name = trim(preg_replace('/[^a-zA-Z0-9_\-\.]/', '', $_POST['fname'] ?? ''));
        if ($name) {
            $new = $target_dir . '/' . $name;
            if (!file_exists($new)) { mkdir($new, 0755); chown($new, web_user()); chgrp($new, web_user()); flash("✅ Folder <b>$name</b> dibuat!"); }
            else { flash('❌ Folder 已存在!', 'err'); }
        }
        $d = urlencode($fd); redirect("files&dir=$d");
    }

    // --- DELETE FOLDER ---
    if ($act === 'delete_folder') {
        $fd = $_POST['fd_dir'] ?? '';
        $target_dir = resolve_existing_under_root(WWW_ROOT . '/' . ltrim($fd, '/'), WWW_ROOT);
        if ($target_dir && str_starts_with($target_dir . '/', '/var/www/manager/')) { flash('❌ 不能在面板目录创建', 'err'); redirect('files'); }
        if (!$target_dir) $target_dir = canonical_root(WWW_ROOT);
        $fname = $_POST['fname'] ?? '';
        $fp = $target_dir . '/' . basename($fname);
        if (is_dir($fp) && strpos(realpath($fp), realpath(WWW_ROOT)) === 0
            && strpos(realpath($fp), '/var/www/manager') !== 0) { // FIX-06：面板目录及其子目录不可删
            $empty = count(scandir($fp)) <= 2;
            if ($empty) { rmdir($fp); flash("✅ Folder 删除!"); }
            else { flash('❌ 目录非空！', 'err'); }
        } else { flash('❌ 无法 menghapus!', 'err'); }
        $d = urlencode($fd); redirect("files&dir=$d");
    }

    // --- ADD REDIRECT ---
    // --- PANEL SELF HTTPS (self-signed) ---
    if ($act === 'panel_https_toggle') {
        $mode = in_array($_POST['pmode'] ?? '', ['on','redirect','off'], true) ? $_POST['pmode'] : 'off';
        $panel_conf = is_alpine() ? '/etc/nginx/http.d/vps-manager.conf' : (is_rhel() ? '/etc/nginx/conf.d/vps-manager.conf' : '/etc/nginx/sites-available/vps-manager');
        if (!file_exists($panel_conf)) { flash('❌ 未找到面板 nginx 配置', 'err'); redirect('ssl'); }
        $cert_dir = '/etc/nginx/ssl/panel';
        $cert = "$cert_dir/panel.crt"; $key = "$cert_dir/panel.key";
        $proxy = "    location / {\n        proxy_pass http://127.0.0.1:9001;\n        proxy_set_header Host \$host;\n        proxy_set_header X-Real-IP \$remote_addr;\n        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;\n        client_max_body_size 100M;\n    }\n";
        if ($mode !== 'off') {
            if (!is_dir($cert_dir)) mkdir($cert_dir, 0755, true);
            if (!file_exists($cert) || !file_exists($key)) {
                $cn = trim(cmd("hostname -f 2>/dev/null || hostname"));
                // SAN 收集本机所有 IPv4/IPv6，浏览器按 IP 访问时不至于完全失配
                $ips = [];
                foreach (['-4','-6'] as $fam) {
                    foreach (explode("\n", trim((string)cmd("hostname $fam -I 2>/dev/null"))) as $l) {
                        foreach (preg_split('/\s+/', trim($l)) as $ip) {
                            if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) { $ips[$ip] = true; }
                        }
                    }
                }
                $sans = ''; $n = 1;
                foreach (array_keys($ips) as $ip) { $sans .= ($n > 1 ? ',' : '') . "IP:$ip"; $n++; }
                $ext = $sans !== '' ? "-addext \"subjectAltName=$sans\"" : '';
                $r = cmd("openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes " .
                         "-keyout " . escapeshellarg($key) . " -out " . escapeshellarg($cert) . " " .
                         "-subj " . escapeshellarg("/CN=" . ($cn ?: 'vps-manager')) . " $ext 2>&1");
                chmod($key, 0600);
                if (!file_exists($cert)) { flash('❌ 自签证书生成失败: ' . sanitize(substr($r, 0, 200)), 'err'); redirect('ssl'); }
            }
            // 保持「root php -S 9001 + nginx 反代」架构（仅 root 模型，T07b）——HTTPS 只改 listen 层，绝不经 fpm
            $tls = "    ssl_certificate $cert;\n    ssl_certificate_key $key;\n    ssl_protocols TLSv1.2 TLSv1.3;\n";
            if ($mode === 'redirect') {
                $conf = "server {\n    listen 8080;\n    server_name _;\n    return 301 https:\$host:8443\$request_uri;\n}\nserver {\n    listen 8443 ssl;\n    server_name _;\n$tls$proxy}\n";
            } else {
                $conf = "server {\n    listen 8080 ssl;\n    server_name _;\n$tls$proxy}\n";
            }
            $bak = $panel_conf . '.bak.' . time();
            copy($panel_conf, $bak);
            file_put_contents($panel_conf, $conf);
            $test = cmd('nginx -t 2>&1');
            if (strpos($test, 'successful') === false) {
                copy($bak, $panel_conf);
                flash('❌ Nginx 配置错误！已回滚。<br><small>' . sanitize(substr($test, 0, 300)) . '</small>', 'err');
            } else {
                cmd(is_alpine() ? 'rc-service nginx reload' : 'systemctl reload nginx');
                flash($mode === 'redirect'
                    ? '✅ 面板 HTTPS 已开启（8080 → 强制跳转 <b>https://IP:8443</b>）'
                    : '✅ 面板 HTTPS 已开启：<b>https://IP:8080</b>（自签证书，浏览器需信任）');
            }
        } else {
            $conf = "server {\n    listen 8080;\n    server_name _;\n$proxy}\n";
            $bak = $panel_conf . '.bak.' . time();
            copy($panel_conf, $bak);
            file_put_contents($panel_conf, $conf);
            if (strpos(cmd('nginx -t 2>&1'), 'successful') !== false) {
                cmd(is_alpine() ? 'rc-service nginx reload' : 'systemctl reload nginx');
                flash('✅ 已关闭面板 HTTPS，还原 HTTP');
            } else { copy($bak, $panel_conf); flash('❌ Nginx 配置错误！已回滚。', 'err'); }
        }
        redirect('ssl');
    }

    if ($act === 'proxy_add') {
        $domain = trim($_POST['pdomain'] ?? '');
        $upstream = trim($_POST['pupstream'] ?? '');
        $ws = isset($_POST['pws']) && $_POST['pws'] === '1';
        $ssl_on = isset($_POST['pssl']) && $_POST['pssl'] === '1';
        // 替换规则：psearch[]/preplace[] 成对数组，数量不限
        $searches = isset($_POST['psearch']) && is_array($_POST['psearch']) ? $_POST['psearch'] : [];
        $replaces = isset($_POST['preplace']) && is_array($_POST['preplace']) ? $_POST['preplace'] : [];
        if (empty($domain) || empty($upstream)) { flash('域名和上游地址必填！', 'err'); redirect('proxy'); }
        if (!validate_domain($domain)) { flash('域名格式无效！', 'err'); redirect('proxy'); }
        if (!preg_match('#^https?://[a-zA-Z0-9.:/_-]+$#', $upstream)) { flash('上游地址格式无效！须以 http:// 或 https:// 开头', 'err'); redirect('proxy'); }
        // 内容替换（原生 sub_filter）+ 头部清洗
        $subs = '';
        $n = min(count($searches), count($replaces));
        for ($i = 0; $i < $n; $i++) {
            $sr = trim($searches[$i]); $rp = (string)$replaces[$i];
            if ($sr === '') continue;
            if (strlen($sr) > 500 || strlen($rp) > 500) { flash('替换单条内容过长', 'err'); redirect('proxy'); }
            // nginx 配置安全：拒绝引号/分号/换行破坏结构
            if (preg_match('/[\r\n]/', $sr . $rp) || strpos($sr, '"') !== false || strpos($rp, '"') !== false) {
                flash('替换内容不能包含引号或换行', 'err'); redirect('proxy');
            }
            $subs .= "        sub_filter '" . addslashes($sr) . "' '" . addslashes($rp) . "';\n";
        }
        $px_conf = '/etc/nginx/conf.d/panel-proxy-' . $domain . '.conf';
        $proxy_block = "proxy_pass $upstream;\n" .
            "        proxy_set_header Host \$host;\n" .
            "        proxy_set_header X-Real-IP \$remote_addr;\n" .
            "        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;\n" .
            "        proxy_set_header X-Forwarded-Proto \$scheme;\n" .
            "        proxy_http_version 1.1;\n" .
            "        proxy_set_header Upgrade \$http_upgrade;\n" .
            "        proxy_set_header Connection \"upgrade\";\n" .
            "        proxy_read_timeout 300;\n" .
            "        proxy_buffering off;\n" .
            "        sub_filter_once off;\n" .
            "        sub_filter_types text/html text/xml text/css application/javascript application/json;\n";
        if ($subs !== '') {
            $proxy_block = "proxy_set_header Accept-Encoding \"\";\n" . $proxy_block . $subs;
        }
        $server = "server {\n    listen 80;\n    server_name $domain;\n\n" .
            "    location / {\n        " . $proxy_block . "    }\n}\n";
        if ($ssl_on) {
            $cert_dir = '/etc/nginx/ssl/proxy-' . $domain;
            if (!is_dir($cert_dir)) mkdir($cert_dir, 0755, true);
            $c = "$cert_dir/proxy.crt"; $k = "$cert_dir/proxy.key";
            if (!file_exists($c)) {
                cmd("openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes -keyout " . escapeshellarg($k) . " -out " . escapeshellarg($c) . " -subj " . escapeshellarg("/CN=$domain") . " 2>&1");
                chmod($k, 0600);
            }
            $server = str_replace('listen 80;', "listen 80;\n    listen 443 ssl;\n    ssl_certificate $c;\n    ssl_certificate_key $k;\n    ssl_protocols TLSv1.2 TLSv1.3;", $server);
        }
        if ($ws) { /* websocket 头已内置 */ }
        file_put_contents($px_conf, $server);
        $test = cmd('nginx -t 2>&1');
        if (strpos($test, 'successful') === false) {
            @unlink($px_conf);
            flash('❌ Nginx 配置错误！已回滚。<br><small>' . sanitize(substr($test, 0, 300)) . '</small>', 'err');
        } else {
            cmd(is_alpine() ? 'rc-service nginx reload' : 'systemctl reload nginx');
            flash('✅ 反代 <b>' . sanitize($domain) . '</b> → <b>' . sanitize($upstream) . '</b> 已生效！' . ($subs !== '' ? '（含替换规则）' : ''));
        }
        redirect('proxy');
    }

    if ($act === 'proxy_del') {
        $domain = trim($_POST['pdomain'] ?? '');
        if (!preg_match('/^[a-zA-Z0-9.-]+$/', $domain)) redirect('proxy');
        $px_conf = '/etc/nginx/conf.d/panel-proxy-' . $domain . '.conf';
        if (file_exists($px_conf)) {
            @unlink($px_conf);
            $test = cmd('nginx -t 2>&1');
            if (strpos($test, 'successful') !== false) {
                cmd(is_alpine() ? 'rc-service nginx reload' : 'systemctl reload nginx');
                flash('✅ 反代 ' . sanitize($domain) . ' 已删除');
            } else flash('⚠️ 已删除配置但 nginx -t 失败，请检查', 'err');
        }
        redirect('proxy');
    }

    // --- NGINX CONFIG EDITOR ---
    // --- CLEANUP SCAN API ---

    // --- NGINX CONFIG EDITOR ---
    // --- DOCKER MANAGEMENT ---
    // --- PROCESS MANAGER (custom services) ---
    // --- F8: CLOUD BACKUP TARGET (任意 rclone remote:path) ---
    if ($act === 'cloud_target_save') {
        $target = trim($_POST['cbtarget'] ?? '');
        if (!empty($target) && (!preg_match('#^[a-zA-Z0-9_-]+:.+$#', $target) || strlen($target) > 200 || preg_match('/[\r\n"\';&|]/', $target))) { flash('远程路径格式无效（应为 remote:path，如 gdrive:backups）', 'err'); redirect('cloudbackup'); }
        file_put_contents('/var/www/manager/.cloud_target', $target, LOCK_EX);
        // 可选：建每日 cron
        if (isset($_POST['cbdaily']) && $_POST['cbdaily'] === '1' && !empty($target)) {
            $current = cmd('crontab -l', false) ?: '';
            if (strpos($current, 'vpsmgr-cloud-sync') === false) {
                $line = "30 3 * * * rclone copy " . escapeshellarg(BACKUP_DIR) . " '" . addslashes($target) . "' --max-age 48h # vpsmgr-cloud-sync\n";
                $ct = tempnam('/tmp', 'ctab_'); chmod($ct, 0600);
                file_put_contents($ct, $current . $line);
                $ec = 0; cmdv(['crontab', $ct], null, $ec); @unlink($ct);
        if ($ec !== 0) { flash('❌ crontab 安装失败（退出码 ' . $ec . '）', 'err'); redirect('cron'); }
            }
            flash('✅ 远程备份目标已保存，且已添加每日 03:30 自动同步备份目录的定时任务');
        } else flash('✅ 远程备份目标已保存');
        redirect('cloudbackup');
    }

    // --- WEBHOOK NOTIFY SETTINGS ---
    if ($act === 'notify_save') {
        $url = trim($_POST['nurl'] ?? '');
        $events = isset($_POST['nevents']) && is_array($_POST['nevents']) ? $_POST['nevents'] : [];
        if (!empty($url) && !preg_match('#^https?://[a-zA-Z0-9.:/_?=&%-]+$#', $url)) { flash('Webhook URL 格式无效', 'err'); redirect('settings'); }
        if (!empty($url)) {
            if (!assert_public_url($url)) {
                flash('❌ 不允许指向内网/保留地址的 Webhook（SSRF 防护）', 'err'); redirect('settings');
            }
        }
        $valid_events = array_intersect($events, ['disk','cert','service','backup','login_fail']);
        if (!empty($url)) {
            // 测试发送
            $payload = json_encode(['text' => '✅ VPS Manager 通知测试成功']);
            $ctx = stream_context_create(['http' => ['method' => 'POST', 'header' => "Content-Type: application/json\r\n", 'content' => $payload, 'timeout' => 5]]);
            $resp = @file_get_contents($url, false, $ctx);
            flash($resp !== false ? '✅ 通知已保存，测试消息已发送！' : '⚠️ 已保存，但测试发送失败（检查 URL）', $resp !== false ? '' : 'err');
        } else flash('✅ 通知已关闭');
        $cfg = ['url' => $url, 'events' => array_values($valid_events)];
        @mkdir(dirname(NOTIFY_FILE), 0755, true);
        file_put_contents(NOTIFY_FILE, json_encode($cfg), LOCK_EX);
        chmod(NOTIFY_FILE, 0600);
        redirect('settings');
    }

    // --- API TOKEN ---
    if ($act === 'api_token_gen') {
        $token = bin2hex(random_bytes(24));
        file_put_contents(API_TOKEN_FILE, $token, LOCK_EX);
        chmod(API_TOKEN_FILE, 0600);
        flash('🔑 新 API Token 已生成（仅显示一次，请立即保存）：<br><code style="user-select:all">' . $token . '</code>');
        redirect('settings');
    }
    if ($act === 'api_token_revoke') {
        @unlink(API_TOKEN_FILE);
        flash('🗑️ API Token 已吊销');
        redirect('settings');
    }

    // --- F15: CLEANUP ---
    if ($act === 'cleanup_run') {
        $targets = isset($_POST['targets']) && is_array($_POST['targets']) ? $_POST['targets'] : [];
        $map = [
            'aptcache' => is_alpine() ? 'apk cache clean 2>&1; rm -rf /var/cache/apk/* 2>&1' : 'apt-get clean 2>&1; rm -rf /var/cache/apt/archives/*.deb 2>&1',
            'journal' => 'journalctl --vacuum-time=3d 2>&1 || true',
            'varlog' => 'sh -c "find /var/log -name *.gz -delete 2>/dev/null; find /var/log -name *.1 -delete 2>/dev/null; find /var/log -name *.old -delete 2>/dev/null; find /var/log -mtime +7 -name *.log -delete 2>/dev/null" 2>&1',
            'tmp' => 'sh -c "find /tmp -type f -atime +3 -not -name vpsmgr* -delete 2>/dev/null" 2>&1',
            'backups' => 'sh -c "find /var/lib/vps-manager/backups -mtime +30 -type f -delete 2>/dev/null" 2>&1',
        ];
        $done = [];
        foreach ($targets as $t) { if (isset($map[$t])) { cmd($map[$t]); $done[] = $t; } }
        flash('🧹 清理完成：' . sanitize(implode(', ', $done)));
        redirect('optimize');
    }

    if ($act === 'proc_add') {
        $name = preg_replace('/[^a-zA-Z0-9_-]/', '', $_POST['pname'] ?? '');
        $workdir = trim($_POST['pworkdir'] ?? '');
        $command = trim($_POST['pcmd'] ?? '');
        $user = trim($_POST['puser'] ?? 'root');
        if (!preg_match('/^[a-zA-Z0-9_-]{1,40}$/', $name)) { flash('进程名只能字母数字-_', 'err'); redirect('procs'); }
        if (empty($command) || strlen($command) > 500) { flash('启动命令必填（≤500字符）', 'err'); redirect('procs'); }
        if (!empty($workdir) && !is_dir($workdir)) { flash('工作目录不存在', 'err'); redirect('procs'); }
        if (!preg_match('/^[a-zA-Z0-9_.-]{1,32}$/', $user)) { flash('用户名无效', 'err'); redirect('procs'); }
        if (preg_match('/["`$\r\n\0]/', $command)) { flash('启动命令不能包含双引号、反引号、$ 或换行/空字节（OpenRC 兼容限制）；需要请先写成包装脚本', 'err'); redirect('procs'); }
        if (preg_match('/[\r\n\0]/', $workdir)) { flash('工作目录含非法字符', 'err'); redirect('procs'); }
        $prefix = 'vpsmgr-';
        if (is_alpine()) {
            $sp = strpos($command, ' ');
            $bin = $sp === false ? $command : substr($command, 0, $sp);
            $args = $sp === false ? '' : substr($command, $sp + 1);
            $rc = "/etc/init.d/vpsmgr-$name";
            $sv = <<<SV
#!/sbin/openrc-run
name="vpsmgr-$name"
command="$bin"
command_args="$args"
command_user="$user"
command_background="yes"
pidfile="/run/vpsmgr-$name.pid"
directory="$workdir"
output_log="/var/log/vpsmgr-$name.log"
error_log="/var/log/vpsmgr-$name.log"

depend() {
    need net
}
SV;
            file_put_contents($rc, $sv);
            chmod($rc, 0755);
            cmd("rc-update add vpsmgr-$name default 2>&1; rc-service vpsmgr-$name start 2>&1");
        } else {
            $unit = "/etc/systemd/system/vpsmgr-$name.service";
            $wd = !empty($workdir) ? "\nWorkingDirectory=$workdir" : '';
            $unit_content = "[Unit]\nDescription=VPS Manager: $name\nAfter=network.target\n\n[Service]\nType=simple\nUser=$user$wd\nExecStart=$command\nRestart=on-failure\nRestartSec=5\nStandardOutput=append:/var/log/vpsmgr-$name.log\nStandardError=append:/var/log/vpsmgr-$name.log\n\n[Install]\nWantedBy=multi-user.target\n";
            file_put_contents($unit, $unit_content);
            cmd("systemctl daemon-reload 2>&1 && systemctl enable --now vpsmgr-$name 2>&1");
        }
        flash("✅ 进程 <b>$name</b> 已创建并启动（崩溃自动重启）");
        redirect('procs');
    }

    if ($act === 'proc_del') {
        $name = preg_replace('/[^a-zA-Z0-9_-]/', '', $_POST['pname'] ?? '');
        if (!preg_match('/^[a-zA-Z0-9_-]{1,40}$/', $name)) redirect('procs');
        if (is_alpine()) {
            cmd("rc-service vpsmgr-$name stop 2>&1; rc-update del vpsmgr-$name default 2>&1");
            @unlink("/etc/init.d/vpsmgr-$name");
        } else {
            cmd("systemctl stop vpsmgr-$name 2>&1; systemctl disable vpsmgr-$name 2>&1");
            @unlink("/etc/systemd/system/vpsmgr-$name.service");
            cmd("systemctl daemon-reload 2>&1");
        }
        flash("🗑️ 进程 $name 已删除");
        redirect('procs');
    }

    if ($act === 'proc_action') {
        $name = preg_replace('/[^a-zA-Z0-9_-]/', '', $_POST['pname'] ?? '');
        $op = in_array($_POST['pop'] ?? '', ['start','stop','restart'], true) ? $_POST['pop'] : '';
        if (!preg_match('/^[a-zA-Z0-9_-]{1,40}$/', $name) || empty($op)) redirect('procs');
        $svc = "vpsmgr-$name";
        cmd(is_alpine() ? "rc-service $svc $op 2>&1" : "systemctl $op $svc 2>&1");
        flash("✅ $name → $op 指令已下发");
        redirect('procs');
    }

    if ($act === 'docker_ctl') {
        $cid = preg_replace('/[^a-zA-Z0-9._-]/', '', $_POST['cid'] ?? '');
        $op = in_array($_POST['dop'] ?? '', ['start','stop','restart'], true) ? $_POST['dop'] : '';
        if (empty($cid) || empty($op)) redirect('docker');
        if (!is_executable('/usr/bin/docker') && !is_executable('/usr/local/bin/docker')) { flash('❌ Docker 未安装', 'err'); redirect('docker'); }
        $docker = is_executable('/usr/bin/docker') ? '/usr/bin/docker' : '/usr/local/bin/docker';
        $out = cmd($docker . ' ' . $op . ' ' . escapeshellarg($cid) . ' 2>&1');
        flash(strpos($out, 'Error') !== false ? '❌ ' . sanitize(substr($out, 0, 200)) : "✅ 容器 $cid → $op");
        redirect('docker');
    }

    if ($act === 'docker_install') {
        if (($_POST['confirm'] ?? '') !== 'yes') {
            flash('⚠ 安装 Docker 需显式确认（daemon 近似 root 权限，且默认不会自动启动）。', 'err');
            redirect('docker');
        }
        if (is_alpine()) {
            cmd('apk update 2>&1 && apk add docker docker-cli-compose 2>&1');
            // T-33：默认不自动启动 daemon，由管理员手动 rc-service docker start
            flash('✅ Docker 包已安装（未自动启动）。启动请执行：rc-service docker start && rc-update add docker default');
        } else {
            // U08：Debian/Ubuntu 优先发行版包；失败才走 get.docker.com 脚本（确认后下载到私有文件再审阅执行）
            $apt_out = cmd('DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-compose-v2 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-compose-plugin 2>&1 || true');
            if (trim((string)@shell_exec('command -v docker')) === '') {
            $tmp = tempnam('/tmp', 'dk_install_'); chmod($tmp, 0600);
            cmd('curl -fsSL https://get.docker.com -o ' . escapeshellarg($tmp) . ' 2>&1');
            $sha = hash_file('sha256', $tmp);
            $out = cmd('sh ' . escapeshellarg($tmp) . ' 2>&1');
            @unlink($tmp);
            flash('✅ Docker 安装脚本已执行（sha256: ' . substr((string)$sha, 0, 16) . '…，未自动启动服务）。⚠ 残余高风险——推荐 apt install docker.io。');
            } else {
                flash('✅ Docker 已通过发行版包安装（docker.io + docker-compose-v2）');
            }
        }
        redirect('docker');
    }

    // --- 伪静态（Rewrite）一键预设 ---
    if ($act === 'save_rewrite') {
        $cfg_name = preg_replace('/[^a-zA-Z0-9._-]/', '', $_POST['conf_name'] ?? '');
        $preset = $_POST['rw_preset'] ?? 'custom';
        $path = $cfg_name ? NGINX_AVAILABLE . '/' . $cfg_name : '';
        if (!$path || !file_exists($path) || strpos(realpath($path) ?: '', realpath(NGINX_AVAILABLE) ?: '') !== 0) {
            flash('配置文件不存在', 'err'); redirect('websites');
        }
        $presets = [
            'wordpress' => "location / {\n        try_files \$uri \$uri/ /index.php?\$query_string;\n    }",
            'typecho'   => "location / {\n        if (!-e \$request_filename) {\n            rewrite ^(.*)\$ /index.php\$1 last;\n        }\n    }",
            'thinkphp'  => "location / {\n        if (!-e \$request_filename) {\n            rewrite ^(.*)\$ /index.php?s=/\$1 last;\n            break;\n        }\n    }",
            'laravel'   => "location / {\n        try_files \$uri \$uri/ /index.php?\$query_string;\n    }",
            'static'    => "location / {\n        try_files \$uri \$uri/ =404;\n    }",
        ];
        if (!isset($presets[$preset])) { flash('未知伪静态预设', 'err'); redirect('siteconf&cfg=' . urlencode($cfg_name)); }
        $orig = file_get_contents($path);
        // 替换第一个 location / { ... } 块
        // 审计修复：callback 返回值不参与反向引用解析，避免 preset 中 $1 被 preg_replace 当反向引用吞掉
        $new_cfg = preg_replace_callback('/location\s+\/\s*\{(?:[^{}]*|\{[^{}]*\})*\}/s', fn() => $presets[$preset], $orig, 1, $cnt);
        if ($cnt === 0) {
            flash('⚠️ 未能在配置中自动定位 location / 块，请在下方编辑器手动修改', 'err');
            redirect('siteconf&cfg=' . urlencode($cfg_name));
        }
        $bak = $path . '.bak.' . time();
        copy($path, $bak);
        file_put_contents($path, $new_cfg);
        $test = cmd('nginx -t 2>&1');
        if (strpos($test, 'successful') === false) {
            copy($bak, $path); @unlink($bak);
            flash('❌ 伪静态规则校验失败，已自动回滚：<br><small>' . sanitize(substr($test, 0, 300)) . '</small>', 'err');
        } else {
            @unlink($bak);
            if (!priv_reload_nginx()) {
                flash('⚠️ 伪静态规则已保存，但 Nginx 重载失败——请手动执行 systemctl reload nginx', 'err');
            } else {
                flash('✅ 伪静态规则（' . sanitize($preset) . '）已应用并重载 Nginx！');
            }
        }
        redirect('siteconf&cfg=' . urlencode($cfg_name));
    }

    if ($act === 'edit_conf') {
        $name = preg_replace('/[^a-zA-Z0-9._-]/', '', $_POST['conf_name'] ?? '');
        if (empty($name)) redirect('websites');
        $path = NGINX_AVAILABLE . '/' . $name;
        if (!file_exists($path) || strpos(realpath($path), realpath(NGINX_AVAILABLE)) !== 0) { flash('配置不存在', 'err'); redirect('websites'); }
        $content = $_POST['conf_content'] ?? '';
        if (strlen($content) > 200000) { flash('配置过大', 'err'); redirect('websites'); }
        $bak = $path . '.bak.' . time();
        copy($path, $bak);
        file_put_contents($path, $content);
        $test = cmd('nginx -t 2>&1');
        if (strpos($test, 'successful') === false) {
            copy($bak, $path);
            flash('❌ 配置校验失败，已回滚：<br><small>' . sanitize(substr($test, 0, 400)) . '</small>', 'err');
        } else {
            if (!priv_reload_nginx()) {
                flash('⚠️ 配置已保存，但 Nginx 重载失败——请手动执行 systemctl reload nginx', 'err');
            } else {
                flash('✅ <b>' . sanitize($name) . '</b> 配置已保存并重载');
            }
        }
        redirect('websites');
    }

    if ($act === 'add_redirect') {
        $domain = trim($_POST['rdomain'] ?? '');
        $from = trim($_POST['rfrom'] ?? '');
        $to = trim($_POST['rto'] ?? '');
        $type = in_array($_POST['rtype'] ?? '', ['301','302']) ? $_POST['rtype'] : '301';
        // T-15：domain 过 validate_domain；from 仅规范化 URL path；to 仅 http/https URL
        if (!validate_domain($domain)) { flash('域名无效', 'err'); redirect('redirects'); }
        if (empty($from) || empty($to)) { flash('所有字段必填!', 'err'); redirect('redirects'); }
        if (preg_match('/[\r\n{};"\']/', $from) || !str_starts_with($from, '/') || str_contains($from, '..')) { flash('From 路径无效（仅允许以 / 开头的路径）', 'err'); redirect('redirects'); }
        if (!preg_match('#^https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$#', $to) || preg_match('/[\r\n{};"\']/', $to)) { flash('To 必须是 http(s):// URL', 'err'); redirect('redirects'); }
        $conf = '/etc/nginx/conf.d/panel-redirects.conf';
        if (!file_exists($conf)) { file_put_contents($conf, "# VPS Manager Redirects\n"); cmd('chmod 644 ' . $conf); }
        $rule = "\n# $domain | $from -> $to | $type | " . date('Y-m-d H:i') . "\n";
        $rule .= "server {\n    listen 80;\n    server_name $domain;\n";
        if ($from === '/') $rule .= "    return $type $to;\n";
        else $rule .= "    location $from { return $type $to; }\n";
        $rule .= "}\n";
        // T-25 口径：私有临时文件 → nginx -t → 原子替换 → reload → 失败回滚
        $orig = file_get_contents($conf);
        $tmp = tempnam(dirname($conf), 'ngx_rd_'); chmod($tmp, 0600);
        file_put_contents($tmp, $orig . $rule);
        $bak = $conf . '.bak.' . bin2hex(random_bytes(4));
        copy($conf, $bak);
        rename($tmp, $conf);
        $test = cmd('nginx -t 2>&1');
        if (strpos($test, 'successful') === false) {
            copy($bak, $conf); @unlink($bak);
            cmd(is_alpine() ? 'nginx -s reload 2>/dev/null' : 'systemctl reload nginx 2>/dev/null');
            flash('❌ Nginx error: ' . sanitize(substr($test, 0, 250)), 'err');
        } else {
            @unlink($bak);
            cmd(is_alpine() ? 'rc-service nginx reload' : 'systemctl reload nginx');
            flash("✅ Redirect <b>$from → $to</b>  ($type) — <b>$domain</b>！");
        }
        redirect('redirects');
    }

    // --- DELETE REDIRECT ---
    if ($act === 'delete_redirect') {
        $num = intval($_POST['rnum'] ?? -1);
        $conf = '/etc/nginx/conf.d/panel-redirects.conf';
        if ($num >= 0 && file_exists($conf)) {
            $blocks = preg_split('/\n(?=# )/', file_get_contents($conf));
            if (isset($blocks[$num])) {
                unset($blocks[$num]);
                file_put_contents($conf, implode("\n", array_values($blocks)));
                cmd('nginx -t 2>&1 && ' . (is_alpine() ? 'rc-service nginx reload' : 'systemctl reload nginx'));
                flash('✅ Redirect 删除!');
            }
        }
        redirect('redirects');
    }

    // --- PURGE CACHE ---
    if ($act === 'purge_cache') {
        $target = $_POST['ctarget'] ?? 'all';
        $cp = '/var/cache/nginx/';
        $deleted = 0;
        if ($target === 'all') {
            $o = cmd("find $cp -type f -delete 2>&1 && echo OK");
            if (strpos($o, 'OK') !== false) $deleted = 1;
        } else {
            $dm = $_POST['cdomain'] ?? '';
            if ($dm && validate_domain($dm) && is_dir($cp)) {
                // T-24：只清该站点子目录（nginx proxy_cache_path 以 $host 或配置 key 分目录时的实际缓存键哈希目录无法直接映射，
                // 这里按安全语义：仅删除以域名命名的子目录；找不到则提示，绝不清空全局缓存）
                $site_dir = $cp . $dm;
                if (is_dir($site_dir)) {
                    cmd("find " . escapeshellarg($site_dir) . " -type f -delete 2>&1");
                    $deleted = 1;
                } else {
                    // 缓存目录按哈希组织，无按域名子目录——报告不清全局
                    flash('⚠ 该站点缓存以哈希目录组织，无法按域名精确清理。如需全清请使用「清理全部缓存」。', 'err');
                    redirect('cache');
                }
            }
        }
        flash($deleted ? '🧹 Cache 已删除!' : '❌ 无缓存或缓存路径未找到', $deleted ? 'ok' : 'err');
        redirect('cache');
    }

    // --- INSTALL FAIL2BAN ---
    if ($act === 'install_f2b') {
        if (is_alpine()) { cmd('apk update 2>&1'); cmd('apk add fail2ban 2>&1'); }
        else { cmd('DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>&1'); cmd('DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban 2>&1'); }
        $jl = "/etc/fail2ban/jail.local";
        $jc = "[DEFAULT]\nbantime = 3600\nfindtime = 600\nmaxretry = 5\nignoreip = 127.0.0.1/8\n\n[sshd]\nenabled = true\nport = ssh\nlogpath = %(sshd_log)s\nbackend = %(sshd_backend)s\n\n[nginx-http-auth]\nenabled = true\nlogpath = /var/log/nginx/error.log\nmaxretry = 3\n\n[nginx-botsearch]\nenabled = true\nlogpath = /var/log/nginx/access.log\nmaxretry = 2\n\n[phpmyadmin]\nenabled = true\nlogpath = /var/log/nginx/access.log\nmaxretry = 3\n";
        file_put_contents($jl, $jc);
        $fd2 = '/etc/fail2ban/filter.d';
        if (!is_dir($fd2)) mkdir($fd2, 0755, true);
        file_put_contents("$fd2/phpmyadmin.conf", "[Definition]\nfailregex = ^<HOST>.*(GET|POST).*(pma|phpmyadmin|phpMyAdmin).* 403\nignoreregex =\n");
        svc_start_enable('fail2ban');
        flash('✅ Fail2Ban 已安装! Jails: sshd, nginx-http-auth, nginx-botsearch, phpmyadmin');
        redirect('security');
    }

    // --- FAIL2BAN UNBAN ---

    // --- PHP: EXTENSION MANAGER (F16) ---
    if ($act === 'php_ext_toggle') {
        $ver = $_POST['version'] ?? '';
        $ext = $_POST['ext'] ?? '';
        $op  = $_POST['op'] ?? '';
        if (!in_array($ver, ['8.2','8.3','8.4','8.5'], true)) { flash('版本无效', 'err'); redirect('php'); }
        if (!in_array($op, ['install','remove'], true)) { flash('操作无效', 'err'); redirect('php'); }
        $extmap = [
            'opcache' => ['deb' => 'php{V}-opcache',      'apk' => 'php{P}-opcache'],
            'apcu'    => ['deb' => 'php{V}-apcu',         'apk' => 'php{P}-pecl-apcu'],
            'redis'   => ['deb' => 'php{V}-redis',        'apk' => 'php{P}-pecl-redis'],
            'igbinary'=> ['deb' => 'php{V}-igbinary',    'apk' => null],
            'imagick' => ['deb' => 'php{V}-imagick',      'apk' => 'php{P}-pecl-imagick'],
            'memcached'=>['deb' => 'php{V}-memcached',    'apk' => 'php{P}-pecl-memcached'],
            'swoole'  => ['deb' => 'php{V}-swoole',       'apk' => null],
            'xdebug'  => ['deb' => 'php{V}-xdebug',       'apk' => 'php{P}-pecl-xdebug'],
            'ssh2'    => ['deb' => 'php{V}-ssh2',         'apk' => null],
            'zstd'    => ['deb' => 'php{V}-zstd',         'apk' => null],
            'yaml'    => ['deb' => 'php{V}-yaml',         'apk' => null],
            'grpc'    => ['deb' => 'php{V}-grpc',         'apk' => null],
        ];
        if (!isset($extmap[$ext])) { flash('不支持的扩展', 'err'); redirect('php'); }
        $m = $extmap[$ext];
        $alpine = is_alpine();
        if ($alpine) {
            if ($m['apk'] === null) { flash("❌ $ext 在 Alpine 无预编译包（需 pecl 编译，暂不支持）", 'err'); redirect('php'); }
            $pkg = str_replace('{P}', str_replace('.', '', $ver), $m['apk']);
        } else {
            $pkg = str_replace('{V}', $ver, $m['deb']);
        }
        $task_id = 'phpext_' . bin2hex(random_bytes(8));
        $logfile = '/tmp/progress_' . $task_id . '.log';
        file_put_contents($logfile, "🧩 PHP $ver 扩展 $ext -> $op ...\n");
        $fpm_svc = $alpine ? 'php-fpm' . str_replace('.', '', $ver) : 'php' . $ver . '-fpm';
        if ($alpine) {
            $verb = $op === 'install' ? 'apk add' : 'apk del';
            $reload = 'rc-service ' . $fpm_svc . ' restart';
            $pre = $op === 'install' ? 'apk update >> ' : 'true >> ';
        } else {
            $verb = $op === 'install' ? 'apt-get install -y -qq' : 'apt-get remove -y -qq';
            $reload = 'systemctl reload ' . $fpm_svc . ' || systemctl restart ' . $fpm_svc;
            $pre = $op === 'install' ? 'apt-get update -qq >> ' : 'true >> ';
        }
        $cmd = "( " . $pre . " $logfile 2>&1; " .
               "$verb $pkg >> $logfile 2>&1; " .
               "echo '---reload fpm---' >> $logfile; " .
               "$reload >> $logfile 2>&1; " .
               "echo '___COMPLETE___' >> $logfile) > /dev/null 2>&1 &";
        exec($cmd);
        ?><!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><meta http-equiv="refresh" content="2;url=?page=progress&task=<?= $task_id ?>&back=php"><title>正在<?= $op === 'install' ? '安装' : '卸载' ?>扩展...</title></head><body style="font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh">🧩 正在<?= $op === 'install' ? '安装' : '卸载' ?> PHP <?= $ver ?> <?= $ext ?>，请稍候...（2 秒后自动跳转进度页）</body></html><?php
        exit;
    }

    // --- PHP PER-SITE SETTINGS ---
    if ($act === 'php_per_site_save') {
        $dm = $_POST['ps_domain'] ?? '';
        // T-16：域名校验 + 值白名单，只生成允许字段，拒绝换行/注入
        if (!validate_domain($dm)) { flash('域名无效', 'err'); redirect('phpsite'); }
        $sz_re = '/^\d+[KMG]?$/i';
        $up = preg_match($sz_re, $_POST['ps_upload'] ?? '') ? $_POST['ps_upload'] : '20M';
        $post = preg_match($sz_re, $_POST['ps_post'] ?? '') ? $_POST['ps_post'] : '25M';
        $mem = preg_match($sz_re, $_POST['ps_memory'] ?? '') ? $_POST['ps_memory'] : '256M';
        $exec = intval($_POST['ps_exec'] ?? 120);
        $vars = intval($_POST['ps_vars'] ?? 3000);
        $disp = ($_POST['ps_errors'] ?? 'Off') === 'On' ? 'On' : 'Off';
        $settings_file = '/var/www/manager/.site_php.json';
        $all = file_exists($settings_file) ? json_decode(file_get_contents($settings_file), true) : [];
        $all[$dm] = [
            'upload_max_filesize' => $up,
            'post_max_size' => $post,
            'max_execution_time' => $exec,
            'memory_limit' => $mem,
            'display_errors' => $disp,
            'max_input_vars' => $vars,
        ];
        // 原子写设置文件
        $stmp = tempnam(dirname($settings_file), 'sphp_'); chmod($stmp, 0600);
        file_put_contents($stmp, json_encode($all, JSON_PRETTY_PRINT));
        rename($stmp, $settings_file);
        // Apply to site root
        $sites_all = [];
        foreach (glob(NGINX_AVAILABLE . '/*') as $f) {
            $cn = preg_replace('/\.conf$/', '', basename($f)); if ($cn === 'default') continue;
            $cfg = file_get_contents($f);
            preg_match('/server_name\s+([^;]+);/', $cfg, $sn);
            if (strpos($sn[1] ?? '', $dm) !== false) {
                preg_match('/root\s+([^;]+);/', $cfg, $rm);
                $rt = resolve_existing_under_root($rm[1] ?? (WWW_ROOT . '/' . $dm), WWW_ROOT);
                if ($rt === null) break; // 站点目录越界拒绝
                $ini = "upload_max_filesize = {$all[$dm]['upload_max_filesize']}\npost_max_size = {$all[$dm]['post_max_size']}\nmax_execution_time = {$all[$dm]['max_execution_time']}\nmemory_limit = {$all[$dm]['memory_limit']}\ndisplay_errors = {$all[$dm]['display_errors']}\nmax_input_vars = {$all[$dm]['max_input_vars']}\n";
                // 原子写 .user.ini（临时文件 → rename）
                $itmp = $rt . '/.user.ini.tmp.' . bin2hex(random_bytes(4));
                file_put_contents($itmp, $ini);
                chmod($itmp, 0644);
                rename($itmp, "$rt/.user.ini");
                break;
            }
        }
        flash("✅ <b>$dm</b> 的 PHP 设置已保存！重启 PHP-FPM 后生效。");
        redirect('phpsite');
    }

    // --- CACHE PER-SITE ENABLE/DISABLE ---
    if ($act === 'cache_toggle_site') {
        $dm = $_POST['cd_domain'] ?? '';
        if (!preg_match('/^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/', $dm)) { flash('域名格式无效', 'err'); redirect('sites'); }
        $enable = ($_POST['cd_enable'] ?? '0') === '1';
        $cache_conf = '/etc/nginx/conf.d/cache-per-site.conf';
        $bak = $cache_conf . '.bak';
        if (file_exists($cache_conf)) copy($cache_conf, $bak);
        $rules = file_exists($cache_conf) ? file_get_contents($cache_conf) : '';
        // 迁移旧的非法顶层 set/if 片段（nginx 不允许在 http 上下文直接 set/if）
        $rules = preg_replace('/\n?# cache:[^\n]+\n(set \$skip_cache[^\n]+|if \(\$host[^)]*\) \{[^}]*\})\n?/s', "\n", $rules);
        if ($enable) {
            if (strpos($rules, "# cache:$dm") === false) {
                $rules .= "\n# cache:$dm\nmap \$host \$skip_cache_$dm { default 1; $dm 0; }\n";
            }
        } else {
            $rules = preg_replace('/\n# cache:' . preg_quote($dm, '/') . '\nmap \\$host \\$skip_cache_' . preg_quote($dm, '/') . ' \{[^}]*\}\n?/s', "\n", $rules);
        }
        file_put_contents($cache_conf, $rules);
        $nt = cmd('nginx -t 2>&1');
        if (strpos($nt, 'successful') === false) {
            if (file_exists($bak)) copy($bak, $cache_conf); else @unlink($cache_conf);
            cmd('nginx -t 2>&1');
            flash('❌ 缓存配置校验失败已回滚', 'err'); redirect('cache');
        }
        if (!priv_reload_nginx()) { flash('⚠️ 缓存配置已保存，但 Nginx 重载失败——请手动 reload', 'err'); }
        else { flash("✅ Cache " . ($enable ? '启用' : '停用') . " — <b>$dm</b>！"); }
        redirect('cache');
    }

    // --- CLOUD BACKUP ---
    if ($act === 'cloud_backup') {
        $dm = $_POST['cb_domain'] ?? '';
        if (empty($dm) || !preg_match('/^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/', $dm)) { flash('域名格式无效', 'err'); redirect('cloudbackup'); }
        $ts = date('Ymd_His');
        $bf = BACKUP_DIR . "/{$dm}_$ts.zip";
        if (!is_dir(BACKUP_DIR)) { flash('❌ 备份目录不可用（ensure_dirs 失败）', 'err'); redirect('backups'); } // U09：mkdir 统一由 ensure_dirs 兜底
        $root = WWW_ROOT . '/' . $dm;
        $exclude = is_dir("$root/uploads") ? '-x ' . escapeshellarg($root . '/uploads/*') : '';
        cmd("cd " . escapeshellarg(dirname($root)) . " && zip -rq " . escapeshellarg($bf) . " " . escapeshellarg(basename($root)) . " $exclude 2>&1");
        if (file_exists($bf)) @chmod($bf, 0600);
        $sz = file_exists($bf) ? round(filesize($bf) / 1024, 1) : 0;
        // Try rclone sync if configured (prefer mega, then gdrive, then first remote)
        $rclone_msg = '';
        $rclone = is_executable('/usr/bin/rclone');
        $rclone_remotes = $rclone ? trim(cmd('rclone listremotes 2>/dev/null')) : '';
        if ($rclone && $rclone_remotes) {
            $rlist = array_map('trim', explode("\n", trim($rclone_remotes)));
            // Priority: mega first
            $remote = in_array('mega:', $rlist) ? 'mega:' : (in_array('gdrive:', $rlist) ? 'gdrive:' : $rlist[0]);
            if ($remote) {
                $sync = cmd("rclone copy " . escapeshellarg($bf) . " " . escapeshellarg($remote . 'vps-backups/') . " 2>&1");
                $rclone_msg = " + Synced ke cloud: $remote";
            }
        }
        flash("✅ Backup {$sz}KB — <b>$dm</b> 完成！$rclone_msg"); redirect('cloudbackup');
    }

    // --- INSTALL RCLONE ---
    if ($act === 'install_rclone') {
        // T-33：禁止"下载即执行"。优先使用发行版包管理器（可审计、可升级）；管道安装需显式二次确认
        if (($_POST['confirm'] ?? '') !== 'yes') {
            flash('⚠ 远程脚本安装有供应链风险。请在安装按钮勾选确认后再执行（推荐改用发行版包：apt/apk install rclone）。', 'err');
            redirect('cloudbackup');
        }
        // T04：优先发行版包
        $rc_bin = trim((string)@shell_exec('command -v rclone'));
        if ($rc_bin === '') {
            if (is_alpine()) { cmd('apk add rclone 2>&1'); }
            else { cmd('apt-get update 2>&1 && apt-get install -y rclone 2>&1'); }
            $rc_bin = trim((string)@shell_exec('command -v rclone'));
        }
        if ($rc_bin !== '') { flash('✅ Rclone 已安装（发行版包）。'); redirect('cloudbackup'); }
        $tmp = tempnam('/tmp', 'rc_install_'); chmod($tmp, 0600);
        cmd('curl -fsSL ' . escapeshellarg('https://rclone.org/install.sh') . ' -o ' . escapeshellarg($tmp) . ' 2>&1');
        $sha = hash_file('sha256', $tmp);
        $out = cmd('bash ' . escapeshellarg($tmp) . ' 2>&1');
        @unlink($tmp);
        mkdir('/root/.config/rclone', 0700, true);
        flash('✅ Rclone 安装脚本已执行（sha256: ' . substr((string)$sha, 0, 16) . '…）。⚠ 这是残余高风险操作——建议改用发行版包。');
        redirect('cloudbackup');
    }

    // --- RCLONE GDRIVE SETUP STEP 1: Get auth URL ---
    if ($act === 'rclone_gdrive_step1') {
        $cid = trim($_POST['gdrive_cid'] ?? '');
        $csec = trim($_POST['gdrive_csec'] ?? '');
        if (empty($cid) || empty($csec)) { flash('❌ Client ID & Secret 必填!', 'err'); redirect('cloudbackup'); }
        // 审计修复：cid/csec 白名单（rclone.conf 注入面，FIX-03）
        if (!preg_match('/^[A-Za-z0-9._-]{1,256}$/', $cid) || !preg_match('/^[A-Za-z0-9._-]{1,256}$/', $csec)) { flash('❌ Client ID / Secret 含非法字符', 'err'); redirect('cloudbackup'); }
        $_SESSION['rclone_cid'] = $cid;
        $_SESSION['rclone_csec'] = $csec;
        // Generate auth URL - rclone outputs the URL then waits for token
        $ec = 0;
        $out = cmdv(['timeout','3','rclone','authorize','drive',$cid,$csec,'--auth-no-open-browser'], '', $ec);
        preg_match('/(https:\/\/accounts\.google\.com\/o\/oauth2\/auth[^\s]+)/', $out, $m);
        $_SESSION['rclone_auth_url'] = $m[1] ?? '';
        if (empty($_SESSION['rclone_auth_url'])) {
            // Try alternative parsing
            preg_match('/(https:\/\/[^\s]+accounts\.google\.com[^\s]+)/', $out, $m2);
            $_SESSION['rclone_auth_url'] = $m2[1] ?? '';
        }
        flash('🔗 授权链接已生成！请按后续步骤操作。');
        redirect('cloudbackup');
    }

    // --- RCLONE GDRIVE SETUP STEP 2: Exchange token ---
    if ($act === 'rclone_gdrive_step2') {
        $code = trim($_POST['gdrive_code'] ?? '');
        $cid = $_SESSION['rclone_cid'] ?? '';
        $csec = $_SESSION['rclone_csec'] ?? '';
        if (empty($code) || empty($cid)) { flash('❌ Verification code 必填!', 'err'); redirect('cloudbackup'); }
        if (!preg_match('/^[A-Za-z0-9._-]{1,256}$/', $cid) || !preg_match('/^[A-Za-z0-9._-]{1,256}$/', $csec)) { flash('❌ Client ID / Secret 非法', 'err'); redirect('cloudbackup'); }
        // Exchange code for token via rclone
        $ec = 0;
        $out = cmdv(['rclone','authorize','drive',$cid,$csec,'--auth-no-open-browser'], $code, $ec);
        // Parse the token JSON from rclone output
        preg_match('/\{[^{]*"access_token"[^}]+\}/s', $out, $tm);
        $token_json = $tm[0] ?? '';
        if (empty($token_json)) {
            // Try broader match
            preg_match('/\{.*?"access_token".*?\}/s', $out, $tm2);
            $token_json = $tm2[0] ?? '';
        }
        if (empty($token_json)) {
            flash('❌ 失败 exchange token!<br><small>' . sanitize(substr($out, 0, 300)) . '</small>', 'err');
            redirect('cloudbackup');
        }
        if (!is_array(json_decode($token_json, true))) { flash('❌ Token JSON 解析失败', 'err'); redirect('cloudbackup'); } // FIX-03
        // Create rclone config
        $rclone_conf = "/root/.config/rclone/rclone.conf";
        if (!is_dir(dirname($rclone_conf))) mkdir(dirname($rclone_conf), 0700, true);
        $conf = "[gdrive]\ntype = drive\nscope = drive\nclient_id = $cid\nclient_secret = $csec\ntoken = " . addslashes($token_json) . "\n";
        file_put_contents($rclone_conf, $conf);
        chmod($rclone_conf, 0600);
        // Test connection
        $test = trim(cmd('rclone about gdrive: 2>&1'));
        if (strpos($test, 'Used:') !== false || strpos($test, 'Total:') !== false) {
            flash('✅ Google Drive 连接成功! 🎉<br><small>' . sanitize(substr($test, 0, 200)) . '</small>');
        } else {
            flash('⚠️ Config 已保存, 但连接测试失败: <small>' . sanitize(substr($test, 0, 200)) . '</small>');
        }
        unset($_SESSION['rclone_cid'], $_SESSION['rclone_csec'], $_SESSION['rclone_auth_url']);
        redirect('cloudbackup');
    }

    // --- RCLONE MEGA CONNECT ---
    if ($act === 'rclone_mega_connect') {
        $email = trim($_POST['mega_email'] ?? '');
        $pass = $_POST['mega_pass'] ?? '';
        if (empty($email) || empty($pass)) { flash('❌ Email & password 必填!', 'err'); redirect('cloudbackup'); }
        $rconf = '/root/.config/rclone/rclone.conf';
        if (!is_dir(dirname($rconf))) mkdir(dirname($rconf), 0700, true);
        $out = cmd('rclone config create mega mega user=' . escapeshellarg($email) . ' pass=' . escapeshellarg($pass) . ' 2>&1');
        if (strpos($out, 'Already have') !== false || strpos($out, 'Storage') !== false || strpos($out, 'Used') !== false) {
            $about = trim(cmd('rclone about mega: 2>&1'));
            flash('✅ Mega.nz 连接成功! 🎉<br><small>' . sanitize(substr($about, 0, 200)) . '</small>');
        } else {
            flash('❌ 失败 konek Mega: <small>' . sanitize(substr($out, 0, 300)) . '</small>', 'err');
        }
        redirect('cloudbackup');
    }

    // --- RCLONE REMOVE REMOTE ---
    if ($act === 'rclone_remove') {
        $remote = trim($_POST['rr_remote'] ?? '');
        if ($remote) {
            $conf = "/root/.config/rclone/rclone.conf";
            if (file_exists($conf)) {
                $c = file_get_contents($conf);
                // Remove the [remote] section
                $c = preg_replace('/\[' . preg_quote(rtrim($remote, ':'), '/') . '\].*?(?=\[|$)/s', '', $c);
                file_put_contents($conf, trim($c) . "\n");
                flash("✅ Remote <b>$remote</b> 删除!");
            }
        }
        redirect('cloudbackup');
    }

    // --- DNS: ADD RECORD ---
    if ($act === 'dns_add') {
        $zone = trim($_POST['d_zone'] ?? '');
        $name = trim($_POST['d_name'] ?? '');
        $type = strtoupper(trim($_POST['d_type'] ?? 'A'));
        $content = trim($_POST['d_content'] ?? '');
        $ttl = intval($_POST['d_ttl'] ?? 120);
        $token = trim($_POST['d_token'] ?? '');
        // FIX-05：Token 先处理——校验格式（无 \r\n"'\0，长度 ≤200）并 0600 落盘；仅设 Token 的表单允许 zone 为空
        if ($token !== '') {
            if (strlen($token) > 200 || preg_match('/[\r\n"\'\0]/', $token)) { flash('❌ Token 格式无效', 'err'); redirect('dns'); }
            @mkdir(dirname('/var/www/manager/.cf_token'), 0700, true);
            file_put_contents('/var/www/manager/.cf_token', $token);
            @chmod('/var/www/manager/.cf_token', 0600);
        } else {
            $token = cf_token_load();
        }
        if ($zone === '') { flash('✅ Cloudflare API Token 已保存！'); redirect('dns'); }
        if (!validate_domain($zone)) { flash('Zone 域名无效', 'err'); redirect('dns'); }
        if (empty($name) || empty($content)) { flash('记录字段必填！', 'err'); redirect('dns'); }
        if (!$token) { flash('❌ 需要 Cloudflare API Token！', 'err'); redirect('dns'); }
        // Get zone ID
        $ch = curl_init("https://api.cloudflare.com/client/v4/zones?name=" . urlencode($zone));
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => ["Authorization: Bearer $token", 'Content-Type: application/json']]);
        $resp = json_decode(curl_exec($ch), true);
        curl_close($ch);
        $zone_id = $resp['result'][0]['id'] ?? '';
        if (!$zone_id) { flash('❌ 未找到 Zone！请检查域名与 Token。', 'err'); redirect('dns'); }
        // Create record
        $ch = curl_init("https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records");
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => ["Authorization: Bearer $token", 'Content-Type: application/json'],
            CURLOPT_POSTFIELDS => json_encode(['type' => $type, 'name' => $name, 'content' => $content, 'ttl' => $ttl, 'proxied' => false])
        ]);
        $resp2 = json_decode(curl_exec($ch), true);
        curl_close($ch);
        if ($resp2['success'] ?? false) flash("✅ DNS record <b>$name $type $content</b> 添加!");
        else flash('❌ 失败: ' . ($resp2['errors'][0]['message'] ?? 'Unknown'), 'err');
        redirect('dns');
    }

    // --- DNS: DELETE RECORD ---
    if ($act === 'dns_del') {
        $zone = trim($_POST['d_zone'] ?? '');
        if (!validate_domain($zone)) { flash('Zone 域名无效', 'err'); redirect('dns'); }
        $rec_id = trim($_POST['d_recid'] ?? '');
        $token = cf_token_load();
        if (!$token || !$zone || !$rec_id) { flash('Invalid!', 'err'); redirect('dns'); }
        $ch = curl_init("https://api.cloudflare.com/client/v4/zones?name=" . urlencode($zone));
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => ["Authorization: Bearer $token", 'Content-Type: application/json']]);
        $resp = json_decode(curl_exec($ch), true);
        curl_close($ch);
        $zone_id = $resp['result'][0]['id'] ?? '';
        if (!$zone_id) { flash('未找到 Zone！', 'err'); redirect('dns'); }
        $ch = curl_init("https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$rec_id");
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_CUSTOMREQUEST => 'DELETE', CURLOPT_HTTPHEADER => ["Authorization: Bearer $token"]]);
        $resp2 = json_decode(curl_exec($ch), true);
        curl_close($ch);
        flash(($resp2['success'] ?? false) ? '✅ DNS record 删除!' : ('❌ ' . ($resp2['errors'][0]['message'] ?? 'Error')));
        redirect('dns');
    }

    if ($act === 'unban_ip') {
        $ip = trim($_POST['uip'] ?? '');
        $jail = trim($_POST['ujail'] ?? '');
        if ($ip && preg_match('/^\d{1,3}(\.\d{1,3}){3}$/', $ip) && preg_match('/^[a-zA-Z0-9_-]+$/', $jail)) {
            cmd("fail2ban-client set " . escapeshellarg($jail) . " unbanip " . escapeshellarg($ip) . " 2>&1");
            flash("✅ IP <b>$ip</b> 已从 <b>$jail</b> 解封");
        } else { flash('❌ 请填写 IP 和 jail！', 'err'); }
        redirect('security');
    }

    // --- UPTIME CHECK NOW ---
    if ($act === 'uptime_check') {
        // We need $sites from later in the file, but the POST handler runs before that
        // Re-gather sites here
        $_sites = [];
        foreach (glob(NGINX_AVAILABLE . '/*') as $f) {
            $cn = preg_replace('/\.conf$/', '', basename($f)); if ($cn === 'default' || strpos($cn, '.bak.') !== false) continue;
            $cfg = @file_get_contents($f) ?: '';
            if (strpos($cfg, 'server {') === false) continue;
            preg_match('/server_name\s+([^;]+);/', $cfg, $sn);
            $dms = preg_split('/\s+/', trim($sn[1] ?? ''));
            $dm = $dms[0] ?? '';
            if ($dm === '' || $dm === '_' || strpos($dm, '.') === false || strpos($cfg, 'proxy_pass http://127.0.0.1:9001') !== false) continue;
            $_sites[$dm] = ['domain' => $dm, 'ssl' => strpos($cfg, 'ssl_certificate') !== false];
        }
        $up = 0; $total = count($_sites);
        foreach ($_sites as $dm => $s) {
            $url = ($s['ssl'] ? 'https' : 'http') . '://' . $dm;
            $ch = curl_init($url);
            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 8, CURLOPT_NOBODY => true, CURLOPT_FOLLOWLOCATION => false, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2]);
            curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($code > 0 && $code < 500) $up++;
            @mkdir(dirname(UPTIME_LOG), 0700, true);
        file_put_contents(UPTIME_LOG, date('Y-m-d H:i:s') . "|$dm|$code\n", FILE_APPEND);
        }
        flash("✅ Check 完成: <b>$up/$total</b> sites UP");
        redirect('uptime');
    }

    // --- UPTIME CLEAR LOG ---
    if ($act === 'clear_uptime') {
        file_put_contents(UPTIME_LOG, '');
        flash('✅ Log uptime direset!');
        redirect('uptime');
    }



    // --- MIGRATION: CREATE FULL BACKUP ---
    $act = $_POST['action'] ?? '';
    if ($act === 'migration_backup') {
        $include_ssl = isset($_POST['include_ssl']) && $_POST['include_ssl'] === '1';
        $ts = date('Ymd_His');
        $hostname = preg_replace('/[^A-Za-z0-9._-]/', '-', trim(cmd('hostname')));
        $bfname = "migration-VPS-{$hostname}-{$ts}";
        $migdir = MIGRATION_DIR;
        if (!is_dir($migdir)) @mkdir($migdir, 0700, true);
        
        $task_id = 'migbackup_' . bin2hex(random_bytes(8));
        $logfile = '/tmp/progress_' . $task_id . '.log';
        $tmpdir = '/tmp/' . $bfname;
        mkdir($tmpdir, 0755, true);
        mkdir("$tmpdir/www", 0755, true);
        mkdir("$tmpdir/nginx", 0755, true);
        mkdir("$tmpdir/panel", 0755, true);
        mkdir("$tmpdir/ssl", 0755, true);
        
        file_put_contents($logfile, "Memulai System Migration Backup...\nHostname: $hostname\nTanggal: " . date('Y-m-d H:i:s') . "\n");
        
        $cmd = "(";
        // 1. System info
        $cmd .= "echo '📊 正在收集系统信息...' >> $logfile; ";
        $sysinfo = [];
        $sysinfo['hostname'] = trim(cmd('hostname'));
        $sysinfo['date'] = date('Y-m-d H:i:s');
        $sysinfo['panel_version'] = '1.0';
        $sysinfo['os'] = trim(cmd("lsb_release -d 2>/dev/null | cut -f2") ?: cmd("cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'"));
        $sysinfo['kernel'] = trim(cmd('uname -r'));
        $sysinfo['cpu'] = trim(cmd("grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2"));
        $sysinfo['memory'] = trim(cmd("free -m | grep '^Mem:' | awk '{print \$2}'"));
        $sysinfo['disk_total'] = disk_total();
        $sysinfo['disk_free'] = disk_free();
        $sysinfo['php_version'] = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
        file_put_contents("$tmpdir/system_info.json", json_encode($sysinfo, JSON_PRETTY_PRINT));
        $cmd .= "echo '✅ System info collected' >> $logfile; ";
        
        // 2. MySQL dump --all-databases
        $cmd .= "echo '🗄️ Dumping semua database MySQL...' >> $logfile; ";
        $cmd .= mysqldump_cli("--all-databases --events --routines --triggers") . " > $tmpdir/all_databases.sql 2>> $logfile; ";
        $cmd .= "echo '✅ Database dump 完成' >> $logfile; ";
        
        // 3. Website files (exclude manager)
        $cmd .= "echo '🌐 Menyalin website files...' >> $logfile; ";
        $www_dirs = glob('/var/www/*');
        if (is_array($www_dirs)) {
            foreach ($www_dirs as $d) {
                if (!is_dir($d)) continue;
                $bn = basename($d);
                if ($bn === 'manager') continue;
                $cmd .= "cp -a " . escapeshellarg($d) . " $tmpdir/www/ >> $logfile 2>&1; ";
            }
        }
        $cmd .= "echo '✅ Website files 复制' >> $logfile; ";
        
        // 4. Nginx configs
        $cmd .= "echo '🔧 Menyalin Nginx configs...' >> $logfile; ";
        $cmd .= "cp -a /etc/nginx/sites-available/* $tmpdir/nginx/ 2>/dev/null; ";
        $cmd .= "cp -a /etc/nginx/nginx.conf $tmpdir/nginx/ 2>/dev/null; ";
        $cmd .= "[ -d /etc/nginx/conf.d ] && cp -a /etc/nginx/conf.d $tmpdir/nginx/conf.d 2>/dev/null; ";
        $cmd .= "echo '✅ Nginx configs 复制' >> $logfile; ";
        
        // 5. Panel settings
        $cmd .= "echo '⚙️ Menyalin panel settings...' >> $logfile; ";
        // T11：.users 旧格式——不进迁移包（panel.db 已含用户库）
        // T11/T15：.passwd 旧格式机密——不进迁移包（panel.db 已含用户库）
        $cmd .= "cp /var/www/manager/.site_php.json $tmpdir/panel/ 2>/dev/null; ";
        $cmd .= "cp " . DB_FILE . " $tmpdir/panel/panel.db 2>/dev/null; ";
        // T11/T20：.notify.json 含 webhook URL（机密），不进迁移包
        // $cmd .= "cp /var/www/manager/.notify.json $tmpdir/panel/ 2>/dev/null; ";
        // T11/T15：.api_token 机密——不进迁移包
        // $cmd .= "cp /var/www/manager/.api_token $tmpdir/panel/ 2>/dev/null; ";
        $cmd .= "cp /var/www/manager/.cloud_target $tmpdir/panel/ 2>/dev/null; ";
        // T11/U03：.cf_token 机密——不进迁移包
        // $cmd .= "cp /var/www/manager/.cf_token $tmpdir/panel/ 2>/dev/null; ";
        $cmd .= "true; ";
        $cmd .= "echo '✅ Panel settings 复制' >> $logfile; ";
        
        // 6. SSL certificates (optional)
        if ($include_ssl) {
            $cmd .= "echo '🔒 正在复制 SSL 证书（可能较慢）...' >> $logfile; ";
            $cmd .= "[ -d /etc/letsencrypt ] && cp -a /etc/letsencrypt $tmpdir/ssl/letsencrypt 2>> $logfile; ";
            $cmd .= "echo '✅ SSL certificates 复制' >> $logfile; ";
        } else {
            $cmd .= "echo '⏭️ 跳过 SSL 证书（可选）' >> $logfile; ";
        }
        
        // 7. Cron jobs
        $cmd .= "echo '⏰ Menyalin cron jobs...' >> $logfile; ";
        $cmd .= "crontab -l > $tmpdir/crontab.txt 2>/dev/null; ";
        $cmd .= "echo '✅ Cron jobs 复制' >> $logfile; ";
        
        // 8. UFW rules
        $cmd .= "echo '🛡 Menyalin UFW rules...' >> $logfile; ";
        $cmd .= "ufw status numbered > $tmpdir/ufw_rules.txt 2>/dev/null; ";
        $cmd .= "echo '✅ UFW rules 复制' >> $logfile; ";
        
        // 9. PHP versions info
        $cmd .= "echo '🐘 正在收集 PHP 版本信息...' >> $logfile; ";
        $phpinfo = [];
        foreach (['8.2','8.3','8.4','8.5'] as $pv) {
            if (!file_exists(php_bin($pv))) continue;
            $fpmok = svc_status(is_alpine() ? 'php-fpm' . str_replace('.', '', $pv) : "php$pv-fpm") ? 'running' : 'stopped';
            $phpinfo[] = ['version' => $pv, 'fpm' => $fpmok, 'path' => php_bin($pv)];
        }
        $default_php = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
        $phpall = ['default' => $default_php, 'versions' => $phpinfo];
        file_put_contents("$tmpdir/php_versions.json", json_encode($phpall, JSON_PRETTY_PRINT));
        $cmd .= "echo '✅ PHP versions info collected' >> $logfile; ";
        
        // 10. Create tar.gz
        $cmd .= "echo '📦 Membuat arsip tar.gz...' >> $logfile; ";
        $tgz = MIGRATION_DIR . '/' . $bfname . '.tar.gz';
        $cmd .= "cd /tmp && tar czf " . escapeshellarg($tgz) . " " . escapeshellarg($bfname) . " 2>> $logfile; ";
$cmd .= "chmod 600 " . escapeshellarg($tgz) . " 2>> $logfile; ";
        $cmd .= "rm -rf " . escapeshellarg($tmpdir) . "; ";
        $cmd .= "echo '___COMPLETE___' >> $logfile; ";
        $cmd .= ") > /dev/null 2>&1 &";
        exec($cmd);
        
        $_SESSION['mig_task_id'] = $task_id;
        $_SESSION['mig_backup_file'] = $bfname . '.tar.gz';
        
        ?><!DOCTYPE html><html lang="id"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>正在创建备份...</title>
        <style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:linear-gradient(160deg,#dfd9cf,#f5f0e8);color:#2d3748;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}.box{background:#fafaf7;padding:44px;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,.1);width:90%;max-width:650px;text-align:center;border-top:4px solid #1e3a5f}.spinner{width:48px;height:48px;border:4px solid #e2ddd5;border-top:4px solid #1e3a5f;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 20px}@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}h2{color:#1a365d;margin-bottom:8px;font-weight:700}pre{background:#fdfcfb;padding:16px;border-radius:8px;text-align:left;max-height:350px;overflow:auto;font-family:monospace;font-size:12px;color:#5a6170;line-height:1.6;margin-top:20px;border:1px solid #e2ddd5}.progress-bar{width:100%;height:10px;background:#e2ddd5;border-radius:99px;overflow:hidden;margin-top:16px}.progress-fill{height:100%;background:linear-gradient(90deg,#1e3a5f,#2c5282);border-radius:99px;width:0%;transition:width .5s}.done{display:none;margin-top:16px}.btn-green2{background:linear-gradient(135deg,#1e3a5f,#2c5282);color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block;box-shadow:0 2px 8px rgba(30,58,95,.25)}.btn-green2:hover{box-shadow:0 4px 14px rgba(30,58,95,.35)}</style></head><body>
        <div class="box"><div class="spinner" id="spinner"></div>
        <h2 id="title">正在创建系统备份...</h2>
        <p style="color:#64748b;font-size:14px">File: <b><?= $bfname ?>.tar.gz</b></p>
        <div class="progress-bar"><div class="progress-fill" id="pfill"></div></div>
        <pre id="log">准备中...</pre>
        <div class="done" id="done"><a href="?page=migration" class="btn-green2">返回 Migration</a></div></div>
        <script>
        var tid='<?= $task_id ?>',check=0,steps=10;
        function poll(){fetch('?progress='+tid).then(r=>r.text()).then(t=>{document.getElementById('log').textContent=t;var done=t.indexOf('___COMPLETE___')>-1;var pct=done?100:Math.min(((t.match(/✅/g)||[]).length/steps)*100,95);document.getElementById('pfill').style.width=pct+'%';if(done){document.getElementById('spinner').style.display='none';document.getElementById('title').textContent='Backup 完成!';document.getElementById('done').style.display='block'}else{check++;document.getElementById('title').textContent='正在创建备份... ('+Math.ceil(check*1.5)+'s)';setTimeout(poll,1500)}})}poll();
        </script></body></html><?php exit;
    }

    // --- MIGRATION: RESTORE ---
    if ($act === 'migration_restore') {
        $restore_ssl = isset($_POST['restore_ssl']) && $_POST['restore_ssl'] === '1';
        $restore_cron = isset($_POST['restore_cron']) && $_POST['restore_cron'] === '1';
        $restore_ufw = isset($_POST['restore_ufw']) && $_POST['restore_ufw'] === '1';
        $restore_panel = isset($_POST['restore_panel']) && $_POST['restore_panel'] === '1';
        
        if (empty($_FILES['migfile']['tmp_name']) || $_FILES['migfile']['error'] !== UPLOAD_ERR_OK) {
            flash('请先上传备份文件！', 'err'); redirect('migration');
        }
        
        $ts = date('Ymd_His');
        // T-31：随机任务 ID（不可预测）、进度日志在私有目录、上传文件 0600
        $task_id = 'migrestore_' . bin2hex(random_bytes(8));
        $workroot = '/tmp/vpsmgr_mig_' . bin2hex(random_bytes(8));
        mkdir($workroot, 0700, true);
        $logfile = '/tmp/progress_' . $task_id . '.log';
        
        $uploaded = $workroot . '/mig.tar.gz';
        if (!move_uploaded_file($_FILES['migfile']['tmp_name'], $uploaded)) { @rmdir($workroot); flash('❌ 保存上传失败', 'err'); redirect('migration'); }
        chmod($uploaded, 0600);
        
        $extract_dir = $workroot . '/extract';
        mkdir($extract_dir, 0700, true);
        
        // 归档安全预检（T-31）：解包后校验所有条目——绝对路径、..、symlink、文件数/体积超限一律拒绝
        exec('tar xzf ' . escapeshellarg($uploaded) . ' -C ' . escapeshellarg($extract_dir) . ' 2>&1', $xo, $xec);
        $bad = false; $total = 0; $total_size = 0;
        if ($xec === 0) {
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($extract_dir, FilesystemIterator::SKIP_DOTS));
            foreach ($it as $f) {
                $total++;
                if ($total > 100000) { $bad = true; break; }
                $total_size += $f->isFile() ? $f->getSize() : 0;
                if ($total_size > 20 * 1024 * 1024 * 1024) { $bad = true; break; }
                if ($f->isLink()) { $bad = true; break; } // 拒绝符号链接（防覆盖任意文件）
                $rp = realpath($f->getPathname());
                if ($rp === false || !str_starts_with($rp, $extract_dir)) { $bad = true; break; }
            }
        }
        if ($xec !== 0 || $bad) {
            shell_exec('rm -rf ' . escapeshellarg($workroot));
            flash('❌ 迁移包校验失败（可能含路径穿越/符号链接/超限），已拒绝', 'err'); redirect('migration');
        }
        // 默认不恢复秘密与全局 Cron：面板设置里的 .api_token/.cf_token/.notify.json/webhook 一律排除
        file_put_contents($logfile, "开始系统迁移恢复...\n" . date('Y-m-d H:i:s') . "\n备份包校验通过，开始恢复...\n");
        
        $cmd = "(";
        // 1. Extract（已完成并校验）
        
        // Find the first subdirectory
        $cmd .= 'BD=$(ls -d ' . escapeshellarg($extract_dir) . '/*/ 2>/dev/null | head -1); ';
        $cmd .= '[ -z "$BD" ] && BD=' . escapeshellarg($extract_dir) . '/; ';
        
        // 2. Check system_info
        $cmd .= "echo '📊 Verifikasi kompatibilitas...' >> $logfile; ";
        $cmd .= 'if [ -f "$BD/system_info.json" ]; then echo "✅ System info 找到" >> ' . escapeshellarg($logfile) . '; else echo "⚠ 没有 system info" >> ' . escapeshellarg($logfile) . '; fi; ';
        
        // 3. Import MySQL
        $cmd .= "echo '🗄 Import database MySQL...' >> $logfile; ";
        $cmd .= 'if [ -f "$BD/all_databases.sql" ]; then ' . mysql_cli('< "$BD/all_databases.sql" 2>> ') . escapeshellarg($logfile) . ' && echo "✅ Database 已导入" >> ' . escapeshellarg($logfile) . ' || echo "⚠ Database import error" >> ' . escapeshellarg($logfile) . '; else echo "⏭ 没有 database dump" >> ' . escapeshellarg($logfile) . '; fi; ';
        
        // 4. Restore websites  
        $cmd .= "echo '🌐 Merestore websites...' >> $logfile; ";
        $cmd .= 'if [ -d "$BD/www" ]; then for d in "$BD/www"/*/; do DN=$(basename "$d"); if [ "$DN" != "manager" ]; then cp -a "$d" /var/www/ 2>> ' . escapeshellarg($logfile) . ' && chown -R ' . web_user() . ':' . web_user() . ' "/var/www/$DN" 2>/dev/null; fi; done; echo "✅ Websites 恢复" >> ' . escapeshellarg($logfile) . '; else echo "⏭ 没有 website data" >> ' . escapeshellarg($logfile) . '; fi; ';
        
        // 5. Restore Nginx configs
        $cmd .= "echo '🔧 Merestore Nginx configs...' >> $logfile; ";
        $cmd .= 'if [ -d "$BD/nginx" ]; then ';
        $cmd .= 'ls "$BD/nginx/"* 2>/dev/null | while read f; do BN=$(basename "$f"); ';
        $cmd .= 'if [ "$BN" != "conf.d" ] && [ -f "$f" ]; then ';
        $cmd .= 'cp "$f" "/etc/nginx/sites-available/$BN" 2>> ' . escapeshellarg($logfile) . '; ';
        $cmd .= 'if echo "$BN" | grep -qEv "^default$"; then ln -sf "/etc/nginx/sites-available/$BN" "/etc/nginx/sites-enabled/$BN" 2>/dev/null; fi; fi; done; ';
        $cmd .= 'if [ -d "$BD/nginx/conf.d" ]; then cp -a "$BD/nginx/conf.d/"* /etc/nginx/conf.d/ 2>/dev/null; fi; ';
        $cmd .= 'fi; ';
        $cmd .= "echo '✅ Nginx configs 恢复' >> $logfile; ";
        $cmd .= "nginx -t >> $logfile 2>&1 && " . (is_alpine() ? "rc-service nginx reload" : "systemctl reload nginx") . " 2>> $logfile; ";
        $cmd .= "echo '✅ Nginx tested & reloaded' >> $logfile; ";
        
        // 6. Restore panel settings
        if ($restore_panel) {
            $cmd .= "echo '⚙ Merestore panel settings...' >> $logfile; ";
            // 排除秘密文件（.api_token/.cf_token/.notify.json/webhook/私钥）——迁移包里的秘密默认不可信
            $cmd .= 'if [ -d "$BD/panel" ]; then find "$BD/panel" -maxdepth 1 -type f ! -name ".api_token" ! -name ".cf_token" ! -name ".notify.json" ! -name "*.key" ! -name "*.pem" ! -name "panel.db" -exec cp {} /var/www/manager/ \\; 2>> ' . escapeshellarg($logfile) . '; ';
            // T-20：迁移包内 panel.db → 恢复为 .panel.db（点前缀）
            $cmd .= 'if [ -f "$BD/panel/panel.db" ]; then cp "$BD/panel/panel.db" ' . escapeshellarg(DB_FILE) . ' 2>> ' . escapeshellarg($logfile) . '; chmod 600 ' . escapeshellarg(DB_FILE) . '; fi; ';
            $cmd .= "chmod 600 /var/www/manager/.passwd /var/www/manager/.users 2>/dev/null; fi; ";
            $cmd .= "echo '✅ Panel settings 恢复' >> $logfile; ";
        } else {
            $cmd .= "echo '⏭ 跳过面板设置' >> $logfile; ";
        }
        
        // 7. Restore SSL
        if ($restore_ssl) {
            $cmd .= "echo '🔒 Merestore SSL certificates...' >> $logfile; ";
            $cmd .= 'if [ -d "$BD/ssl/letsencrypt" ]; then cp -a "$BD/ssl/letsencrypt/" /etc/ 2>> ' . escapeshellarg($logfile) . '; ';
            $cmd .= "echo '✅ SSL certificates 恢复' >> $logfile; else echo '⏭ 没有 SSL data' >> $logfile; fi; ";
        } else {
            $cmd .= "echo '⏭ 跳过 SSL 证书' >> $logfile; ";
        }
        
        // 8. Restore cron
        if ($restore_cron) {
            $cmd .= "echo '⏰ Merestore cron jobs...' >> $logfile; ";
            $cmd .= 'if [ -f "$BD/crontab.txt" ]; then crontab "$BD/crontab.txt" 2>> ' . escapeshellarg($logfile) . ' && echo "✅ Cron jobs 恢复" >> ' . escapeshellarg($logfile) . ' || echo "⚠ Cron restore error" >> ' . escapeshellarg($logfile) . '; else echo "⏭ 没有 cron data" >> ' . escapeshellarg($logfile) . '; fi; ';
        } else {
            $cmd .= "echo '⏭ 跳过定时任务' >> $logfile; ";
        }
        
        // 9. Restore UFW
        if ($restore_ufw) {
            $cmd .= "echo '🛡 Merestore UFW rules...' >> $logfile; ";
            $cmd .= 'if [ -f "$BD/ufw_rules.txt" ]; then echo "⚠ 出于安全考虑，UFW 规则不会自动恢复。备份文件已保留。" >> ' . escapeshellarg($logfile) . '; fi; ';
        } else {
            $cmd .= "echo '⏭ 跳过 UFW 规则' >> $logfile; ";
        }
        
        // Cleanup
        $cmd .= "rm -rf " . escapeshellarg($workroot) . " 2>/dev/null; ";
        $cmd .= "echo '___COMPLETE___' >> $logfile; ";
        $cmd .= ") > /dev/null 2>&1 &";
        exec($cmd);
        
        $_SESSION['mig_restore_task'] = $task_id;
        
        ?><!DOCTYPE html><html lang="id"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Restoring Backup...</title>
        <style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:linear-gradient(160deg,#dfd9cf,#f5f0e8);color:#2d3748;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}.box{background:#fafaf7;padding:44px;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,.1);width:90%;max-width:650px;text-align:center;border-top:4px solid #1e3a5f}.spinner{width:48px;height:48px;border:4px solid #e2ddd5;border-top:4px solid #1e3a5f;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 20px}@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}h2{color:#1a365d;margin-bottom:8px;font-weight:700}pre{background:#fdfcfb;padding:16px;border-radius:8px;text-align:left;max-height:350px;overflow:auto;font-family:monospace;font-size:12px;color:#5a6170;line-height:1.6;margin-top:20px;border:1px solid #e2ddd5}.progress-bar{width:100%;height:10px;background:#e2ddd5;border-radius:99px;overflow:hidden;margin-top:16px}.progress-fill{height:100%;background:linear-gradient(90deg,#1e3a5f,#2c5282);border-radius:99px;width:0%;transition:width .5s}.done{display:none;margin-top:16px}.btn-green2{background:linear-gradient(135deg,#1e3a5f,#2c5282);color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block;box-shadow:0 2px 8px rgba(30,58,95,.25)}.btn-green2:hover{box-shadow:0 4px 14px rgba(30,58,95,.35)}</style></head><body>
        <div class="box"><div class="spinner" id="spinner"></div>
        <h2 id="title">正在恢复系统备份...</h2>
        <p style="color:#64748b;font-size:14px">请不要关闭此页面</p>
        <div class="progress-bar"><div class="progress-fill" id="pfill"></div></div>
        <pre id="log">准备中...</pre>
        <div class="done" id="done"><a href="?page=migration" class="btn-green2">返回 Migration</a></div></div>
        <script>
        var tid='<?= $task_id ?>',check=0,steps=10;
        function poll(){fetch('?progress='+tid).then(r=>r.text()).then(t=>{document.getElementById('log').textContent=t;var done=t.indexOf('___COMPLETE___')>-1;var pct=done?100:Math.min(((t.match(/✅/g)||[]).length/steps)*100,95);document.getElementById('pfill').style.width=pct+'%';if(done){document.getElementById('spinner').style.display='none';document.getElementById('title').textContent='Restore 完成!';document.getElementById('done').style.display='block'}else{check++;document.getElementById('title').textContent='正在恢复... ('+Math.ceil(check*1.5)+'s)';setTimeout(poll,1500)}})}poll();
        </script></body></html><?php exit;
    }

    // --- MIGRATION: DELETE BACKUP ---
    if ($act === 'migration_delete') {
        $f = $_POST['file'] ?? '';
        $fp = MIGRATION_DIR . '/' . basename($f);
        if (file_exists($fp)) { unlink($fp); flash('Migration backup 删除!'); }
        else { flash('文件未找到！', 'err'); }
        redirect('migration');
    }
    }


$flash = get_flash();
$msg = $flash ? "<div class='{$flash['type']}'>" . flash_html($flash['msg']) . "</div>" : '';

// ===== SYSTEM INFO =====
$nginx_ok = svc_status('nginx');
$mysql_ok = is_mysql_available() && svc_status('mariadb');
$php_ok = svc_status(php_fpm_svc());
$uptime = uptime_str();
$load = sys_getloadavg();
$mem_info = cmd("free -m | awk '/^Mem:/ {print \$3\"M/\"\$2\"M\"}'");
$disk_pct = round(100 - (disk_free() / disk_total() * 100));

// Get websites list (parse domain from server_name, not filename)
$sites = [];
$sites_by_cfg = [];
foreach (glob(NGINX_AVAILABLE . '/*') as $f) {
    $cfg = @file_get_contents($f) ?: '';
    if (strpos($cfg, 'server {') === false) continue; // RHEL conf.d 内部片段（php-fpm.conf 等）非 server 块
    $cfg_name = preg_replace('/\.conf$/', '', basename($f));
    if ($cfg_name === 'default' || strpos($cfg_name, '.bak.') !== false) continue;
    $enabled = is_link(cfg_path($cfg_name, 'enabled')) || file_exists(cfg_path($cfg_name, 'enabled'));
    
    // Extract primary domain from server_name
    preg_match('/server_name\s+([^;]+);/', $cfg, $sn);
    $server_names = $sn[1] ?? $cfg_name;
    $domains = preg_split('/\s+/', trim($server_names));
    $domain = $domains[0];
    if ($domain === '_' || $domain === '' || !str_contains($domain, '.')) continue; // 排除反代/兜底 server（vps-manager.conf）
    
    // Extract document root
    preg_match('/root\s+([^;]+);/', $cfg, $rm);
    $root = $rm[1] ?? (WWW_ROOT . '/' . $domain);
    
    $ssl = strpos($cfg, 'ssl_certificate') !== false;
    $root_exists = is_dir($root);
    
    $sites[$domain] = [
        'domain' => $domain,
        'cfg_name' => $cfg_name,
        'enabled' => $enabled,
        'root' => $root,
        'root_exists' => $root_exists,
        'ssl' => $ssl
    ];
    $sites_by_cfg[$cfg_name] = $domain;
}
ksort($sites);

// Get databases
$dbs = [];
$raw = cmd(mysql_cli("-e 'SHOW DATABASES;' -N 2>/dev/null"));
foreach (explode("\n", $raw) as $db) {
    $db = trim($db);
    if ($db && !in_array($db, ['information_schema', 'performance_schema', 'mysql', 'sys', 'Database']) && preg_match('/^[a-zA-Z0-9_-]{1,64}$/', $db)) {
                $dbs[] = $db;
            }
}
sort($dbs);

// Get backups
$backups = [];
if (is_dir(BACKUP_DIR)) {
    foreach (array_merge(glob(BACKUP_DIR . '/*.zip') ?: [], glob(BACKUP_DIR . '/*.sql') ?: [], glob(BACKUP_DIR . '/*.gz') ?: [], glob(BACKUP_DIR . '/*.tar') ?: []) as $f) {
        $backups[] = ['name' => basename($f), 'size' => round(filesize($f) / 1024, 1), 'time' => filemtime($f)];
    }
}
usort($backups, fn($a, $b) => $b['time'] - $a['time']);

// PHP versions
$php_versions = [];
foreach (['8.2','8.3','8.4','8.5'] as $v) {
    if (file_exists(php_bin($v))) $php_versions[] = $v;
}
if (empty($php_versions)) $php_versions = [selected_php_version()];

// ===== PAGE CONTENT FUNCTIONS =====
function nav_link($p, $icon, $label, $current) {
    $active = $current === $p ? ' active' : '';
    return "<a href='?page=$p' class='nav-link$active'>$icon $label</a>";
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VPS Manager</title>
<style>
:root {
  --bg: #f5f0e8; --surface: #fafaf7; --surface2: #f0ebe0;
  --border: #e2ddd5; --text: #2d3748; --text2: #718096;
  --green: #1e3a5f; --blue: #2c5282; --red: #c53030; --yellow: #b7791f;
  --primary: #1e3a5f; --primary-light: #2c5282; --primary-dark: #1a365d;
  --radius: 10px; --shadow-sm: 0 1px 3px rgba(0,0,0,.06); --shadow: 0 4px 16px rgba(0,0,0,.08); --shadow-lg: 0 8px 32px rgba(0,0,0,.12);
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:linear-gradient(180deg,#ebe5d9 0%,#f5f0e8 100%);color:var(--text);min-height:100vh}
a{color:var(--blue);text-decoration:none;transition:color .15s}a:hover{color:var(--primary-dark)}
.topbar{background:linear-gradient(135deg,#1a365d,#1e3a5f,#2c5282);padding:14px 28px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;box-shadow:0 2px 12px rgba(26,54,93,.25);position:sticky;top:0;z-index:100}
.topbar .logo{font-size:19px;font-weight:800;color:#fff;letter-spacing:-.3px}
.topbar .sysinfo{font-size:11px;color:rgba(255,255,255,.8);display:flex;gap:12px;flex-wrap:wrap;align-items:center}
.topbar .sysinfo span{padding:4px 12px;background:rgba(255,255,255,.12);border-radius:99px;color:#fff;backdrop-filter:blur(4px)}
.topbar .sysinfo .dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px}
.dot-ok{background:#68d391;box-shadow:0 0 6px rgba(104,211,145,.4)}.dot-err{background:#fc8181;box-shadow:0 0 6px rgba(252,129,129,.4)}
.layout{display:flex;min-height:calc(100vh - 61px)}
.sidebar{width:230px;background:var(--surface);padding:20px 10px;border-right:1px solid var(--border);flex-shrink:0;box-shadow:2px 0 12px rgba(0,0,0,.04)}
.sidebar .nav-section{font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:#a0a5b0;padding:18px 14px 8px;font-weight:700}
.nav-link{display:flex;align-items:center;gap:10px;padding:10px 14px;color:#5a6170;border-radius:8px;margin-bottom:2px;font-size:13px;transition:all .2s;text-decoration:none;font-weight:500}
.nav-link:hover{background:#eae3d6;color:#1a365d;transform:translateX(2px)}
.nav-link.active{background:linear-gradient(135deg,#1e3a5f,#2c5282);color:#fff;font-weight:600;box-shadow:0 2px 8px rgba(30,58,95,.3)}
.content{flex:1;padding:28px 32px;overflow:auto}
.card{background:var(--surface);border-radius:var(--radius);padding:22px;margin-bottom:18px;border:1px solid var(--border);box-shadow:var(--shadow-sm);transition:box-shadow .2s}
.card:hover{box-shadow:var(--shadow)}
.card h2{font-size:16px;margin-bottom:14px;color:var(--primary);display:flex;align-items:center;gap:8px;font-weight:700}
.card h3{font-size:14px;margin-bottom:12px;color:var(--text);font-weight:600}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:14px;margin-bottom:22px}
.stat{background:var(--surface);padding:22px 18px;border-radius:var(--radius);border:1px solid var(--border);text-align:center;box-shadow:var(--shadow-sm);transition:all .25s;cursor:default}
.stat:hover{transform:translateY(-2px);box-shadow:var(--shadow)}
.stat .val{font-size:28px;font-weight:800;color:var(--primary)}
.stat .val.warn{color:var(--yellow)}.stat .val.danger{color:var(--red)}
.stat .lbl{font-size:11px;color:var(--text2);margin-top:6px;text-transform:uppercase;letter-spacing:.5px;font-weight:600}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:12px 14px;background:var(--surface2);color:var(--text2);font-weight:700;border-bottom:2px solid var(--border);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
td{padding:11px 14px;border-bottom:1px solid var(--border)}
tr:hover td{background:#efe9db}
.btn{padding:9px 18px;border-radius:8px;font-size:13px;font-weight:600;border:none;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:6px;transition:all .2s;letter-spacing:.2px}
.btn:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(0,0,0,.14)}
.btn:active{transform:translateY(0)}
.btn-sm{padding:5px 11px;font-size:11px;border-radius:6px}.btn-xs{padding:3px 9px;font-size:10px;border-radius:5px}
.btn-green{background:linear-gradient(135deg,#1e3a5f,#2c5282);color:#fff;box-shadow:0 2px 6px rgba(30,58,95,.25)}.btn-green:hover{background:linear-gradient(135deg,#1a365d,#2c5282);box-shadow:0 4px 14px rgba(30,58,95,.35)}
.btn-blue{background:#2c5282;color:#fff}.btn-blue:hover{background:#1e3a5f}
.btn-red{background:#c53030;color:#fff}.btn-red:hover{background:#9b2c2c}
.btn-yellow{background:#b7791f;color:#fff}.btn-yellow:hover{background:#975a16}
.btn-gray{background:#eae3d6;color:#5a6170;border:1px solid #d5cec0}.btn-gray:hover{background:#ddd5c5}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}
.ok{background:#f0f5ee;color:#2d5016;padding:14px 18px;border-radius:8px;margin-bottom:16px;font-size:13px;border-left:4px solid #5a9e3e}
.err{background:#fdf2f2;color:#822727;padding:14px 18px;border-radius:8px;margin-bottom:16px;font-size:13px;border-left:4px solid #c53030}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px}
.form-group{display:flex;flex-direction:column;gap:5px}
.form-group label{font-size:11px;color:var(--text2);font-weight:700;text-transform:uppercase;letter-spacing:.5px}
.form-group input,.form-group select,.form-group textarea{width:100%;padding:10px 14px;border-radius:8px;border:2px solid var(--border);background:var(--surface);color:var(--text);font-size:14px;outline:none;transition:all .2s}
.form-group input:focus,.form-group select:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(30,58,95,.08)}
.form-group small{font-size:11px;color:var(--text2)}
.help{font-size:11px;color:var(--text2);margin-top:4px}
.badge{display:inline-block;padding:3px 12px;border-radius:99px;font-size:10px;font-weight:700;letter-spacing:.3px}
.badge-ok{background:#e3eed9;color:#2d5016}.badge-err{background:#fde8e8;color:#822727}
.badge-blue{background:#dce4f0;color:#1a365d}.badge-yellow{background:#f5eedb;color:#6b4d14}
.service-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:18px}
.service-card{background:var(--surface);border-radius:var(--radius);padding:24px;border:1px solid var(--border);text-align:center;box-shadow:var(--shadow-sm);transition:all .25s}
.service-card:hover{transform:translateY(-2px);box-shadow:var(--shadow)}
.service-card .svc-icon{font-size:40px;margin-bottom:10px}
.service-card .svc-name{font-weight:700;margin-bottom:4px;font-size:15px}
.service-card .svc-status{font-size:12px;margin-bottom:14px}
.dashed{background:var(--bg);border:2px dashed var(--border);border-radius:var(--radius);padding:40px;text-align:center;color:var(--text2);cursor:pointer;transition:all 0.2s}
.dashed:hover{border-color:var(--primary);color:var(--text)}
@media(max-width:768px){.layout{flex-direction:column}.sidebar{width:100%;padding:8px;display:flex;flex-wrap:wrap;gap:4px;box-shadow:none}.sidebar .nav-section{display:none}.nav-link{font-size:12px;padding:6px 10px;margin:0}.content{padding:16px}}
</style>
</head>
<body>
<?php if (!empty($GLOBALS['NOT_ROOT_WARN'])): ?><div style="background:#7f1d1d;color:#fff;padding:10px 16px;font-size:14px">⛔ 面板未以 root 运行——所有写操作已被禁用。请将 PHP-FPM 配置为 root 运行（见使用说明）。</div><?php endif; ?>
<?php if (!empty($GLOBALS['ENSURE_DIRS_WARN'])): ?><div style="background:#7f1d1d;color:#fff;padding:10px 16px;font-size:14px">⚠️ 备份目录 <?= BACKUP_DIR ?> 创建失败（需要 root 运行面板）——备份/迁移功能不可用</div><?php endif; ?>

<div class="topbar">
  <div class="logo">🖥️ VPS Manager</div>
  <div class="sysinfo">
    <span><span class="dot <?= $nginx_ok?'dot-ok':'dot-err' ?>"></span>Nginx</span>
    <span><span class="dot <?= $mysql_ok?'dot-ok':'dot-err' ?>"></span>MySQL</span>
    <span><span class="dot <?= $php_ok?'dot-ok':'dot-err' ?>"></span>PHP</span>
    <span>💾 <?= disk_free() ?>GB</span>
    <span>⏱ <?= $uptime ?></span>
    <form method="POST" style="display:inline;margin-left:8px"><?= csrf_field() ?><input type="hidden" name="action" value="logout"><button class="btn btn-red btn-sm" title="退出登录">🚪</button></form>
          <span style="background:rgba(255,255,255,.2)">👤 <?= sanitize(current_user()['user'] ?? 'admin') ?> (<?= is_admin() ? '管理员' : '用户' ?>)</span>
  </div>
</div>

<div class="layout">
<div class="sidebar">
  <div class="nav-section">Main</div>
  <?= nav_link('dashboard', '📊', '仪表盘', $page) ?>
  <?= nav_link('websites', '🌐', '网站', $page) ?>
  <?= nav_link('databases', '🗄️', '数据库', $page) ?>
  <a href="/pma/" target="_blank" class="nav-link">🛢️ phpMyAdmin</a>
  <div class="nav-section">Management</div>
  <?= nav_link('backups', '💾', '备份与恢复', $page) ?>
  <?= nav_link('services', '⚙️', '服务', $page) ?>
  <?= nav_link('php', '🐘', 'PHP', $page) ?>
  <?= nav_link('node', '🟢', 'Node.js', $page) ?>
  <?= nav_link('ssl', '🔒', 'SSL 证书', $page) ?>
  <?= nav_link('proxy', '🔀', '反向代理', $page) ?>
  <?= nav_link('docker', '🐳', 'Docker', $page) ?>
  <?= nav_link('procs', '🧩', '进程托管', $page) ?>
  <?= nav_link('monitor', '📊', '监控', $page) ?>
  <?= nav_link('firewall', '🛡️', '防火墙', $page) ?>
  <?= nav_link('files', '📁', '文件管理', $page) ?>
  <?= nav_link('logs', '📝', '日志', $page) ?>
  <?= nav_link('cron', '⏰', '定时任务', $page) ?>
  <?= nav_link('optimize', '🚀', '优化', $page) ?>
  <?= nav_link('redirects', '🔄', '重定向', $page) ?>
  <?= nav_link('cache', '🧹', '缓存', $page) ?>
  <?= nav_link('uptime', '📡', '在线状态', $page) ?>
  <?= nav_link('security', '🛡️', '安全', $page) ?>
  <?= nav_link('cloudbackup', '☁️', '云备份', $page) ?>
  <?= nav_link('migration', '🔄', '迁移', $page) ?>
  <?= nav_link('terminal', '💻', '终端', $page) ?>
  <?= nav_link('phpsite', '⚡', '站点 PHP 设置', $page) ?>
  <?= nav_link('dns', '🌍', 'DNS 管理', $page) ?>
  <?php if (is_admin()): ?><?php endif; ?>
  <div class="nav-section">System</div>
  <?= nav_link('settings', '⚙️', '设置', $page) ?>
</div>

<div class="content">
<?= $msg ?>

<?php
// ===== DASHBOARD =====
if ($page === 'dashboard'):
?>
<div class="stats">
  <div class="stat"><div class="val <?= $disk_pct>80?'danger':($disk_pct>60?'warn':'') ?>"><?= disk_free() ?> GB</div><div class="lbl">可用磁盘 (<?= disk_total() ?> GB)</div></div>
  <div class="stat"><div class="val"><?= round($load[0], 2) ?></div><div class="lbl">CPU 负载 (1m)</div></div>
  <div class="stat"><div class="val"><?= count($sites) ?></div><div class="lbl">网站</div></div>
  <div class="stat"><div class="val"><?= count($dbs) ?></div><div class="lbl">数据库</div></div>
  <div class="stat"><div class="val"><?= count($backups) ?></div><div class="lbl">备份数</div></div>
  <div class="stat"><div class="val" style="font-size:16px"><?= $uptime ?></div><div class="lbl">系统运行时间</div></div>
</div>

<div class="service-grid">
  <div class="service-card">
    <div class="svc-icon">🌐</div>
    <div class="svc-name">Nginx</div>
    <div class="svc-status"><span class="badge <?= $nginx_ok?'badge-ok':'badge-err' ?>"><?= $nginx_ok?'运行中':'已停止' ?></span></div>
    <?php if($nginx_ok): ?><span style="font-size:12px;color:var(--text2)"><?= trim(cmd("nginx -v 2>&1")) ?></span><?php endif; ?>
  </div>
  <div class="service-card">
    <div class="svc-icon">🗄️</div>
    <div class="svc-name">MySQL / MariaDB</div>
    <div class="svc-status"><span class="badge <?= $mysql_ok?'badge-ok':'badge-err' ?>"><?= $mysql_ok?'运行中':(is_mysql_available()?'已停止':'未安装（SQLite 模式）') ?></span></div>
    <?php if($mysql_ok): ?><span style="font-size:12px;color:var(--text2)"><?= $mysql_ok ? trim(cmd(mysql_cli("-V 2>/dev/null | head -1"))) : "SQLite 模式（MySQL 未安装）" ?></span><?php endif; ?>
  </div>
  <div class="service-card">
    <div class="svc-icon">🐘</div>
    <div class="svc-name">PHP-FPM</div>
    <div class="svc-status"><span class="badge <?= $php_ok?'badge-ok':'badge-err' ?>"><?= $php_ok?'运行中':'已停止' ?></span></div>
    <?php if($php_ok): ?><span style="font-size:12px;color:var(--text2)"><?= trim(cmd("php -v 2>/dev/null | head -1")) ?></span><?php endif; ?>
  </div>
</div>

<div class="card">
  <h2>📋 快捷操作</h2>
  <div class="actions">
    <a href="?page=websites" class="btn btn-green">➕ New Website</a>
    <a href="?page=databases" class="btn btn-blue">🗄️ New Database</a>
    <a href="?page=backups" class="btn btn-yellow">💾 Create Backup</a>
    <a href="?page=services" class="btn btn-gray">⚙️ Manage Services</a>
  </div>
</div>

<?php if(!empty($sites)): ?>
<div class="card">
  <h2>🌐 运行中的网站</h2>
  <table>
    <thead><tr><th>域名</th><th>状态</th><th>SSL</th><th>根目录</th><th>操作</th></tr></thead>
    <tbody>
    <?php foreach(array_slice($sites, 0, 10) as $s): ?>
    <tr>
      <td><strong><?= sanitize($s['domain']) ?></strong></td>
      <td><span class="badge <?= $s['enabled']?'badge-ok':'badge-err' ?>"><?= $s['enabled']?'Active':'Disabled' ?></span></td>
      <td><?= $s['ssl']?'🔒 SSL':'—' ?></td>
      <td style="font-size:12px;color:var(--text2)"><?= sanitize($s['root']) ?></td>
      <td>
        <a href="http://<?= $s['domain'] ?>" target="_blank" class="btn btn-blue btn-xs">🔗 Visit</a>
        <?php if($s['root_exists']): ?>
        <a href="?page=backups" class="btn btn-yellow btn-xs">💾 Backup</a>
        <?php endif; ?>
      </td>
    </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
</div>
<?php endif; ?>

<?php
// ===== WEBSITES =====
elseif ($page === 'websites'):
?>
<div class="actions">
  <button onclick="showModal('createSiteModal')" class="btn btn-green">➕ 创建网站</button>
  <button onclick="showModal('deleteSiteModal')" class="btn btn-red">🗑️ Delete Site</button>
</div>

<div class="card">
  <h2>🌐 全部网站</h2>
  <?php if(empty($sites)): ?>
    <p style="color:var(--text2);text-align:center;padding:40px">暂无网站。点击「创建网站」开始。</p>
  <?php else: ?>
  <table>
    <thead><tr><th>域名</th><th>状态</th><th>SSL</th><th>网站根目录</th><th>目录存在</th><th>操作</th></tr></thead>
    <tbody>
    <?php foreach($sites as $s): $exists = $s['root_exists']; ?>
    <tr>
      <td><strong><?= sanitize($s['domain']) ?></strong></td>
      <td><span class="badge <?= $s['enabled']?'badge-ok':'badge-err' ?>"><?= $s['enabled']?'Active':'Disabled' ?></span></td>
      <td><?= $s['ssl']?'🔒 SSL':'—' ?></td>
      <td style="font-size:12px;color:var(--text2)"><?= sanitize($s['root']) ?></td>
      <td><?= $exists ? '✅' : '❌' ?></td>
      <td>
        <a href="http://<?= $s['domain'] ?>" target="_blank" class="btn btn-blue btn-xs">🔗</a>
        <a href="?page=backups" class="btn btn-yellow btn-xs">💾</a>
        <a href="?page=siteconf&cfg=<?= urlencode($s['cfg_name']) ?>" class="btn btn-green btn-xs" title="伪静态 / 编辑 Nginx 配置">📝 伪静态/配置</a>
        <form method="POST" style="display:inline" <?= confirm_attr('删除 ' . $s['domain'] . ' 的全部数据？数据库不会删除.') ?>><?= csrf_field() ?>
          <input type="hidden" name="action" value="delete_site">
          <input type="hidden" name="domain" value="<?= sanitize($s['domain']) ?>">
          <input type="hidden" name="cfg_name" value="<?= sanitize($s['cfg_name']) ?>">
          <button class="btn btn-red btn-xs">✕</button>
        </form>
      </td>
    </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  <?php endif; ?>
</div>

<!-- Create Site Modal -->
<div id="createSiteModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:999;display:none;align-items:flex-start;justify-content:center;padding-top:5vh;overflow-y:auto" onclick="if(event.target===this)hideModal('createSiteModal')">
  <div style="background:var(--surface);border-radius:var(--radius);width:90%;max-width:650px;border:1px solid var(--border);box-shadow:0 20px 60px rgba(0,0,0,0.5);max-height:90vh;overflow-y:auto">
    <div style="padding:24px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
      <h3 style="font-size:18px;color:var(--green)">➕ Create New Website</h3>
      <button onclick="hideModal('createSiteModal')" style="background:none;border:none;color:var(--text2);font-size:24px;cursor:pointer">&times;</button>
    </div>
    <form method="POST" style="padding:24px"><?= csrf_field() ?>
      <input type="hidden" name="action" value="create_site">
      <div class="form-grid">
        <div class="form-group">
          <label>Domain *</label>
          <input name="domain" placeholder="contoh: mysite.com" required>
          <small>无需 http/https，只填域名</small>
        </div>
        <div class="form-group">
          <label>PHP 版本</label>
          <select name="php_ver">
            <?php foreach($php_versions as $v): ?><option value="<?= $v ?>" <?= $v===selected_php_version()?'selected':'' ?>>PHP <?= $v ?></option><?php endforeach; ?>
          </select>
        </div>
      </div>
      
      <div style="margin:20px 0;padding:16px;background:var(--bg);border-radius:8px;display:flex;align-items:center;gap:12px">
        <input type="checkbox" name="create_db" id="create_db" <?= is_mysql_available() ? 'checked' : 'disabled title="MySQL 未安装"' ?> style="width:18px;height:18px">
        <label for="create_db" style="font-weight:600">🗄️ Create Database</label>
      </div>
      
      <div class="form-grid" id="dbFields">
        <div class="form-group">
          <label>数据库名</label>
          <input name="dbname" placeholder="留空则由域名自动生成">
          <small>留空则由域名自动生成</small>
        </div>
        <div class="form-group">
          <label>数据库用户</label>
          <input name="dbuser" placeholder="留空则由库名自动生成">
        </div>
        <div class="form-group">
          <label>数据库密码</label>
          <input name="dbpass" placeholder="auto: random 16 chars">
        </div>
      </div>
      
      <div style="margin:20px 0;padding:16px;background:var(--bg);border-radius:8px;display:flex;align-items:center;gap:12px">
        <input type="checkbox" name="install_wp" id="install_wp" style="width:18px;height:18px">
        <label for="install_wp" style="font-weight:600">📦 Auto-install WordPress (requires database)</label>
      </div>
      
      <div style="display:flex;gap:12px;justify-content:flex-end;margin-top:20px">
        <button type="button" onclick="hideModal('createSiteModal')" class="btn btn-gray">取消</button>
        <button type="submit" class="btn btn-green">🚀 Create Website</button>
      </div>
    </form>
  </div>
</div>

<!-- Delete Site Modal -->
<div id="deleteSiteModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:999;display:none;align-items:center;justify-content:center" onclick="if(event.target===this)hideModal('deleteSiteModal')">
  <div style="background:var(--surface);border-radius:var(--radius);width:90%;max-width:400px;border:1px solid var(--border);padding:24px">
    <h3 style="margin-bottom:16px">🗑️ Delete Nginx Config</h3>
    <form method="POST"><?= csrf_field() ?>
      <input type="hidden" name="action" value="delete_site">
      <input type="hidden" name="cfg_name" id="modal_cfg_name" value="">
      <div class="form-group" style="margin-bottom:16px">
        <label>域名</label>
        <select name="domain" onchange="var o=this.selectedOptions[0];if(o)this.form.cfg_name.value=o.dataset.cfg" style="width:100%;padding:10px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:8px">
          <?php foreach($sites as $s): ?><option value="<?= sanitize($s['domain']) ?>" data-cfg="<?= sanitize($s['cfg_name']) ?>"><?= sanitize($s['domain']) ?></option><?php endforeach; ?>
        </select>
        <small style="color:var(--red)">删除 Nginx 配置、网站文件与 SSL 证书。数据库不会删除。</small>
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end">
        <button type="button" onclick="hideModal('deleteSiteModal')" class="btn btn-gray">取消</button>
        <button type="submit" class="btn btn-red" onclick="return confirm('Yakin hapus config?')">🗑️ Delete</button>
      </div>
    </form>
  </div>
</div>

<script>
function showModal(id) { document.getElementById(id).style.display = 'flex'; }
function hideModal(id) { document.getElementById(id).style.display = 'none'; }
document.getElementById('create_db').addEventListener('change', function() {
  document.getElementById('dbFields').style.opacity = this.checked ? '1' : '0.4';
  document.getElementById('install_wp').disabled = !this.checked;
});
</script>

<?php
// ===== DATABASES =====
elseif ($page === 'databases'):
?>
<div class="actions">
  <button onclick="showModal('createDbModal')" class="btn btn-green">🗄️ Create Database</button>
</div>

<div class="card">
  <h2>🗄️ Databases (<?= count($dbs) ?>)</h2>
  <?php if(empty($dbs)): ?>
    <p style="color:var(--text2);text-align:center;padding:40px">还没有 database user.</p>
  <?php else: ?>
  <table>
    <thead><tr><th>数据库</th><th>表数量</th><th>大小</th><th>操作</th></tr></thead>
    <tbody>
    <?php foreach($dbs as $db):
      $tbl_count = trim(cmd(mysql_cli("-e 'SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=\"$db\";' -N 2>/dev/null")) ?: '0');
      $db_size = trim(cmd(mysql_cli("-e \"SELECT ROUND(SUM(data_length+index_length)/1024/1024,1) FROM information_schema.tables WHERE table_schema='$db';\" -N 2>/dev/null")) ?: '0');
    ?>
    <tr>
      <td><strong>🗄️ <?= sanitize($db) ?></strong></td>
      <td><?= $tbl_count ?> tables</td>
      <td><?= $db_size ?> MB</td>
      <td>
        <a href="?page=backups&db=<?= urlencode($db) ?>" class="btn btn-yellow btn-xs">💾 Backup</a>
        <form method="POST" style="display:inline"><?= csrf_field() ?>
          <input type="hidden" name="action" value="site_db_bind">
          <input type="hidden" name="dbname" value="<?= sanitize($db) ?>">
          <input type="text" name="domain" placeholder="站点域名" style="width:130px;font-size:12px;padding:4px 6px" required>
          <button class="btn btn-blue btn-xs">🔗 绑定站点</button>
        </form>
        <?php
        $bound_to = [];
        foreach (site_db_map_load() as $dm => $dbs) { if (in_array($db, (array)$dbs, true)) $bound_to[] = $dm; }
        if ($bound_to): ?><span style="font-size:11px;color:var(--text2)">已绑: <?= sanitize(implode(', ', $bound_to)) ?></span><?php endif; ?>
        <form method="POST" style="display:inline" <?= confirm_attr('删除数据库 ' . $db . '？数据无法恢复！') ?>><?= csrf_field() ?>
          <input type="hidden" name="action" value="delete_db">
          <input type="hidden" name="dbname" value="<?= sanitize($db) ?>">
          <button class="btn btn-red btn-xs">🗑️</button>
        </form>
      </td>
    </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  <?php endif; ?>
</div>

<!-- Create DB Modal -->
<div id="createDbModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:999;display:none;align-items:center;justify-content:center" onclick="if(event.target===this)hideModal('createDbModal')">
  <div style="background:var(--surface);border-radius:var(--radius);width:90%;max-width:450px;border:1px solid var(--border);padding:24px">
    <h3 style="font-size:18px;color:var(--green);margin-bottom:20px">🗄️ Create Database</h3>
    <form method="POST"><?= csrf_field() ?>
      <input type="hidden" name="action" value="create_db">
      <div class="form-group" style="margin-bottom:12px">
        <label>Database Name *</label>
        <input name="dbname" placeholder="my_database" required>
        <small>仅限字母、数字、下划线</small>
      </div>
      <div class="form-group" style="margin-bottom:12px">
        <label>用户名</label>
        <input name="dbuser" placeholder="auto: dbname_user">
      </div>
      <div class="form-group" style="margin-bottom:20px">
        <label>密码</label>
        <input name="dbpass" placeholder="auto: random password">
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end">
        <button type="button" onclick="hideModal('createDbModal')" class="btn btn-gray">取消</button>
        <button type="submit" class="btn btn-green">创建数据库</button>
      </div>
    </form>
  </div>
</div>

<script>
function showModal(id) { document.getElementById(id).style.display = 'flex'; }
function hideModal(id) { document.getElementById(id).style.display = 'none'; }
</script>

<?php
// ===== BACKUPS =====
elseif ($page === 'backups'):
?>
<div class="actions">
  <button onclick="showModal('backupSiteModal')" class="btn btn-yellow">💾 Backup Website</button>
  <button onclick="showModal('restoreSiteModal')" class="btn btn-green">📥 Restore Website</button>
</div>

<div class="card">
  <h2>📦 Backup History (<?= count($backups) ?>)</h2>
  <?php if(empty($backups)): ?>
    <p style="color:var(--text2);text-align:center;padding:40px">暂无备份。选择要备份的网站。</p>
  <?php else: ?>
  <table>
    <thead><tr><th>文件</th><th>大小</th><th>日期</th><th>操作</th></tr></thead>
    <tbody>
    <?php foreach($backups as $b): ?>
    <tr>
      <td><strong><?= sanitize($b['name']) ?></strong></td>
      <td><?= $b['size'] ?> KB</td>
      <td style="font-size:12px;color:var(--text2)"><?= date('d/m/Y H:i', $b['time']) ?></td>
      <td>
        <a href="?dl_backup=<?= urlencode($b['name']) ?>" class="btn btn-blue btn-xs">⬇️ Download</a>
        <form method="POST" style="display:inline" onsubmit="return confirm('删除 backup?')"><?= csrf_field() ?>
          <input type="hidden" name="action" value="delete_backup">
          <input type="hidden" name="file" value="<?= sanitize($b['name']) ?>">
          <button class="btn btn-red btn-xs">🗑️</button>
        </form>
      </td>
    </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  <?php endif; ?>
</div>

<!-- Backup Modal -->
<div id="backupSiteModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:999;display:none;align-items:center;justify-content:center" onclick="if(event.target===this)hideModal('backupSiteModal')">
  <div style="background:var(--surface);border-radius:var(--radius);width:90%;max-width:450px;border:1px solid var(--border);padding:24px">
    <h3 style="font-size:18px;color:var(--yellow);margin-bottom:20px">💾 Backup Website</h3>
    <form method="POST"><?= csrf_field() ?>
      <input type="hidden" name="action" value="backup_site">
      <div class="form-group" style="margin-bottom:20px">
        <label>选择网站</label>
        <select name="domain" style="width:100%;padding:10px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:8px">
          <?php foreach($sites as $s): if($s['root_exists']): ?>
            <option value="<?= sanitize($s['domain']) ?>"><?= sanitize($s['domain']) ?></option>
          <?php endif; endforeach; ?>
        </select>
        <small>备份网站文件 + 数据库（仅限已绑定库）</small>
        <?php $bdbmap = site_db_map_load(); $bdblist = [];
        foreach ($bdbmap as $bdom => $bdbs) $bdblist[] = sanitize($bdom) . ' → ' . sanitize(implode(', ', (array)$bdbs));
        if ($bdblist): ?><div style="font-size:11px;color:var(--text2);margin-top:6px">已绑定：<?= implode('；', $bdblist) ?></div>
        <?php else: ?><div style="font-size:11px;color:#b45309;margin-top:6px">⚠ 尚无站点绑定数据库——站点备份将不包含数据库（到「数据库」页绑定）</div><?php endif; ?>
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end">
        <button type="button" onclick="hideModal('backupSiteModal')" class="btn btn-gray">取消</button>
        <button type="submit" class="btn btn-yellow">💾 Create Backup</button>
      </div>
    </form>
  </div>
</div>

<!-- Restore Modal -->
<div id="restoreSiteModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:999;display:none;align-items:flex-start;justify-content:center;padding-top:5vh;overflow-y:auto" onclick="if(event.target===this)hideModal('restoreSiteModal')">
  <div style="background:var(--surface);border-radius:var(--radius);width:90%;max-width:550px;border:1px solid var(--border);padding:24px;max-height:90vh;overflow-y:auto">
    <h3 style="font-size:18px;color:var(--green);margin-bottom:20px">📥 Restore Website</h3>
    <form method="POST" enctype="multipart/form-data"><?= csrf_field() ?>
      <input type="hidden" name="action" value="restore_site">
      <div class="form-group" style="margin-bottom:14px">
        <label>Target Domain *</label>
        <input name="restore_domain" placeholder="mysite.com" required>
        <small>若不存在会自动创建 Nginx 配置</small>
      </div>
      <div class="form-group" style="margin-bottom:14px">
        <label>上传 ZIP（网站文件）</label>
        <input type="file" name="zipfile" accept=".zip" style="padding:8px">
        <small>可选：上传网站 .zip 备份</small>
      </div>
      <div class="form-group" style="margin-bottom:20px">
        <label>上传 SQL（数据库）</label>
        <input type="file" name="sqlfile" accept=".sql" style="padding:8px">
        <small>可选：上传数据库 .sql 备份</small>
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end">
        <button type="button" onclick="hideModal('restoreSiteModal')" class="btn btn-gray">取消</button>
        <button type="submit" class="btn btn-green">📥 Restore</button>
      </div>
    </form>
  </div>
</div>

<script>
function showModal(id) { document.getElementById(id).style.display = 'flex'; }
function hideModal(id) { document.getElementById(id).style.display = 'none'; }
</script>

<?php
// ===== NODE.JS =====
elseif ($page === 'node'):
  $node_ok = node_installed();
  $nver = $node_ok ? node_version() : '';
  $nsites = node_sites_all();
?>
<div class="card" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px">
  <h2 style="margin:0">🟢 Node.js 管理</h2>
  <?php if($node_ok): ?>
    <span class="badge badge-ok">Node <?= sanitize($nver) ?></span>
  <?php else: ?>
    <form method="POST" onsubmit="return confirm('安装 Node.js 20 LTS + npm？（约 1-3 分钟）')"><?= csrf_field() ?><input type="hidden" name="action" value="node_install"><button class="btn btn-green">📦 安装 Node.js（可选）</button></form>
  <?php endif; ?>
</div>

<?php if($node_ok): ?>
<div class="card">
  <h3>➕ 创建 Node 站点</h3>
  <form method="POST" style="display:flex;gap:10px;flex-wrap:wrap;align-items:end">
    <?= csrf_field() ?>
    <input type="hidden" name="action" value="node_site_add">
    <div><label style="font-size:12px;color:var(--text2)">域名</label><br><input name="ndomain" placeholder="app.example.com" required style="padding:8px 12px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text)"></div>
    <div><label style="font-size:12px;color:var(--text2)">应用端口</label><br><input name="nport" type="number" min="1024" max="65535" placeholder="3000" required style="width:100px;padding:8px 12px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text)"></div>
    <div><label style="font-size:12px;color:var(--text2)">入口文件</label><br><input name="nentry" value="app.js" placeholder="app.js / dist/index.js" style="width:180px;padding:8px 12px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text)"></div>
    <label style="font-size:13px;display:inline-flex;align-items:center;gap:6px"><input type="checkbox" name="nnpm" value="1"> 自动 npm install</label>
    <button class="btn btn-green">➕ 创建</button>
  </form>
  <p style="font-size:11px;color:var(--text2);margin-top:8px">自动生成模板 app.js / package.json、systemd|OpenRC 守护（vpsmgr-node-域名，崩溃自动重启）、nginx 反代（含 WebSocket 升级头）。上传代码到 <code>/var/www/域名/</code> 后点 npm install / Start。</p>
</div>
<?php else: ?>
<div class="card"><p style="color:var(--text2);text-align:center;padding:24px">Node.js 未安装。点击上方「安装 Node.js（可选）」开始（NodeSource 20 LTS / Alpine apk）。</p></div>
<?php endif; ?>

<?php if(!empty($nsites)): ?>
<div class="card">
  <h3>📦 Node 站点（<?= count($nsites) ?>）</h3>
  <table>
    <thead><tr><th>域名</th><th>端口</th><th>入口</th><th>守护状态</th><th>操作</th></tr></thead>
    <tbody>
    <?php foreach($nsites as $dm => $ns): $svc = 'vpsmgr-node-' . preg_replace('/[^a-z0-9-]/','-',$dm); $run = svc_status($svc); ?>
    <tr>
      <td><strong><?= sanitize($dm) ?></strong><br><a href="http://<?= sanitize($dm) ?>" target="_blank" style="font-size:11px">🔗 Visit</a></td>
      <td><?= intval($ns['port']) ?></td>
      <td style="font-size:12px;color:var(--text2)"><?= sanitize($ns['entry']) ?></td>
      <td><span class="badge <?= $run?'badge-ok':'badge-err' ?>"><?= $run?'🟢 运行中':'🔴 已停止' ?></span></td>
      <td style="display:flex;gap:4px;flex-wrap:wrap">
        <form method="POST" style="display:inline"><?= csrf_field() ?><input type="hidden" name="action" value="node_app_action"><input type="hidden" name="ndomain" value="<?= sanitize($dm) ?>"><input type="hidden" name="op" value="<?= $run?'restart':'start' ?>"><button class="btn <?= $run?'btn-yellow':'btn-green' ?> btn-xs"><?= $run?'↻ Restart':'▶ Start' ?></button></form>
        <?php if($run): ?><form method="POST" style="display:inline"><?= csrf_field() ?><input type="hidden" name="action" value="node_app_action"><input type="hidden" name="ndomain" value="<?= sanitize($dm) ?>"><input type="hidden" name="op" value="stop"><button class="btn btn-red btn-xs">⏹ Stop</button></form><?php endif; ?>
        <form method="POST" style="display:inline"><?= csrf_field() ?><input type="hidden" name="action" value="node_app_action"><input type="hidden" name="ndomain" value="<?= sanitize($dm) ?>"><input type="hidden" name="op" value="npm_install"><button class="btn btn-blue btn-xs">📥 npm i</button></form>
        <form method="POST" style="display:inline"><?= csrf_field() ?><input type="hidden" name="action" value="node_app_action"><input type="hidden" name="ndomain" value="<?= sanitize($dm) ?>"><input type="hidden" name="op" value="npm_build"><button class="btn btn-gray btn-xs">🔨 build</button></form>
        <form method="POST" style="display:inline" <?= confirm_attr('删除 Node 站点 ' . $dm . '？目录/守护/nginx 配置将一并删除！') ?>><?= csrf_field() ?><input type="hidden" name="action" value="node_site_del"><input type="hidden" name="ndomain" value="<?= sanitize($dm) ?>"><button class="btn btn-red btn-xs">🗑️</button></form>
      </td>
    </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  <p style="font-size:11px;color:var(--text2);margin-top:8px">应用日志：<code>/var/log/vpsmgr-node-域名.log</code></p>
</div>
<?php endif; ?>

<?php
elseif ($page === 'services'):
  $nginx_installed = pkg_installed('nginx');
  $php_installed = is_alpine() ? is_executable(php_bin(selected_php_version())) : pkg_installed(php_fpm_svc());
  $mysql_installed = is_mysql_available();
  $pma_installed = is_dir('/usr/share/phpmyadmin');
  $all_installed = $nginx_installed && $php_installed;
?>

<?php if(!$all_installed): ?>
<div class="card" style="border:2px solid var(--primary);background:linear-gradient(135deg,#dce4f0,#eae3d6)">
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px">
    <div>
      <h2 style="color:#1a365d;margin-bottom:4px">🚀 VPS Belum Siap?</h2>
      <p style="color:#94a3b8;font-size:13px">一键安装全部组件：Nginx、PHP 8.1、MariaDB、phpMyAdmin</p>
      <p style="color:#fbbf24;font-size:12px;margin-top:4px">⚠️ 安装过程约需 2-5 分钟，取决于 VPS 网络速度</p>
    </div>
    <form method="POST" onsubmit="return confirm('Install semua service? Proses 2-5 menit.')"><?= csrf_field() ?>
      <input type="hidden" name="action" value="install_all">
      <label style="font-size:13px;color:var(--text2);display:inline-flex;align-items:center;gap:6px;margin-right:12px"><input type="checkbox" name="with_mysql" value="1" <?= is_mysql_available() ? '' : 'checked' ?>> 同时安装 MySQL/MariaDB</label>
      <button class="btn btn-green" style="font-size:16px;padding:14px 28px;white-space:nowrap">⚡ 一键安装 (<?= is_mysql_available() ? 'LEMP Stack' : 'LNMP（SQLite 模式，不含 MySQL）' ?>)</button>
    </form>
  </div>
</div>
<?php endif; ?>

<div class="card">
  <h2>⚙️ 服务状态与控制</h2>
</div>

<div class="service-grid">
  <!-- Nginx -->
  <div class="service-card">
    <div class="svc-icon">🌐</div>
    <div class="svc-name">Nginx Web Server</div>
    <small style="color:var(--text2);display:block;margin-bottom:8px"><?= sanitize(trim(cmd('nginx -v 2>&1') ?: 'nginx')) ?: 'Reverse proxy & static files' ?></small>
    <?php if($nginx_installed): ?>
      <div class="svc-status"><span class="badge <?= $nginx_ok?'badge-ok':'badge-err' ?>"><?= $nginx_ok?'🟢 Running':'🔴 Stopped' ?></span></div>
      <div style="display:flex;gap:6px;justify-content:center;flex-wrap:wrap">
        <?php if(!$nginx_ok): ?><form method="POST"><?= csrf_field() ?><input type="hidden" name="action" value="svc_action"><input type="hidden" name="svc" value="nginx"><input type="hidden" name="svc_action" value="start"><button class="btn btn-green btn-sm">▶ Start</button></form><?php endif; ?>
        <?php if($nginx_ok): ?><form method="POST"><?= csrf_field() ?><input type="hidden" name="action" value="svc_action"><input type="hidden" name="svc" value="nginx"><input type="hidden" name="svc_action" value="stop"><button class="btn btn-red btn-sm">⏹ Stop</button></form><?php endif; ?>
        <form method="POST"><?= csrf_field() ?><input type="hidden" name="action" value="svc_action"><input type="hidden" name="svc" value="nginx"><input type="hidden" name="svc_action" value="restart"><button class="btn btn-yellow btn-sm">🔄 重启</button></form>
        <form method="POST"><?= csrf_field() ?><input type="hidden" name="action" value="svc_action"><input type="hidden" name="svc" value="nginx"><input type="hidden" name="svc_action" value="reload"><button class="btn btn-blue btn-sm">↻ Reload</button></form>
      </div>
    <?php else: ?>
      <div class="svc-status"><span class="badge badge-err">❌ Not Installed</span></div>
      <form method="POST"><?= csrf_field() ?><input type="hidden" name="action" value="install_svc"><input type="hidden" name="svc" value="nginx"><button class="btn btn-green btn-sm">📦 Install Nginx</button></form>
    <?php endif; ?>
  </div>

  <!-- PHP -->
  <div class="service-card">
    <div class="svc-icon">🐘</div>
    <div class="svc-name">PHP <?= selected_php_version() ?>-FPM</div>
    <small style="color:var(--text2);display:block;margin-bottom:8px">curl, gd, mbstring, xml, zip, intl（扩展可在 PHP 页管理）</small>
    <?php if($php_installed): ?>
      <div class="svc-status"><span class="badge <?= $php_ok?'badge-ok':'badge-err' ?>"><?= $php_ok?'🟢 Running':'🔴 Stopped' ?></span></div>
      <div style="display:flex;gap:6px;justify-content:center;flex-wrap:wrap">
        <?php if(!$php_ok): ?><form method="POST"><?= csrf_field() ?><input type="hidden" name="action" value="svc_action"><input type="hidden" name="svc" value="php"><input type="hidden" name="svc_action" value="start"><button class="btn btn-green btn-sm">▶ Start</button></form><?php endif; ?>
        <?php if($php_ok): ?><form method="POST"><?= csrf_field() ?><input type="hidden" name="action" value="svc_action"><input type="hidden" name="svc" value="php"><input type="hidden" name="svc_action" value="stop"><button class="btn btn-red btn-sm">⏹ Stop</button></form><?php endif; ?>
        <form method="POST"><?= csrf_field() ?><input type="hidden" name="action" value="svc_action"><input type="hidden" name="svc" value="php"><input type="hidden" name="svc_action" value="restart"><button class="btn btn-yellow btn-sm">🔄 重启</button></form>
      </div>
    <?php else: ?>
      <div class="svc-status"><span class="badge badge-err">❌ Not Installed</span></div>
      <form method="POST"><?= csrf_field() ?><input type="hidden" name="action" value="install_svc"><input type="hidden" name="svc" value="php"><button class="btn btn-green btn-sm">📦 Install PHP <?= selected_php_version() ?></button></form>
    <?php endif; ?>
  </div>

  <!-- MySQL -->
  <div class="service-card">
    <div class="svc-icon">🗄️</div>
    <div class="svc-name">MariaDB / MySQL</div>
    <small style="color:var(--text2);display:block;margin-bottom:8px">Database server v10.6+</small>
    <?php if($mysql_installed): ?>
      <div class="svc-status"><span class="badge <?= $mysql_ok?'badge-ok':'badge-err' ?>"><?= $mysql_ok?'🟢 Running':'🔴 Stopped' ?></span></div>
      <div style="display:flex;gap:6px;justify-content:center;flex-wrap:wrap">
        <?php if(!$mysql_ok): ?><form method="POST"><?= csrf_field() ?><input type="hidden" name="action" value="svc_action"><input type="hidden" name="svc" value="mysql"><input type="hidden" name="svc_action" value="start"><button class="btn btn-green btn-sm">▶ Start</button></form><?php endif; ?>
        <?php if($mysql_ok): ?><form method="POST"><?= csrf_field() ?><input type="hidden" name="action" value="svc_action"><input type="hidden" name="svc" value="mysql"><input type="hidden" name="svc_action" value="stop"><button class="btn btn-red btn-sm">⏹ Stop</button></form><?php endif; ?>
        <form method="POST"><?= csrf_field() ?><input type="hidden" name="action" value="svc_action"><input type="hidden" name="svc" value="mysql"><input type="hidden" name="svc_action" value="restart"><button class="btn btn-yellow btn-sm">🔄 重启</button></form>
      </div>
    <?php else: ?>
      <div class="svc-status"><span class="badge badge-err">❌ Not Installed</span></div>
      <form method="POST"><?= csrf_field() ?><input type="hidden" name="action" value="install_svc"><input type="hidden" name="svc" value="mysql"><button class="btn btn-green btn-sm">📦 Install MariaDB</button></form>
    <?php endif; ?>
  </div>

  <!-- phpMyAdmin -->
  <div class="service-card">
    <div class="svc-icon">🛢️</div>
    <div class="svc-name">phpMyAdmin</div>
    <small style="color:var(--text2);display:block;margin-bottom:8px">Database management via web UI</small>
    <?php if($pma_installed): ?>
      <div class="svc-status"><span class="badge badge-ok">✅ Installed</span></div>
      <a href="/pma/" target="_blank" class="btn btn-blue btn-sm">🔗 Buka phpMyAdmin</a>
    <?php else: ?>
      <div class="svc-status"><span class="badge badge-err">❌ Not Installed</span></div>
      <form method="POST"><?= csrf_field() ?><input type="hidden" name="action" value="install_svc"><input type="hidden" name="svc" value="phpmyadmin"><button class="btn btn-green btn-sm">📦 Install phpMyAdmin</button></form>
    <?php endif; ?>
  </div>
</div>

<div class="card" style="margin-top:20px">
  <h2>📋 系统信息</h2>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;font-size:13px">
    <div><strong style="color:var(--text2)">OS:</strong> <?= trim(cmd('lsb_release -d 2>/dev/null | cut -f2') ?: cmd('cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d \'"\'')) ?></div>
    <div><strong style="color:var(--text2)">Kernel:</strong> <?= trim(cmd('uname -r')) ?></div>
    <div><strong style="color:var(--text2)">CPU:</strong> <?= trim(cmd("grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2")) ?></div>
    <div><strong style="color:var(--text2)">Memory:</strong> <?= trim($mem_info) ?></div>
    <div><strong style="color:var(--text2)">Disk:</strong> <?= disk_free() ?>GB free / <?= disk_total() ?>GB</div>
    <div><strong style="color:var(--text2)">Uptime:</strong> <?= $uptime ?></div>
  </div>
</div>

<?php
// ===== PHP VERSIONS =====
elseif ($page === 'php'):
  $all_versions = ['8.2','8.3','8.4','8.5'];
  $installed = [];
  if (is_rhel()) {
    // RHEL 系：默认只装一个无版本号 PHP（/usr/bin/php），按实际 CLI 版本报告
    $rv = trim(cmd("php -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;' 2>/dev/null") ?: '');
    if (in_array($rv, $all_versions, true)) {
      $ext_count = count(explode("\n", trim(cmd("php -m 2>/dev/null") ?: '')));
      $installed[$rv] = ['fpm' => svc_status('php-fpm'), 'extensions' => $ext_count];
    }
  } else {
  foreach ($all_versions as $v) {
    if (file_exists(php_bin($v))) {
      $fpm_ok = svc_status(is_alpine() ? 'php-fpm' . str_replace('.', '', $v) : "php$v-fpm");
      $ext_count = count(explode("\n", trim(cmd(escapeshellarg(php_bin($v)) . " -m 2>/dev/null") ?: '')));
      $installed[$v] = ['fpm' => $fpm_ok, 'extensions' => $ext_count];
    }
  }
  }
  $default_cli = trim(cmd("php -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;' 2>/dev/null") ?: '?');
?>
<div class="card"><h2>🐘 PHP Version Manager</h2></div>

<div class="stats">
  <div class="stat"><div class="val"><?= count($installed) ?></div><div class="lbl">已安装版本</div></div>
  <div class="stat"><div class="val" style="font-size:18px"><?= $default_cli ?></div><div class="lbl">Default CLI</div></div>
  <div class="stat"><div class="val"><?= count(array_filter($installed, fn($i) => $i['fpm'])) ?></div><div class="lbl">FPM Running</div></div>
</div>

<div class="card"><h2>📦 已安装版本</h2>
  <?php if(empty($installed)): ?>
    <p style="color:var(--text2);text-align:center;padding:40px">尚未安装任何 PHP 版本。从下方列表安装。</p>
  <?php else: ?>
  <table><thead><tr><th>版本</th><th>FPM 状态</th><th>扩展</th><th>CLI</th><th>操作</th></tr></thead><tbody>
  <?php foreach($installed as $v => $info): ?>
  <tr>
    <td><strong style="font-size:16px">🐘 PHP <?= $v ?></strong></td>
    <td><span class="badge <?= $info['fpm']?'badge-ok':'badge-err' ?>"><?= $info['fpm']?'🟢 Running':'🔴 Stopped' ?></span></td>
    <td><?= $info['extensions'] ?> modules</td>
    <td><?= $v === $default_cli ? '<span class="badge badge-ok">✅ Default</span>' : '' ?></td>
    <td>
      <?php if($v !== $default_cli): ?><form method="POST" style="display:inline"><?= csrf_field() ?><input type="hidden" name="action" value="php_default"><input type="hidden" name="version" value="<?= $v ?>"><button class="btn btn-blue btn-xs">⭐ Set Default</button></form><?php endif; ?>
      <form method="POST" style="display:inline" <?= confirm_attr('删除 PHP ' . $v . '？') ?>><?= csrf_field() ?><input type="hidden" name="action" value="php_remove"><input type="hidden" name="version" value="<?= $v ?>"><button class="btn btn-red btn-xs">🗑️</button></form>
    </td>
  </tr>
  <?php endforeach; ?>
  </tbody></table>
  <?php endif; ?>
</div>

<div class="card"><h2>📥 Install PHP Version</h2>
  <div style="display:flex;flex-wrap:wrap;gap:8px">
    <?php foreach($all_versions as $v): $is_installed = isset($installed[$v]); ?>
    <form method="POST" style="display:inline" <?= confirm_attr('安装 PHP ' . $v . '？（约 5-10 分钟）') ?>><?= csrf_field() ?>
      <input type="hidden" name="action" value="php_install">
      <input type="hidden" name="version" value="<?= $v ?>">
      <button class="btn <?= $is_installed?'btn-gray':'btn-green' ?> btn-sm" <?= $is_installed?'disabled title="Sudah 已安装"':'' ?>>
        🐘 PHP <?= $v ?> <?= $is_installed?'✅':'' ?>
      </button>
    </form>
    <?php endforeach; ?>
  </div>
  <p style="font-size:11px;color:var(--text2);margin-top:12px">
    ⚠️ Setiap versi include: FPM, CLI, MySQL, cURL, GD, MBString, XML, ZIP, Intl, BCMath<br>
    📦 Sumber: ondrej/php PPA (auto-add)
  </p>
</div>

<div class="card"><h2>🧩 PHP 扩展管理</h2>
  <p style="font-size:12px;color:var(--text2);margin-bottom:12px">常用扩展一键安装/卸载，操作后台执行并自动重载 FPM。🟢=已启用</p>
  <div id="extwrap" style="overflow-x:auto"><p style="color:var(--text2)">加载中...</p></div>
  <script>
  (function(){
    var EXTS = ['opcache','apcu','redis','igbinary','imagick','memcached','swoole','xdebug','ssh2','zstd','yaml','grpc'];
    var CSRF = '<?= csrf_field() ?>';
    fetch('?php_ext_scan=1').then(r=>r.json()).then(function(data){
      var html = '<table><thead><tr><th>扩展</th>';
      var vers = Object.keys(data);
      vers.forEach(function(v){ html += '<th>PHP '+v+'</th>'; });
      html += '</tr></thead><tbody>';
      EXTS.forEach(function(e){
        html += '<tr><td><strong>'+e+'</strong></td>';
        vers.forEach(function(v){
          var on = data[v] && data[v][e];
          html += '<td>'+(on
            ? '<form method="POST" style="display:inline" onsubmit="return confirm(\'卸载 '+e+' (PHP '+v+')?\')"><?= csrf_field() ?>'+CSRF+'<input type="hidden" name="action" value="php_ext_toggle"><input type="hidden" name="version" value="'+v+'"><input type="hidden" name="ext" value="'+e+'"><input type="hidden" name="op" value="remove"><button class="btn btn-red btn-xs" title="已启用，点击卸载">🟢 卸载</button></form>'
            : '<form method="POST" style="display:inline">'+CSRF+'<input type="hidden" name="action" value="php_ext_toggle"><input type="hidden" name="version" value="'+v+'"><input type="hidden" name="ext" value="'+e+'"><input type="hidden" name="op" value="install"><button class="btn btn-green btn-xs" title="未启用，点击安装">⚪ 安装</button></form>')+'</td>';
        });
        html += '</tr>';
      });
      html += '</tbody></table>';
      document.getElementById('extwrap').innerHTML = html;
    }).catch(function(){ document.getElementById('extwrap').innerHTML = '<p style="color:var(--red)">加载失败</p>'; });
  })();
  </script>
</div>

<div class="card"><h2>🔄 Website PHP Versions</h2>
  <p style="font-size:12px;color:var(--yellow);margin-bottom:12px">⚠️ 切换前, 请确认网站代码兼容目标 PHP 版本。<br>例如： arrow function <code>fn()</code> hanya support PHP 7.4+. Kalau error 500 setelah switch, balikkan ke versi se尚未nya.</p>
  <?php
  // Scan all nginx configs for PHP socket version
  $site_php = [];
  foreach (glob(NGINX_AVAILABLE . '/*') as $f) {
    $cfg = @file_get_contents($f) ?: '';
    if (strpos($cfg, 'server {') === false) continue; // RHEL conf.d 内部片段
    $cfg_name = preg_replace('/\.conf$/', '', basename($f));
    if ($cfg_name === 'default' || strpos($cfg_name, '.bak.') !== false) continue;
    preg_match('/server_name\s+([^;]+);/', $cfg, $sn);
    $domain = trim(explode(' ', $sn[1] ?? '')[0] ?? '');
    if ($domain === '_' || strpos($domain, '.') === false || strpos($cfg, 'proxy_pass http://127.0.0.1:9001') !== false) continue;
    if ($domain === '_' || !str_contains($domain, '.')) continue; // 反代/兜底 server
    preg_match('/unix:(?:\/var\/run\/php\/php([\d.]+)-fpm\.sock|\/run\/php-fpm(\d+)\/php-fpm\.sock)/', $cfg, $phpm);
    if (isset($phpm[2])) { $php_ver = $phpm[2][0] . '.' . substr($phpm[2], 1); } else { $php_ver = $phpm[1] ?? '?'; }
    $site_php[] = ['domain' => $domain, 'php' => $php_ver, 'cfg_name' => $cfg_name];
  }
  if (empty($site_php)): ?>
    <p style="color:var(--text2);text-align:center;padding:40px">还没有 website.</p>
  <?php else: ?>
  <table><thead><tr><th>网站</th><th>PHP 版本</th><th>切换到</th></tr></thead><tbody>
  <?php foreach($site_php as $sp): ?>
  <tr>
    <td><strong><?= sanitize($sp['domain']) ?></strong></td>
    <td><span class="badge <?= isset($installed[$sp['php']])?'badge-ok':'badge-err' ?>">🐘 PHP <?= $sp['php'] ?></span></td>
    <td>
      <form method="POST" style="display:flex;gap:6px;align-items:center"><?= csrf_field() ?>
        <input type="hidden" name="action" value="php_switch_site">
        <input type="hidden" name="domain" value="<?= sanitize($sp['domain']) ?>">
        <select name="version" style="padding:6px 10px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:6px;font-size:12px">
          <?php foreach($installed as $v => $info): ?><option value="<?= $v ?>" <?= $v===$sp['php']?'selected':'' ?>>PHP <?= $v ?></option><?php endforeach; ?>
        </select>
        <button class="btn btn-green btn-xs" onclick="return confirm(<?= js_str('将 ' . $sp['domain'] . ' 切换到此 PHP 版本？') ?>)">🔄 Switch</button>
      </form>
    </td>
  </tr>
  <?php endforeach; ?>
  </tbody></table>
  <?php endif; ?>
</div>

<?php
// ===== SSL =====
elseif ($page === 'ssl'):
  $certbot_ok = is_executable('/usr/bin/certbot');
  $timer_ok = svc_status('certbot.timer') || (is_alpine() && trim(cmd('crontab -l 2>/dev/null | grep -c certbot || true')) !== '0');
  
  // Get SSL status for each site
  $ssl_sites = [];
  foreach (glob(NGINX_AVAILABLE . '/*') as $f) {
    if (is_link($f) && strpos((string)@readlink($f), $f) !== false) continue;
    $cfg_name = preg_replace('/\.conf$/', '', basename($f));
    if ($cfg_name === 'default' || strpos($cfg_name, '.bak.') !== false) continue; // 备份与 default 排除
    $cfg = @file_get_contents($f);
    if ($cfg === false || strpos($cfg, 'server {') === false || strpos($cfg, 'server_name') === false) continue; // 非 server 块 conf（php-fpm.conf 等）
    preg_match('/server_name\s+([^;]+);/', $cfg, $sn);
    $domains = preg_split('/\s+/', trim($sn[1] ?? ''));
    $domain = $domains[0] ?? '';
    if ($domain === '' || $domain === '_' || strpos($domain, '.') === false || strpos($domain, 'vps-manager') !== false) continue; // 面板 conf/默认/无点域名
    if (strpos($cfg, 'proxy_pass http://127.0.0.1:9001') !== false) continue; // 面板反代 conf
    $has_ssl = strpos($cfg, 'ssl_certificate') !== false;
    $cert_path = '/etc/letsencrypt/live/' . $domain;
    $cert_exists = is_dir($cert_path);
    $expiry = '';
    if ($cert_exists) {
      $expiry_out = cmd("openssl x509 -enddate -noout -in $cert_path/fullchain.pem 2>/dev/null");
      preg_match('/notAfter=(.+)/', $expiry_out ?? '', $em);
      $expiry = $em[1] ?? '';
      if ($expiry) {
        $exp = strtotime($expiry);
        $days = ceil(($exp - time()) / 86400);
        $expiry = date('d/m/Y', $exp) . " ($days days left)";
      }
    }
    $ssl_sites[] = ['domain' => $domain, 'ssl' => $has_ssl, 'cert_exists' => $cert_exists, 'expiry' => $expiry, 'cfg_name' => $cfg_name];
  }
?>

<div class="card">
  <h2>🔒 SSL 证书管理</h2>
</div>

<div class="card">
  <h3>🛡️ 面板自身 HTTPS（自签证书）</h3>
  <p style="color:var(--text2);font-size:13px">为面板本身启用 HTTPS。自签证书 10 年有效，浏览器首次访问需手动信任（点"高级→继续前往"）。加密强度与正规证书相同。</p>
  <?php $pcf = is_alpine() ? '/etc/nginx/http.d/vps-manager.conf' : (is_rhel() ? '/etc/nginx/conf.d/vps-manager.conf' : '/etc/nginx/sites-available/vps-manager');
  $panel_https = is_file($pcf) && strpos(file_get_contents($pcf), 'ssl_certificate') !== false; ?>
  <?php if ($panel_https): ?>
    <p style="color:#4ade80;font-size:13px">✅ 当前已启用 HTTPS（证书：/etc/nginx/ssl/panel/）</p>
  <?php else: ?>
    <p style="color:var(--text2);font-size:13px">当前为 HTTP 模式</p>
  <?php endif; ?>
  <form method="POST" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><?= csrf_field() ?>
    <input type="hidden" name="action" value="panel_https_toggle">
    <select name="pmode" style="padding:8px 12px;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--foreground)">
      <option value="on">HTTPS（8080 端口直接 https 访问）</option>
      <option value="redirect">HTTP 跳转 HTTPS（8080 → https://IP:8443）</option>
      <?php if ($panel_https): ?><option value="off">关闭 HTTPS（还原纯 HTTP）</option><?php endif; ?>
    </select>
    <button class="btn btn-blue btn-sm">应用</button>
  </form>
</div>

<?php if(!$certbot_ok): ?>
<div class="card" style="border:2px solid var(--yellow)">
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px">
    <div>
      <strong style="color:var(--yellow)">⚠️ Certbot 尚未 已安装</strong>
      <p style="font-size:13px;color:var(--text2)">安装与续期 Let's Encrypt 证书需要 Certbot</p>
    </div>
    <form method="POST"><?= csrf_field() ?><input type="hidden" name="action" value="install_certbot"><button class="btn btn-green">📦 Install Certbot</button></form>
  </div>
</div>
<?php else: ?>

<div class="stats">
  <div class="stat">
    <div class="val <?= $timer_ok?'':'warn' ?>"><?= $timer_ok?'🟢 Active':'⚠️ Off' ?></div>
    <div class="lbl">自动续期定时器</div>
  </div>
  <div class="stat">
    <div class="val"><?= count($ssl_sites) ?></div>
    <div class="lbl">监控站点数</div>
  </div>
  <div class="stat">
    <div class="val"><?= count(array_filter($ssl_sites, fn($s) => $s['ssl'])) ?>/<?= count($ssl_sites) ?></div>
    <div class="lbl">SSL Active</div>
  </div>
</div>

<div class="actions">
  <button onclick="showModal('installSslModal')" class="btn btn-green">🔒 Install SSL</button>
  <form method="POST" style="display:inline" onsubmit="return confirm('Renew semua sertifikat SSL sekarang?')"><?= csrf_field() ?>
    <input type="hidden" name="action" value="ssl_renew">
    <button class="btn btn-blue">🔄 Renew All Now</button>
  </form>
  <?php if(!$timer_ok): ?>
  <form method="POST" style="display:inline"><?= csrf_field() ?>
    <input type="hidden" name="action" value="ssl_autorenew">
    <button class="btn btn-yellow">⏰ Enable Auto-Renew</button>
  </form>
  <?php endif; ?>
</div>

<?php endif; ?>

<div class="card">
  <h2>🌐 Website SSL Status</h2>
  <?php if(empty($ssl_sites)): ?>
    <p style="color:var(--text2);text-align:center;padding:40px">暂无网站。请先到 🌐 网站菜单创建。</p>
  <?php else: ?>
  <table>
    <thead><tr><th>域名</th><th>SSL</th><th>证书</th><th>到期</th><th>操作</th></tr></thead>
    <tbody>
    <?php foreach($ssl_sites as $s): ?>
    <tr>
      <td><strong><?= sanitize($s['domain']) ?></strong></td>
      <td><span class="badge <?= $s['ssl']?'badge-ok':'badge-err' ?>"><?= $s['ssl']?'🔒 Active':'❌ No SSL' ?></span></td>
      <td><span class="badge <?= $s['cert_exists']?'badge-ok':'badge-err' ?>"><?= $s['cert_exists']?'✅ Valid':'❌ None' ?></span></td>
      <td style="font-size:12px;color:<?= (strpos($s['expiry'],'days')!==false && (int)$s['expiry']<30)?'var(--red)':'var(--text2)' ?>"><?= $s['expiry'] ?: '—' ?></td>
      <td>
        <?php if(!$s['ssl']): ?>
        <form method="POST" style="display:inline" <?= confirm_attr('为 ' . $s['domain'] . ' 安装 SSL？') ?>><?= csrf_field() ?>
          <input type="hidden" name="action" value="ssl_install">
          <input type="hidden" name="domain" value="<?= sanitize($s['domain']) ?>">
          <input type="hidden" name="email" value="admin@<?= sanitize($s['domain']) ?>">
          <button class="btn btn-green btn-xs">🔒 Install SSL</button>
        </form>
        <?php else: ?>
        <a href="https://<?= $s['domain'] ?>" target="_blank" class="btn btn-blue btn-xs">🔗 Test</a>
        <?php endif; ?>
      </td>
    </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  <?php endif; ?>
</div>

<!-- Install SSL Modal -->
<div id="installSslModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:999;display:none;align-items:center;justify-content:center" onclick="if(event.target===this)hideModal('installSslModal')">
  <div style="background:var(--surface);border-radius:var(--radius);width:90%;max-width:450px;border:1px solid var(--border);padding:24px">
    <h3 style="font-size:18px;color:var(--green);margin-bottom:20px">🔒 Install SSL Certificate</h3>
    <form method="POST"><?= csrf_field() ?>
      <input type="hidden" name="action" value="ssl_install">
      <div class="form-group" style="margin-bottom:14px">
        <label>Domain *</label>
        <select name="domain" style="width:100%;padding:10px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:8px">
          <?php foreach($ssl_sites as $s): if(!$s['ssl']): ?><option value="<?= sanitize($s['domain']) ?>"><?= sanitize($s['domain']) ?></option><?php endif; endforeach; ?>
        </select>
        <small>选择 domain yg 还没有 SSL</small>
      </div>
      <div class="form-group" style="margin-bottom:20px">
        <label>邮箱（Let's Encrypt）</label>
        <input name="email" placeholder="admin@domain.com">
        <small>用于到期提醒</small>
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end">
        <button type="button" onclick="hideModal('installSslModal')" class="btn btn-gray">取消</button>
        <button type="submit" class="btn btn-green">🔒 Install SSL</button>
      </div>
    </form>
  </div>
</div>

<script>
function showModal(id) { document.getElementById(id).style.display = 'flex'; }
function hideModal(id) { document.getElementById(id).style.display = 'none'; }
</script>

<?php
// ===== MONITOR =====
elseif ($page === 'monitor'):
  $cpu = trim(cmd("top -bn1 | grep 'Cpu(s)' | awk '{print \$2+\$4}' 2>/dev/null") ?: '0');
  $mem_total = trim(cmd("free -m | grep Mem | awk '{print \$2}'"));
  $mem_used = trim(cmd("free -m | grep Mem | awk '{print \$3}'"));
  $mem_pct = $mem_total > 0 ? round($mem_used / $mem_total * 100) : 0;
  $disk_info = [];
  $df = cmd("df -h --type=ext4 --type=xfs 2>/dev/null || df -h / 2>/dev/null");
  foreach (explode("\n", trim($df)) as $i => $line) {
    if ($i === 0) continue;
    $p = preg_split('/\s+/', trim($line));
    if (count($p) >= 6) $disk_info[] = ['fs' => $p[0], 'size' => $p[1], 'used' => $p[2], 'avail' => $p[3], 'pct' => $p[4], 'mount' => $p[5]];
  }
  $net_rx = trim(cmd("cat /sys/class/net/eth0/statistics/rx_bytes 2>/dev/null || cat /sys/class/net/ens3/statistics/rx_bytes 2>/dev/null || echo 0"));
  $net_tx = trim(cmd("cat /sys/class/net/eth0/statistics/tx_bytes 2>/dev/null || cat /sys/class/net/ens3/statistics/tx_bytes 2>/dev/null || echo 0"));
  $load = sys_getloadavg();
  $uptime = uptime_str();
  $procs = proc_top(10);
?>
<div class="card"><h2>📊 系统监控</h2>
  <p style="color:var(--text2);font-size:13px">实时曲线（每 5 秒刷新，历史保留 1 小时，仅存内存 /dev/shm，重启即清空）</p>
</div>
<div class="card">
  <canvas id="mChart" height="180" style="width:100%"></canvas>
  <div style="display:flex;gap:20px;font-size:12px;color:var(--text2);margin-top:8px;flex-wrap:wrap">
    <span><span style="color:#4f8ef7">━</span> CPU %</span>
    <span><span style="color:#f59e0b">━</span> 内存 %</span>
    <span><span style="color:#10b981">━</span> 负载 ×100</span>
  </div>
</div>
<script>
(function(){
  var cv=document.getElementById('mChart'), ctx=cv.getContext('2d');
  var hist=[], timer=null;
  function draw(){
    var W=cv.width=cv.parentNode.clientWidth-40, H=cv.height=180;
    ctx.clearRect(0,0,W,H);
    // 网格
    ctx.strokeStyle='rgba(128,128,128,.15)'; ctx.lineWidth=1;
    for(var g=0;g<=4;g++){var y=10+g*(H-30)/4;ctx.beginPath();ctx.moveTo(40,y);ctx.lineTo(W,y);ctx.stroke();
      ctx.fillStyle='#888';ctx.font='11px sans-serif';ctx.fillText((100-g*25)+'',8,y+4);}
    if(hist.length<2)return;
    var n=hist.length, step=(W-50)/(720-1), x0=W-50-(n-1)*step;
    function line(get,color,scale){
      ctx.strokeStyle=color;ctx.lineWidth=2;ctx.beginPath();
      for(var i=0;i<n;i++){var v=Math.min(get(hist[i])/scale,1.05);var x=x0+i*step,y=10+(1-v)*(H-30);i?ctx.lineTo(x,y):ctx.moveTo(x,y);}
      ctx.stroke();
    }
    line(function(h){return h.cpu;},'#4f8ef7',100);
    line(function(h){return h.mem;},'#f59e0b',100);
    line(function(h){return h.load*100;},'#10b981',100);
  }
  function poll(){
    fetch('?api=metrics',{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){
      hist=d.hist;
      var el=document.getElementById('m-now');
      if(el) el.textContent='CPU '+d.now.cpu+'% · 内存 '+d.now.mem+'% · 负载 '+d.now.load;
      draw();
    }).catch(function(){});
  }
  poll(); timer=setInterval(poll,5000);
  window.addEventListener('resize',draw);
})();
</script>
<div class="card"><h3 style="margin:0;font-size:14px" id="m-now">加载中…</h3></div>
<div class="stats">
  <div class="stat"><div class="val" style="color:<?= $cpu>80?'var(--red)':($cpu>50?'var(--yellow)':'var(--green)') ?>"><?= $cpu ?>%</div><div class="lbl">CPU Usage</div></div>
  <div class="stat"><div class="val" style="color:<?= $mem_pct>80?'var(--red)':($mem_pct>50?'var(--yellow)':'var(--green)') ?>"><?= $mem_pct ?>%</div><div class="lbl">Memory (<?= $mem_used ?>M/<?= $mem_total ?>M)</div></div>
  <div class="stat"><div class="val"><?= round($load[0], 2) ?></div><div class="lbl">负载均衡</div></div>
  <div class="stat"><div class="val" style="font-size:14px"><?= $uptime ?></div><div class="lbl">Uptime</div></div>
</div>
<div class="card"><h2>💾 磁盘</h2>
  <table><thead><tr><th>文件系统</th><th>大小</th><th>已用</th><th>可用</th><th>Use%</th><th>挂载点</th></tr></thead><tbody>
  <?php foreach($disk_info as $d): ?>
  <tr><td><?= $d['fs'] ?></td><td><?= $d['size'] ?></td><td><?= $d['used'] ?></td><td><?= $d['avail'] ?></td><td><?= $d['pct'] ?></td><td><?= $d['mount'] ?></td></tr>
  <?php endforeach; ?>
  </tbody></table>
</div>
<div class="card"><h2>🌐 网络</h2>
  <div class="stats">
    <div class="stat"><div class="val" style="font-size:18px"><?= round($net_rx/1073741824, 2) ?> GB</div><div class="lbl">累计下载</div></div>
    <div class="stat"><div class="val" style="font-size:18px"><?= round($net_tx/1073741824, 2) ?> GB</div><div class="lbl">累计上传</div></div>
  </div>
</div>
<div class="card"><h2>🔝 资源占用排行</h2>
  <table><thead><tr><th>CPU%</th><th>MEM%</th><th>进程</th></tr></thead><tbody>
  <?php foreach(array_slice(explode("\n", trim($procs)), 1) as $pl): $pp = preg_split('/\s+/', trim($pl)); if(count($pp)>=3): ?>
  <tr><td><?= $pp[0] ?></td><td><?= $pp[1] ?></td><td style="font-family:monospace;font-size:12px"><?= sanitize($pp[2]) ?></td></tr>
  <?php endif; endforeach; ?>
  </tbody></table>
</div>

<?php
// ===== FIREWALL =====
elseif ($page === 'firewall'):
  $fw_active = trim(cmd('ufw status 2>/dev/null | head -1 | grep -o active')) === 'active';
  $fw_rules = [];
  $raw = cmd('ufw status numbered 2>/dev/null');
  if ($raw) {
    foreach (explode("\n", $raw) as $line) {
      if (preg_match('/^\[\s*(\d+)\]\s+(.+)/', trim($line), $m)) {
        $fw_rules[] = ['num' => $m[1], 'rule' => trim($m[2])];
      }
    }
  }
?>
<div class="card"><h2>🛡️ Firewall (UFW)</h2></div>

<div class="card" style="border:2px solid <?= $fw_active?'var(--green)':'var(--red)' ?>">
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px">
    <div>
      <strong style="color:<?= $fw_active?'var(--green)':'var(--red)' ?>"><?= $fw_active?'🟢 Firewall AKTIF':'🔴 Firewall MATI' ?></strong>
      <p style="font-size:13px;color:var(--text2)"><?= $fw_active?'所有入站端口默认拒绝，出站放行':'端口未过滤 — VPS 暴露风险！' ?></p>
    </div>
    <form method="POST"><?= csrf_field() ?>
      <input type="hidden" name="action" value="fw_toggle">
      <input type="hidden" name="enable" value="<?= $fw_active?'0':'1' ?>">
      <button class="btn <?= $fw_active?'btn-red':'btn-green' ?>" onclick="return confirm(<?= js_str($fw_active?'关闭防火墙？':'启用防火墙？') ?>)"><?= $fw_active?'⏹ Disable':'▶ Enable Firewall' ?></button>
    </form>
  </div>
</div>

<?php if($fw_active): ?>
<div class="actions">
  <button onclick="showModal('addRuleModal')" class="btn btn-green">➕ Add Rule</button>
  <button onclick="showModal('quickPresets')" class="btn btn-blue">⚡ Quick Presets</button>
</div>

<div class="card"><h2>📋 规则</h2>
  <?php if(empty($fw_rules)): ?>
    <p style="color:var(--text2);text-align:center;padding:40px">暂无规则。请添加规则以放行所需端口。</p>
  <?php else: ?>
  <table><thead><tr><th>#</th><th>规则</th><th>操作</th></tr></thead><tbody>
  <?php foreach($fw_rules as $r): ?>
  <tr><td><?= $r['num'] ?></td><td><code style="font-size:13px"><?= sanitize($r['rule']) ?></code></td>
    <td><form method="POST" style="display:inline" <?= confirm_attr('删除规则 #' . $r['num'] . '？') ?>><?= csrf_field() ?><input type="hidden" name="action" value="fw_del"><input type="hidden" name="num" value="<?= $r['num'] ?>"><button class="btn btn-red btn-xs">🗑️</button></form></td></tr>
  <?php endforeach; ?>
  </tbody></table>
  <?php endif; ?>
</div>
<?php endif; ?>

<!-- Add Rule Modal -->
<div id="addRuleModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:999;display:none;align-items:center;justify-content:center" onclick="if(event.target===this)hideModal('addRuleModal')">
  <div style="background:var(--surface);border-radius:var(--radius);width:90%;max-width:400px;border:1px solid var(--border);padding:24px">
    <h3 style="margin-bottom:16px">➕ Add Firewall Rule</h3>
    <form method="POST"><?= csrf_field() ?>
      <input type="hidden" name="action" value="fw_add">
      <div class="form-group" style="margin-bottom:12px"><label>动作</label><select name="fw_action" style="width:100%;padding:10px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:8px"><option value="allow">✅ Allow</option><option value="deny">❌ Deny</option></select></div>
      <div class="form-group" style="margin-bottom:12px"><label>端口</label><input name="port" placeholder="80" required></div>
      <div class="form-group" style="margin-bottom:16px"><label>协议</label><select name="proto" style="width:100%;padding:10px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:8px"><option value="tcp">TCP</option><option value="udp">UDP</option></select></div>
      <div style="display:flex;gap:8px;justify-content:flex-end"><button type="button" onclick="hideModal('addRuleModal')" class="btn btn-gray">取消</button><button class="btn btn-green">添加规则</button></div>
    </form>
  </div>
</div>
<!-- Quick Presets Modal -->
<div id="quickPresets" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:999;display:none;align-items:center;justify-content:center" onclick="if(event.target===this)hideModal('quickPresets')">
  <div style="background:var(--surface);border-radius:var(--radius);width:90%;max-width:400px;border:1px solid var(--border);padding:24px">
    <h3 style="margin-bottom:16px">⚡ Quick Presets</h3>
    <p style="font-size:12px;color:var(--text2);margin-bottom:12px">点击放行常用端口：</p>
    <div style="display:flex;flex-wrap:wrap;gap:6px">
      <?php foreach([22=>'SSH',80=>'HTTP',443=>'HTTPS',8080=>'Panel',3306=>'MySQL',21=>'FTP',25=>'SMTP',53=>'DNS 管理'] as $p=>$l): ?>
      <form method="POST" style="display:inline"><?= csrf_field() ?><input type="hidden" name="action" value="fw_add"><input type="hidden" name="fw_action" value="allow"><input type="hidden" name="port" value="<?= $p ?>"><input type="hidden" name="proto" value="tcp"><button class="btn btn-blue btn-sm"><?= $p ?> (<?= $l ?>)</button></form>
      <?php endforeach; ?>
    </div>
    <button onclick="hideModal('quickPresets')" class="btn btn-gray" style="margin-top:16px;width:100%">关闭</button>
  </div>
</div>
<script>function showModal(id){document.getElementById(id).style.display='flex'}function hideModal(id){document.getElementById(id).style.display='none'}</script>

<?php
// ===== LOGS =====
elseif ($page === 'logs'):
  $log_type = $_GET['type'] ?? 'access';
  $log_site = basename($_GET['site'] ?? '');
  if ($log_site !== '' && !preg_match('/^[a-zA-Z0-9._-]+\.log$/', $log_site)) $log_site = '';
  $log_lines = intval($_GET['lines'] ?? 50);
  $log_content = '';
  $log_file = '';
  
  $sites_list = [];
  foreach (glob('/var/log/nginx/*access*') as $f) $sites_list[] = basename($f);
  foreach (glob('/var/log/nginx/*error*') as $f) $sites_list[] = basename($f);
  $sites_list = array_unique($sites_list);
  
  if ($log_type === 'access' && $log_site) $log_file = "/var/log/nginx/$log_site";
  elseif ($log_type === 'error' && $log_site) $log_file = "/var/log/nginx/$log_site";
  elseif ($log_type === 'sys') $log_file = '/var/log/syslog';
  elseif ($log_type === 'php') $log_file = is_alpine() ? '/var/log/php-fpm.log' : '/var/log/php' . selected_php_version() . '-fpm.log';
  elseif ($log_type === 'mysql') $log_file = '/var/log/mysql/error.log';
  
  if ($log_file && file_exists($log_file)) {
    $log_content = cmd("tail -n $log_lines " . escapeshellarg($log_file) . " 2>/dev/null");
  }
?>
<div class="card"><h2>📝 日志查看器</h2></div>

<div class="card">
  <form method="GET" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end">
    <input type="hidden" name="page" value="logs">
    <div class="form-group"><label>类型</label><select name="type" style="padding:10px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:8px"><option value="access" <?= $log_type==='access'?'selected':'' ?>>Nginx Access</option><option value="error" <?= $log_type==='error'?'selected':'' ?>>Nginx Error</option><option value="sys" <?= $log_type==='sys'?'selected':'' ?>>System (syslog)</option><option value="php" <?= $log_type==='php'?'selected':'' ?>>PHP-FPM</option><option value="mysql" <?= $log_type==='mysql'?'selected':'' ?>>MySQL</option></select></div>
    <?php if(in_array($log_type, ['access','error'])): ?>
    <div class="form-group"><label>站点</label><select name="site" style="padding:10px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:8px"><option value="">-- pilih --</option><?php foreach($sites_list as $s): ?><option value="<?= $s ?>" <?= $log_site===$s?'selected':'' ?>><?= $s ?></option><?php endforeach; ?></select></div>
    <?php endif; ?>
    <div class="form-group"><label>行数</label><input name="lines" value="<?= $log_lines ?>" style="width:80px;padding:10px"></div>
    <button class="btn btn-green">🔍 View</button>
  </form>
</div>

<?php if($log_file && file_exists($log_file)): ?>
<div class="card"><h3>📄 <?= basename($log_file) ?> (last <?= $log_lines ?> lines)</h3>
  <pre style="background:var(--bg);padding:16px;border-radius:8px;overflow:auto;max-height:600px;font-family:monospace;font-size:12px;line-height:1.6;color:#94a3b8"><?= sanitize($log_content) ?></pre>
</div>
<?php elseif($log_file): ?>
<div class="card"><p style="color:var(--text2);text-align:center;padding:40px">📂 文件未找到：<?= sanitize($log_file) ?></p></div>
<?php else: ?>
<div class="card"><p style="color:var(--text2);text-align:center;padding:40px">👆 选择日志类型和站点查看。</p></div>
<?php endif; ?>

<?php
// ===== CRON JOBS =====
elseif ($page === 'cron'):
  $crontab = cmd('crontab -l', false) ?: '';
  $cron_jobs = [];
  foreach (explode("\n", trim($crontab)) as $line) {
    $line = trim($line);
    if (empty($line) || $line[0] === '#') continue;
    if (preg_match('/^(@\w+|[\d*,\/\-]+\s+[\d*,\/\-]+\s+[\d*,\/\-]+\s+[\d*,\/\-]+\s+[\d*,\/\-]+)\s+(.+)/', $line, $m)) {
      $cron_jobs[] = ['schedule' => $m[1], 'command' => $m[2]];
    }
  }
?>
<div class="card"><h2>⏰ 定时任务</h2></div>

<div class="actions">
  <button onclick="showModal('cronAddModal')" class="btn btn-green">➕ Add Cron Job</button>
  <button onclick="showModal('cronPresets')" class="btn btn-blue">⚡ Common Presets</button>
</div>

<div class="card"><h2>📋 Scheduled Jobs (<?= count($cron_jobs) ?>)</h2>
  <?php if(empty($cron_jobs)): ?>
    <p style="color:var(--text2);text-align:center;padding:40px">暂无定时任务。点击添加。</p>
  <?php else: ?>
  <table><thead><tr><th>#</th><th>计划</th><th>命令</th><th>操作</th></tr></thead><tbody>
  <?php foreach($cron_jobs as $i => $j): ?>
  <tr>
    <td><?= $i + 1 ?></td>
    <td><code style="background:var(--bg);padding:3px 8px;border-radius:4px;font-size:12px"><?= sanitize($j['schedule']) ?></code></td>
    <td><code style="font-size:12px;color:var(--green)"><?= sanitize($j['command']) ?></code></td>
    <td><form method="POST" style="display:inline" <?= confirm_attr('删除 cron 任务 #' . ($i+1) . '？') ?>><?= csrf_field() ?><input type="hidden" name="action" value="cron_del"><input type="hidden" name="num" value="<?= $i+1 ?>"><button class="btn btn-red btn-xs">🗑️</button></form></td>
  </tr>
  <?php endforeach; ?>
  </tbody></table>
  <?php endif; ?>
</div>

<!-- Add Cron Modal -->
<div id="cronAddModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:999;display:none;align-items:center;justify-content:center" onclick="if(event.target===this)hideModal('cronAddModal')">
  <div style="background:var(--surface);border-radius:var(--radius);width:90%;max-width:550px;border:1px solid var(--border);padding:24px;max-height:90vh;overflow-y:auto">
    <h3 style="margin-bottom:16px">➕ Add Cron Job</h3>
    <form method="POST"><?= csrf_field() ?>
      <input type="hidden" name="action" value="cron_add">
      <div class="form-group" style="margin-bottom:12px"><label>Schedule (cron expression) *</label><input name="expr" placeholder="*/5 * * * *  (setiap 5 menit)" required><small style="font-size:11px;color:var(--text2)">Format: menit jam hari bulan hari-minggu | <b>* * * * *</b> = setiap menit</small></div>
      <div class="form-group" style="margin-bottom:16px"><label>Command *</label><input name="cmd" placeholder="php /var/www/manager/cron.php" required></div>
      <div style="display:flex;gap:8px;justify-content:flex-end"><button type="button" onclick="hideModal('cronAddModal')" class="btn btn-gray">取消</button><button class="btn btn-green">添加任务</button></div>
    </form>
  </div>
</div>

<!-- Cron Presets Modal -->
<div id="cronPresets" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:999;display:none;align-items:center;justify-content:center" onclick="if(event.target===this)hideModal('cronPresets')">
  <div style="background:var(--surface);border-radius:var(--radius);width:90%;max-width:550px;border:1px solid var(--border);padding:24px">
    <h3 style="margin-bottom:16px">⚡ Common Presets</h3>
    <div style="display:flex;flex-direction:column;gap:6px">
      <?php
      $presets = [
        ['0 2 * * *', 'certbot renew --quiet && nginx -s reload', '🔄 Renew SSL setiap jam 2 pagi'],
        ['0 3 * * 0', '(mysqldump -u root --all-databases || mariadb-dump -u root --all-databases) > /var/backups/db_$(date +\%Y\%m\%d).sql', '💾 Backup semua DB setiap Minggu jam 3'],
        ['*/30 * * * *', 'find /tmp -type f -mmin +60 -delete', '🧹 Bersihkan /tmp setiap 30 menit'],
        ['0 4 * * *', is_alpine() ? 'apk update -q && apk upgrade -q' : 'apt-get update -qq && apt-get upgrade -y -qq', '📦 每日 4 点自动更新系统'],
        ['0 0 1 * *', 'nginx -t && ' . (is_alpine() ? 'rc-service nginx reload' : 'systemctl reload nginx'), '🔄 每月1日重载 Nginx'],
      ];
      foreach($presets as $p): ?>
      <form method="POST" style="display:inline"><?= csrf_field() ?><input type="hidden" name="action" value="cron_add"><input type="hidden" name="expr" value="<?= $p[0] ?>"><input type="hidden" name="cmd" value="<?= sanitize($p[1]) ?>"><button class="btn btn-blue btn-sm" style="text-align:left;width:100%"><?= $p[2] ?><br><small style="opacity:0.7"><?= $p[0] ?> <?= sanitize($p[1]) ?></small></button></form>
      <?php endforeach; ?>
    </div>
    <button onclick="hideModal('cronPresets')" class="btn btn-gray" style="margin-top:16px;width:100%">关闭</button>
  </div>
</div>
<script>function showModal(id){document.getElementById(id).style.display='flex'}function hideModal(id){document.getElementById(id).style.display='none'}</script>

<?php
// ===== OPTIMIZE =====
elseif ($page === 'optimize'):
  $ram_mb = intval(trim(cmd("free -m | grep Mem | awk '{print \$2}'")));
  $cpu = intval(trim(cmd('nproc')));
  $tier = $ram_mb >= 4096 ? 'High (4GB+)' : ($ram_mb >= 2048 ? 'Medium (2GB+)' : ($ram_mb >= 1024 ? 'Standard (1GB+)' : 'Low (512MB)'));
  $nginx_opt = (strpos(file_get_contents('/etc/nginx/nginx.conf'), 'gzip on;') !== false);
?>
<div class="card"><h2>🚀 性能优化器</h2></div>

<div class="card">
  <h3>🧹 批量清理</h3>
  <p style="color:var(--text2);font-size:13px;margin-bottom:10px">扫描可清理的缓存与日志，勾选后执行。清理项均为可再生数据，不影响业务。</p>
  <button class="btn btn-blue btn-sm" onclick="scanCleanup(this)">🔍 扫描可清理项</button>
  <div id="cleanupBox" style="margin-top:14px"></div>
</div>
<script>
function scanCleanup(btn){
  btn.disabled=true; btn.textContent='扫描中…';
  fetch('?cleanup_scan=1',{cache:'no-store'}).then(r=>r.json()).then(d=>{
    btn.disabled=false; btn.textContent='🔍 重新扫描';
    var box=document.getElementById('cleanupBox'); box.innerHTML='';
    var any=false;
    var f=document.createElement('form'); f.method='POST'; f.innerHTML='<input type="hidden" name="action" value="cleanup_run">';
    <?php if (function_exists('csrf_field')): ?>f.innerHTML+=`<?= csrf_field() ?>`;<?php endif; ?>
    Object.keys(d).forEach(function(k){
      var it=d[k]; if(!it||!it.label)return; any=true;
      var lbl=document.createElement('label');
      lbl.style.cssText='display:flex;gap:8px;align-items:center;font-size:13px;margin:4px 0';
      lbl.innerHTML='<input type="checkbox" name="targets[]" value="'+k+'" checked> '+it.label+' <b style="color:var(--accent)">'+(it.size||'—')+'</b>';
      f.appendChild(lbl);
    });
    if(!any){box.innerHTML='<p style="color:var(--text2);font-size:13px">未获取到可清理项</p>';return;}
    var b=document.createElement('button'); b.className='btn btn-green btn-sm'; b.style.marginTop='10px'; b.textContent='🧹 清理选中项';
    b.onclick=function(){return confirm('确认清理？均为可再生数据，不可恢复。');};
    f.appendChild(b); box.appendChild(f);
  }).catch(function(){btn.disabled=false;btn.textContent='🔍 扫描失败，点击重试';});
}
</script>

<div class="stats">
  <div class="stat"><div class="val"><?= $ram_mb ?> MB</div><div class="lbl">Total RAM</div></div>
  <div class="stat"><div class="val"><?= $cpu ?> Core</div><div class="lbl">CPU</div></div>
  <div class="stat"><div class="val"><?= $tier ?></div><div class="lbl">Tier</div></div>
</div>

<div class="card" style="border:2px solid var(--yellow)">
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px">
    <div>
      <strong style="color:var(--yellow)">⚡ Optimize All</strong>
      <p style="font-size:13px;color:var(--text2)">自动调优 Nginx + PHP + MySQL + 系统内核，在 <?= $ram_mb ?>MB 内存下支撑 1000+ 并发</p>
      <p style="font-size:11px;color:var(--text2)">✅ Backup config 自动 se尚未 ubah</p>
    </div>
    <form method="POST" onsubmit="return confirm('Optimasi semua service? 会先备份原配置。')"><?= csrf_field() ?>
      <input type="hidden" name="action" value="optimize">
      <input type="hidden" name="target" value="all">
      <button class="btn btn-green" style="padding:14px 28px;font-size:15px">🚀 Optimize All</button>
    </form>
  </div>
</div>

<div class="service-grid">
  <!-- Nginx -->
  <div class="service-card">
    <div class="svc-icon">🌐</div>
    <div class="svc-name">Nginx</div>
    <small style="color:var(--text2)">worker_processes auto · gzip · fastcgi cache</small>
    <div style="margin-top:12px">
      <span class="badge <?= $nginx_opt?'badge-ok':'badge-err' ?>"><?= $nginx_opt?'Optimized':'Default' ?></span>
    </div>
    <form method="POST" style="margin-top:8px"><?= csrf_field() ?><input type="hidden" name="action" value="optimize"><input type="hidden" name="target" value="nginx"><button class="btn btn-blue btn-sm">🔧 Optimize</button></form>
  </div>
  <!-- PHP -->
  <div class="service-card">
    <div class="svc-icon">🐘</div>
    <div class="svc-name">PHP-FPM + OPCache</div>
    <small style="color:var(--text2)">pm ondemand · max_children auto · opcache</small>
    <div style="margin-top:12px">
      <span class="badge badge-err">Default</span>
    </div>
    <form method="POST" style="margin-top:8px"><?= csrf_field() ?><input type="hidden" name="action" value="optimize"><input type="hidden" name="target" value="php"><button class="btn btn-blue btn-sm">🔧 Optimize</button></form>
  </div>
  <!-- MySQL -->
  <div class="service-card">
    <div class="svc-icon">🗄️</div>
    <div class="svc-name">MySQL / MariaDB</div>
    <small style="color:var(--text2)">innodb_buffer_pool · connections · tmp_table</small>
    <div style="margin-top:12px">
      <span class="badge badge-err">Default</span>
    </div>
    <form method="POST" style="margin-top:8px"><?= csrf_field() ?><input type="hidden" name="action" value="optimize"><input type="hidden" name="target" value="mysql"><button class="btn btn-blue btn-sm">🔧 Optimize</button></form>
  </div>
  <!-- System -->
  <div class="service-card">
    <div class="svc-icon">⚙️</div>
    <div class="svc-name">系统内核</div>
    <small style="color:var(--text2)">swappiness · file limits · TCP tuning</small>
    <div style="margin-top:12px">
      <span class="badge badge-err">Default</span>
    </div>
    <form method="POST" style="margin-top:8px"><?= csrf_field() ?><input type="hidden" name="action" value="optimize"><input type="hidden" name="target" value="system"><button class="btn btn-blue btn-sm">🔧 Optimize</button></form>
  </div>
</div>

<div class="card"><h2>📊 优化内容（目标：1000+ 并发）</h2>
  <table><thead><tr><th>服务</th><th>设置</th><th>512MB</th><th>1GB</th><th>2GB+</th></tr></thead><tbody>
    <tr><td><strong>Nginx</strong></td><td>worker_connections</td><td>2048</td><td>4096</td><td>4096</td></tr>
    <tr><td><strong>Nginx</strong></td><td>gzip + fastcgi_cache</td><td colspan="3" style="text-align:center">✅ Enabled (level 5, 64MB cache)</td></tr>
    <tr><td><strong>PHP-FPM</strong></td><td>max_children (ondemand)</td><td>12</td><td>25</td><td>50</td></tr>
    <tr><td><strong>PHP</strong></td><td>memory_limit</td><td>128M</td><td>192M</td><td>256M</td></tr>
    <tr><td><strong>OPCache</strong></td><td>memory_consumption</td><td>64MB</td><td>128MB</td><td>256MB</td></tr>
    <tr><td><strong>MySQL</strong></td><td>innodb_buffer_pool_size</td><td>128M</td><td>256M</td><td>512M</td></tr>
    <tr><td><strong>MySQL</strong></td><td>max_connections</td><td>50</td><td>100</td><td>200</td></tr>
    <tr><td><strong>System</strong></td><td>swappiness / file-max / TCP</td><td colspan="3" style="text-align:center">swappiness=10、file-max=65535、TCP fastopen</td></tr>
  </tbody></table>
</div>

<div class="card"><h2>💾 备份与恢复</h2>
  <p style="font-size:13px;color:var(--text2);margin-bottom:12px">每次优化前自动备份原配置到：</p>
  <code style="background:var(--bg);padding:8px;border-radius:4px;display:block;font-size:12px">/var/lib/vps-manager/backups/optimize/YYYYMMDD_HHMMSS/</code>
</div>

<?php
// ===== SETTINGS =====
elseif ($page === 'settings'):
  $pw_set = file_exists(PASSWD_FILE);
?>
<div class="card"><h2>⚙️ 设置</h2></div>

<div class="card">
  <h2>🔔 事件通知（Webhook）</h2>
  <p style="font-size:13px;color:var(--text2);margin-bottom:14px">关键事件推送到 Telegram Bot / 钉钉 / 企业微信 / 自定义 Webhook（POST JSON）。Telegram 用 <code>https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<ID></code> 格式不适用——请用 <code>https://api.telegram.org/bot&lt;token&gt;/sendMessage</code> 加 chat_id 的自定义中转，或直接填企业微信/钉钉机器人地址。</p>
  <?php $notify = is_file(NOTIFY_FILE) ? (json_decode(file_get_contents(NOTIFY_FILE), true) ?: []) : []; $nurl = $notify['url'] ?? ''; $nev = $notify['events'] ?? []; ?>
  <form method="POST"><?= csrf_field() ?>
    <input type="hidden" name="action" value="notify_save">
    <div class="form-group" style="max-width:640px"><label>Webhook URL（留空关闭）</label>
      <input type="text" name="nurl" value="<?= sanitize($nurl) ?>" placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx"></div>
    <div style="font-size:13px;margin:8px 0;display:flex;gap:16px;flex-wrap:wrap">
      <label><input type="checkbox" name="nevents[]" value="disk" <?= in_array('disk',$nev)?'checked':'' ?>> 磁盘超 90%</label>
      <label><input type="checkbox" name="nevents[]" value="cert" <?= in_array('cert',$nev)?'checked':'' ?>> 证书 30 天内到期</label>
      <label><input type="checkbox" name="nevents[]" value="service" <?= in_array('service',$nev)?'checked':'' ?>> 核心服务异常</label>
      <label><input type="checkbox" name="nevents[]" value="backup" <?= in_array('backup',$nev)?'checked':'' ?>> 备份完成/失败</label>
      <label><input type="checkbox" name="nevents[]" value="login_fail" <?= in_array('login_fail',$nev)?'checked':'' ?>> 登录被限速</label>
    </div>
    <button class="btn btn-blue btn-sm">💾 保存并发送测试</button>
  </form>
</div>

<div class="card">
  <h2>🔑 API Token（REST 接口）</h2>
  <p style="font-size:13px;color:var(--text2);margin-bottom:14px">生成 Token 后可程序化调用只读 API：<code>curl "http://IP:8080/?api=status&token=YOUR_TOKEN"</code>。Token 保存于 <code>/var/www/manager/.api_token</code>（0600）。</p>
  <?php $has_token = is_file(API_TOKEN_FILE); ?>
  <?php if ($has_token): ?><p style="color:#4ade80;font-size:13px">✅ Token 已存在</p><?php else: ?><p style="color:var(--text2);font-size:13px">当前无 Token</p><?php endif; ?>
  <form method="POST" style="display:flex;gap:10px"><?= csrf_field() ?>
    <button class="btn btn-blue btn-sm" name="action" value="api_token_gen"><?= $has_token ? '🔄 重新生成（旧 Token 立即失效）' : '🔑 生成 Token' ?></button>
    <?php if ($has_token): ?><button class="btn btn-red btn-sm" name="action" value="api_token_revoke" onclick="return confirm('吊销 Token？')">🗑️ 吊销</button><?php endif; ?>
  </form>
</div>

<div class="card">
  <h2>🔐 修改密码</h2>
  <p style="font-size:13px;color:var(--text2);margin-bottom:16px">
    <?= $pw_set ? '当前密码以 bcrypt 哈希保存在 SQLite（panel.db）' : '⚠️ 仍在使用默认密码！请立即修改。' ?>
  </p>
  <form method="POST" style="max-width:400px"><?= csrf_field() ?>
    <input type="hidden" name="action" value="change_pass">
    <div class="form-group" style="margin-bottom:12px">
      <label>旧密码</label>
      <input type="password" name="old_pass" placeholder="输入当前密码" required>
    </div>
    <div class="form-group" style="margin-bottom:12px">
      <label>新密码</label>
      <input type="password" name="new_pass" placeholder="至少 6 karakter" required>
    </div>
    <div class="form-group" style="margin-bottom:16px">
      <label>确认新密码</label>
      <input type="password" name="confirm_pass" placeholder="重试 password baru" required>
    </div>
    <button class="btn btn-green">💾 保存 Password</button>
  </form>
</div>

<div class="card">
  <h2>📋 系统信息</h2>
  <table>
    <tr><td style="width:200px;color:var(--text2)">面板版本</td><td><strong>v2.2</strong></td></tr>
    <tr><td style="color:var(--text2)">面板路径</td><td><code style="font-size:12px">/var/www/manager/index.php</code></td></tr>
    <tr><td style="color:var(--text2)">密码存储</td><td><code style="font-size:12px"><?= $pw_set ? '✅ .passwd exists' : '❌ Not set (using default)' ?></code></td></tr>
    <tr><td style="color:var(--text2)">PHP 版本</td><td><?= phpversion() ?></td></tr>
    <tr><td style="color:var(--text2)">备份</td><td><code style="font-size:12px"><?= BACKUP_DIR ?>/</code></td></tr>
    <tr><td style="color:var(--text2)">GitHub</td><td><a href="https://github.com/mnbwc/vps-manager" target="_blank">mnbwc/vps-manager</a></td></tr>
  </table>
</div>

<?php
// ===== FILE MANAGER =====
elseif ($page === 'files'):
  $ROOT = '/var/www';
  $dir = $_GET['dir'] ?? '';
  $current = resolve_existing_under_root($ROOT . '/' . ltrim($dir, '/'), $ROOT);
  if (!$current) $current = $ROOT;
  $PANEL_DIR = realpath('/var/www/manager');
  $panel_protected = $PANEL_DIR && strpos($current . '/', $PANEL_DIR . '/') === 0;
  
  function formatSize($bytes) {
    if ($bytes >= 1073741824) return round($bytes/1073741824,1).' GB';
    if ($bytes >= 1048576) return round($bytes/1048576,1).' MB';
    if ($bytes >= 1024) return round($bytes/1024,1).' KB';
    return $bytes.' B';
  }
  
  // Handle file view/edit
  $file_action = $_GET['fa'] ?? '';
  $file_name = $_GET['file'] ?? '';
  $file_content = '';
  $files_msg = '';
  if ($file_action === 'view' && $file_name) {
    $fp = $current . '/' . basename($file_name);
    if (!$panel_protected && file_exists($fp) && !is_dir($fp)) {
      $file_content = htmlspecialchars(file_get_contents($fp));
    }
  }
  if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['fa'] ?? '') === 'save') {
    $fp = $current . '/' . basename($_POST['file'] ?? '');
    if (!$panel_protected && file_exists($fp) && is_writable($fp)) {
      file_put_contents($fp, $_POST['content'] ?? '');
      $files_msg = '<div class="ok">✅ 文件已保存！</div>';
    } else { $files_msg = '<div class="err">❌ 面板目录文件受保护</div>'; }
    $file_action = 'view';
    $file_name = $_POST['file'] ?? '';
    $file_content = $panel_protected ? '' : @htmlspecialchars((string)@file_get_contents($fp));
  }
  if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['fa'] ?? '') === 'delete' && ($_POST['file'] ?? '')) {
    $fp = $current . '/' . basename($_POST['file']);
    if (!$panel_protected && file_exists($fp) && !is_dir($fp)) {
      unlink($fp);
      $files_msg = '<div class="ok">✅ 已删除！</div>';
    } else { $files_msg = '<div class="err">❌ 面板目录文件受保护</div>'; }
  }
  
  // Breadcrumb
  $parts = explode('/', trim(str_replace($ROOT, '', $current), '/'));
  $bc = '<a href="?page=files">📁 /var/www</a>';
  $build = '';
  foreach ($parts as $p) {
    if (empty($p)) continue;
    $build .= '/' . $p;
    $bc .= ' / <a href="?page=files&dir=' . urlencode(ltrim($build, '/')) . '">' . sanitize($p) . '</a>';
  }
  
  echo $files_msg;
  
  if ($file_action !== 'view'):
  ?>
  <div class="card" style="padding:14px 20px">
    <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end">
      <form method="POST" enctype="multipart/form-data" style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap"><?= csrf_field() ?>
        <input type="hidden" name="action" value="upload_file">
        <input type="hidden" name="up_dir" value="<?= sanitize($dir) ?>">
        <div style="margin-bottom:0">
          <label style="display:block;margin-bottom:3px;font-size:11px;color:var(--text2);font-weight:700;text-transform:uppercase">📤 上传文件</label>
          <input type="file" name="upfile" required style="padding:7px 10px;font-size:12px;border-radius:6px;border:1px solid var(--border)">
        </div>
        <button class="btn btn-blue btn-sm" style="margin-top:18px">⬆️ Upload</button>
      </form>
      <form method="POST" style="display:flex;gap:8px;align-items:flex-end"><?= csrf_field() ?>
        <input type="hidden" name="action" value="new_folder">
        <input type="hidden" name="fd_dir" value="<?= sanitize($dir) ?>">
        <div style="margin-bottom:0">
          <label style="display:block;margin-bottom:3px;font-size:11px;color:var(--text2);font-weight:700;text-transform:uppercase">📁 新建目录</label>
          <input type="text" name="fname" placeholder="folder-name" required style="padding:7px 10px;font-size:12px;border-radius:6px;border:1px solid var(--border);width:160px">
        </div>
        <button class="btn btn-gray btn-sm" style="margin-top:18px">➕ Create</button>
      </form>
    </div>
    <p style="font-size:11px;color:var(--text2);margin-top:8px">Max upload: <?= ini_get('upload_max_filesize') ?>。文件名会自动清洗。</p>
  </div>
  <?php endif; ?>
  <?php
  
  if ($file_action === 'view'):
  ?>
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h3>📝 Edit: <?= sanitize($file_name) ?></h3>
      <a href="?page=files&dir=<?= urlencode($dir) ?>" class="btn btn-gray btn-sm">← Kembali</a>
    </div>
    <form method="POST"><?= csrf_field() ?>
      <input type="hidden" name="fa" value="save">
      <input type="hidden" name="file" value="<?= sanitize($file_name) ?>">
      <textarea name="content" style="width:100%;min-height:500px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:16px;font-family:monospace;font-size:13px;resize:vertical"><?= $file_content ?></textarea>
      <div style="display:flex;gap:8px;margin-top:12px">
        <button class="btn btn-green">💾 保存</button>
        <a href="?page=files&dir=<?= urlencode($dir) ?>" class="btn btn-gray">Batal</a>
      </div>
    </form>
  </div>
  <?php else: ?>
  <div class="card">
    <h2><?= $bc ?></h2>
    <table>
      <thead><tr><th>名称</th><th style="width:100px">Size</th><th style="width:180px">Modified</th><th style="width:160px">Actions</th></tr></thead>
      <tbody>
      <?php
      $items = scandir($current);
      $dirs = []; $files = [];
      foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        if (is_dir($current . '/' . $item)) $dirs[] = $item; else $files[] = $item;
      }
      sort($dirs); sort($files);
      $all = array_merge($dirs, $files);
      
      if ($current !== $ROOT) {
        $parent = dirname(str_replace($ROOT, '', $current));
        echo "<tr><td><a href='?page=files&dir=" . urlencode(ltrim($parent, '/')) . "'>📂 ..</a></td><td></td><td></td><td></td></tr>";
      }
      
      foreach ($all as $item) {
        $fp = $current . '/' . $item;
        $isdir = is_dir($fp);
        $size = $isdir ? '-' : formatSize(filesize($fp));
        $mtime = date('d/m/Y H:i', filemtime($fp));
        $rel = ltrim(str_replace($ROOT, '', $current), '/');
        $rel = $rel ? urlencode($rel) : '';
        $ext = pathinfo($item, PATHINFO_EXTENSION);
        $icon = $isdir ? '📁' : match($ext) {
          'php' => '🐘', 'html' => '🌐', 'css' => '🎨', 'js' => '📜',
          'sql' => '🗄️', 'jpg','png','gif','svg','webp' => '🖼️',
          'zip','tar','gz' => '📦', 'pdf' => '📄', 'txt','md' => '📝',
          default => '📄'
        };
        
        $editable = !$isdir && in_array($ext, ['php','html','css','js','txt','md','sql','json','xml','yml','env','conf','htaccess','log','sh']);
        
        echo "<tr>
          <td><a href='" . ($isdir ? "?page=files&dir=" . ($rel ? "$rel/" : "") . urlencode($item) : "?page=files&fa=view&dir=$rel&file=" . urlencode($item)) . "'>$icon " . sanitize($item) . "</a></td>
          <td style='font-size:12px;color:var(--text2)'>$size</td>
          <td style='font-size:12px;color:var(--text2)'>$mtime</td>
          <td>";
        if ($editable) echo "<a href='?page=files&fa=view&dir=$rel&file=" . urlencode($item) . "' class='btn btn-blue btn-xs'>✏️ Edit</a> ";
        echo "<form method='POST' style='display:inline' " . confirm_attr('删除 ' . $item . '？') . ">" . csrf_field() . "<input type='hidden' name='fa' value='delete'><input type='hidden' name='dir' value='" . sanitize($rel) . "'><input type='hidden' name='file' value='" . sanitize($item) . "'><button class='btn btn-red btn-xs'>🗑️</button></form>";
        echo "</td></tr>";
      }
      ?>
      </tbody>
    </table>
  </div>
  <?php endif; ?>
  

<?php
// ===== PROCESS MANAGER =====
elseif ($page === 'procs'):
  $proc_list = [];
  if (is_alpine()) {
    foreach (glob('/etc/init.d/vpsmgr-*') ?: [] as $f) {
      $name = substr(basename($f), 7);
      $running = svc_status(basename($f));
      $proc_list[] = ['name' => $name, 'running' => $running, 'log' => '/var/log/' . basename($f) . '.log'];
    }
  } else {
    $raw = cmd("systemctl list-units --type=service --all 'vpsmgr-*' --no-legend --plain 2>/dev/null");
    foreach (explode("\n", trim($raw)) as $line) {
      $f = preg_split('/\s+/', trim($line));
      if (count($f) >= 4 && strpos($f[0], 'vpsmgr-') === 0) {
        $proc_list[] = ['name' => substr($f[0], 7, -8), 'running' => $f[3] === 'running', 'log' => '/var/log/' . $f[0] . '.log'];
      }
    }
  }
?>
<div class="card"><h2>⚙️ 进程托管</h2>
  <p style="color:var(--text2);font-size:13px">把任意长驻命令（node/python/二进制…）注册为系统服务：开机自启、崩溃自动拉起、日志落 /var/log/。基于 systemd（Alpine 用 OpenRC）。</p>
</div>
<div class="card">
  <h3>➕ 托管新进程</h3>
  <form method="POST"><?= csrf_field() ?>
    <input type="hidden" name="action" value="proc_add">
    <div class="form-grid">
      <div class="form-group"><label>进程名</label><input type="text" name="pname" placeholder="my-api" required></div>
      <div class="form-group"><label>运行用户</label><input type="text" name="puser" value="root"></div>
      <div class="form-group" style="grid-column:1/-1"><label>启动命令</label><input type="text" name="pcmd" placeholder="/usr/bin/node /app/server.js" required></div>
      <div class="form-group" style="grid-column:1/-1"><label>工作目录（可选）</label><input type="text" name="pworkdir" placeholder="/app"></div>
    </div>
    <button class="btn btn-green btn-sm">⚡ 创建并启动</button>
  </form>
</div>
<div class="card">
  <h3>📋 已托管（<?= count($proc_list) ?>）</h3>
  <?php if (empty($proc_list)): ?><p style="color:var(--text2)">暂无托管进程</p>
  <?php else: ?>
  <table><thead><tr><th>名称</th><th>状态</th><th>操作</th></tr></thead><tbody>
  <?php foreach ($proc_list as $pr): ?>
    <tr>
      <td><strong><?= sanitize($pr['name']) ?></strong><br><small style="color:var(--text2)"><a href="?page=proclog&name=<?= urlencode($pr['name']) ?>">📄 日志</a></small></td>
      <td><?= $pr['running'] ? '<span style="color:#4ade80">● 运行中</span>' : '<span style="color:#f87171">● 已停止</span>' ?></td>
      <td style="white-space:nowrap">
        <form method="POST" style="display:inline"><?= csrf_field() ?>
          <input type="hidden" name="action" value="proc_action"><input type="hidden" name="pname" value="<?= sanitize($pr['name']) ?>">
          <button class="btn btn-blue btn-xs" name="pop" value="restart">🔄</button>
          <?php if ($pr['running']): ?><button class="btn btn-yellow btn-xs" name="pop" value="stop">⏹</button>
          <?php else: ?><button class="btn btn-green btn-xs" name="pop" value="start">▶</button><?php endif; ?>
        </form>
        <form method="POST" style="display:inline" <?= confirm_attr('删除进程 ' . $pr['name'] . '？') ?>><?= csrf_field() ?>
          <input type="hidden" name="action" value="proc_del"><input type="hidden" name="pname" value="<?= sanitize($pr['name']) ?>">
          <button class="btn btn-red btn-xs">🗑️</button>
        </form>
      </td>
    </tr>
  <?php endforeach; ?>
  </tbody></table>
  <?php endif; ?>
</div>

<?php
// ===== PROC LOG =====
elseif ($page === 'proclog'):
  $name = preg_replace('/[^a-zA-Z0-9_-]/', '', $_GET['name'] ?? '');
  $logfile = $name ? '/var/log/vpsmgr-' . $name . '.log' : '';
  $logs = ($logfile && is_file($logfile)) ? cmd("tail -n 300 " . escapeshellarg($logfile) . " 2>/dev/null") : '（无日志）';
?>
<div class="card"><h2>📄 进程日志 — <?= sanitize($name) ?> <a href="?page=procs" class="btn btn-blue btn-xs" style="margin-left:8px">← 返回</a></h2></div>
<div class="card">
  <pre style="background:#0d1117;color:#c9d1d9;padding:16px;border-radius:10px;overflow:auto;max-height:560px;font-size:12px;line-height:1.5"><?= sanitize($logs) ?></pre>
</div>

<?php
// ===== DOCKER =====
elseif ($page === 'docker'):
  $docker = is_executable('/usr/bin/docker') ? '/usr/bin/docker' : (is_executable('/usr/local/bin/docker') ? '/usr/local/bin/docker' : '');
  $containers = [];
  if ($docker) {
    $raw = cmd($docker . " ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}' 2>/dev/null");
    foreach (explode("\n", trim($raw)) as $line) {
      if (empty(trim($line))) continue;
      $f = explode('|', $line, 5);
      if (count($f) >= 4) $containers[] = ['id' => $f[0], 'name' => $f[1], 'image' => $f[2], 'status' => $f[3], 'ports' => $f[4] ?? ''];
    }
  }
  $docker_ok = (bool)$docker;
?>
<div class="card"><h2>🐳 Docker 容器</h2>
<?php if (!$docker_ok): ?>
  <p style="color:var(--text2);font-size:13px">未安装 Docker。容器跑起来比 systemd 服务更省心。</p>
  <form method="POST"><?= csrf_field() ?><input type="hidden" name="action" value="docker_install"><label style="font-size:13px;display:block;margin-bottom:8px"><input type="checkbox" name="confirm" value="yes" required> 我了解这会下载并以 root 身份执行远程安装脚本</label><button class="btn btn-green btn-sm">📦 一键安装 Docker</button></form>
<?php else: ?>
  <p style="color:var(--text2);font-size:13px">共 <?= count($containers) ?> 个容器 · Docker 已就绪</p>
<?php endif; ?>
</div>

<?php if ($docker_ok && !empty($containers)): ?>
<div class="card">
  <table><thead><tr><th>名称</th><th>镜像</th><th>状态</th><th>端口</th><th>操作</th></tr></thead><tbody>
  <?php foreach ($containers as $c): $running = strpos($c['status'], 'Up') === 0; ?>
    <tr>
      <td><strong><?= sanitize($c['name']) ?></strong><br><small style="color:var(--text2)"><?= sanitize(substr($c['id'],0,12)) ?></small></td>
      <td style="font-size:12px"><?= sanitize($c['image']) ?></td>
      <td><?= $running ? '<span style="color:#4ade80">● ' . sanitize($c['status']) . '</span>' : '<span style="color:#f87171">● ' . sanitize($c['status']) . '</span>' ?></td>
      <td style="font-size:12px;color:var(--text2)"><?= sanitize($c['ports']) ?></td>
      <td style="white-space:nowrap">
        <form method="POST" style="display:inline" <?= confirm_attr('重启容器 ' . $c['name'] . '？') ?>><?= csrf_field() ?>
          <input type="hidden" name="action" value="docker_ctl"><input type="hidden" name="cid" value="<?= sanitize($c['name']) ?>">
          <button class="btn btn-blue btn-xs" name="dop" value="restart">🔄</button>
          <?php if ($running): ?><button class="btn btn-yellow btn-xs" name="dop" value="stop">⏹</button>
          <?php else: ?><button class="btn btn-green btn-xs" name="dop" value="start">▶</button><?php endif; ?>
        </form>
        <a href="?page=dockerlogs&cid=<?= urlencode($c['name']) ?>" class="btn btn-xs" style="background:var(--accent);color:#fff">📄</a>
      </td>
    </tr>
  <?php endforeach; ?>
  </tbody></table>
</div>
<?php endif; ?>

<?php
// ===== DOCKER LOGS =====
elseif ($page === 'dockerlogs'):
  $docker = is_executable('/usr/bin/docker') ? '/usr/bin/docker' : (is_executable('/usr/local/bin/docker') ? '/usr/local/bin/docker' : '');
  $cid = preg_replace('/[^a-zA-Z0-9._-]/', '', $_GET['cid'] ?? '');
  $logs = ($docker && $cid) ? cmd($docker . ' logs --tail 300 ' . escapeshellarg($cid) . ' 2>&1') : '';
?>
<div class="card"><h2>📄 容器日志 — <?= sanitize($cid) ?> <a href="?page=docker" class="btn btn-blue btn-xs" style="margin-left:8px">← 返回</a></h2></div>
<div class="card">
  <pre style="background:#0d1117;color:#c9d1d9;padding:16px;border-radius:10px;overflow:auto;max-height:560px;font-size:12px;line-height:1.5"><?= sanitize($logs) ?></pre>
</div>

<?php
// ===== SITE NGINX CONFIG EDITOR =====
elseif ($page === 'progress'):
  $task = preg_replace('/[^a-zA-Z0-9_]/', '', $_GET['task'] ?? '');
  $back = preg_replace('/[^a-z]/', '', $_GET['back'] ?? 'dashboard');
  $logfile = $task !== '' ? '/tmp/progress_' . $task . '.log' : '';
?>
<div class="card"><h2>⏳ 任务进度</h2>
  <pre id="plog" style="background:var(--bg);padding:14px;border-radius:8px;max-height:420px;overflow:auto;font-size:12px;white-space:pre-wrap">加载中...</pre>
  <div style="display:flex;gap:8px;margin-top:12px">
    <button class="btn btn-green btn-sm" onclick="location='?page=<?= $back ?>'">✅ 完成，返回</button>
    <button class="btn btn-gray btn-sm" onclick="location.reload()">🔄 刷新</button>
  </div>
</div>
<script>
(function poll(){
  fetch('?progress=<?= urlencode($task) ?>').then(r=>r.text()).then(t=>{
    var el=document.getElementById('plog'); el.textContent=t||'（无输出）';
    el.scrollTop=el.scrollHeight;
    if(t.indexOf('___COMPLETE___')===-1 && t.indexOf('___DONE___')===-1){ setTimeout(poll,2000); } else { el.textContent=t.replace('___COMPLETE___','').replace('___DONE___',''); }
  });
})();
</script>
<?php
elseif ($page === 'siteconf'):
  $cfg_name = preg_replace('/[^a-zA-Z0-9._-]/', '', $_GET['cfg'] ?? '');
  $path = $cfg_name ? NGINX_AVAILABLE . '/' . $cfg_name : '';
  $conf_ok = $path && file_exists($path) && strpos(realpath($path), realpath(NGINX_AVAILABLE)) === 0;
?>
<?php if (!$conf_ok): ?>
<div class="card"><h2>❌ 配置不存在</h2><p><a href="?page=websites" class="btn btn-blue btn-sm">← 返回网站列表</a></p></div>
<?php else: ?>
<div class="card">
  <h3>🔀 伪静态规则（一键预设）</h3>
  <p style="color:var(--text2);font-size:12px;margin-bottom:12px">选择程序类型即可自动替换站点配置中的 <code>location /</code> 伪静态区块，并自动校验重载 Nginx。</p>
  <form method="POST" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><?= csrf_field() ?>
    <input type="hidden" name="action" value="save_rewrite">
    <input type="hidden" name="conf_name" value="<?= sanitize($cfg_name) ?>">
    <select name="rw_preset" style="padding:8px 14px;border-radius:8px;border:2px solid var(--border);background:var(--surface);color:var(--text);font-size:13px">
      <option value="wordpress">WordPress / LiteBlog / 通用单入口 (try_files)</option>
      <option value="typecho">Typecho (Pathinfo Rewrite)</option>
      <option value="thinkphp">ThinkPHP (s=/$1 Rewrite)</option>
      <option value="laravel">Laravel (try_files)</option>
      <option value="static">纯静态站点 (=404)</option>
    </select>
    <button class="btn btn-blue btn-sm">⚡ 一键应用伪静态</button>
  </form>
</div>
<div class="card">
  <h2>📝 编辑 Nginx 配置 — <?= sanitize($cfg_name) ?></h2>
  <p style="color:var(--text2);font-size:13px">保存前会自动 <code>nginx -t</code> 校验，失败自动回滚。<a href="?page=websites" style="margin-left:8px">← 返回</a></p>
  <form method="POST"><?= csrf_field() ?>
    <input type="hidden" name="action" value="edit_conf">
    <input type="hidden" name="conf_name" value="<?= sanitize($cfg_name) ?>">
    <textarea name="conf_content" spellcheck="false" style="width:100%;min-height:420px;font-family:ui-monospace,monospace;font-size:13px;padding:12px;border-radius:10px;border:2px solid var(--border);background:var(--card);color:var(--foreground);line-height:1.5"><?= sanitize(file_get_contents($path)) ?></textarea>
    <div style="margin-top:10px"><button class="btn btn-green">💾 保存并重载 Nginx</button></div>
  </form>
</div>
<?php endif; ?>

<?php
// ===== REVERSE PROXY =====
elseif ($page === 'proxy'):
  $px_list = [];
  foreach (glob('/etc/nginx/conf.d/panel-proxy-*.conf') ?: [] as $f) {
    $cfg = file_get_contents($f);
    preg_match('/server_name\s+([^;]+);/', $cfg, $sn);
    preg_match('/proxy_pass\s+([^;]+);/', $cfg, $up);
    preg_match_all("/sub_filter\s+'((?:[^'\\\\]|\\\\.)*)'\s+'((?:[^'\\\\]|\\\\.)*)'/", $cfg, $sm, PREG_SET_ORDER);
    $subs = [];
    foreach ($sm as $x) $subs[] = [$x[1], $x[2]];
    $has_ssl = strpos($cfg, 'listen 443') !== false;
    $px_list[] = ['domain' => trim($sn[1] ?? basename($f)), 'upstream' => trim($up[1] ?? '?'), 'subs' => $subs, 'ssl' => $has_ssl, 'file' => basename($f)];
  }
  $subs_ok = trim(cmd("nginx -V 2>&1 | grep -o with-http_sub_module | head -1")) !== '';
?>
<div class="card"><h2>🔀 反向代理</h2>
  <?php if (!$subs_ok): ?><p style="color:#fbbf24;font-size:13px">⚠️ 当前 nginx 未编译 http_sub_module（内容替换需要），反代本身仍可用。Debian/Ubuntu 与 Alpine 官方 nginx 均已内置。</p><?php endif; ?>
</div>

<div class="card">
  <h3>➕ 添加反向代理</h3>
  <form method="POST" id="proxyForm"><?= csrf_field() ?>
    <input type="hidden" name="action" value="proxy_add">
    <div class="form-grid">
      <div class="form-group">
        <label>域名（需已解析到本机）</label>
        <input type="text" name="pdomain" placeholder="app.example.com" required>
      </div>
      <div class="form-group">
        <label>上游地址</label>
        <input type="text" name="pupstream" placeholder="http://127.0.0.1:3000 或 https://target.com" required>
      </div>
    </div>
    <div class="form-group">
      <label>替换规则（响应内容替换，可加多条；留空则跳过）</label>
      <div id="subRows">
        <div style="display:flex;gap:8px;margin-bottom:6px">
          <input type="text" name="psearch[]" placeholder="查找（原内容）" style="flex:1">
          <input type="text" name="preplace[]" placeholder="替换为（留空=删除原内容）" style="flex:1">
        </div>
      </div>
      <button type="button" class="btn btn-blue btn-xs" onclick="addSubRow()">➕ 加一条替换</button>
      <span style="color:var(--text2);font-size:12px;margin-left:8px">适合替换反代页面里的域名/链接/文案</span>
    </div>
    <label style="display:inline-flex;align-items:center;gap:6px;font-size:13px;margin-right:16px"><input type="checkbox" name="pws" value="1" checked> 支持 WebSocket</label>
    <label style="display:inline-flex;align-items:center;gap:6px;font-size:13px"><input type="checkbox" name="pssl" value="1"> 同时启用 HTTPS（自签证书）</label>
    <div style="margin-top:12px"><button class="btn btn-green">⚡ 创建反代</button></div>
  </form>
</div>
<script>
function addSubRow() {
  var d = document.createElement('div');
  d.style.cssText = 'display:flex;gap:8px;margin-bottom:6px';
  d.innerHTML = '<input type="text" name="psearch[]" placeholder="查找（原内容）" style="flex:1">' +
                '<input type="text" name="preplace[]" placeholder="替换为（留空=删除）" style="flex:1">' +
                '<button type="button" class="btn btn-red btn-xs" onclick="this.parentNode.remove()">✕</button>';
  document.getElementById('subRows').appendChild(d);
}
</script>

<div class="card">
  <h3>📡 已有反代（<?= count($px_list) ?>）</h3>
  <?php if (empty($px_list)): ?><p style="color:var(--text2)">暂无反代站点</p>
  <?php else: ?>
  <table><thead><tr><th>域名</th><th>上游</th><th>HTTPS</th><th>替换规则</th><th></th></tr></thead><tbody>
  <?php foreach ($px_list as $px): ?>
    <tr>
      <td><strong><?= sanitize($px['domain']) ?></strong></td>
      <td><?= sanitize($px['upstream']) ?></td>
      <td><?= $px['ssl'] ? '🔒 是' : '—' ?></td>
      <td style="font-size:12px;color:var(--text2)">
        <?php if (empty($px['subs'])) echo '—';
        else foreach ($px['subs'] as $x) echo '<code>' . sanitize($x[0]) . '</code> → <code>' . sanitize($x[1]) . '</code><br>'; ?>
      </td>
      <td>
        <form method="POST" style="display:inline" <?= confirm_attr('删除反向代理 ' . $px['domain'] . '？') ?>><?= csrf_field() ?>
          <input type="hidden" name="action" value="proxy_del">
          <input type="hidden" name="pdomain" value="<?= sanitize($px['domain']) ?>">
          <button class="btn btn-red btn-xs">🗑️</button>
        </form>
      </td>
    </tr>
  <?php endforeach; ?>
  </tbody></table>
  <?php endif; ?>
</div>

<?php
// ===== REDIRECT MANAGER =====
elseif ($page === 'redirects'):
  $rconf = '/etc/nginx/conf.d/panel-redirects.conf';
  $redirects = [];
  if (file_exists($rconf)) {
    $blocks = preg_split('/\n(?=# )/', trim(file_get_contents($rconf)));
    foreach ($blocks as $idx => $block) {
      if (empty(trim($block)) || strpos($block, '# VPS Manager') === 0) continue;
      preg_match('/# (.+?) \| (.+?) -> (.+?) \| (.+?) \|/', $block, $m);
      if ($m) $redirects[] = ['domain' => $m[1], 'from' => $m[2], 'to' => $m[3], 'type' => $m[4], 'date' => $m[5], 'num' => $idx];
    }
  }
?>
<div class="card"><h2>🔄 重定向管理</h2></div>

<div class="card">
  <h3>➕ 添加重定向</h3>
  <form method="POST"><?= csrf_field() ?>
    <input type="hidden" name="action" value="add_redirect">
    <div class="form-grid">
      <div class="form-group">
        <label>域名</label>
        <select name="rdomain" style="width:100%;padding:10px 14px;border-radius:8px;border:2px solid var(--border);background:var(--surface);color:var(--text);font-size:14px">
          <?php foreach($sites as $s): ?><option value="<?= $s['domain'] ?>"><?= $s['domain'] ?></option><?php endforeach; ?>
        </select>
      </div>
      <div class="form-group">
        <label>重定向类型</label>
        <select name="rtype" style="width:100%;padding:10px 14px;border-radius:8px;border:2px solid var(--border);background:var(--surface);color:var(--text);font-size:14px">
          <option value="301">301 Permanen</option>
          <option value="302">302 Sementara</option>
        </select>
      </div>
      <div class="form-group">
        <label>来源路径</label>
        <input name="rfrom" placeholder="/old 或 /" required>
        <small>/ 表示重定向整个域名</small>
      </div>
      <div class="form-group">
        <label>目标 (URL)</label>
        <input name="rto" placeholder="https://example.com/path" required>
        <small>完整 URL（含 http/https）</small>
      </div>
    </div>
    <button class="btn btn-green" style="margin-top:16px">➕ 添加 Redirect</button>
  </form>
</div>

<div class="card">
  <h3>📋 Daftar Redirect (<?= count($redirects) ?>)</h3>
  <?php if(empty($redirects)): ?>
    <p style="color:var(--text2);text-align:center;padding:40px">还没有 redirect. File: <code>/etc/nginx/conf.d/panel-redirects.conf</code></p>
  <?php else: ?>
  <table>
    <thead><tr><th>域名</th><th>来源</th><th>Ke</th><th>类型</th><th>日期</th><th>操作</th></tr></thead>
    <tbody>
    <?php foreach($redirects as $r): ?>
    <tr>
      <td><strong><?= sanitize($r['domain']) ?></strong></td>
      <td><code style="font-size:12px"><?= sanitize($r['from']) ?></code></td>
      <td><code style="font-size:12px"><?= sanitize($r['to']) ?></code></td>
      <td><span class="badge badge-blue"><?= $r['type'] ?></span></td>
      <td style="font-size:12px;color:var(--text2)"><?= $r['date'] ?></td>
      <td>
        <form method="POST" style="display:inline" <?= confirm_attr('删除重定向 ' . $r['from'] . ' → ' . $r['to'] . '？') ?>><?= csrf_field() ?>
          <input type="hidden" name="action" value="delete_redirect">
          <input type="hidden" name="rnum" value="<?= $r['num'] ?>">
          <button class="btn btn-red btn-xs">🗑️</button>
        </form>
      </td>
    </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  <?php endif; ?>
</div>

<?php
// ===== CACHE MANAGER =====
elseif ($page === 'cache'):
  $cache_path = '/var/cache/nginx/';
  $cache_exists = is_dir($cache_path);
  $cache_size = $cache_exists ? trim(cmd("du -sh $cache_path 2>/dev/null | awk '{print $1}'")) : 'N/A';
?>
<div class="card"><h2>🧹 缓存管理</h2></div>

<div class="stats">
  <div class="stat">
    <div class="val" style="font-size:20px"><?= $cache_exists ? '✅ Active' : '❌ Not Found' ?></div>
    <div class="lbl">FastCGI 缓存</div>
  </div>
  <div class="stat">
    <div class="val" style="font-size:20px"><?= $cache_size ?></div>
    <div class="lbl">Cache Size</div>
  </div>
</div>

<div class="card">
  <h3>🧹 Purge Cache</h3>
  <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end">
    <form method="POST" onsubmit="return confirm('删除 SEMUA Nginx cache?')"><?= csrf_field() ?>
      <input type="hidden" name="action" value="purge_cache">
      <input type="hidden" name="ctarget" value="all">
      <button class="btn btn-red">🗑️ Purge All Cache</button>
    </form>
    <form method="POST" style="display:flex;gap:8px;align-items:flex-end" onsubmit="return confirm('清除该域名的缓存？')"><?= csrf_field() ?>
      <input type="hidden" name="action" value="purge_cache">
      <input type="hidden" name="ctarget" value="site">
      <select name="cdomain" style="padding:10px 14px;border-radius:8px;border:2px solid var(--border);background:var(--surface);color:var(--text);font-size:14px">
        <?php foreach($sites as $s): ?><option value="<?= $s['domain'] ?>"><?= $s['domain'] ?></option><?php endforeach; ?>
      </select>
      <button class="btn btn-yellow">🧹 Purge Per Site</button>
    </form>
  </div>
  <p style="font-size:11px;color:var(--text2);margin-top:12px">
    📍 缓存路径：<code>/var/cache/nginx/</code> — 更新内容后请清缓存，改动才能立即生效。
  </p>
</div>

<?php
// ===== UPTIME MONITOR =====
elseif ($page === 'uptime'):
  $ulog = UPTIME_LOG;
  $uhistory = [];
  if (file_exists($ulog)) {
    $lines = array_reverse(file($ulog, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
    $uhistory = array_slice($lines, 0, 50);
  }
  // Quick status for each site
  $ustatus = [];
  foreach ($sites as $dm => $s) {
    $url = ($s['ssl'] ? 'https' : 'http') . '://' . $dm;
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 3, CURLOPT_CONNECTTIMEOUT => 2, CURLOPT_NOBODY => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_SSL_VERIFYPEER => false]);
    $start = microtime(true);
    curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $time = round((microtime(true) - $start) * 1000);
    curl_close($ch);
    $ustatus[] = ['domain' => $dm, 'code' => $code, 'time' => $time, 'up' => $code > 0 && $code < 500, 'ssl' => $s['ssl']];
  }
?>
<div class="card"><h2>📡 在线状态监控</h2></div>

<div class="actions">
  <form method="POST" style="display:inline"><?= csrf_field() ?>
    <input type="hidden" name="action" value="uptime_check">
    <button class="btn btn-green">🔄 Check All Now</button>
  </form>
  <form method="POST" style="display:inline" onsubmit="return confirm('Reset log uptime?')"><?= csrf_field() ?>
    <input type="hidden" name="action" value="clear_uptime">
    <button class="btn btn-gray">🗑️ Clear Log</button>
  </form>
</div>

<div class="card">
  <h3>🌐 Website Status</h3>
  <?php if(empty($ustatus)): ?>
    <p style="color:var(--text2);text-align:center;padding:40px">还没有 website.</p>
  <?php else: ?>
  <table>
    <thead><tr><th>域名</th><th>状态</th><th>HTTP 状态码</th><th>响应</th><th>操作</th></tr></thead>
    <tbody>
    <?php foreach($ustatus as $us): 
      $color = $us['up'] ? ($us['time'] > 1000 ? 'var(--yellow)' : 'var(--green)') : 'var(--red)';
    ?>
    <tr>
      <td><strong><?= sanitize($us['domain']) ?></strong></td>
      <td><span class="badge <?= $us['up'] ? 'badge-ok' : 'badge-err' ?>"><?= $us['up'] ? '🟢 UP' : '🔴 DOWN' ?></span></td>
      <td><?= $us['code'] ?: 'N/A' ?></td>
      <td style="color:<?= $color ?>;font-weight:600"><?= $us['time'] ?>ms</td>
      <td>
        <a href="<?= $us['ssl'] ? 'https' : 'http' ?>://<?= $us['domain'] ?>" target="_blank" class="btn btn-blue btn-xs">🔗 Visit</a>
      </td>
    </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  <?php endif; ?>
</div>

<div class="card">
  <h3>📋 Riwayat Uptime (<?= count($uhistory) ?> entries)</h3>
  <?php if(empty($uhistory)): ?>
    <p style="color:var(--text2);text-align:center;padding:40px">还没有 data. Klik "Check All Now".</p>
  <?php else: ?>
  <table>
    <thead><tr><th>时间</th><th>域名</th><th>状态</th></tr></thead>
    <tbody>
    <?php foreach($uhistory as $h): 
      $parts = explode('|', $h);
      if (count($parts) >= 3):
    ?>
    <tr>
      <td style="font-size:12px;color:var(--text2)"><?= $parts[0] ?></td>
      <td><strong><?= sanitize($parts[1]) ?></strong></td>
      <td><span class="badge <?= ($parts[2] > 0 && $parts[2] < 500) ? 'badge-ok' : 'badge-err' ?>"><?= $parts[2] ?: 'ERR' ?></span></td>
    </tr>
    <?php endif; endforeach; ?>
    </tbody>
  </table>
  <?php endif; ?>
</div>

<?php
// ===== SECURITY (FAIL2BAN) =====
elseif ($page === 'security'):
  $f2b_installed = is_executable('/usr/bin/fail2ban-client');
  $f2b_active = $f2b_installed && svc_status('fail2ban');
  
  // Get jail status
  $jails = [];
  if ($f2b_active) {
    $raw = cmd("fail2ban-client status 2>/dev/null");
    preg_match_all('/`- ([a-zA-Z0-9_-]+)/', $raw, $jm);
    foreach (($jm[1] ?? []) as $j) {
      $js = cmd("fail2ban-client status $j 2>/dev/null");
      preg_match('/Currently banned:\s+(\d+)/', $js, $bm);
      preg_match('/Total banned:\s+(\d+)/', $js, $tm);
      $banned_ips = [];
      preg_match_all('/\t([0-9.]+)/', $js, $ips);
      $jails[] = ['name' => $j, 'banned' => intval($bm[1] ?? 0), 'total' => intval($tm[1] ?? 0), 'ips' => $ips[1] ?? []];
    }
  }
?>
<div class="card"><h2>🛡️ Security (Fail2Ban)</h2></div>

<?php if(!$f2b_installed): ?>
<div class="card" style="border:2px solid var(--yellow)">
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px">
    <div>
      <strong style="font-size:16px;color:var(--yellow)">⚠️ Fail2Ban 尚未 已安装</strong>
      <p style="font-size:13px;color:var(--text2);margin-top:4px">Fail2Ban 防护 SSH / Nginx / phpMyAdmin 的暴力破解攻击</p>
    </div>
    <form method="POST" onsubmit="return confirm('Install & konfigurasi Fail2Ban? (1-2 menit)')"><?= csrf_field() ?>
      <input type="hidden" name="action" value="install_f2b">
      <button class="btn btn-green">⚡ Install Fail2Ban</button>
    </form>
  </div>
</div>
<?php else: ?>

<div class="stats">
  <div class="stat">
    <div class="val" style="font-size:22px;color:<?= $f2b_active ? 'var(--green)' : 'var(--red)' ?>"><?= $f2b_active ? '🟢 Aktif' : '🔴 Mati' ?></div>
    <div class="lbl">Fail2Ban Status</div>
  </div>
  <div class="stat">
    <div class="val"><?= count($jails) ?></div>
    <div class="lbl">Jails Aktif</div>
  </div>
  <?php $tb = array_sum(array_column($jails, 'banned')); ?>
  <div class="stat">
    <div class="val" style="color:<?= $tb > 0 ? 'var(--red)' : 'var(--green)' ?>"><?= $tb ?></div>
    <div class="lbl">IP Dibanned</div>
  </div>
</div>

<?php if(!empty($jails)): ?>
<div class="card">
  <h3>🔒 Jail Status</h3>
  <table>
    <thead><tr><th>Jail</th><th>当前封禁</th><th>累计封禁</th><th>封禁 IP 列表</th><th>操作</th></tr></thead>
    <tbody>
    <?php foreach($jails as $j): ?>
    <tr>
      <td><strong><?= sanitize($j['name']) ?></strong></td>
      <td><span class="badge <?= $j['banned'] > 0 ? 'badge-err' : 'badge-ok' ?>"><?= $j['banned'] ?></span></td>
      <td><?= $j['total'] ?></td>
      <td style="font-size:11px;font-family:monospace">
        <?php if(empty($j['ips'])): echo '<span style="color:var(--text2)">—</span>'; else: ?>
        <?php foreach($j['ips'] as $ip): echo sanitize($ip) . ' '; endforeach; ?>
        <?php endif; ?>
      </td>
      <td>
        <?php foreach($j['ips'] as $ip): ?>
        <form method="POST" style="display:inline" <?= confirm_attr('解封 IP ' . $ip . '？') ?>><?= csrf_field() ?>
          <input type="hidden" name="action" value="unban_ip">
          <input type="hidden" name="uip" value="<?= $ip ?>">
          <input type="hidden" name="ujail" value="<?= $j['name'] ?>">
          <button class="btn btn-green btn-xs">🔓 Unban</button>
        </form>
        <?php endforeach; ?>
      </td>
    </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
</div>
<?php endif; ?>
<?php endif; ?>


<?php
// ===== CLOUD BACKUP =====
elseif ($page === 'cloudbackup'):
  $rclone_ok = is_executable('/usr/bin/rclone');
  $rclone_remotes = $rclone_ok ? trim(cmd('rclone listremotes 2>/dev/null')) : '';
  $rclone_remote_list = $rclone_remotes ? explode("\n", trim($rclone_remotes)) : [];
  $gdrive_connected = $rclone_ok && in_array('gdrive:', $rclone_remote_list);
  $gdrive_info = $gdrive_connected ? trim(cmd('rclone about gdrive: 2>&1')) : '';
  $auth_url = $_SESSION['rclone_auth_url'] ?? '';
  $setup_step = $auth_url ? 2 : 1;
?>
<div class="card"><h2>☁️ 云备份</h2></div>

<div class="card">
  <h3>🎯 远程备份目标（rclone）</h3>
  <p style="color:var(--text2);font-size:13px">备份包除本地保存外，自动同步到 rclone 远程（已连 gdrive/mega 则自动用；也可自定义任意 remote:path，如 <code>gdrive:vps-backups</code>、<code>mega:backup</code>）。可加开每日 03:30 自动同步。</p>
  <?php $saved_target = is_file('/var/www/manager/.cloud_target') ? trim(file_get_contents('/var/www/manager/.cloud_target')) : ''; ?>
  <form method="POST"><?= csrf_field() ?>
    <input type="hidden" name="action" value="cloud_target_save">
    <div class="form-grid">
      <div class="form-group" style="grid-column:1/-1">
        <label>远程路径（留空 = 仅本地）</label>
        <input type="text" name="cbtarget" value="<?= sanitize($saved_target) ?>" placeholder="gdrive:vps-backups">
      </div>
    </div>
    <label style="display:inline-flex;align-items:center;gap:6px;font-size:13px;margin-right:14px"><input type="checkbox" name="cbdaily" value="1"> 每日 03:30 自动同步备份目录</label>
    <button class="btn btn-green btn-sm">💾 保存</button>
  </form>
</div>

<?php if(!$rclone_ok): ?>
<div class="card" style="border:2px solid var(--yellow)">
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px">
    <div>
      <strong style="font-size:16px">⚠️ Rclone 尚未 已安装</strong>
      <p style="font-size:13px;color:var(--text2);margin-top:4px">需先安装 Rclone 才能连接云存储。</p>
    </div>
    <form method="POST"><?= csrf_field() ?>
      <input type="hidden" name="action" value="install_rclone">
      <label style="font-size:13px;display:block;margin-bottom:8px"><input type="checkbox" name="confirm" value="yes" required> 我了解这会下载并以 root 身份执行远程安装脚本</label>
      <button class="btn btn-green">📦 Install Rclone</button>
    </form>
  </div>
</div>
<?php endif; ?>

<?php if($rclone_ok): ?>
<div class="stats">
  <div class="stat">
    <div class="val" style="font-size:20px;color:var(--green)">✅ Installed</div>
    <div class="lbl">Rclone Status</div>
  </div>
  <div class="stat">
    <div class="val"><?= count($rclone_remote_list) ?></div>
    <div class="lbl">云端远程存储</div>
  </div>
  <?php $mega_connected = in_array('mega:', $rclone_remote_list); ?>
  <?php if($mega_connected): ?>
  <div class="stat">
    <div class="val" style="font-size:14px;color:var(--green)">✅ Mega.nz</div>
    <div class="lbl">20GB Free</div>
  </div>
  <?php endif; ?>
  <?php if($gdrive_connected): ?>
  <div class="stat">
    <div class="val" style="font-size:14px;color:var(--green)">✅ 已连接</div>
    <div class="lbl">Google Drive</div>
  </div>
  <?php endif; ?>
</div>

<!-- ===== MEGA.NZ SETUP (SUPER SIMPLE) ===== -->
<?php if(!$mega_connected): ?>
<div class="card" style="border-left:4px solid #e83737">
  <div style="display:flex;align-items:flex-start;gap:16px;flex-wrap:wrap">
    <div style="font-size:40px">🅼</div>
    <div style="flex:1;min-width:250px">
      <h3 style="color:#e83737;margin-bottom:4px">⚡ Mega.nz — Paling Mudah!</h3>
      <p style="font-size:12px;color:var(--text2);margin-bottom:12px">Gratis 20GB. Cukup email + password. Gak perlu OAuth, gak perlu bikin API key, gak ribet.</p>
      <form method="POST"><?= csrf_field() ?>
        <input type="hidden" name="action" value="rclone_mega_connect">
        <div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
          <div class="form-group" style="margin-bottom:0">
            <label>Mega.nz 邮箱</label>
            <input name="mega_email" placeholder="email@example.com" required style="width:220px;padding:10px 14px;border-radius:8px;border:2px solid var(--border);background:var(--surface);color:var(--text);font-size:14px">
          </div>
          <div class="form-group" style="margin-bottom:0">
            <label>密码</label>
            <input type="password" name="mega_pass" placeholder="password mega" required style="width:180px;padding:10px 14px;border-radius:8px;border:2px solid var(--border);background:var(--surface);color:var(--text);font-size:14px">
          </div>
          <button class="btn" style="background:#e83737;color:#fff;padding:10px 20px">⚡ Connect Mega</button>
        </div>
      </form>
      <p style="font-size:10px;color:var(--text2);margin-top:8px">🔒 密码不落盘，仅写入 rclone 配置。如果还没有账号： <a href="https://mega.nz/register" target="_blank" style="color:var(--blue)">daftar gratis</a>.</p>
    </div>
  </div>
</div>
<?php else: ?>
<div class="card">
  <h3>🅼 Mega.nz Storage</h3>
  <p style="color:var(--text2);font-size:12px"><?= sanitize(trim(cmd('rclone about mega: 2>&1'))) ?></p>
</div>
<?php endif; ?>

<!-- ===== GOOGLE DRIVE SETUP WIZARD ===== -->
<?php if(!$gdrive_connected): ?>
<div class="card" style="border-left:4px solid #2563eb">
  <h3>🔗 Setup Google Drive — 第 <?= $setup_step ?> / 2 步</h3>
  
  <?php if($setup_step === 1): ?>
  <p style="font-size:13px;color:var(--text2);margin-bottom:16px">
    两步即可连接 Google Drive，按下方指引操作。
  </p>
  
  <div style="background:var(--bg);padding:16px;border-radius:8px;margin-bottom:16px">
    <strong style="color:var(--primary)">📋 准备：在 Google Cloud Console 创建 OAuth 凭据</strong>
    <ol style="font-size:12px;color:var(--text2);margin-top:8px;padding-left:20px;line-height:2">
      <li>Buka <a href="https://console.cloud.google.com/apis/credentials" target="_blank" style="color:var(--blue)">Google Cloud Console → Credentials</a></li>
      <li>Klik <b>+ CREATE CREDENTIALS → OAuth client ID</b></li>
      <li>选择 <b>Application type: Desktop app</b>, beri nama bebas</li>
      <li>点击 <b>CREATE</b> — 生成 <b>Client ID</b> 和 <b>Client Secret</b></li>
      <li>把两者粘贴到下方表单 👇</li>
    </ol>
  </div>

  <form method="POST"><?= csrf_field() ?>
    <input type="hidden" name="action" value="rclone_gdrive_step1">
    <div class="form-grid">
      <div class="form-group">
        <label>🔑 Google OAuth Client ID</label>
        <input name="gdrive_cid" placeholder="xxxxx.apps.googleusercontent.com" required style="font-family:monospace;font-size:12px">
      </div>
      <div class="form-group">
        <label>🔒 Google OAuth Client Secret</label>
        <input name="gdrive_csec" placeholder="GOCSPX-xxxxx" required style="font-family:monospace;font-size:12px">
      </div>
    </div>
    <button class="btn btn-green" style="margin-top:14px">➡️ Generate Auth URL</button>
  </form>

  <?php else: ?>
  <p style="font-size:13px;color:var(--text2);margin-bottom:16px">
    Step 2: Buka URL di bawah di browser, login ke Google, lalu copy-paste verification code.
  </p>

  <div style="background:var(--bg);padding:16px;border-radius:8px;margin-bottom:16px">
    <strong style="color:var(--primary)">🔗 第 2a 步：在浏览器（手机/电脑）打开此链接</strong>
    <div style="word-break:break-all;padding:12px;background:#fdfcfb;border:1px solid var(--border);border-radius:6px;margin-top:8px;font-size:11px;font-family:monospace;max-height:80px;overflow:auto">
      <a href="<?= htmlspecialchars($auth_url) ?>" target="_blank" style="color:var(--blue)"><?= htmlspecialchars($auth_url) ?></a>
    </div>
    <p style="font-size:11px;color:var(--text2);margin-top:8px">
      ⚠️ 请选择与 OAuth 凭据相同的 Google 账号。<br>
      Klik <b>Allow</b> / <b>继续kan</b> sampai muncul kode verifikasi.
    </p>
  </div>

  <div style="background:var(--bg);padding:16px;border-radius:8px;margin-bottom:16px">
    <strong style="color:var(--primary)">📋 第 2b 步：粘贴 Google 返回的授权码</strong>
    <form method="POST"><?= csrf_field() ?>
      <input type="hidden" name="action" value="rclone_gdrive_step2">
      <div class="form-group" style="margin-top:8px">
        <input name="gdrive_code" placeholder="4/0AanRRr..." required style="font-family:monospace;font-size:12px">
        <small>授权码通常以 <b>4/</b> 开头</small>
      </div>
      <button class="btn btn-green" style="margin-top:10px">✅ 连接 Google Drive</button>
    </form>
  </div>

  <form method="POST" style="display:inline"><?= csrf_field() ?>
    <input type="hidden" name="action" value="rclone_remove">
    <input type="hidden" name="rr_remote" value="">
    <button class="btn btn-gray btn-sm" onclick="return confirm('取消配置？')">↩️ 取消配置</button>
  </form>
  <?php endif; ?>
</div>
<?php endif; ?>

<!-- ===== CONNECTED REMOTES ===== -->
<?php if(!empty($rclone_remote_list)): ?>
<div class="card">
  <h3>🔗 Connected Cloud Remotes</h3>
  <table><thead><tr><th>远程存储</th><th>状态</th><th>信息</th><th>操作</th></tr></thead><tbody>
  <?php foreach($rclone_remote_list as $rm): $rn = rtrim($rm, ':'); ?>
  <tr>
    <td><strong><?= sanitize($rm) ?></strong></td>
    <td><span class="badge badge-ok">✅ 已连接</span></td>
    <td style="font-size:11px;color:var(--text2)">
      <?php if($rn === 'gdrive' && $gdrive_info): ?>
        <?= sanitize(substr($gdrive_info, 0, 120)) ?>
      <?php else: ?>
        <?= sanitize(trim(cmd("rclone about $rm 2>/dev/null | head -1"))) ?>
      <?php endif; ?>
    </td>
    <td>
      <form method="POST" style="display:inline" <?= confirm_attr('断开远程存储连接 ' . $rn . '？') ?>><?= csrf_field() ?>
        <input type="hidden" name="action" value="rclone_remove">
        <input type="hidden" name="rr_remote" value="<?= sanitize($rn) ?>">
        <button class="btn btn-red btn-xs">🗑️ Disconnect</button>
      </form>
    </td>
  </tr>
  <?php endforeach; ?>
  </tbody></table>
</div>
<?php endif; ?>
<?php endif; ?>

<!-- ===== BACKUP FORM ===== -->
<?php if($mega_connected || $gdrive_connected || !empty($rclone_remote_list)): ?>
<div class="card">
  <h3>💾 备份并同步到云端</h3>
  <form method="POST"><?= csrf_field() ?>
    <input type="hidden" name="action" value="cloud_backup">
    <div style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap">
      <div class="form-group">
        <label>网站</label>
        <select name="cb_domain" style="padding:10px 14px;border-radius:8px;border:2px solid var(--border);background:var(--surface);color:var(--text);font-size:14px">
          <?php foreach($sites as $s): if($s['root_exists']): ?><option value="<?= $s['domain'] ?>"><?= $s['domain'] ?></option><?php endif; endforeach; ?>
        </select>
      </div>
      <button class="btn btn-green" style="margin-bottom:0">💾 备份并同步到云端</button>
    </div>
  </form>
  <p style="font-size:11px;color:var(--text2);margin-top:8px">
    网站文件先备份到 <code><?= BACKUP_DIR ?>/</code>，再同步到 Google Drive 的 <b>vps-backups/</b>
  </p>
</div>
<?php endif; ?>

<?php
// ===== PHP SETTINGS PER SITE =====
elseif ($page === 'phpsite'):
  $ps_file = '/var/www/manager/.site_php.json';
  $ps_all = file_exists($ps_file) ? json_decode(file_get_contents($ps_file), true) : [];
  $ps_domain = $_GET['domain'] ?? '';
  $ps_current = $ps_domain && isset($ps_all[$ps_domain]) ? $ps_all[$ps_domain] : ['upload_max_filesize' => '20M', 'post_max_size' => '25M', 'max_execution_time' => 120, 'memory_limit' => '256M', 'display_errors' => 'Off', 'max_input_vars' => 3000];
?>
<div class="card"><h2>⚡ PHP Settings per Website</h2></div>

<div class="card">
  <h3>📋 Konfigurasi per Website</h3>
  <?php if(empty($ps_all)): ?>
    <p style="color:var(--text2);text-align:center;padding:20px">暂无站点级配置。在下方选择网站。</p>
  <?php else: ?>
  <table><thead><tr><th>网站</th><th>上传上限</th><th>内存</th><th>执行时间</th><th>错误显示</th><th>操作</th></tr></thead><tbody>
  <?php foreach($ps_all as $dm => $cfg): ?>
  <tr>
    <td><strong><?= sanitize($dm) ?></strong></td>
    <td><?= $cfg['upload_max_filesize'] ?></td>
    <td><?= $cfg['memory_limit'] ?></td>
    <td><?= $cfg['max_execution_time'] ?>s</td>
    <td><span class="badge <?= $cfg['display_errors'] === 'On' ? 'badge-err' : 'badge-ok' ?>"><?= $cfg['display_errors'] ?></span></td>
    <td><a href="?page=phpsite&domain=<?= urlencode($dm) ?>" class="btn btn-blue btn-xs">✏️ Edit</a></td>
  </tr>
  <?php endforeach; ?>
  </tbody></table>
  <?php endif; ?>
</div>

<div class="card">
  <h3><?= $ps_domain ? '✏️ Edit: ' . sanitize($ps_domain) : '➕ Konfigurasi Website Baru' ?></h3>
  <form method="POST"><?= csrf_field() ?>
    <input type="hidden" name="action" value="php_per_site_save">
    <div class="form-grid">
      <div class="form-group">
        <label>网站</label>
        <select name="ps_domain" style="padding:10px 14px;border-radius:8px;border:2px solid var(--border);background:var(--surface);color:var(--text);font-size:14px">
          <?php foreach($sites as $s): $sel = $s['domain'] === $ps_domain ? 'selected' : ''; ?>
          <option value="<?= $s['domain'] ?>" <?= $sel ?>><?= $s['domain'] ?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="form-group"><label>上传大小上限</label><input name="ps_upload" value="<?= $ps_current['upload_max_filesize'] ?>"><small>Contoh: 2M, 20M, 100M</small></div>
      <div class="form-group"><label>POST 大小上限</label><input name="ps_post" value="<?= $ps_current['post_max_size'] ?>"><small>Harus ≥ upload max</small></div>
      <div class="form-group"><label>最大执行时间（秒）</label><input name="ps_exec" type="number" value="<?= $ps_current['max_execution_time'] ?>"></div>
      <div class="form-group"><label>内存限制</label><input name="ps_memory" value="<?= $ps_current['memory_limit'] ?>"><small>128M, 256M, 512M</small></div>
      <div class="form-group"><label>显示错误</label><select name="ps_errors" style="padding:10px 14px;border-radius:8px;border:2px solid var(--border);background:var(--surface);color:var(--text);font-size:14px"><option value="Off" <?= $ps_current['display_errors']==='Off'?'selected':'' ?>>Off (Production)</option><option value="On" <?= $ps_current['display_errors']==='On'?'selected':'' ?>>On (Debug)</option></select></div>
      <div class="form-group"><label>Max Input Vars</label><input name="ps_vars" type="number" value="<?= $ps_current['max_input_vars'] ?>"></div>
    </div>
    <button class="btn btn-green" style="margin-top:16px">💾 保存 & 应用到 .user.ini</button>
  </form>
  <p style="font-size:11px;color:var(--text2);margin-top:12px">
    ⚠️ 设置保存到网站根目录的 <code>.user.ini</code>。重启 PHP-FPM 后生效。
  </p>
</div>

<?php
// ===== MIGRATION (SYSTEM BACKUP & RESTORE) =====
elseif ($page === 'migration'):
  if (!is_dir(MIGRATION_DIR)) mkdir(MIGRATION_DIR, 0755, true);
  $migrations = [];
  foreach (glob(MIGRATION_DIR . '/*.tar.gz') as $f) {
      $migrations[] = ['name' => basename($f), 'size' => round(filesize($f) / 1024, 1), 'time' => filemtime($f)];
  }
  usort($migrations, function($a, $b) { return $b['time'] - $a['time']; });
  $hostname = trim(cmd('hostname'));
  $php_versions_installed = [];
  foreach (['8.2','8.3','8.4','8.5'] as $pv) {
      if (file_exists(php_bin($pv))) $php_versions_installed[] = $pv;
  }
  if (empty($php_versions_installed)) $php_versions_installed = [selected_php_version()];
  
  // Count items to backup
  $www_count = 0;
  $www_dirs = glob('/var/www/*');
  if (is_array($www_dirs)) {
      foreach ($www_dirs as $d) { if (is_dir($d) && basename($d) !== 'manager') $www_count++; }
  }
  $ssl_exists = is_dir('/etc/letsencrypt/live') && count(glob('/etc/letsencrypt/live/*')) > 0;
?>
<div class="card"><h2>🔄 系统迁移</h2></div>

<div class="stats">
  <div class="stat"><div class="val"><?= $www_count ?></div><div class="lbl">要备份的网站</div></div>
  <div class="stat"><div class="val"><?= count($dbs) ?></div><div class="lbl">数据库</div></div>
  <div class="stat"><div class="val"><?= count($migrations) ?></div><div class="lbl">迁移备份文件</div></div>
  <div class="stat"><div class="val" style="font-size:14px"><?= sanitize($hostname) ?></div><div class="lbl">VPS Hostname</div></div>
</div>

<!-- BACKUP SECTION -->
<div class="card" style="border-left:4px solid #1e3a5f">
  <h3>📦 Create Full System Backup</h3>
  <p style="font-size:13px;color:var(--text2);margin-bottom:16px">
    Backup mencakup: semua website, semua database MySQL, Nginx configs, panel settings, cron jobs, UFW rules, PHP versions, system info.
  </p>
  
  <details style="margin-bottom:16px;font-size:12px;color:var(--text2)">
    <summary style="cursor:pointer;font-weight:600;color:var(--primary)">📋 将备份的内容</summary>
    <div style="margin-top:8px;padding-left:16px;line-height:2">
      ✅ /var/www/ 下所有网站（面板自身除外）<br>
      ✅ Semua database MySQL (full dump --all-databases)<br>
      ✅ Nginx configs: sites-available, sites-enabled, conf.d<br>
      ✅ Panel settings: .users, .passwd, .site_php.json, uptime.log（.cf_token 机密不随包迁移）<br>
      ✅ SSL 证书（可选，在下方勾选）<br>
      ✅ Cron jobs (crontab -l root)<br>
      ✅ UFW firewall rules<br>
      ✅ Daftar PHP versions + version default<br>
      ✅ System info (untuk verifikasi kompatibilitas restore)
    </div>
  </details>
  
  <form method="POST" onsubmit="return confirm('Buat full system backup? Proses 1-5 menit tergantung jumlah data.')"><?= csrf_field() ?>
    <input type="hidden" name="action" value="migration_backup">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
      <input type="checkbox" name="include_ssl" id="include_ssl" value="1" <?= $ssl_exists ? '' : 'disabled' ?> style="width:18px;height:18px">
      <label for="include_ssl" style="font-weight:600;font-size:14px">🔒 Include SSL certificates (/etc/letsencrypt/) <?= !$ssl_exists ? '(没有 SSL)' : '' ?></label>
    </div>
    <small style="color:var(--text2);display:block;margin-bottom:14px">
      ⚠ SSL 数据可能较大（50-500MB）。不包含 SSL 时备份通常为 5-200MB。
    </small>
    <button class="btn btn-green" style="font-size:15px;padding:12px 24px">📦 Create Full Backup</button>
  </form>
</div>

<!-- RESTORE SECTION -->
<div class="card" style="border-left:4px solid #2c5282">
  <h3>📥 Restore from Backup</h3>
  <p style="font-size:13px;color:var(--text2);margin-bottom:16px">
    上传迁移生成的 <b>.tar.gz</b> 备份文件。普通「备份」菜单的 <b>.zip</b> 在这里不可用。
  </p>
  
  <form method="POST" enctype="multipart/form-data" onsubmit="return confirm('从备份恢复？现有数据可能被覆盖。 Pastikan Anda yakin!')"><?= csrf_field() ?>
    <input type="hidden" name="action" value="migration_restore">
    <div class="form-group" style="margin-bottom:14px">
      <label>Upload Migration Backup (*.tar.gz)</label>
      <input type="file" name="migfile" accept=".tar.gz,.tgz" required style="padding:10px">
      <small>File format: migration-VPS-HOSTNAME-YYYYMMDD-HHMMSS.tar.gz</small>
    </div>
    
    <div style="background:var(--bg);padding:16px;border-radius:8px;margin-bottom:16px">
      <strong style="font-size:13px;color:var(--primary)">Opsi Restore:</strong>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;margin-top:8px">
        <label style="display:flex;align-items:center;gap:8px;font-size:13px">
          <input type="checkbox" name="restore_panel" value="1" checked style="width:16px;height:16px"> ⚙ Panel Settings
        </label>
        <label style="display:flex;align-items:center;gap:8px;font-size:13px">
          <input type="checkbox" name="restore_ssl" value="1" style="width:16px;height:16px"> 🔒 SSL Certs
        </label>
        <label style="display:flex;align-items:center;gap:8px;font-size:13px">
          <input type="checkbox" name="restore_cron" value="1" checked style="width:16px;height:16px"> ⏰ Cron Jobs
        </label>
        <label style="display:flex;align-items:center;gap:8px;font-size:13px">
          <input type="checkbox" name="restore_ufw" value="1" style="width:16px;height:16px"> 🛡 UFW Rules
        </label>
      </div>
    </div>
    
    <button class="btn btn-blue" style="font-size:15px;padding:12px 24px">📥 Restore from Backup</button>
  </form>
</div>

<!-- MIGRATION FILES LIST -->
<div class="card">
  <h3>📋 Migration Backup Files (<?= count($migrations) ?>)</h3>
  <?php if(empty($migrations)): ?>
    <p style="color:var(--text2);text-align:center;padding:40px">还没有 file migration backup. Klik "Create Full Backup" di atas.</p>
  <?php else: ?>
  <table>
    <thead><tr><th>文件</th><th>大小</th><th>日期</th><th>操作</th></tr></thead>
    <tbody>
    <?php foreach($migrations as $m): ?>
    <tr>
      <td><strong style="font-size:12px">📦 <?= sanitize($m['name']) ?></strong></td>
      <td><span class="badge badge-blue"><?= $m['size'] >= 1024 ? round($m['size']/1024,1).' MB' : $m['size'].' KB' ?></span></td>
      <td style="font-size:12px;color:var(--text2)"><?= date('d/m/Y H:i', $m['time']) ?></td>
      <td>
        <a href="?dl_migration=<?= urlencode($m['name']) ?>" class="btn btn-blue btn-xs">⬇ Download</a>
        <form method="POST" style="display:inline" <?= confirm_attr('删除迁移备份 ' . $m['name'] . '？') ?>><?= csrf_field() ?>
          <input type="hidden" name="action" value="migration_delete">
          <input type="hidden" name="file" value="<?= sanitize($m['name']) ?>">
          <button class="btn btn-red btn-xs">🗑</button>
        </form>
      </td>
    </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  <?php endif; ?>
</div>

<?php
// ===== TERMINAL =====
elseif ($page === 'terminal'):
?>
<div class="card">
  <h2>💻 网页终端</h2>
  <p style="color:#888;margin-bottom:16px">浏览器内完整终端。输入 <code>exit</code> 关闭，<code>Ctrl+C</code> 中断。</p>
  <?php $ttyd_ok = (bool)cmd("ss -tln 2>/dev/null | grep -q ':8081' && echo ok", false); ?>
  <?php if ($ttyd_ok): ?>
  <div style="border:2px solid #1e3a5f;border-radius:12px;overflow:hidden;background:#1a1a2e">
    <iframe id="terminal-frame" style="width:100%;height:520px;border:0" sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-modals"></iframe>
  </div>
  <script>
  document.getElementById("terminal-frame").src = (location.protocol === "https:" ? "https://" : "http://") + location.hostname + ":8081";
  </script>
  <?php else: ?>
  <div style="background:var(--card2, #f6f2ea);border:2px dashed var(--text2);border-radius:12px;padding:32px;text-align:center;color:var(--text2)">
    <p style="font-size:15px;margin-bottom:8px">⚠️ 网页终端服务（ttyd, 端口 8081）未运行</p>
    <p style="font-size:13px">安装：<code>apt/dnf/apk install ttyd && ttyd -p 8081 bash</code><br>
    NAT 环境还需把宿主端口映射到 8081，并放行防火墙。</p>
    <p style="font-size:12px;margin-top:8px">也可以直接用 SSH 客户端连接服务器操作。</p>
  </div>
  <?php endif; ?>
</div>
<?php
elseif ($page === 'dns'):
  $cf_token = cf_token_load();
  $dns_zone = $_GET['zone'] ?? '';
  $dns_records = [];
  $dns_zones = [];
  if ($cf_token && $dns_zone) {
    $ch = curl_init("https://api.cloudflare.com/client/v4/zones?name=$dns_zone");
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => ["Authorization: Bearer $cf_token", 'Content-Type: application/json']]);
    $resp = json_decode(curl_exec($ch), true);
    curl_close($ch);
    $zone_id = $resp['result'][0]['id'] ?? '';
    if ($zone_id) {
      $ch = curl_init("https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?per_page=100");
      curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => ["Authorization: Bearer $cf_token", 'Content-Type: application/json']]);
      $resp2 = json_decode(curl_exec($ch), true);
      curl_close($ch);
      $dns_records = $resp2['result'] ?? [];
    }
  }
  if ($cf_token) {
    $ch = curl_init("https://api.cloudflare.com/client/v4/zones?per_page=50");
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => ["Authorization: Bearer $cf_token", 'Content-Type: application/json']]);
    $resp3 = json_decode(curl_exec($ch), true);
    curl_close($ch);
    $dns_zones = $resp3['result'] ?? [];
  }
?>
<div class="card"><h2>🌍 DNS Management (Cloudflare)</h2></div>

<?php if(!$cf_token): ?>
<div class="card" style="border:2px solid var(--yellow)">
  <h3>⚙️ Setup Cloudflare API Token</h3>
  <form method="POST" style="max-width:500px"><?= csrf_field() ?>
    <input type="hidden" name="action" value="dns_add">
    <input type="hidden" name="d_zone" value="">
    <input type="hidden" name="d_name" value="">
    <input type="hidden" name="d_type" value="A">
    <input type="hidden" name="d_content" value="1.1.1.1">
    <div class="form-group"><label>Cloudflare API Token</label><input name="d_token" placeholder="输入 API token..." required><small>获取 dari Cloudflare Dashboard → Profile → API Tokens</small></div>
    <button class="btn btn-green" style="margin-top:12px">💾 保存 Token & 继续</button>
  </form>
  <p style="font-size:11px;color:var(--text2);margin-top:12px">
    Token 保存到 <code>/var/www/manager/.cf_token</code>。权限：Zone:DNS:Edit。
  </p>
</div>
<?php else: ?>
<div class="stats">
  <div class="stat"><div class="val" style="font-size:20px;color:var(--green)">✅ 已连接</div><div class="lbl">Cloudflare API</div></div>
  <div class="stat"><div class="val"><?= count($dns_zones) ?></div><div class="lbl">Zone 数</div></div>
</div>

<div class="card"><h3>📋 Cloudflare Zones</h3>
  <?php if(empty($dns_zones)): ?><p style="color:var(--text2);padding:20px">没有 zones. 检查 token.</p>
  <?php else: ?>
  <table><thead><tr><th>域名</th><th>状态</th><th>套餐</th><th>NS 服务器</th><th>操作</th></tr></thead><tbody>
  <?php foreach($dns_zones as $z): ?>
  <tr>
    <td><strong><?= sanitize($z['name']) ?></strong></td>
    <td><span class="badge <?= $z['status']==='active'?'badge-ok':'badge-err' ?>"><?= $z['status'] ?></span></td>
    <td><?= $z['plan']['name'] ?></td>
    <td style="font-size:11px;color:var(--text2)"><?= sanitize(implode(', ', $z['name_servers'] ?? [])) ?></td>
    <td><a href="?page=dns&zone=<?= urlencode($z['name']) ?>" class="btn btn-blue btn-xs">📋 Records</a></td>
  </tr>
  <?php endforeach; ?>
  </tbody></table>
  <?php endif; ?>
</div>

<?php if($dns_zone): ?>
<div class="card">
  <h3>➕ 添加记录 — <?= sanitize($dns_zone) ?></h3>
  <form method="POST"><?= csrf_field() ?>
    <input type="hidden" name="action" value="dns_add">
    <input type="hidden" name="d_zone" value="<?= sanitize($dns_zone) ?>">
    <input type="hidden" name="d_token" value="">
    <div class="form-grid">
      <div class="form-group"><label>名称</label><input name="d_name" placeholder="@、www 或 sub.domain.com" required></div>
      <div class="form-group"><label>类型</label><select name="d_type" style="padding:10px 14px;border-radius:8px;border:2px solid var(--border);background:var(--surface);color:var(--text);font-size:14px"><option>A</option><option>AAAA</option><option>CNAME</option><option>MX</option><option>TXT</option><option>NS</option></select></div>
      <div class="form-group"><label>内容</label><input name="d_content" placeholder="IP 地址或目标域名" required></div>
      <div class="form-group"><label>TTL</label><input name="d_ttl" type="number" value="120"><small>1 = 自动</small></div>
    </div>
    <button class="btn btn-green" style="margin-top:14px">➕ 添加记录</button>
  </form>
</div>

<div class="card">
  <h3>📋 DNS 记录 (<?= count($dns_records) ?>)</h3>
  <?php if(empty($dns_records)): ?><p style="color:var(--text2);padding:20px">没有 records.</p>
  <?php else: ?>
  <table><thead><tr><th>类型</th><th>名称</th><th>内容</th><th>TTL</th><th>代理</th><th>操作</th></tr></thead><tbody>
  <?php foreach($dns_records as $r): ?>
  <tr>
    <td><span class="badge badge-blue"><?= $r['type'] ?></span></td>
    <td><strong><?= sanitize($r['name']) ?></strong></td>
    <td><code style="font-size:12px"><?= sanitize($r['content']) ?></code></td>
    <td><?= $r['ttl'] === 1 ? '自动' : $r['ttl'] ?></td>
    <td><?= ($r['proxied'] ?? false) ? '☁️' : '➡️' ?></td>
    <td>
      <form method="POST" style="display:inline" <?= confirm_attr('删除 DNS 记录 ' . $r['name'] . ' (' . $r['type'] . ')？') ?>><?= csrf_field() ?>
        <input type="hidden" name="action" value="dns_del">
        <input type="hidden" name="d_zone" value="<?= sanitize($dns_zone) ?>">
        <input type="hidden" name="d_recid" value="<?= $r['id'] ?>">
        <button class="btn btn-red btn-xs">🗑️</button>
      </form>
    </td>
  </tr>
  <?php endforeach; ?>
  </tbody></table>
  <?php endif; ?>
</div>
<?php endif; ?>
<?php endif; ?>

<?php endif; ?>
</div></div>

</body></html>
