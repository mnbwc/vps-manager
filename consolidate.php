<?php
/**
 * VPS Manager 单用户收敛 CLI（T-02 / T07c）——必须以 root 在服务器上执行，位于 DocumentRoot 之外。
 * 用法：php consolidate.php [--keep USER] [--dry-run]
 *   - 恰有 1 个 admin 且未指定 --keep：保留它
 *   - 多账号：必须指定 --keep USER（不静默挑号）
 *   - --dry-run 只列出将要执行的操作，不改库
 */
if (PHP_SAPI !== 'cli') { http_response_code(403); exit("CLI only\n"); }
if ((function_exists('posix_geteuid') ? posix_geteuid() : (int)trim((string)@shell_exec('id -u'))) !== 0) { fwrite(STDERR, "✗ 必须 root 执行\n"); exit(1); }

$keep = null; $dry = false;
$args = array_slice($argv, 1);
for ($i = 0; $i < count($args); $i++) {
    $a = $args[$i];
    if ($a === '--dry-run') $dry = true;
    elseif (preg_match('/^--keep=(.+)$/', $a, $m)) $keep = $m[1];
    elseif ($a === '--keep') { $keep = $args[++$i] ?? null; if ($keep === null) { fwrite(STDERR, "✗ --keep 缺少用户名\n"); exit(1); } }
    else { fwrite(STDERR, "未知参数: $a\n"); exit(1); }
}

$DB = '/var/www/manager/.panel.db';
$LEGACY_USERS = '/var/www/manager/.users';
$LEGACY_PASSWD = '/var/www/manager/.passwd';
$ARCHIVE_DIR = '/var/lib/vps-manager';
$SESSION_DIR = ini_get('session.save_path') ?: '/var/lib/php/sessions';

if (!file_exists($DB)) { fwrite(STDERR, "✗ 未找到 $DB\n"); exit(1); }
@mkdir($ARCHIVE_DIR, 0700, true);
$stamp = date('YmdHis');
$dbbak = "$ARCHIVE_DIR/panel.db.pre-consolidate.$stamp";
copy($DB, $dbbak); chmod($dbbak, 0600);
echo "✓ 备份: $dbbak\n";
if ($dry) echo "（--dry-run：以下操作不会真正执行）\n";

$db = new PDO('sqlite:' . $DB);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$rows = $db->query('SELECT user, pass, role FROM users')->fetchAll(PDO::FETCH_ASSOC);
$admins = array_values(array_filter($rows, fn($r) => ($r['role'] ?? '') === 'admin'));

if (count($rows) === 0) { fwrite(STDERR, "✗ 库为空（无用户）。请用安装脚本初始化 admin。\n"); exit(3); }

if ($keep === null) {
    if (count($admins) === 1 && count($rows) === 1) { $keep = $admins[0]['user']; echo "✓ 恰有 1 个 admin，保留: $keep\n"; }
    else { fwrite(STDERR, "✗ 存在 " . count($rows) . " 个账号（admin " . count($admins) . " 个）。必须用 --keep USER 指定保留者。\n账号列表：\n");
        foreach ($rows as $r) fwrite(STDERR, "  - {$r['user']} ({$r['role']})\n"); exit(3); }
} else {
    if (!in_array($keep, array_column($rows, 'user'), true)) { fwrite(STDERR, "✗ --keep 指定的用户 '$keep' 不存在\n"); exit(2); }
}

$del = count($rows) - 1;
if ($dry) {
    echo "将执行: DELETE FROM users WHERE user != '$keep'（删除 $del 行），并把 '$keep' role 设为 admin\n";
    foreach ($rows as $r) echo "  - {$r['user']} (" . ($r['user'] === $keep ? '保留→admin' : $r['role']) . ")\n";
    exit(0);
}
$db->prepare('DELETE FROM users WHERE user != ?')->execute([$keep]);
$db->prepare("UPDATE users SET role = 'admin' WHERE user = ?")->execute([$keep]);

$n = (int)$db->query('SELECT COUNT(*) FROM users')->fetchColumn();
$role = (string)$db->query("SELECT role FROM users WHERE user = " . $db->quote($keep))->fetchColumn();
if ($n !== 1 || $role !== 'admin') { fwrite(STDERR, "✗ 收敛后校验失败（users=$n, role=$role），请检查备份 $dbbak\n"); exit(4); }
echo "✓ 已删除 $del 个账号，唯一 admin = $keep\n";

// 归档遗留文件（防重导入）
foreach ([$LEGACY_USERS => '.users.migrated.', $LEGACY_PASSWD => '.passwd.migrated.'] as $f => $pfx) {
    if (file_exists($f)) { rename($f, "$ARCHIVE_DIR/$pfx$stamp"); echo "✓ 归档 $f → $ARCHIVE_DIR/$pfx$stamp\n"; }
}

// 作废旧 session
if (is_dir($SESSION_DIR)) {
    $cnt = 0;
    foreach (glob("$SESSION_DIR/sess_*") ?: [] as $sf) { @unlink($sf); $cnt++; }
    echo "✓ 已清除 $cnt 个旧 session\n";
}
echo "✅ 收敛完成。回滚：cp $dbbak $DB\n";
