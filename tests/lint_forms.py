#!/usr/bin/env python3
"""T03 验收：静态检查 index.php 表单 CSRF / on* 属性 / confirm 转义。
用法: python3 tests/lint_forms.py index.php   → 输出违规数，0 = PASS"""
import re, sys

def main(path):
    src = open(path, encoding='utf-8').read()
    violations = []

    # ① on* 属性内不得出现 csrf_field
    for m in re.finditer(r'on\w+\s*=\s*"[^"]*csrf_field[^"]*"', src):
        violations.append((src[:m.start()].count('\n') + 1, 'csrf_field 出现在 on* 属性内'))

    # ② 每个 POST form 在 </form> 前须含 csrf_field() 或 name="csrf"
    for m in re.finditer(r'<form\b[^>]*method=["\']POST["\'][^>]*>(.*?)</form>', src, re.S | re.I):
        body, ln = m.group(1), src[:m.start()].count('\n') + 1
        if 'csrf_field()' not in body and 'name="csrf"' not in body and "name='csrf'" not in body and "'+CSRF+'" not in body and "$GLOBALS['csrf']" not in body and "<?= csrf_field() ?>" not in body:
            violations.append((ln, 'POST 表单缺少 csrf token'))

    # ③ confirm( 内不得出现未经 js_str 的 <?= 输出（confirm_attr 生成的是 js_str，合法）
    for m in re.finditer(r'confirm\([^)]*<\?=', src):
        ln = src[:m.start()].count('\n') + 1
        line = src.split('\n')[ln - 1]
        if 'confirm_attr' not in line and 'js_str' not in line:
            violations.append((ln, 'confirm() 内含未转义 PHP 输出'))

    for ln, msg in violations:
        print(f'line {ln}: {msg}')
    print(f'violations={len(violations)}')
    sys.exit(0 if not violations else 1)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'index.php')
