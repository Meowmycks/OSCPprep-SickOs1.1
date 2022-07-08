# Boot2RootCTF_SickOs1.1

```Note: This box was completed long ago and I am going off of the VMware snapshot I saved after completion, some visuals will be missing and explained instead.```

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

After configuring Firefox with the proxy of ```192.168.57.130:3128```, we can access
