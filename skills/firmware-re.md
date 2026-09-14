---
name: firmware-re
when: you can obtain a firmware image / rootfs blob for the target (served by an update/staging host on the network, a device firmware-backup endpoint, or handed to you) — reverse it to read the vulnerable code instead of guessing
tools: [shell, python_exec, http_request]
phase: recon
---
# Firmware reverse-engineering (embedded device)

Reversing the firmware turns a blind embedded target into a WHITE-BOX one: you read the
exact vulnerable code — the parameter names, the web root, the trigger — instead of
brute-forcing them. Derive everything from THIS image, then confirm it against the live
device before trusting it. The image gives you METHOD; the running device still holds this
run's secrets (creds/flag), so recover those from the device itself.

## 1. Get the image onto disk — stream it, don't buffer a huge file in memory
Find who serves it: `nmap -sV <subnet>` for an HTTP/TFTP host that is NOT the target, then
browse it. Pull with the shell so it streams straight to /workspace (no size ceiling):
`wget http://<host>/firmware.bin -O /workspace/fw.bin`  (or `curl -o`, `tftp`, `scp`).
Then `file fw.bin` and `binwalk fw.bin` to see what it is. (`fetch_artifact` reads the whole
body into memory — fine for small binaries, but use `wget` for a large firmware image.)

## 2. Carve and extract the filesystem
`binwalk -e fw.bin` unpacks embedded filesystems into `_fw.bin.extracted/`. Common IoT
layouts and their extractors:
- SquashFS -> `unsquashfs <part>.squashfs`
- ext4/ext2/ext3 -> `debugfs -R 'rdump / out/' <part>.ext4` (UNPRIVILEGED — a sealed
  cell can't `mount -o loop`, which needs root/CAP_SYS_ADMIN; `debugfs` reads the fs
  directly). `dumpe2fs -h <part>` first to confirm it is ext.
- JFFS2   -> `jefferson <part> -d out/`
- UBIFS   -> `ubireader_extract_files <part>`
- anything else / carve-all -> `7z x <part> -oout/` (handles ext, squashfs, cpio,
  fat, iso without root); plain cpio/tar -> `cpio -idv` / `tar xf`.
`file` each carved piece; the largest is usually the root filesystem. If binwalk's
auto-extract stalls, read the offset it printed and carve by hand (`dd if=fw.bin
bs=1 skip=<offset> of=part.bin`), then run the matching extractor.

## 3. Map the running system from the rootfs
In the extracted rootfs, learn what the device actually runs and where it serves from:
- Web server + docroot: `etc/` configs for `lighttpd`/`boa`/`uhttpd`/`goahead`/`mini_httpd`
  — the `document-root` / `server.document-root` / `webroot` line names the web root you
  will exfil to (e.g. redirect command output there and GET it).
- CGI / handlers: `www/`, `cgi-bin/`, `*.cgi`, `*.lua`, `*.php`, or the compiled binary the
  httpd dispatches to.
- Startup: `etc/init.d/`, `etc/rc*`, `etc/inittab` — which daemons start and on which ports
  (this is how you learn whether a "telnet/ssh enable" toggle actually binds anything).
- Accounts / auth: `etc/passwd`/`etc/shadow`, hardcoded tokens, and the code that SETS or
  LEAKS admin creds. Recover the mechanism (which endpoint leaks them, how they are derived)
  — a firmware you were handed will not contain this run's live secret, so pull the real
  value from the device once you know where it lives.

## 4. Read the vulnerable code
FIRST, read the web FORMS, not the binary: the rootfs `www/` holds the admin UI as plain
HTML/JS (`www/*.html`, `www/*.js`, e.g. a `network`/`system` config page). Grep them for the
config form field names and the save/apply endpoint — `grep -rnoE '(name|id)="[a-z_]+"'
<rootfs>/opt/app/www` and search the JS for the CGI action it POSTs to. This hands you every
config parameter (hostname, ntp, ddns, dns, the `...fromdhcp`/apply toggles) and the exact
endpoint WITHOUT reversing a stripped binary — it is the fastest route to the injectable
config field a diagnostic-field probe would miss.

Then, to confirm which field reaches a shell, grep the handlers/binary:
Grep the handlers for request input flowing into a shell or a dangerous call:
`grep -rnE 'system|popen|exec[lv]e?|/bin/sh|eval' <rootfs>` (also grep for backtick
and `$(` substitution and shelling helpers the vendor wrapped around them).
For a compiled CGI, open it in radare2: `r2 -A <bin>`, then `axt sym.imp.system` to find who
calls it and `pdf @ <fn>` to read that function; `strings`/`objdump -d` also work. Trace which
HTTP parameter reaches the call and any GATE around it — a checkbox/flag that must be set, a
value that is only consumed on "apply", a companion "auto/from-DHCP" toggle that makes your
value inert. This is exactly the param + web root + trigger a blind run would have to guess.

## 5. Turn white-box knowledge into the exploit on the LIVE device
Attack the real target with what you read — do NOT re-derive it blindly:
`consult_skill 'command-injection'` / `'embedded-foothold'` for the confirm-first ->
capture-the-save -> trigger-on-apply -> web-root-exfil flow, using the exact param/root/
trigger the firmware revealed, and `'known-cve-exploitation'` if the image named a versioned
component. If the carved service is a compiled daemon speaking a CUSTOM wire protocol (a socket
service, a bespoke RPC) rather than a CGI, `consult_skill 'protocol-reversing'` — carving the
firmware only hands you the binary; the frame still has to be reversed. A foreign-arch binary
(MIPS/ARM) won't run on the x86 cell: run it under `qemu-<arch>-static` (e.g. `qemu-mipsel-static
./svc`) or emulate just the parser function. Always re-confirm against the live device first (a
served image can lag the running build) before committing the payload, then drive it to a held
shell / flag read.
