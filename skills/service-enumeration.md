---
name: service-enumeration
when: you have open ports and need to fingerprint and probe each service
tools: [shell, http_request, session]
phase: recon
---
# Service enumeration by port

- 21 FTP: `nc TARGET 21`; try anonymous (`ftp`/anonymous:anything); `ls`, download configs.
- 22 SSH: banner (version -> CVE?); try found creds; `ssh -o StrictHostKeyChecking=no`.
- 25/110/143 mail: banner grab; VRFY user enumeration.
- 80/443/8080/8000 HTTP: `whatweb`, headers, `curl -sik`; then `web-content-discovery`.
- 139/445 SMB: `netexec smb TARGET`, `smbclient -N -L //TARGET/`, `enum4linux-ng TARGET`; null sessions, shares.
- 3306 MySQL / 5432 Postgres: try default/blank creds (`mysql -h TARGET -u root`; `psql -h TARGET -U postgres`).
- 6379 Redis: `redis-cli -h TARGET info`; unauth -> write SSH key / webshell via `config set dir`.
- 2049 NFS: `showmount -e TARGET`; mount and read.
- Unknown/custom port: `nc TARGET PORT` and interact (open a session); it may be a pwn target
  (download the binary if offered) - see `pwn-triage`.
Record versions with record_service and note the single most likely weakness per service as a finding.
