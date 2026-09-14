---
name: network-recon
when: start of a run - find what is listening on the target
tools: [shell, session]
phase: recon
---
# Network recon (sealed cell: connect scans only)

The cell may deny raw sockets, so use CONNECT scans, not SYN.
```
nmap -sT -Pn -n -T4 --top-ports 2000 TARGET          # fast connect scan
nmap -sT -Pn -n -p- --min-rate 2000 TARGET           # full range if time allows
nmap -sT -sV -sC -Pn -n -p 22,80,443,... TARGET      # versions + default scripts on found ports
```
If nmap will not run, sweep with bash:
```
for p in 21 22 23 25 53 80 110 139 143 443 445 3306 5432 6379 8000 8080 8443 9000; do
  (echo >/dev/tcp/TARGET/$p) 2>/dev/null && echo "$p open"; done
```
Record every open port with record_service. UDP is rarely needed and slow in a connect-only cell.
Then enumerate each service (see `service-enumeration`) and pick the most promising (web, then auth
services, then anything with a known-vuln banner).
