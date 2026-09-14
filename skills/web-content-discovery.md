---
name: web-content-discovery
when: an HTTP service is present and you need to map endpoints and the tech stack
tools: [shell, http_request, browser]
phase: recon
---
# Web content discovery

```
whatweb -a3 http://TARGET                                   # stack/CMS/version
gobuster dir -u http://TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,txt,html,bak,zip -t 40 -k
ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc all -fc 404
gobuster dir -u http://TARGET/cgi-bin/ -w .../CGIs.txt -x cgi,sh,pl   # cgi (shellshock etc.)
```
Also check by hand: `/robots.txt`, `/sitemap.xml`, `/.git/` (dump with git-dumper if present),
`/.env`, `/backup`, `/admin`, `/api`, `/swagger`, source comments, JS files for endpoints/keys.
vhosts: `ffuf -u http://TARGET -H 'Host: FUZZ.target' -w subdomains.txt -fs <baselen>`.
Use `browser` only for pages that need JS to render. Record each interesting endpoint/param as a finding
with the vuln class you suspect, then hand promising ones to the web workflow.
