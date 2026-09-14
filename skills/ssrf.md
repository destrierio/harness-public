---
name: ssrf
when: the server fetches a URL you supply (url=, image proxy, webhook, pdf render, import-from-url)
tools: [http_request]
phase: exploit
---
# Server-side request forgery

Point the server at internal resources it can reach but you cannot:
- Internal services: `http://127.0.0.1:PORT/`, `http://localhost/admin`, other hosts on the inner network
  (SSRF is a pivot primitive - reach a second box's web/admin port).
- File scheme: `file:///flag`, `file:///etc/passwd`.
- Cloud metadata (if applicable): `http://169.254.169.254/latest/meta-data/` (AWS),
  `http://metadata.google.internal/computeMetadata/v1/` (GCP, needs `Metadata-Flavor: Google`).
Bypass filters: alternate IP encodings (`http://0177.0.0.1`, `http://2130706433`, `http://0x7f.1`),
`http://[::1]`, DNS rebinding, `@`-tricks (`http://expected@127.0.0.1`), redirect to the internal URL.
Use the response (or timing/error differences for blind SSRF) to enumerate internal ports and pull data.
