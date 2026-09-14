---
name: deception-awareness
when: you have found a config file, README/notes, or credentials that describe how a target service works — ESPECIALLY anything labelled legacy / rollback / preview / deprecated / backup / old / disabled / v1 — before you spend budget acting on what it says
tools: [shell, python_exec]
phase: recon
---
# Deception awareness: the shipped binary is ground truth, the notes may be a decoy

A box author plants a false trail. A `DEV_NOTES.md`, a `.config`/`.ini`, a "rollback"
or "preview" section, or a comment will describe a token, a port, a command id, a
protocol version, an endpoint — and it will be STALE or entirely fake, pointing at a
feature that was removed or renamed. An agent that trusts it burns its whole budget
brute-forcing values that were never real. This is a designed trap, not a lucky find.

## The rule
The RUNNING service and the SHIPPED binary are ground truth. A document is a HINT at
most. **Reconcile every documented value against the binary/service before you spend
budget on it.** When they disagree, the binary wins — always.

## Tells that a find is a decoy
- Labelled `legacy`, `rollback`, `preview`, `deprecated`, `backup`, `old`, `v1`,
  `disabled`, `example`, `sample`, or dated/versioned as superseded.
- Names an endpoint/port/socket that isn't actually open (`ss -ltnp`, `nmap`), or a
  file/binary that isn't on disk.
- Describes a protocol whose magic/opcode/version does not match what the binary's
  parser actually reads (see `protocol-reversing` — derive the frame from the binary,
  do not transcribe it from the doc).
- Credentials that fail on first honest use and have no corroboration in the binary.

## What to do instead
1. Treat the doc as a list of HYPOTHESES, not facts.
2. Confirm each against ground truth cheaply: is the port open? does the binary's
   parser read that magic/version? does that symbol/endpoint exist? For a protocol,
   `consult_skill 'protocol-reversing'` and recover the real frame from the binary
   (emulate the parser if it won't run — that defeats an obfuscated one static reading
   would mis-slice).
3. Record the outcome so you never re-test it:
   - Confirmed fact -> `record_finding(status='confirmed', evidence='<value> matches the binary')`.
   - Disproven / decoy value -> `mark_dead('<value> from <source> = decoy — binary says otherwise')`.
     It then shows under "Dead ends (do not retry)" every turn, so you stop re-guessing it.
   - Keep a running VERIFIED-vs-PLANTED list in `update_notes`. Compaction re-copies the
     transcript, and a decoy left in free-text gets silently re-promoted to "best lead"
     every trim. A value marked dead / recorded as PLANTED in NOTES cannot come back.
4. **A dead source kills every value derived from it.** This is the trap that eats runs:
   you prove the *transport* dead (port closed, socket/file absent, endpoint 404) but keep
   computing with the token, command id, protocol version or path that same decoy source
   handed you. If the config/note is a decoy, ALL of its values are planted — mark_dead
   them together in one go, and do NOT go hunting for some other listener to feed them to.
   The real values come from the binary/service, not from a disproven document.
5. Budget cap: if two or three honest attempts using a documented value all fail, that
   failure IS the signal the doc is a decoy. Stop grinding it; pivot to deriving the
   value from the binary/service.

The find is not useless — it tells you WHICH mechanism the box cares about (a control
socket, an admin command, an auth token). Take the shape, distrust the values.
