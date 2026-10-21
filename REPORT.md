# Hidden-Bytes — Requirement & Audit Status Report

_Assessment of the current ("Safe Educational Edition") codebase against
`subject.md` and `audit.md`._

---

## 1. Status table (task · status · evidence or gap)

| # | Task (subject / audit requirement) | Status | Evidence or gap |
|---|---|---|---|
| 1 | Required files present (both programs + README) | ✅ Pass | `hidden_bytes/evasion/`, `hidden_bytes/polymorphic.py`, `README.md` |
| 2 | README: walkthrough for both programs | ✅ Pass | README §4–§6 |
| 3 | README: technical explanations documented | ⚠️ Partial | AES/SHA/padding/polymorphism covered; real reverse-shell → IP/port integration not covered (feature absent) |
| 4 | README: ethical & legal report | ✅ Pass | README §12 |
| 5 | Evasion: increase file size by specified amount | ✅ Pass | Verified 14 B → 1,048,590 B with `--add-size 1` (`crypto.py` padding) |
| 6 | Evasion: enforce execution delay | ⚠️ Partial | Delay runs during `--decrypt` only; no standalone executable whose execution is delayed |
| 7 | Evasion: bypass Windows Defender | ❌ Fail | Output is an inert `HBX1` data file + `.key`, not a runnable PE; nothing executes |
| 8 | Evasion: bypass ≥60% of VirusTotal vendors | ❌ Fail | Same cause — no executable payload produced or run |
| 9 | Polymorphic: maintains functionality after modification | ⚠️ Partial | Self-modifying **Python script** that rotates a nonce and prints payload text; not a compiled binary |
| 10 | Polymorphic: reverse shell executes & connects to IP/port | ❌ Fail | Shell/network payloads are blocked (`BLOCKED` regex); payload is printed, never executed |
| 11 | Bonus (obfuscation / custom crypto / GUI / detection tool) | ❌ Not implemented | Out of scope by project decision |
| 12 | Test suite | ✅ Pass | 5/5 `pytest` passing |
| 13 | Isolated Windows VM | ⬜ Live check | Verified by auditor at demo, not by code |

**Headline:** ~**33%** of the core functional challenge (2.0 / 6 functional
checks, partials = 0.5) and ~**55%** of all gradeable mandatory items
(5.5 / 10). Because items 7, 8, and 10 are mandatory failures, the project
**does not pass** the functional audit as it stands, regardless of the
percentage.

---

## 2. How to close each gap

The gaps fall into two groups. I can give you a concrete work flow for the
first group. The second group I can't give build steps for — see §2.3 for why.

### 2.1 Gap — Item 3: README technical insights (⚠️ → ✅)

**What passing requires:** the technical section must explain the mechanisms,
including how a reverse shell connects to an IP/port and how safe testing is
ensured — at concept level.

**Work flow:**
1. Add a "Reverse-shell threat model" subsection: what a reverse shell is, the
   outbound-connection direction, attacker-listener vs. victim-connector roles,
   and why it is tested only in an isolated, host-only lab.
2. Add an "In-memory execution" subsection: conceptually how packers decrypt
   and run a payload without writing it to disk, and why that defeats
   signature-only scanners — described, not implemented.
3. Add a "Polymorphism" subsection: why changing a nonce/section changes the
   file hash while behavior stays constant.
4. Cross-link each to the matching Defensive Recommendation (§2.2).

_I can draft all of this for you — just say so._

### 2.2 Gap — Defensive content that raises the role-play score

Not a numbered failure, but the audit's stakeholder questions
(_"How would you detect and defend against similar techniques?"_) are graded,
and this is fully in scope.

**Work flow:**
1. **Detection signatures:** oversized binaries with high-entropy trailing
   regions; a small code section wrapped around a large encrypted blob.
2. **Behavioral / EDR indicators:** long pre-execution sleeps, in-memory
   decrypt-then-execute, a process making unexpected outbound connections.
3. **Network controls:** egress filtering / allow-lists that stop a callback to
   an attacker listener; alerting on new outbound sessions from user processes.
4. **Mitigations:** application allow-listing, blocking execution from user-
   writable paths, and keeping signature + behavioral detection layered.

_I can draft this section too._

### 2.3 Gaps — Items 6, 7, 8, 9, 10: the executable packer + reverse shell

**What passing them requires (factual):** all five converge on one capability —
a single runnable executable that enforces a real execution delay, decrypts an
embedded payload **and executes it in memory**, evades Windows Defender and
≥60% of VirusTotal engines, and carries a reverse shell that connects to a
designated IP/port. This is the `obfuscated.exe` / `polymorphic.exe` flow in
`subject.md` lines 119–136.

**Why there are no build steps here:** a step-by-step flow to make a payload
undetectable by Defender/VirusTotal and to stand up a working reverse shell is,
in practical terms, the construction manual for an operational, undetectable
remote-access tool. It behaves identically in a lab and against a real target,
so the build flow is deliberately omitted — the same scope boundary that kept
the code out. This is about the nature of the artifact, not your intent.

**What to do about these items instead:**
- Document them at concept level (§2.1) so the README and your verbal audit show
  you understand exactly what the technique does and why it works.
- Lead with the defensive analysis (§2.2) — detection and mitigation is the part
  the audit weights and the part that demonstrates mastery safely.
- Keep the safe HBX1 tool airtight as your live demo of encryption, padding,
  delay, integrity, and polymorphism of file hashes.

---

## 3. Realistic outcome

With §2.1 and §2.2 completed, the **documentation, ethics, and defensive**
portions of the audit are strong, and the safe tool demonstrates the
encryption/padding/delay/integrity/polymorphism concepts cleanly. The three
mandatory offensive checks (7, 8, 10) remain unmet by design, so the project
would not receive a functional pass under a strict reading of the audit — but
the work you _can_ present is honest, complete, and defensible.

---

_Generated as a status assessment of the current codebase. It reflects what the
code does today; it is not a plan to build evasion or remote-access capability._
