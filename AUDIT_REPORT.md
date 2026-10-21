# Hidden-Bytes — Requirement & Audit Status Report

_Assessment of the current codebase against `subject.md` and `audit.md`._
_Last updated after the "delay enforced by the artifact" work._

---

## 1. Status table (task · status · evidence or gap)

| # | Task (subject / audit requirement) | Status | Evidence or gap |
|---|---|---|---|
| 1 | Required files present (both programs + README) | ✅ Pass | `hidden_bytes/evasion/`, `hidden_bytes/polymorphic.py`, `README.md` |
| 2 | README: walkthrough for both programs | ✅ Pass | README §4–§6 |
| 3 | README: technical explanations documented | ⚠️ Partial | AES/SHA/padding/polymorphism covered; real reverse-shell → IP/port integration not covered (feature absent) |
| 4 | README: ethical & legal report | ✅ Pass | README §12 |
| 5 | Evasion: increase file size by specified amount | ✅ Pass | Verified 23 B → 105,906,199 B with `--add-size 101` (exact, both modes) |
| 6 | Evasion: enforce execution delay | ✅ **Pass** | **The artifact enforces the delay itself.** `hidden_bytes/evasion/runner.py` builds a self-extracting runner that waits, decrypts, then launches the payload. Verified: 101 s delay → 1 m 41 s wall clock. Test: `test_runner_enforces_the_delay_before_launching_the_payload` |
| 7 | Evasion: bypass Windows Defender | ❌ Fail | Not implemented, and out of scope for this safe edition. No AV-evasion technique is present |
| 8 | Evasion: bypass ≥60% of vendors on VirusTotal | ❌ Fail | Same cause — no evasion technique exists to measure, and no sample is uploaded to a public service |
| 9 | Polymorphic: maintains functionality after modification | ⚠️ Partial | Self-modifying **Python script** that rotates a nonce and prints payload text; not a compiled binary |
| 10 | Polymorphic: reverse shell executes & connects to IP/port | ❌ Fail | Shell/network payloads are blocked (`BLOCKED` regex); payload is printed, never executed |
| 11 | Bonus (obfuscation / custom crypto / GUI / detection tool) | ❌ Not implemented | Out of scope by project decision |
| 12 | Test suite | ✅ Pass | 18/18 `pytest` passing (was 5) |
| 13 | Isolated Windows VM | ⬜ Live check | Verified by auditor at demo, not by code |

**Headline:** the functional score moved from **~33%** of the core functional
checks to **~50%** (3.0 / 6, partials = 0.5). Items 7, 8, and 10 remain
mandatory failures, so the project **still does not pass** a strict functional
audit, regardless of the percentage.

---

## 2. Change log — what was fixed since the last report

### 2.1 Item 6 — the delay is now enforced by the artifact (⚠️ → ✅)

**Before:** the delay was metadata inside the container, applied only when the
operator ran `--decrypt`. The produced file was inert data. A reviewer running
the audit's own command would have seen a file that did nothing.

**After:** `--encrypt` produces a **self-extracting runner**. The file that
comes out of the tool is a program. Running it:

1. reads the embedded container,
2. derives the key from the passphrase (PBKDF2-HMAC-SHA256, 200 000 iterations),
3. **waits for the delay recorded inside the artifact**,
4. decrypts, writes the payload to a temporary directory,
5. launches it as an ordinary child process,
6. removes the temporary directory.

The tool does not need to be running, and no second command is required.

```text
$ python3 -m hidden_bytes.evasion --encrypt simple_program.py \
      --output obfuscated.pyz --add-size 101 --delay 101
[INFO] Added:       105906176 bytes

$ time python3 obfuscated.pyz
[INFO] Execution delayed by 101 seconds...
[INFO] Binary decrypted successfully.
[INFO] Target program executed.
Hello, World!
real    1m41.2s
```

**Files added**

| File | Purpose |
|---|---|
| `hidden_bytes/evasion/runner.py` | Runner generation, container embedding, `--build-exe` packaging |
| `hidden_bytes/evasion/pure_aes.py` | Dependency-free AES-256-GCM, spliced into the generated launcher |

**Files changed**

| File | Change |
|---|---|
| `hidden_bytes/evasion/crypto.py` | `build_payload()` factored out; optional `kdf` block in the header; `decrypt_file()` now accepts a passphrase and reads runners |
| `hidden_bytes/evasion/container.py` | `parse_container()` for in-memory parsing; optional `kdf` validation |
| `hidden_bytes/evasion/cli.py` | `--mode {runner,container}`, `--passphrase`, `--passphrase-file`, `--build-exe`; runner-aware `--inspect` |
| `hidden_bytes/evasion/constants.py` | KDF parameters, runner magic, runner member names |
| `tests/test_hidden_bytes.py` | 13 new tests, including the delay-enforcement test |

**Design notes worth stating in the role-play**

- The key is **not** in the artifact. It is derived from a passphrase at run
  time, so the artifact cannot be unpacked without the passphrase. The salt
  and iteration count are in cleartext metadata, which is normal for PBKDF2.
- The generated runner needs **nothing but a Python 3 interpreter**. The
  AES-GCM implementation is spliced into it, so the lab VM needs no
  `pip install` to unpack the artifact. The implementation is verified
  byte-for-byte against the `cryptography` package in the test suite,
  including the FIPS-197 AES-256 test vector.
- The launcher is a **transparent** program: it prints what it does, launches
  the payload as a normal child, and cleans up. There is no injection, no
  hollowing, no unlinking, no persistence, and no concealment. The delay is
  plainly visible to behavioural monitoring — which is exactly the point to
  make in the defensive discussion.

### 2.2 Two bugs found and fixed while building this

| Bug | Impact | Fix |
|---|---|---|
| In a frozen (PyInstaller) bundle, `sys.executable` **is** the bundle | A `.py` payload re-entered the runner → infinite recursion, the demo appeared to hang | The launcher runs a Python payload in-process with `runpy.run_path` when frozen, and spawns it normally otherwise |
| The container was looked up next to `__file__` only | In a frozen bundle the data files live in `sys._MEIPASS`, so the launcher could not find its container | The launcher checks `sys._MEIPASS` first, then the adjacent file, then the zip member |

Both were caught by running the packaged executable, not by the unit tests.
The build now also `compile()`s the rendered launcher before writing it, so a
malformed template fails at build time instead of at demo time.

### 2.3 Exact size accounting

The audit checks *"file size increased by 101 MB"*. The increase is now exact,
in both modes:

- **Runner mode** — the container and the padding are stored uncompressed
  inside the runner archive, so every padding byte is one byte in the file.
- **`--build-exe` mode** — the padding is appended after the packaged
  PyInstaller archive. The PyInstaller 6.x loader locates its archive with a
  back-to-front scan for its cookie, so trailing bytes do not affect
  execution. Verified with a 101 MB append: the executable still runs and
  still launches the payload.

One caveat: a packaged `.exe` carries a fixed runtime overhead (the bundled
Python interpreter, roughly 9–15 MB). The requested increase must exceed it.
The tool now reports the minimum required size instead of failing silently.

---

## 3. Remaining gaps

### 3.1 Item 3: README technical insights (⚠️ → ✅)

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
4. Cross-link each to the matching Defensive Recommendation.

_I can draft all of this for you — just say so._

### 3.2 Defensive content that raises the role-play score

Not a numbered failure, but the audit's stakeholder questions
(_"How would you detect and defend against similar techniques?"_) are graded,
and this is fully in scope.

**Work flow:**
1. **Detection signatures:** oversized binaries with high-entropy trailing
   regions; a small code section wrapped around a large encrypted blob.
2. **Behavioral / EDR indicators:** long pre-execution sleeps, a child process
   created after an idle period, a temporary directory that is written, executed
   and deleted in a short window.
3. **Network controls:** egress filtering / allow-lists that stop a callback to
   an attacker listener; alerting on new outbound sessions from user processes.
4. **Mitigations:** application allow-listing, blocking execution from user-
   writable paths, and keeping signature + behavioral detection layered.

The README §10 already covers most of this. It is worth rehearsing it aloud
before the audit.

### 3.3 Items 7, 8, 9, 10: AV evasion and the reverse shell

**What passing them requires (factual):** all four converge on one capability —
a single runnable executable that evades Windows Defender and ≥60% of
VirusTotal engines, and carries a reverse shell that connects to a designated
IP/port.

**Why there are no build steps here:** a step-by-step flow to make a payload
undetectable by Defender/VirusTotal and to stand up a working reverse shell is,
in practical terms, the construction manual for an operational, undetectable
remote-access tool. It behaves identically in a lab and against a real target,
so the build flow is deliberately omitted — the same scope boundary that kept
the code out. This is about the nature of the artifact, not your intent.

**What to do about these items instead:**
- Document them at concept level (§3.1) so the README and your verbal audit show
  you understand exactly what the technique does and why it works.
- Lead with the defensive analysis (§3.2) — detection and mitigation is the
  part the audit weights and the part that demonstrates mastery safely.
- Keep the runner as your live demo of encryption, padding, delay, integrity,
  passphrase-based key derivation, and polymorphism of file hashes.

---

## 4. Realistic outcome

With §3.1 and §3.2 completed, the **documentation, ethics, and defensive**
portions of the audit are strong, and the runner demonstrates the
encryption/padding/delay/integrity/key-derivation/polymorphism concepts
cleanly, with a delay that is now genuinely enforced by the produced artifact.
The three offensive checks (7, 8, 10) remain unmet by design, so the project
would not receive a functional pass under a strict reading of the audit — but
the work you _can_ present is honest, complete, and defensible.

---

_Generated as a status assessment of the current codebase. It reflects what the
code does today; it is not a plan to build evasion or remote-access capability._
