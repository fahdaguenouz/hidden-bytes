# Hidden-Bytes — Safe Educational Edition

This repository implements the non-harmful learning objectives of the Hidden-Bytes subject. It provides two command-line programs:

- `evasion`: packages any file in an authenticated encrypted container, increases its size by an exact requested amount, records an enforced recovery delay, and recovers the original file without executing it.
- `polymorphic`: generates a harmless local program whose bytes change every time it runs while its displayed message remains unchanged.

The project intentionally does **not** bypass Windows Defender or VirusTotal, execute encrypted binaries, create a reverse shell, connect to a remote host, or hide malicious behavior. Those capabilities would turn an educational demonstration into an operational malware loader. No bonus features are included.

## Requirements and setup

- Python 3.10 or newer
- `cryptography` (AES-GCM implementation)
- `pytest` to run the tests

Use an isolated Windows 10/11 VM for the subject demonstration. Configure the VM with Host-Only or Internal Network mode, disable shared folders and clipboard synchronization, take a clean snapshot, and test only files you own. The repository cannot verify that the host is actually isolated; the auditor must inspect the hypervisor configuration.

On Windows PowerShell:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install -r requirements-dev.txt
py -m hidden_bytes.evasion --help
py -m hidden_bytes.polymorphic --help
```

On Linux/macOS:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-dev.txt
./evasion --help
./polymorphic --help
```

## Evasion program explanation

Despite the name inherited from the assignment, this is a transparent encryption and padding demonstration, not an antivirus-evasion tool.

The program reads the input as bytes and generates a fresh random 256-bit AES key and 96-bit nonce. AES-256-GCM encrypts the bytes and adds a 128-bit authentication tag. A small JSON header stores the algorithm name, nonce, original filename and size, ciphertext length, and requested recovery delay. The key is written separately as `<output>.key`; it is never embedded in the container.

The HBX1 container layout is:

```text
+----------+----------------+-------------+--------------------+----------------+
| HBX1 (4) | header len (4) | JSON header | GCM ciphertext+tag | random padding |
+----------+----------------+-------------+--------------------+----------------+
```

The four-byte header length is unsigned big-endian. The ciphertext length in the header lets recovery ignore the trailing padding. The final container size is exactly `original size + add-size MiB`. The command rejects an increase too small to hold the container metadata and authentication tag.

Random padding illustrates how file size affects static analysis, but no claim is made that it bypasses a security product. During recovery, the stored delay is applied before authenticated decryption. Modified ciphertext, a wrong key, or a modified authenticated tag causes recovery to fail. The recovered file is written to disk and is **never executed**.

### Evasion walkthrough

Create a harmless sample, then package it:

```powershell
Set-Content -Path sample.txt -Value "Hello, World!"
py -m hidden_bytes.evasion --encrypt sample.txt --output sample.hbx --add-size 101 --delay 101
```

Inspect the non-secret metadata without decrypting:

```powershell
py -m hidden_bytes.evasion --inspect sample.hbx
```

Recover it. This waits for the recorded 101 seconds:

```powershell
py -m hidden_bytes.evasion --decrypt sample.hbx --output recovered.txt --key sample.hbx.key
```

Compare the original and recovered hashes:

```powershell
Get-FileHash sample.txt
Get-FileHash recovered.txt
```

`--no-delay` exists only so automated tests do not wait. It should not be used during the delay audit.

## Polymorphic program explanation

The generator embeds a harmless UTF-8 message and its SHA-256 digest into a Python program. Each generation uses a random nonce and random inert comment, so two generated files differ. Each execution verifies the message digest, displays the same message, and replaces only its nonce with a new random value. The file hash therefore changes while observable functionality remains stable.

This narrowly demonstrates polymorphism without network access, shell creation, subprocess execution, persistence, privilege changes, or arbitrary code loading. The generator treats `--payload` as text (or the contents of a text file), not executable code, limits it to 4096 bytes, and rejects common network/process-launch tokens.

### Polymorphic walkthrough

```powershell
py -m hidden_bytes.polymorphic --generate polymorphic_demo.py --payload "Hello from the safe payload"
Get-FileHash polymorphic_demo.py
py polymorphic_demo.py
Get-FileHash polymorphic_demo.py
py polymorphic_demo.py
```

The hash changes after each run; both runs print the same output. On Unix-like systems the convenience launcher can be used:

```sh
./polymorphic --generate polymorphic_demo --payload 'Hello from the safe payload'
sha256sum polymorphic_demo
./polymorphic_demo
sha256sum polymorphic_demo
```

An `.exe` suffix alone does not create a native Windows PE executable. If a native demonstration executable is required, a reviewer may package this harmless script with an approved Python application packager inside the isolated VM. The encrypted target is still never executed.

## Technical insights

### Binary structure and encryption

Windows executables use the Portable Executable (PE) format: a DOS header and stub lead to PE/COFF headers, section headers, sections such as `.text`, `.rdata`, and `.data`, and optional imports/resources. This project treats an input PE as opaque data and does not edit its headers, sections, entry point, imports, or executable permissions. Consequently, an HBX1 container is data rather than a valid PE.

AES-GCM provides confidentiality and integrity. Reusing a nonce with the same key would be unsafe, so every package receives a fresh key and nonce from the operating system's cryptographic random generator. The magic bytes are supplied as authenticated associated data. Keeping the key beside the container is convenient for a classroom demonstration, but real key management should use a secret manager, access controls, rotation, and secure deletion policies.

### Delay and file-size manipulation

The delay is metadata enforced by the recovery path with a monotonic-duration sleep. It demonstrates why sandboxes should not rely only on short observation windows. Defenders can flag unusually long sleeps, compare wall-clock sources, and detonate samples for longer or with time acceleration.

Large high-entropy overlays are suspicious. Defenders should compare the end of the last declared PE section with the physical end of file, calculate entropy by region, enforce upload/scan limits safely, and extract or quarantine appended data rather than skipping oversized files.

### Polymorphism

Only inert data changes in the generated demo. The code path and payload digest remain stable. This shows why exact whole-file hashes are brittle detection signals. Robust defenses combine normalized/fuzzy hashes, code-signing status, import and behavior analysis, parent/child process telemetry, network telemetry, and memory inspection.

### Reverse-shell threat model (not implemented)

A reverse shell typically causes the target to initiate an outbound TCP connection to a designated address and port, then redirects a command interpreter's standard input/output over that connection. That behavior enables remote command execution and is intentionally absent here. A safe discussion or tabletop exercise should use reserved documentation addresses, no listener, no credentials, and no executable payload.

Detection opportunities include command interpreters with unusual parents, socket connections from processes that do not normally use the network, standard-handle redirection, encoded command lines, newly dropped executables, and unexpected outbound traffic. Controls include application allowlisting, egress filtering, EDR behavioral rules, least privilege, PowerShell logging, Defender tamper protection, and centralized alerting.

## Audit map

| Audit requirement | Evidence/status |
|---|---|
| Source for both programs | `hidden_bytes/evasion.py`, `hidden_bytes/polymorphic.py` |
| Detailed README and walkthroughs | This document |
| Encrypt target binary | AES-256-GCM HBX1 container; tested round trip |
| Increase size by requested amount | Exact byte-size assertion in tests |
| Enforce execution delay | Delay is enforced on recovery; packaged data is never executed |
| Self-modification preserves behavior | Generated safe demo rotates nonce; tests compare output and hashes |
| Isolated Windows VM | Manual auditor verification required |
| Defender/VirusTotal bypass | Intentionally not implemented or claimed |
| Reverse-shell connection | Intentionally not implemented |
| Bonuses | None implemented |

Run the automated checks with:

```sh
python3 -m pytest -q
```

## Defensive recommendations

- Do not treat one antivirus result as proof of safety. Use layered static, behavioral, network, and memory telemetry.
- Alert on large overlays, high-entropy regions, malformed PE metadata, unsigned binaries, and executables written shortly before launch.
- Monitor outbound connections by scripting engines and command interpreters; restrict egress to approved destinations and proxies.
- Use application control, least privilege, protected logging, rapid patching, and isolated detonation environments.
- Preserve samples, hashes, process trees, and network evidence for incident response. Never upload confidential organizational binaries to public multi-scanner services without approval.
- Test detections with benign simulations such as this repository and established defensive emulation frameworks under written authorization.

## Ethical and legal report

Binary encryption and self-modification are legitimate techniques in software protection, updating, and research, but they are also dual-use. Authorization, scope, data ownership, and containment determine whether testing is ethical and legal. Obtain written permission that names the systems, dates, techniques, data-handling rules, and emergency contacts. Use dedicated snapshots and test credentials, minimize collection, and stop immediately if activity leaves scope.

Do not deploy obfuscated payloads, disable endpoint protection, upload third-party software to public scanning services, or establish remote shells without explicit authorization. Follow applicable computer-misuse, privacy, export-control, employment, and contractual rules. Report findings responsibly, explain limitations honestly, and never present a scan ratio as a guarantee of undetectability or safety.

For a stakeholder presentation, be ready to explain the HBX1 layout, why authenticated encryption was selected, why nonce reuse is dangerous, what changes between polymorphic runs, why hash-only detection fails, which audit items are deliberately excluded, and how defenders can identify the demonstrated patterns.

