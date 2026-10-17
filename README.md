# Hidden-Bytes — Safe Educational Edition

> **Purpose:** study binary containers, authenticated encryption, file-size manipulation, file-level polymorphism, self-modification, integrity checking, and defensive detection in a controlled lab.
>
> **Safety boundary:** this edition does not implement antivirus evasion, a working reverse shell, remote command execution, persistence, or automatic execution of encrypted files. It does not claim to bypass Microsoft Defender, VirusTotal, or any other security product.

## Contents

- [1. Project overview](#1-project-overview)
- [2. Subject and audit scope](#2-subject-and-audit-scope)
- [3. Requirements and setup](#3-requirements-and-setup)
- [4. Tool 1 — Evasion / HBX1 container](#4-tool-1--evasion--hbx1-container)
- [5. Tool 2 — Polymorphic generator](#5-tool-2--polymorphic-generator)
- [6. End-to-end lab walkthrough](#6-end-to-end-lab-walkthrough)
- [7. Technical concepts](#7-technical-concepts)
- [8. Diagrams](#8-diagrams)
- [9. Audit checklist and evidence](#9-audit-checklist-and-evidence)
- [10. Defensive analysis](#10-defensive-analysis)
- [11. Limitations and known caveats](#11-limitations-and-known-caveats)
- [12. Ethics and lab safety](#12-ethics-and-lab-safety)

---

## 1. Project overview

Hidden-Bytes is a command-line educational project with two separate programs:

| Program | Main purpose | Output | Does it execute the input file? |
|---|---|---|---|
| `evasion` | Encrypt a file into an authenticated HBX1 data container, add random padding, and recover the original after an optional delay | `.hbx` container and separate `.key` file | **No** |
| `polymorphic` | Generate a harmless Python program whose inert signature changes while its displayed text stays the same | A generated `.py` program | It executes only its own safe demo logic when the generated script is run; the supplied payload is displayed as text, not executed |

The `evasion` name is retained because it comes from the assignment. The implementation is a **container and encryption demonstration**, not an antivirus-evasion mechanism.

### What this project demonstrates

- AES-256-GCM authenticated encryption.
- A simple binary container format with a magic value, metadata, ciphertext, and padding.
- Exact final-size calculation for a requested padding increase.
- A recovery delay applied before decryption.
- Authentication failure when the wrong key or modified ciphertext is supplied.
- A generated program with randomized inert data and a self-updating signature.
- Why whole-file hashes change when even non-functional bytes change.
- How defenders can investigate unusual file structure and behavior.

### What it deliberately does not implement

- Bypassing or disabling endpoint protection.
- A claimed Defender or VirusTotal detection-bypass percentage.
- A PE loader or automatic execution of encrypted binaries.
- A reverse shell, remote listener, command-and-control, or remote command execution.
- Persistence, privilege escalation, stealthy process injection, or anti-analysis tricks.
- The optional bonus features from the original subject.

These exclusions are part of the scope, not unfinished features to silently assume are present.

---
## HBX1 Encryption and Recovery Flow

### 1. Encryption flow

```mermaid
flowchart TD
    A["Original file"] --> B["Read file bytes"]
    B --> C["Generate AES-256 key and nonce"]
    C --> D["Encrypt using AES-256-GCM"]
    D --> E["Produce ciphertext and authentication tag"]
    E --> F["Build JSON metadata"]
    F --> G["Build HBX1 container"]
    G --> H["Add random padding"]
    H --> I["Save .hbx container"]
    C --> J["Save separate .key file"]

    G -. "Container contains magic bytes, header length, metadata, ciphertext and tag" .-> K["HBX1 format"]
```

### 2. Inspection and recovery flow

```mermaid
flowchart TD
    A["Existing .hbx container"] --> B["Read magic bytes and header length"]
    B --> C["Parse JSON metadata"]
    C --> D{"Requested operation?"}

    D -- "Inspect" --> E["Display metadata"]
    E --> F["Finish without decrypting"]

    D -- "Decrypt" --> G["Load separate key file"]
    G --> H{"Delay enabled?"}
    H -- "Yes" --> I["Wait for configured delay"]
    H -- "No" --> J["Attempt authenticated decryption"]
    I --> J

    J --> K{"Authentication succeeds?"}
    K -- "No" --> L["Report decryption failure"]
    K -- "Yes" --> M["Write recovered file bytes"]
    M --> N["Compare SHA-256 hashes"]
    N --> O["Confirm byte-for-byte recovery"]
```

### 3. How to read the container

```mermaid
flowchart TD
    A["HBX1 container"] --> B["4-byte magic value"]
    B --> C["4-byte header length"]
    C --> D["JSON metadata"]
    D --> E["AES-GCM ciphertext"]
    E --> F["16-byte authentication tag"]
    F --> G["Random padding"]
```

**Important notes**

- **Magic value:** identifies the container format.
- **Header length:** a 4-byte unsigned, big-endian integer specifying the JSON metadata length in bytes.
- **JSON metadata:** stores information such as the algorithm, nonce, original filename, original size, ciphertext length, and recovery delay.
- **Ciphertext and authentication tag:** AES-256-GCM encrypts the original bytes and produces a tag used to verify authenticity and integrity during decryption.
- **Random padding:** increases the container size; it is not part of the original file and does not strengthen the encryption.
- **Recovery delay:** the recovery program waits before attempting decryption. The container does not decrypt itself or execute the recovered file.
- **SHA-256 comparison:** matching hashes provide evidence that the recovered file is byte-for-byte identical to the original.

**Note:** `--inspect` displays metadata without authenticating the ciphertext. Authentication is checked when decryption is attempted.


---

## 2. Subject and audit scope

The original subject discusses binary manipulation, encryption, file-size changes, delayed behavior, polymorphism, reverse shells, and antivirus detection. This repository implements safe demonstrations of several underlying concepts, while leaving operational malware capabilities out.

| Subject / audit topic | This implementation | How to demonstrate it |
|---|---|---|
| Encrypt an input file | Implemented using AES-256-GCM | Encrypt, then recover and compare SHA-256 hashes |
| Modify final file size | Implemented using random padding | Compare original size and container size |
| Requested size increase | Exact to the rounded MiB amount requested | Check `stat` / file properties and the CLI's size report |
| Delay | Stored in metadata and enforced before recovery | Use a non-zero delay and observe the wait |
| Inspect binary/container structure | Implemented for HBX1 metadata | Run `--inspect` and examine the layout diagram |
| Polymorphic variants | Implemented with random nonce/comment data | Generate two files and compare hashes |
| Self-modification | Implemented by changing the generated script's nonce | Hash a generated script, run it, and hash it again |
| Stable behavior | Same embedded message is displayed on each run | Capture output from multiple runs |
| Native Windows PE output | Not generated by the scripts themselves | A `.py` file or `.exe` filename does not by itself establish PE validity |
| Defender / VirusTotal bypass | Not implemented or claimed | Record this as out of scope; do not report an unmeasured bypass rate |
| Reverse-shell connection | Not implemented | Explain the threat model and defensive telemetry; no shell or connection is created |
| Isolated Windows VM | Must be verified manually by the auditor | Capture hypervisor network and integration settings |
| Bonus features | None implemented | Mark as not implemented |

**Important audit wording:** the delay is a **recovery delay**, not an execution delay. The encrypted HBX1 file is data and is not launched as a program.

---

## 3. Requirements and setup

### Prerequisites

- Python 3.10 or newer.
- The packages listed in `requirements-dev.txt` (including `cryptography` and `pytest`).
- A terminal: PowerShell on Windows, or a shell on Linux/macOS.
- For the subject demonstration, a dedicated Windows 10/11 virtual machine configured and inspected by the auditor.

### Recommended repository layout

```text
Hidden-Bytes/
├── hidden_bytes/
│   ├── __init__.py
│   ├── evasion.py
│   └── polymorphic.py
├── tests/
├── requirements.txt
├── requirements-dev.txt
├── README.md
└── output/                  # generated examples; optional
```

The precise test filenames may differ in your checkout. Run the test command shown below from the project root.

### Windows PowerShell

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install -r requirements-dev.txt

py -m hidden_bytes.evasion --help
py -m hidden_bytes.polymorphic --help
```

If PowerShell blocks virtual-environment activation due to local policy, use the Python executable in `.venv\Scripts\python.exe` directly rather than changing a system-wide execution policy just for this project.

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements-dev.txt

python3 -m hidden_bytes.evasion --help
python3 -m hidden_bytes.polymorphic --help
```

If the repository includes executable wrapper scripts, they may also be used:

```bash
./evasion --help
./polymorphic --help
```

### Isolated lab configuration

Before any Windows demonstration, ask the auditor to verify:

1. The VM uses **Host-Only** or **Internal Network** mode as required by the lab scope.
2. Shared folders, shared clipboard, and drag-and-drop are disabled.
3. A clean snapshot exists and can be restored.
4. Only owned, harmless test files are used.
5. No confidential organizational file is uploaded to a public scanning service.
6. Evidence is saved without exposing keys or sensitive sample contents.

A README cannot prove the VM is isolated. Isolation must be checked in the hypervisor settings.

---

## 4. Tool 1 — Evasion / HBX1 container

> **Scope note:** `evasion` is the assignment's original tool name. This safe edition demonstrates authenticated encryption, binary-container parsing, padding, and delayed recovery. It does **not** bypass antivirus, execute recovered files, or implement a malware loader.

### 4.1 What the tool does

`hidden_bytes.evasion` has three modes:

- `--encrypt`: reads a file as bytes, encrypts it using AES-256-GCM, writes an HBX1 container, and writes the generated key to a separate `<output>.key` file.
- `--inspect`: parses and displays the container metadata without decrypting its contents.
- `--decrypt`: reads the container and key, waits for the recorded recovery delay unless `--no-delay` is supplied, authenticates and decrypts the ciphertext, then writes the recovered bytes to disk. It never executes the recovered file.

The optional `--add-size` value requests an increase in the **final container size**. The tool fills the container with random padding to reach the target size. Padding is not encrypted content and does not make the encryption stronger.

### 4.2 CLI reference — all options

Display help:

```bash
python3 -m hidden_bytes.evasion --help
```

The module expects exactly one mode (`--encrypt`, `--decrypt`, or `--inspect`) and a positional input path called `source`.

| Option | Meaning | Notes |
|---|---|---|
| `source` | Input file or HBX1 container | Required positional argument |
| `--encrypt` | Encrypt/package the source file | Must be used with `--output` |
| `--decrypt` | Recover a file from an HBX1 container | Must be used with `--output` |
| `--inspect` | Print container metadata | Does not decrypt the payload |
| `--output PATH` | Destination path | Required for encryption and decryption |
| `--add-size MB` | Requested increase in final container size | Help default: `0.01` MB; `1` requests 1 MiB (1,048,576 bytes) |
| `--delay SECONDS` | Recovery delay stored in the container | Help default: `101` seconds; set a small value such as `2` for a quick demo |
| `--key PATH` | Key file to use during decryption | Encryption generates `<output>.key` automatically |
| `--no-delay` | Skip the stored delay during recovery | Useful for controlled tests; do not use it when demonstrating the delay |

The defaults shown above are those reported by this project's CLI help. Explicitly set `--add-size` and `--delay` in demonstrations so the behavior is reproducible.

### 4.3 Complete Linux / Kali walkthrough

Run commands from the repository root (`~/Desktop/hidden-bytes`) with the virtual environment activated.

#### Step 1 — Create a harmless sample

```bash
printf 'Hello from Hidden-Bytes -- sample file\n' > sample.txt
wc -c sample.txt
```

`wc -c` shows the exact input length. The example string above is **39 bytes**, including its final newline.

#### Step 2 — Encrypt and add 1 MiB to the final size

```bash
python3 -m hidden_bytes.evasion \
  --encrypt sample.txt \
  --output sample.hbx \
  --add-size 1 \
  --delay 2
```

Expected artifacts:

```text
sample.txt       # original test file
sample.hbx       # encrypted HBX1 data container
sample.hbx.key   # generated key; keep it private
```

Representative output from the tested 39-byte sample:

```text
[OK] Encryption completed.
[INFO] Input:       sample.txt
[INFO] Container:   sample.hbx
[INFO] Key:         .../sample.hbx.key
[INFO] Original:    39 bytes
[INFO] Container:   1048615 bytes
[INFO] Added:       1048576 bytes
[INFO] Delay:       2 second(s)
[INFO] The container is data only; nothing is executed.
```

The exact key path depends on where the repository is located. `--add-size 1` requests 1 MiB (1,048,576 bytes) above the input size, so this sample's final container is 39 + 1,048,576 = **1,048,615 bytes**. Metadata and encryption overhead are accounted for inside that final-size target.

#### Step 3 — Inspect the container

```bash
python3 -m hidden_bytes.evasion --inspect sample.hbx
```

The command prints metadata similar to:

```json
{
  "algorithm": "AES-256-GCM",
  "ciphertext_length": 55,
  "container_ciphertext_bytes": 55,
  "container_magic": "HBX1",
  "container_size_bytes": 1048615,
  "delay_seconds": 2.0,
  "nonce": "<random Base64 value>",
  "original_name": "sample.txt",
  "original_size": 39
}
```

The nonce changes between encryption runs, so the example nonce above is a placeholder. Inspection shows metadata; it does not reveal the secret key and does not by itself validate the ciphertext's authenticity. Authentication is checked during decryption.

#### Step 4 — Recover the original file

```bash
python3 -m hidden_bytes.evasion \
  --decrypt sample.hbx \
  --output recovered.txt \
  --key sample.hbx.key
```

Expected behavior for a container created with `--delay 2`:

```text
[INFO] Recovery delayed for 2 second(s)...
[OK] Recovery completed.
[INFO] Recovered file: recovered.txt
[INFO] The recovered file was written to disk but was NOT executed.
```

For a quick test that skips the configured wait:

```bash
python3 -m hidden_bytes.evasion \
  --decrypt sample.hbx \
  --output recovered-no-delay.txt \
  --key sample.hbx.key \
  --no-delay
```

Use a different output filename if you want to keep both recovery results. `--no-delay` bypasses only the demonstration wait; it does not bypass encryption or authentication.

#### Step 5 — Verify recovery using SHA-256

```bash
sha256sum sample.txt recovered.txt
```

In the test run shared during this project, both files produced the same hash:

```text
06570c37ec2d0014c9bb0c10e6e4934f13de8adc8ca73b11107afdeebdca2310  sample.txt
06570c37ec2d0014c9bb0c10e6e4934f13de8adc8ca73b11107afdeebdca2310  recovered.txt
```

That hash belongs to the exact file content used in that recorded run. If you create a new sample using the command above, the hash will be different, but the original and recovered hashes should still match. Matching SHA-256 hashes provide evidence that the recovered file is byte-for-byte identical to the original.

Alternative byte-for-byte comparison:

```bash
cmp sample.txt recovered.txt && echo 'Files match'
```

Check file sizes:

```bash
stat -c '%n: %s bytes' sample.txt sample.hbx recovered.txt
```

### 4.4 Other useful test commands

Inspect the CLI options:

```bash
python3 -m hidden_bytes.evasion --help
```

Create a second container with a different delay and size increase:

```bash
python3 -m hidden_bytes.evasion \
  --encrypt sample.txt \
  --output sample-small.hbx \
  --add-size 0.1 \
  --delay 5
```

Inspect it:

```bash
python3 -m hidden_bytes.evasion --inspect sample-small.hbx
```

Recover it without waiting (for a quick test):

```bash
python3 -m hidden_bytes.evasion \
  --decrypt sample-small.hbx \
  --output recovered-small.txt \
  --key sample-small.hbx.key \
  --no-delay
```

Compare the recovered content:

```bash
sha256sum sample.txt recovered-small.txt
```

Run the project's automated tests from the repository root:

```bash
python3 -m pytest -q
```

### 4.5 HBX1 container layout

The container is a custom **data format**, not a Windows PE executable.

```text
+-----------------------------------------+
| Magic: "HBX1"                 (4 bytes) |
+-----------------------------------------+
| Header length (uint32, big-endian)       |
+-----------------------------------------+
| JSON metadata                            |
| algorithm, nonce, original name/size,    |
| ciphertext length, recovery delay       |
+-----------------------------------------+
| AES-GCM ciphertext                       |
| encrypted original bytes + 16-byte tag   |
+-----------------------------------------+
| Random padding                           |
| fills remaining bytes to target size    |
+-----------------------------------------+
```

The `ciphertext_length` metadata field identifies the encrypted section's length, including the GCM authentication tag. The recovery code uses this length to avoid treating padding as ciphertext.

### 4.6 Encryption flow diagram

```mermaid
flowchart TD
    A[Input file: sample.txt] --> B[Read original bytes]
    B --> C[Generate fresh AES-256 key and 96-bit nonce]
    C --> D[Encrypt bytes with AES-256-GCM]
    D --> E[Create metadata: name, size, nonce, delay, ciphertext length]
    E --> F[Build HBX1: magic + header length + metadata + ciphertext]
    F --> G[Append random padding to requested final size]
    G --> H[Write sample.hbx]
    C --> I[Write separate sample.hbx.key]
    H --> J[Container and key are ready]
    I --> J
```

### 4.7 Inspection and recovery flow diagram

```mermaid
flowchart TD
    A[HBX1 container] --> B[Read magic and header length]
    B --> C[Parse JSON metadata]
    C --> D[Display metadata for --inspect]
    C --> E[For --decrypt: read declared ciphertext bytes]
    E --> F[Wait for stored delay unless --no-delay]
    F --> G[Load the supplied key]
    G --> H{AES-GCM authentication succeeds?}
    H -- No --> I[Report decryption/authentication failure]
    H -- Yes --> J[Check recovered byte length]
    J --> K[Write recovered file to disk]
    K --> L[Stop: never execute recovered file]
```

### 4.8 What the tool does and does not prove

- **Encryption:** the input bytes are encrypted using AES-256-GCM.
- **Authentication:** a wrong key or modified authenticated ciphertext should fail authentication during recovery.
- **Size manipulation:** padding makes the final container reach the requested size increase.
- **Delay:** the configured wait occurs before recovery, not before execution.
- **Integrity evidence:** matching original/recovered SHA-256 hashes demonstrates successful byte-for-byte recovery.
- **No antivirus bypass:** encryption, padding, file-size changes, and matching recovery hashes do not demonstrate Defender or VirusTotal evasion.
- **Key handling:** the `.key` file is separate from the container but is saved beside it by default. Protect it and do not commit it to version control.
- **No execution:** the container is data; recovered bytes are written to disk and never launched by this tool.

## 5. Tool 2 — Polymorphic generator

### 5.1 What it does

`hidden_bytes.polymorphic` generates a Python demonstration program that contains:

- A text payload (or the contents of a UTF-8 text file).
- A SHA-256 digest of that text.
- A random nonce used as a signature value.
- An inert random comment to make independently generated files different.

When the generated program runs, it checks that the embedded text matches the digest, prints the text, and updates its own nonce. Thus, its file hash changes while the displayed message remains the same.

The supplied payload is treated as **text**, not Python code. It is not passed to `eval`, `exec`, a shell, or a process launcher.

### 5.2 Generate a demonstration

PowerShell:

```powershell
py -m hidden_bytes.polymorphic --generate polymorphic_demo.py --payload "Hello from the safe payload"
```

Linux/macOS:

```bash
python3 -m hidden_bytes.polymorphic \
  --generate polymorphic_demo.py \
  --payload "Hello from the safe payload"
```

You can also supply a text file:

```powershell
Set-Content -Path message.txt -Value "This is text, not executable code."
py -m hidden_bytes.polymorphic --generate polymorphic_demo.py --payload message.txt
```

```bash
printf 'This is text, not executable code.\n' > message.txt
python3 -m hidden_bytes.polymorphic \
  --generate polymorphic_demo.py \
  --payload message.txt
```

The generator limits the payload to 4096 UTF-8 bytes and rejects some common shell/process-related tokens. **That token filter is only a basic guardrail, not a security sandbox or a reliable classifier.** The key safety property is that the payload is displayed as text rather than executed.

### 5.3 Observe the changing hash

PowerShell:

```powershell
Get-FileHash polymorphic_demo.py -Algorithm SHA256
py polymorphic_demo.py
Get-FileHash polymorphic_demo.py -Algorithm SHA256
py polymorphic_demo.py
Get-FileHash polymorphic_demo.py -Algorithm SHA256
```

Linux/macOS:

```bash
sha256sum polymorphic_demo.py
python3 polymorphic_demo.py
sha256sum polymorphic_demo.py
python3 polymorphic_demo.py
sha256sum polymorphic_demo.py
```

Expected observations:

1. The program prints the same payload message on each run.
2. It verifies the embedded payload's SHA-256 digest before printing.
3. It changes the nonce stored in its source file.
4. The file's SHA-256 hash changes after the self-modification.

The generated file must be writable for the self-modification step. If it is read-only or located in a directory where the user lacks write permission, the signature update can fail.

### 5.4 Generate two variants and compare them

Generate two files with the same text:

```bash
python3 -m hidden_bytes.polymorphic \
  --generate variant_a.py \
  --payload "Same visible behavior"

python3 -m hidden_bytes.polymorphic \
  --generate variant_b.py \
  --payload "Same visible behavior"

sha256sum variant_a.py variant_b.py
```

The files should have different hashes because their nonce and inert variant comment are randomized. The visible message remains the same.

### 5.5 Polymorphic flow

```mermaid
flowchart TD
    A[Text or UTF-8 text file] --> B[Check non-empty and 4096-byte limit]
    B --> C[Apply basic blocked-token checks]
    C --> D[Calculate SHA-256 of text]
    D --> E[Generate random nonce and inert comment]
    E --> F[Write Python demonstration]
    F --> G[Run generated program]
    G --> H[Verify embedded text digest]
    H --> I[Print the same text]
    I --> J[Replace local nonce]
    J --> K[File hash changes; displayed behavior stays stable]
```

### 5.6 What “polymorphism” means in this demo

The example illustrates a narrow form of **file-level variation**: bytes change while the intended visible output stays the same. It does not implement machine-code mutation, a native PE rewriter, an encrypted executable loader, or antivirus evasion.

A `.exe` extension does not turn a Python script into a Windows PE file. If a reviewer requires a native executable for a benign demonstration, any packaging should be done separately with an approved application packager inside the isolated VM. That does not make it an evasion tool.

---

## 6. End-to-end lab walkthrough

Use harmless text samples first. These commands are intended to make the behavior easy to show to an auditor.

### Exercise A — Encryption, padding, recovery, and integrity

1. Create `sample.txt` containing a short message.
2. Encrypt it into `sample.hbx` with a short delay such as five seconds.
3. Inspect the header with `--inspect`.
4. Record the original and container file sizes.
5. Recover to `recovered.txt`.
6. Compare the original and recovered SHA-256 values.
7. Repeat recovery with a deliberately incorrect key file and record that authentication fails. Do not overwrite the original sample during this test.
8. Restore the correct key and verify recovery succeeds again.

### Exercise B — Polymorphism and stable output

1. Generate `polymorphic_demo.py`.
2. Record its SHA-256 hash.
3. Run it and record its output.
4. Record its hash again.
5. Run it a second time and record the hash/output.
6. Confirm that the output message remains the same while the source file hash changes.
7. Generate a second variant with the same message and compare its hash.

### Exercise C — Defensive discussion

For each exercise, document:

- What changed in the file?
- Which parts are metadata, encrypted bytes, or inert random data?
- What did the program verify?
- What evidence proves that the original file was recovered correctly?
- What should an endpoint or sandbox monitor?
- Which original subject requirements are deliberately excluded from this safe edition?

Do not claim a Defender or VirusTotal bypass based on file size, encryption, hash changes, or one scan result.

---

## 7. Technical concepts

### AES-256-GCM

AES is a symmetric cipher. “256” refers to the key size in bits. GCM is an authenticated-encryption mode: it encrypts the plaintext and produces an authentication tag. During decryption, a wrong key or modified authenticated ciphertext should cause authentication to fail rather than produce accepted plaintext.

The container stores the nonce and metadata, but not the AES key. The key is stored separately in `<output>.key`.

### SHA-256

SHA-256 maps input bytes to a 256-bit digest. It is useful for checking whether the original and recovered files are byte-for-byte identical. Even a small change in the generated Python source normally changes its SHA-256 digest, which is why the polymorphic demo's hash changes when its nonce changes.

### File size and random padding

The container is deliberately padded to a target size. Padding illustrates how file length and high-entropy data can complicate static inspection; it does not prove maliciousness or benignness. Defenders should inspect structure and behavior rather than treating a single size or entropy measurement as a verdict.

### PE structure versus HBX1

A Windows Portable Executable normally has a DOS header, PE/COFF headers, section headers, and sections. HBX1 has a different custom layout. If an input file happens to be a PE, this tool encrypts its bytes as opaque data; it does not preserve a directly executable PE image in the container.

### Reverse-shell threat model (discussion only)

A reverse shell typically has a target initiate an outbound connection and redirects command-interpreter input/output over that connection. This project does not create that connection or provide shell code. For the audit, discuss likely evidence: unexpected outbound connections, command interpreters launched by unusual parents, suspicious standard-handle redirection, and unexpected process/network relationships.

---

## 8. Diagrams

### Overall project map

```mermaid
flowchart LR
    U[Auditor / learner] --> E[Evasion CLI]
    U --> P[Polymorphic CLI]
    E --> H[HBX1 container]
    E --> K[Separate key file]
    H --> R[Recovery and integrity check]
    R --> O[Recovered bytes on disk]
    P --> S[Generated Python demo]
    S --> V[Nonce changes on local execution]
    V --> X[File hash changes]
    O --> D[Compare hashes and record evidence]
    X --> D
```

### What changes and what stays the same?

| Demonstration | Changes | Stays the same / verified |
|---|---|---|
| HBX1 encryption | Output representation, size, metadata, ciphertext and padding | Correct recovery reproduces the original bytes |
| Polymorphic generation | Random nonce, inert comment, whole-file hash | Embedded text and intended printed message |
| Polymorphic execution | Nonce in the script source and consequently its hash | Payload text and digest verification logic |

---

## 9. Audit checklist and evidence

Use this checklist during the audit. Mark an item only after collecting evidence.

- [ ] **Setup:** record Python version and installed dependencies.
- [ ] **Isolation:** capture the VM's network mode and disabled integration features.
- [ ] **Encryption:** show the generated `.hbx` and separate `.key` files.
- [ ] **Container structure:** capture `--inspect` output and explain each field.
- [ ] **Size:** record the original and final byte lengths and verify the configured increase.
- [ ] **Delay:** demonstrate a non-zero recovery delay without `--no-delay`.
- [ ] **Recovery:** compare original and recovered SHA-256 hashes.
- [ ] **Integrity failure:** record that recovery with an incorrect key or tampered ciphertext fails authentication.
- [ ] **Polymorphism:** show that two independently generated variants have different hashes.
- [ ] **Self-modification:** show a generated script's hash before and after execution.
- [ ] **Stable output:** preserve output from multiple runs and show that the message stays the same.
- [ ] **Safety review:** verify that the payload is printed as text and no network or shell capability is present in the demonstration.
- [ ] **Limitations:** clearly identify Defender/VT bypass, executable encrypted-payload launching, and reverse-shell behavior as not implemented.
- [ ] **Evidence handling:** store logs/screenshots and test hashes without exposing key contents.

### Suggested evidence directory

```text
audit/
├── environment.txt
├── vm-isolation.png
├── evasion-inspect.json
├── size-results.txt
├── recovery-hashes.txt
├── wrong-key-test.txt
├── polymorphic-hashes.txt
├── polymorphic-output.txt
└── limitations-and-findings.md
```

These are suggested evidence filenames; the tools do not automatically create this directory or capture screenshots.

### Automated tests

Run the repository's tests from its root:

```bash
python3 -m pytest -q
```

On Windows:

```powershell
py -m pytest -q
```

A passing test suite is useful evidence but does not replace the manual isolation check or the demonstrations above. If no test file covers a requirement, report that gap instead of assuming it was tested.

---

## 10. Defensive analysis

The project illustrates patterns that defenders can investigate, but no single indicator is a reliable verdict.

- **Large overlays / unusual file length:** compare file size with declared executable sections and investigate unexpected appended data.
- **High entropy:** encrypted or compressed data often has high entropy, but high entropy alone does not prove malware.
- **Unexpected delay:** monitor long sleeps and consider longer or time-accelerated sandbox observation windows.
- **Changing hashes:** exact hashes identify exact byte sequences; inert changes can produce a new hash without changing visible behavior. Combine hashes with normalized/fuzzy similarity, signing status, code structure, process behavior, memory observations, and network telemetry.
- **Unexpected network activity:** monitor outbound connections from applications that do not normally need them, especially when combined with suspicious child processes or command interpreters.
- **Key handling:** protect key files with access controls; never commit real keys to source control or include them in audit screenshots.

Recommended controls include application control/allowlisting, least privilege, egress filtering, endpoint detection and response, protected logging, rapid patching, and isolated analysis environments.

---

## 11. Limitations and known caveats

1. **Not an antivirus bypass:** no Defender or VirusTotal evasion technique is implemented or claimed.
2. **No executable loader:** HBX1 is a data container. Recovered bytes are written to disk and never executed.
3. **No reverse shell:** the project does not open a remote connection or redirect a command interpreter.
4. **Not a native PE polymorpher:** the generator produces Python source and changes an inert signature.
5. **Token filtering is not a sandbox:** the polymorphic generator's blocked-token list is heuristic and cannot prove arbitrary input text is safe.
6. **Key file security is limited:** storing the key next to the container is suitable only for the educational exercise.
7. **Delay scope:** the delay is applied during recovery, not during execution of the original file.
8. **Manual isolation verification:** source code and README instructions cannot prove the VM is isolated.
9. **Bonus requirements:** anti-debugging, stealth memory execution, custom encryption, a GUI, and a detection tool are not implemented.
10. **Audit results must be measured:** do not claim a detection percentage or a pass without recorded, reproducible evidence.

---

## 12. Ethics and lab safety

Binary encryption, file mutation, and self-modification have legitimate uses in research and software protection, but they are dual-use. Test only in a written, authorized scope with owned samples and an isolated environment. Keep snapshots, use harmless payload text, and restore the VM after the exercise.

Do not disable endpoint protection, deploy obfuscated payloads, upload confidential third-party binaries to public multi-scanner services, or establish remote shells without explicit authorization. Report findings honestly, distinguish implemented features from excluded requirements, and preserve the evidence needed for another reviewer to reproduce the results.

### Questions to prepare for the stakeholder / auditor

- What is the HBX1 format and how is it parsed?
- Why is AES-GCM used, and what happens if the key or ciphertext is wrong?
- Why must a GCM nonce not be reused with the same key?
- How is the final container size calculated?
- At what stage is the delay enforced?
- What changes in a polymorphic run, and what remains stable?
- Why can a whole-file hash change without a meaningful change in behavior?
- Why is an HBX1 container not a PE executable?
- Which original subject requirements are not implemented, and why?
- What evidence supports each audit claim?
