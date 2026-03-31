# Quira Browser — Security Architecture
# "Context Security": A macOS-Inspired Browser Security Model

> Version: 1.0 | Created: 2026-03-30 | Status: Draft
> Author: CEO / Opus

---

## Executive Summary

This document proposes a novel security architecture for Quira Browser by systematically translating macOS's multi-layered defense model into browser-native equivalents. The central insight is that Quira's Context Graph — an automatically constructed personal knowledge graph — represents an entirely new category of sensitive data that no existing browser adequately protects. We call this paradigm **Context Security**: the discipline of protecting personal knowledge structures.

While Chrome, Firefox, and Brave focus on protecting users *from the web* (sandboxing, site isolation, content security policies), none of them protect the *user's own accumulated knowledge* with the same rigor. Quira must do both.

---

## Part 1: macOS Security Layers — Deep Analysis

### 1.1 Gatekeeper

**What it does:** Gatekeeper verifies that applications are signed by an identified developer (or notarized by Apple) before allowing execution. It operates at the launch boundary — the moment a user attempts to open an app for the first time. The verification chain is: App Store (fully reviewed) > Notarized (automated Apple scan) > Developer ID signed > Unsigned (blocked by default). Gatekeeper also checks quarantine attributes (xattr) set by the browser or file manager on download, performs a first-run OCSP check against Apple's revocation server, and re-validates after updates.

**Key principles:**
- Trust is earned through cryptographic proof, not reputation
- Verification happens *before* execution, not after damage
- Users can override (System Preferences > Security), but friction is intentional
- Progressive trust: App Store > Notarized > Signed > Unsigned

### 1.2 XProtect

**What it does:** XProtect is Apple's built-in anti-malware system operating at two levels. XProtect signatures (YARA rules) scan files at first launch and on definition updates. XProtect Remediator runs periodic background scans (every 12 hours approximately) to detect and remove known malware families. Signature updates are delivered silently through macOS's background update mechanism, independent of full OS updates.

**Key principles:**
- Signature-based detection at file open time
- Background remediation runs without user intervention
- Silent updates keep definitions current without requiring user action
- Complements Gatekeeper — catches what slips past signing

### 1.3 System Integrity Protection (SIP)

**What it does:** SIP (rootless) restricts the root account from modifying protected system directories (`/System`, `/usr` (except `/usr/local`), `/bin`, `/sbin`, and Apple's pre-installed apps). Even with root access, these paths are immutable. SIP is enforced at the kernel level via the `com.apple.rootless` sandbox profile and can only be disabled from Recovery Mode (an out-of-band trust boundary). SIP also protects system processes from code injection, debugging attachment (except with SIP-entitled tools), and DYLD environment variable manipulation.

**Key principles:**
- Certain data is immutable even to the most privileged process
- Disabling requires physical access and an out-of-band boot environment
- Protects integrity of the trust chain itself (if malware could modify Gatekeeper, all other protections fail)

### 1.4 App Sandbox

**What it does:** Every App Store app (and optionally other apps) runs inside a sandbox container with minimal default entitlements. The sandbox restricts file system access to the app's own container (`~/Library/Containers/<bundle-id>/`), limits IPC, prevents direct hardware access, and blocks network connections unless entitled. Entitlements are declared at build time, signed into the binary, and cannot be escalated at runtime.

**Key principles:**
- Default-deny: no access unless explicitly granted
- Entitlements are static and cryptographically bound to the binary
- Containers are physically separated on the filesystem
- Compromise of one app cannot directly affect another

### 1.5 TCC (Transparency, Consent, and Control)

**What it does:** TCC mediates access to sensitive user data (camera, microphone, photos, contacts, calendar, location, screen recording, accessibility, full disk access, etc.). Each access requires a one-time user consent dialog. Decisions are stored in `~/Library/Application Support/com.apple.TCC/TCC.db` (user-level) and `/Library/Application Support/com.apple.TCC/TCC.db` (system-level). The TCC database itself is SIP-protected. Apps cannot programmatically grant themselves access. Some categories (screen recording, accessibility) require explicit System Preferences navigation.

**Key principles:**
- Per-resource, per-app consent — not blanket permissions
- Consent is revocable at any time
- The permission database itself is protected from tampering
- Some permissions require elevated friction (manual navigation, not just a dialog)
- Transparency: users can audit all granted permissions in one place

### 1.6 Keychain

**What it does:** Keychain Services provides encrypted storage for passwords, certificates, keys, and secure notes. Items are encrypted with AES-256-GCM using keys derived from the user's login password (and optionally the Secure Enclave). Access control lists (ACLs) on each item specify which apps can read it, whether biometric confirmation is required, and whether the item should be accessible only when the device is unlocked. iCloud Keychain synchronizes items across devices using end-to-end encryption with device-specific keys.

**Key principles:**
- Credentials are never stored in plaintext
- Per-item access control (not all-or-nothing)
- Biometric/password gating for high-value items
- Sync is end-to-end encrypted — Apple cannot read synced items

### 1.7 Data Vault / FileVault

**What it does:** FileVault 2 provides full-disk encryption using XTS-AES-128 (on Intel) or hardware-accelerated AES-256 (on Apple Silicon via the AES engine in the storage controller). The volume encryption key (VEK) is wrapped by one or more key encryption keys (KEKs) derived from user credentials or institutional recovery keys. On Apple Silicon, the Sealed System Volume (SSV) adds a SHA-256 Merkle tree over the system volume, so any modification is detectable at boot. Data Vault is a per-app encryption mechanism within APFS that restricts access to certain directories even from other processes running as the same user.

**Key principles:**
- Encryption at rest is full-volume and hardware-accelerated
- Key derivation ties encryption to user authentication
- Integrity verification (SSV) detects tampering of system files
- Data Vault adds per-app isolation beyond filesystem permissions

### 1.8 Secure Enclave

**What it does:** The Secure Enclave Processor (SEP) is a physically isolated coprocessor with its own boot ROM, AES engine, TRNG, and secure memory. It stores biometric templates (Face ID / Touch ID), generates and manages cryptographic keys that never leave the enclave, performs key operations (sign, decrypt) on behalf of the main processor, and provides hardware-rooted attestation. Keys stored in the SEP cannot be exported — the main CPU sends data to the SEP, which returns results. The SEP has its own firmware (sepOS) updated independently.

**Key principles:**
- Keys exist only inside the hardware boundary
- Operations happen inside the enclave; plaintext keys never cross the bus
- Hardware root of trust — unaffected by software-level compromise
- Anti-replay counter prevents rollback attacks on enclave state

### 1.9 Code Signing & Notarization

**What it does:** Code signing binds a cryptographic identity (developer certificate) to every binary, library, and resource in an app bundle. The signature covers the code directory hash (CDHash), entitlements, info.plist, and all nested code. Notarization adds an Apple-side automated scan (static analysis, sandboxing, malware checks) and staples a ticket to the binary confirming it passed. The kernel checks signatures at page-in time (not just at launch), so modification of a running binary's code pages triggers SIGKILL.

**Key principles:**
- Every executable byte is covered by a signature
- Runtime integrity: re-verified at memory page level during execution
- Notarization provides a second opinion (automated, not manual)
- Revocation is possible after distribution (Apple can revoke tickets)

### 1.10 Privacy Nutrition Labels

**What it does:** App Store Privacy Nutrition Labels require developers to declare what data types they collect (identifiers, usage data, diagnostics, etc.), how each type is used (analytics, advertising, product personalization, etc.), and whether the data is linked to the user's identity. This is displayed prominently on the App Store listing before download. It is self-reported but Apple audits and rejects apps with false declarations.

**Key principles:**
- Transparency *before* installation, not buried in a privacy policy
- Standardized categories enable comparison across apps
- Machine-readable format enables automated analysis
- Declaration is part of the distribution contract (false claims have consequences)

### 1.11 Lockdown Mode

**What it does:** Lockdown Mode (macOS Ventura+) is a hardened profile for users at extreme risk (journalists, activists, government targets). It disables JIT compilation in Safari (except for trusted sites), blocks most message attachment types, disables link previews, blocks FaceTime calls from unknown contacts, removes shared albums in Photos, blocks wired connections to computers when locked, blocks MDM profile installation, and reduces the attack surface of kernel extensions and system services.

**Key principles:**
- Security and usability are a spectrum, not a fixed point
- For high-risk users, the correct tradeoff shifts dramatically toward security
- Specific, well-researched attack surfaces are disabled (JIT is a major exploit vector)
- User explicitly opts in, understanding the functionality cost

### 1.12 Rapid Security Response

**What it does:** RSR delivers targeted security patches between major OS updates. These are small, focused updates (often < 100 MB) that can be applied and reversed without a full OS update cycle. They address actively exploited vulnerabilities with turnaround times of days rather than weeks. Users can configure automatic installation.

**Key principles:**
- Security patches should be decoupled from feature releases
- Smaller, faster updates reduce the exposure window
- Reversibility reduces the risk of applying a patch quickly
- Automatic application (with consent) removes the human delay factor

---

## Part 2: macOS-to-Browser Mapping — Quira Security Equivalents

### 2.1 Context Gatekeeper (Extension & Script Verification)

**macOS analog:** Gatekeeper

**Quira implementation:**

Every entity that can interact with the Context Graph must pass through Context Gatekeeper before gaining any access:

| Trust Level | Entity | Verification | Graph Access |
|-------------|--------|-------------|--------------|
| **L4 (Trusted)** | Quira first-party code | Signed by Quira release key | Full |
| **L3 (Verified)** | Extensions from Quira Extension Store | Code-reviewed + signed + notarized | Declared entitlements only |
| **L2 (Identified)** | Side-loaded extensions with developer ID | Developer signature verified | User-approved entitlements |
| **L1 (Unknown)** | Unsigned scripts, injected content | No signature | Zero graph access |
| **L0 (Blocked)** | Known malicious signatures | Blocklist match | Blocked from execution |

**Specific mechanisms:**
- Extensions declare a `context_entitlements.json` manifest at build time specifying which graph operations they request (read nodes, write edges, query embeddings, etc.)
- Entitlements are cryptographically bound to the extension signature — runtime escalation is impossible
- First-run quarantine: new extensions run in an observation period (first 24 hours) where graph writes are journaled and reversible
- Quira Extension Store performs automated static analysis (no obfuscated code, no dynamic script loading from external URLs) plus human review for extensions requesting L3 graph entitlements

**What this adds beyond current browsers:** Chrome extensions request permissions at install time but can use those permissions without further verification. Firefox AMO reviews extensions but has no per-extension cryptographic entitlement system. Neither browser has a concept of "graph entitlements" because neither has a knowledge graph to protect.

### 2.2 Context XProtect (Real-Time Threat Detection)

**macOS analog:** XProtect

**Quira implementation:**

A background threat detection engine that continuously monitors for patterns targeting the Context Graph:

| Layer | Detection Target | Method |
|-------|-----------------|--------|
| **Network** | Exfiltration attempts | Monitor for outbound requests containing graph node data, embedding vectors, or entity lists |
| **Content** | Phishing targeting graph data | Pattern match on pages that attempt to mimic `quira://` internal pages |
| **Script** | Malicious content scripts | YARA-like rules for scripts that probe `ContextGraph.*` APIs or attempt prototype pollution |
| **Extension** | Post-install malicious behavior | Behavioral analysis — flag extensions that read graph data then immediately make network requests |

**Signature updates:**
- Threat definitions are delivered via a lightweight update channel (separate from browser updates)
- Community-contributed rules (similar to uBlock filter lists) with Quira team curation
- Local heuristic engine runs on-device — never sends browsing data to a cloud scanner

**Key innovation: Context Exfiltration Detection (CED)**
No browser currently monitors for *knowledge graph exfiltration*. Quira's CED detects when any process (extension, injected script, or compromised component) attempts to:
1. Bulk-read Context Graph nodes
2. Serialize graph data into network-sendable format
3. Transmit data matching the structure of graph nodes/edges/embeddings

This is analogous to Data Loss Prevention (DLP) systems in enterprise environments, but adapted for personal knowledge.

### 2.3 Context Integrity Protection (CIP)

**macOS analog:** System Integrity Protection (SIP)

**Quira implementation:**

The Context Graph's structural integrity is protected by a mechanism analogous to SIP. Certain graph data is immutable except through verified code paths:

**Protected artifacts:**
| Artifact | Protection | Override |
|----------|-----------|---------|
| Graph schema (tables, indexes) | Immutable at runtime | Requires browser update signed by Quira |
| AI model weights | Read-only after installation | Requires model update signed by Quira |
| Permission database (Context TCC records) | Write-only through CIP-verified kernel module | Cannot be modified by extensions or content scripts |
| Extension entitlement declarations | Immutable after install | Requires extension re-sign and re-install |
| Audit log | Append-only | Cannot be truncated or modified |

**Implementation mechanism:**
- The SQLite database containing graph permissions and audit logs uses a separate WAL with an integrity check on every read
- A SHA-256 Merkle tree covers the permission tables — any external modification is detected at next access
- The CIP-protected data lives in a separate SQLite database file with restrictive filesystem ACLs
- Critical browser components (graph engine, permission manager, AI pipeline) are loaded with integrity verification (hash of .so/.dylib checked against signed manifest)

**What this protects against:**
- An extension that somehow escapes its sandbox cannot grant itself new graph permissions
- A compromised AI model cannot alter the permission system
- Malware that gains filesystem access cannot silently modify the audit trail

### 2.4 Context Sandbox (Per-Tab & Per-Extension Isolation)

**macOS analog:** App Sandbox

**Quira implementation:**

Quira extends Gecko's existing process isolation with Context Graph-specific sandboxing:

```
+----------------------------------------------------------+
|  Browser Chrome Process (privileged)                      |
|  +------------------------------------------------------+|
|  |  Context Graph Engine (CIP-protected)                ||
|  |  Permission Manager (CIP-protected)                  ||
|  |  AI Pipeline Manager                                 ||
|  +------------------------------------------------------+|
+----------------------------------------------------------+
|  Tab Process A          Tab Process B                     |
|  +---------------+     +---------------+                  |
|  | Content        |     | Content        |                 |
|  | (site A)       |     | (site B)       |                 |
|  |                |     |                |                 |
|  | Graph Proxy:   |     | Graph Proxy:   |                 |
|  | - Can request  |     | - Can request  |                 |
|  |   own node     |     |   own node     |                 |
|  | - Cannot see   |     | - Cannot see   |                 |
|  |   other nodes  |     |   other nodes  |                 |
|  +---------------+     +---------------+                  |
+----------------------------------------------------------+
|  Extension Process X    Extension Process Y               |
|  +---------------+     +---------------+                  |
|  | Entitlements:  |     | Entitlements:  |                 |
|  | - read:nodes   |     | - (none)       |                 |
|  | - query:nlp    |     |                |                 |
|  |                |     | Graph Access:   |                 |
|  | Graph Access:   |     | DENIED         |                 |
|  | read-only via  |     |                |                 |
|  | IPC to Engine  |     |                |                 |
|  +---------------+     +---------------+                  |
+----------------------------------------------------------+
```

**Key rules:**
- Content processes (tabs) have **zero direct access** to the graph database file
- All graph operations go through IPC to the chrome process's Graph Engine
- The Graph Engine enforces entitlements per-caller: tab processes get only their own node; extension processes get only what their signed entitlements declare
- Extensions run in isolated processes (not shared with content or chrome)
- The AI pipeline runs in a separate process with read-only graph access and no network capability

### 2.5 Context TCC (Transparency, Consent, and Control for Browsing Data)

**macOS analog:** TCC

**This is the most novel component of Quira's security model.**

Context TCC introduces per-resource consent for browsing knowledge — a concept that exists nowhere in current browsers.

**Protected resources:**

| Resource | Description | Access Requestors |
|----------|-------------|-------------------|
| `context.nodes.read` | Read Context Graph nodes (titles, summaries, entities) | Extensions, cloud AI |
| `context.nodes.write` | Create or modify graph nodes | Extensions |
| `context.edges.read` | Read graph edges (navigation paths, inferred connections) | Extensions, cloud AI |
| `context.edges.write` | Create or modify edges | Extensions |
| `context.embeddings.read` | Read semantic embedding vectors | Extensions, cloud AI |
| `context.query.nlp` | Execute natural language queries | Extensions |
| `context.spaces.read` | Read Space names and metadata | Extensions |
| `context.research.read` | Read Research Session data | Extensions |
| `context.export` | Export graph data in any format | Extensions, user scripts |
| `context.history.full` | Access complete browsing history (all nodes, all time) | Only cloud AI (explicit) |

**Consent UX:**

```
+----------------------------------------------------------+
|  Extension "ResearchHelper" wants to:                     |
|                                                           |
|  [graph icon] Read your Context Graph nodes               |
|     See titles and summaries of pages you've visited      |
|                                                           |
|  [link icon] Read connection paths                        |
|     See how your visited pages are connected              |
|                                                           |
|  [Allow Once] [Allow for This Space] [Allow Always]       |
|                                                           |
|  [Deny]                    [What data will it see? ->]    |
+----------------------------------------------------------+
```

**Key innovations:**
1. **Granular, not binary:** Extensions don't get "access to browsing data" — they get specific graph capabilities
2. **Space-scoped consent:** Users can allow access only within a specific Context Space (e.g., "ResearchHelper can see my 'Work' Space but not my 'Personal' Space")
3. **Temporal consent:** "Allow for this session" expires when the browser closes
4. **Audit dashboard:** `quira://settings/privacy/permissions` shows every extension's access, with a timeline of what data was actually read
5. **Consent for cloud AI:** When the user enables Cloud AI (Level 2), Context TCC mediates exactly what graph data is sent — the user explicitly consents per-resource, not blanket "send everything"

**What this protects against:**
- An extension that legitimately needs to read node titles cannot also silently read embedding vectors (which encode semantic meaning of the user's interests)
- Cloud AI integration cannot access navigation edge data (which reveals how the user thinks) unless explicitly consented
- The user maintains a clear mental model of who can see what about their knowledge

### 2.6 Context Keychain (Encrypted Credential & Context Storage)

**macOS analog:** Keychain

**Quira implementation:**

A dedicated encrypted store for the most sensitive context data:

| Item Type | Encryption | Access Control |
|-----------|-----------|----------------|
| Saved passwords | AES-256-GCM, per-item key | Biometric or master password per access |
| Context Graph embeddings | AES-256-GCM, graph-level key | Biometric unlock on first session access |
| AI model inference cache | AES-256-GCM, session key | Cleared on session end |
| Research Session summaries | AES-256-GCM, per-space key | Space-level unlock |
| Extension tokens/secrets | AES-256-GCM, per-extension key | Extension identity verification |

**Key design decisions:**
- **Per-space encryption keys:** Each Context Space can have its own encryption key, enabling scenarios like "my Work space requires biometric unlock; my Personal space uses password only"
- **Session-scoped decryption:** Embedding vectors (the most semantically rich data) are only decrypted into memory when actively needed for queries, then wiped
- **Keychain sync:** When Quira eventually adds cross-device sync, the keychain model enables end-to-end encryption where the sync server never has plaintext keys

### 2.7 Context Vault (Encryption at Rest)

**macOS analog:** FileVault / Data Vault

**Quira implementation:**

All Context Graph data is encrypted at rest, always, with no opt-out:

```
+----------------------------------------------+
|           Context Vault Architecture          |
|                                               |
|  SQLite DB File (context_graph.db)            |
|  +-------------------------------------------+|
|  |  SQLite Encryption Extension (SEE)        ||
|  |  or sqlcipher                             ||
|  |  +--------------------------------------+ ||
|  |  |  Volume Encryption Key (VEK)         | ||
|  |  |  AES-256-XTS                         | ||
|  |  +------------------+-------------------+ ||
|  |                     |                     ||
|  |  +------------------v-------------------+ ||
|  |  |  Key Encryption Key (KEK)            | ||
|  |  |  Derived from:                       | ||
|  |  |  - User master password              | ||
|  |  |  - Hardware key (if available)        | ||
|  |  |  - Argon2id KDF                      | ||
|  |  +--------------------------------------+ ||
|  +-------------------------------------------+|
|                                               |
|  Embedding Store (embeddings.vault)           |
|  +-------------------------------------------+|
|  |  Separate encryption key                  ||
|  |  Requires biometric/password on unlock    ||
|  |  Decrypted into secure memory only        ||
|  +-------------------------------------------+|
|                                               |
|  Integrity Merkle Tree (integrity.db)         |
|  +-------------------------------------------+|
|  |  SHA-256 tree over graph + embeddings     ||
|  |  Verified on open, updated on write       ||
|  |  Detects tampering at any level           ||
|  +-------------------------------------------+|
+----------------------------------------------+
```

**Why embeddings are separated:**
Embedding vectors are the most dangerous data to leak. They encode the *semantic meaning* of everything the user has browsed. A leaked embedding store is effectively a compressed version of the user's entire intellectual life. By separating them with a stronger access gate, even a partial database compromise doesn't reveal the semantic layer.

### 2.8 Hardware-Backed Context Security

**macOS analog:** Secure Enclave

**Quira implementation:**

On platforms with hardware security modules, Quira leverages them for Context Graph key management:

| Platform | Hardware | Use |
|----------|----------|-----|
| macOS (Apple Silicon) | Secure Enclave via CryptoKit | Graph KEK generation, biometric gating |
| macOS (Intel with T2) | T2 Security Chip | Graph KEK storage |
| Linux (with TPM 2.0) | TPM via tpm2-tools / PKCS#11 | Graph KEK sealing to PCR state |
| Windows (future) | TPM 2.0 / Windows Hello | Graph KEK via NCrypt |

**Behavior:**
- The Key Encryption Key for the Context Graph is generated inside the hardware module and never exported
- Decryption operations happen by sending encrypted data to the HSM and receiving plaintext back
- On systems without HSM: fallback to software-derived KEK from master password via Argon2id (still strong, but not hardware-bound)
- Hardware binding means a stolen database file is useless without the original device

### 2.9 Context Code Signing (Extension & Component Trust Chain)

**macOS analog:** Code Signing & Notarization

**Quira implementation:**

```
Trust Chain:

  Quira Root CA
       |
       +-- Browser Release Key (signs browser binaries)
       |
       +-- Extension Store Key (signs verified extensions)
       |       |
       |       +-- Developer Keys (delegated, revocable)
       |
       +-- AI Model Key (signs model weights)
       |
       +-- Threat Definition Key (signs XProtect-equivalent rules)
```

**Specific mechanisms:**
- All browser components are signed and verified at load time
- Extensions carry a CDHash covering all code, manifest, and entitlements
- AI model weights are signed to prevent model poisoning (a malicious model could exfiltrate graph data through its outputs)
- Graph database migrations are signed — a tampered migration script cannot alter the schema in unauthorized ways
- Certificate Transparency-style log: all extension signatures and revocations are published to an append-only public log

### 2.10 Context Privacy Labels

**macOS analog:** Privacy Nutrition Labels

**Quira implementation:**

Every extension in the Quira Extension Store displays a **Context Privacy Label**:

```
+----------------------------------------------------------+
|  Context Privacy Label -- "ResearchHelper v2.1"           |
|                                                           |
|  DATA ACCESSED                                            |
|  [Y] Graph node titles         (read only)                |
|  [Y] AI-generated summaries    (read only)                |
|  [N] Embedding vectors         (not accessed)             |
|  [N] Navigation paths          (not accessed)             |
|  [N] Full URLs                 (not accessed)             |
|                                                           |
|  DATA USAGE                                               |
|  > On-device processing only                              |
|  > No data sent to external servers                       |
|  > No data shared with third parties                      |
|                                                           |
|  DATA RETENTION                                           |
|  > Session only -- cleared when extension closes          |
|                                                           |
|  VERIFIED: Quira Extension Store automated scan [ok]      |
|            Manual code review [ok]                        |
+----------------------------------------------------------+
```

**Innovations beyond App Store labels:**
- Labels are **machine-enforced**, not just self-declared — if the label says "no embedding access" but the code requests embeddings, the entitlement system blocks it
- Labels include **data flow direction** (on-device only vs. external transmission)
- Labels include **data retention policy** (session / persistent / user-controlled)
- Automated differential analysis: if an extension update changes its data access pattern, the label is re-generated and the user is prompted to re-consent

### 2.11 Context Lockdown Mode

**macOS analog:** Lockdown Mode

**Quira implementation:**

A hardened mode for high-risk users (journalists investigating surveillance, activists, researchers on sensitive topics):

| Restriction | Normal Mode | Lockdown Mode |
|-------------|------------|---------------|
| JavaScript JIT | Enabled | Disabled (interpreter only) |
| WebAssembly | Enabled | Disabled |
| WebGL/WebGPU | Enabled | WebGPU for graph only; disabled for web content |
| Extensions | All installed | Only L4 (first-party) trusted |
| Context Graph | Auto-captures all (except excluded) | Manual capture only (explicit button press per page) |
| AI Processing | Automatic | Manual trigger only |
| Cloud AI | Available if opted in | Completely disabled |
| Media autoplay | Per-site setting | Disabled globally |
| Link previews | Enabled | Disabled |
| USB/external connections | Normal | Blocked while browser is open |
| Remote fonts | Loaded | Blocked (use system fonts) |
| PDF rendering | In-browser | External viewer only |
| Search suggestions | Enabled | Disabled (no keystroke transmission) |

**Threat model addressed:**
- State-level adversaries attempting to exploit browser engine vulnerabilities
- Targeted surveillance via extension-based spyware
- Forensic analysis of the device (Lockdown Mode enables panic wipe of graph data via keyboard shortcut)
- Network-level attackers injecting malicious content

**Panic features (Lockdown Mode only):**
- **Rapid Context Wipe:** `Cmd+Shift+Delete+Delete` (double-delete prevents accidental trigger) securely wipes the Context Graph, embeddings, and session data in < 5 seconds
- **Stealth Mode:** Quira can be configured to leave no filesystem traces on close (all data kept in encrypted RAM-backed storage, lost on shutdown)

### 2.12 Rapid Context Response (RCR)

**macOS analog:** Rapid Security Response

**Quira implementation:**

Security patches for the Context Graph system that ship independently of browser updates:

| Component | Update Channel | Frequency |
|-----------|---------------|-----------|
| Threat definitions (Context XProtect) | Background, automatic | Daily |
| Extension revocation list | Background, automatic | As needed |
| Graph engine security fixes | Prompted, small delta | As needed (target < 72hr from discovery) |
| Full browser updates | Standard update flow | Bi-weekly |

**Mechanism:**
- RCR patches are signed by Quira's Browser Release Key
- They can modify only security-critical components (graph engine, sandbox, permission manager)
- They are reversible if they cause issues
- Auto-install is available with user consent (enabled by default in Lockdown Mode)

---

## Part 3: What No Current Browser Implements

This section identifies security concepts that are absent from Chrome, Firefox, Brave, Arc, and all other current browsers. These represent Quira's differentiation opportunities.

### 3.1 No Browser Has TCC for Browsing Data

**Current state:** Browser extensions request permissions (tabs, history, bookmarks) at install time. Once granted, the extension has full, permanent, unaudited access. There is no per-resource consent, no temporal scoping, no Space-level isolation, and no audit log of what the extension actually read.

**Quira difference:** Context TCC provides per-resource, per-Space, temporally-scoped, auditable consent for knowledge graph access. Extensions cannot silently read data they didn't explicitly request, and users can see exactly what was accessed.

### 3.2 No Browser Encrypts Browsing Knowledge at Rest with Hardware Keys

**Current state:** Chrome stores browsing history, bookmarks, and passwords in SQLite databases that are readable by any process running as the user. Firefox uses a primary password for the password store but leaves history and bookmarks unencrypted. Brave adds no encryption beyond what Chrome provides. None use hardware security modules.

**Quira difference:** Context Vault encrypts the entire Context Graph at rest using SQLCipher. The encryption key is optionally bound to hardware (Secure Enclave, TPM). Embedding vectors — the most semantically dangerous data — are in a separately encrypted store with a higher access gate.

### 3.3 No Browser Has Lockdown Mode

**Current state:** Tor Browser is the closest analog, but it is a separate product, not a mode within a mainstream browser. No Chrome/Firefox/Brave user can switch into a hardened mode when they need maximum security and switch back for normal browsing.

**Quira difference:** Context Lockdown Mode is a toggle within the same browser. It disables JIT, blocks extensions, makes graph capture manual-only, and adds panic wipe capability. Users can activate it when investigating sensitive topics and deactivate it afterward.

### 3.4 No Browser Has Integrity Protection for Its Own Data Structures

**Current state:** If malware gains filesystem access, it can freely modify Chrome's history database, inject bookmarks, alter extension permissions, or tamper with cached data. There is no integrity verification.

**Quira difference:** Context Integrity Protection uses Merkle trees over the permission database and audit logs. The graph schema is immutable at runtime. AI model weights are signature-verified. Any external modification is detected.

### 3.5 No Browser Has Knowledge Exfiltration Detection

**Current state:** Browsers detect some forms of data theft (e.g., Content Security Policy can restrict where scripts send data), but none monitor for structured knowledge exfiltration — the bulk extraction and transmission of the user's browsing patterns, semantic embeddings, or knowledge graph.

**Quira difference:** Context XProtect includes a Context Exfiltration Detection engine that monitors for patterns consistent with graph data theft: bulk reads, serialization into network formats, and transmission of graph-structured data.

### 3.6 No Browser Has Per-Workspace Security Scoping

**Current state:** Browser profiles provide some isolation, but within a profile, all data is equally accessible. Tab groups and workspaces (Arc Spaces, Vivaldi workspaces) have zero security boundaries.

**Quira difference:** Context Spaces are security boundaries. Permissions can be scoped per-Space. Encryption can use per-Space keys. An extension approved for the "Work" Space has no access to the "Personal" Space.

### 3.7 No Browser Treats AI Models as Signed, Integrity-Verified Components

**Current state:** Brave and Opera integrate AI features but treat model weights as regular downloaded files. There is no signature verification, no protection against model poisoning, and no entitlement system for what data the model can access.

**Quira difference:** AI models are signed components in the trust chain. Model weights are verified before loading. The AI pipeline runs in a sandboxed process with read-only graph access and no network capability. A poisoned model cannot exfiltrate data because it has no outbound channel.

### 3.8 No Browser Has Differential Privacy Labels for Extensions

**Current state:** Chrome Web Store and Firefox AMO have permission descriptions, but they are static, not enforced beyond the initial permission grant, and don't describe data flow, retention, or actual usage patterns.

**Quira difference:** Context Privacy Labels are machine-enforced (the entitlement system guarantees the label's accuracy), include data flow direction and retention policy, and are automatically re-evaluated on extension updates.

---

## Part 4: Novel Security Architecture Proposal — "Context Security"

### 4.1 The Paradigm: Context Security

We define **Context Security** as: *the discipline of protecting automatically constructed personal knowledge structures from unauthorized access, exfiltration, corruption, and inference.*

This is distinct from:
- **Web Security** (protecting users from malicious websites) — already well-served by CSP, CORS, site isolation
- **Application Security** (protecting the browser code from exploitation) — already well-served by sandboxing, ASLR, CFI
- **Network Security** (protecting data in transit) — already well-served by TLS, HSTS, Certificate Transparency

Context Security addresses threats that are unique to knowledge-aware systems:
- **Knowledge Inference:** Even without direct access, an attacker who observes graph queries can infer what the user is researching
- **Semantic Exfiltration:** Embedding vectors leak meaning even without plaintext — a stolen embedding store reveals interests, expertise, and intellectual trajectory
- **Temporal Pattern Analysis:** The structure of the graph over time reveals working patterns, deadlines, and decision processes
- **Context Poisoning:** Injecting false nodes into the graph could manipulate the user's AI-generated summaries and research conclusions

### 4.2 The Five Pillars of Context Security

```
+----------------------------------------------------------------+
|                    CONTEXT SECURITY MODEL                       |
|                                                                 |
|  +----------+ +----------+ +----------+ +----------+ +--------+ |
|  |INTEGRITY | |CONFIDEN- | | CONSENT  | |TRANSPAR- | |RESIL-  | |
|  |          | |TIALITY   | |          | |ENCY      | |IENCE   | |
|  |          | |          | |          | |          | |        | |
|  | CIP      | | Vault    | | TCC      | | Labels   | | RCR    | |
|  | Merkle   | | HW Keys  | | Per-     | | Audit    | | Lock   | |
|  | Signing  | | SQLCipher| | Resource | | Dashboard| | down   | |
|  |          | |          | | Per-     | | Diff     | | Panic  | |
|  |          | |          | | Space    | | Analysis | | Wipe   | |
|  +----------+ +----------+ +----------+ +----------+ +--------+ |
|                                                                 |
|  +-------------------------------------------------------------+|
|  |              DEFENSE-IN-DEPTH LAYERS                        ||
|  |                                                              ||
|  |  L1: Gatekeeper (verify before access)                      ||
|  |  L2: Sandbox (isolate at runtime)                           ||
|  |  L3: XProtect (detect threats continuously)                 ||
|  |  L4: Vault (encrypt at rest)                                ||
|  |  L5: Integrity (detect tampering)                           ||
|  +-------------------------------------------------------------+|
+----------------------------------------------------------------+
```

### 4.3 Context Graph Threat Model

| Threat | Attacker | Vector | Impact | Mitigation |
|--------|----------|--------|--------|------------|
| **Knowledge theft** | Malicious extension | Read graph data, exfiltrate via network | User's entire research history exposed | TCC + Sandbox + CED |
| **Semantic profiling** | Nation-state | Steal embedding store from filesystem | User's intellectual profile reconstructed | Vault + HSM + separate embedding encryption |
| **Context poisoning** | Compromised website | Inject misleading content to create false graph nodes | AI summaries and query results become unreliable | CIP + Node provenance verification |
| **Research surveillance** | Employer/ISP | Monitor graph query patterns over network | Deduce what user is researching | All graph ops local-only; cloud AI sends only query, not graph structure |
| **Forensic analysis** | Law enforcement with device access | Read graph database from seized device | Complete browsing knowledge recovered | Vault + HSM + Lockdown stealth mode |
| **Model poisoning** | Supply chain attack | Replace AI model weights with backdoored version | Exfiltrate graph data through model outputs | Code signing + model integrity verification |
| **Temporal inference** | Co-user of shared device | Observe graph growth patterns | Deduce browsing schedule and research topics | Per-profile encryption + biometric unlock |
| **Extension escalation** | Post-compromise of legitimate extension | Extension update adds graph exfiltration | Trusted extension silently steals knowledge | Differential label analysis + re-consent on capability change |

### 4.4 Context Security Integration with Local AI Pipeline

The local AI pipeline is both a critical component to protect and a potential tool for security:

**AI as protected component:**
```
+-----------------------------------------------------------+
|  AI Pipeline Sandbox                                       |
|                                                            |
|  +-----------+    +-------------+    +-----------------+   |
|  | Model      |    | Inference   |    | Output          |   |
|  | Weights    |--->| Engine      |--->| (summaries,     |   |
|  | (verified) |    | (sandboxed) |    |  entities,      |   |
|  +-----------+    +------+------+    |  embeddings)    |   |
|                          |           +--------+--------+   |
|                   Read-only IPC              |             |
|                   to Graph Engine     Write IPC to         |
|                          |           Graph Engine          |
|                          |                |                |
|  Capabilities:           |                |                |
|  [Y] Read graph nodes    |                |                |
|  [Y] Write summaries/entities             |                |
|  [N] Network access      |                |                |
|  [N] Filesystem access   |                |                |
|  [N] Extension IPC       |                |                |
+-----------------------------------------------------------+
```

**AI as security tool:**
- **Anomaly detection:** The local AI can analyze graph access patterns to detect anomalous behavior (e.g., an extension that normally reads 2-3 nodes per session suddenly reads 500)
- **Context-aware phishing detection:** The AI can identify when a page is attempting to mimic content the user has previously visited (deepfake of familiar context)
- **Natural language permission explanation:** When Context TCC shows a permission dialog, the AI generates a plain-language explanation of what the extension will be able to learn about the user

### 4.5 Implementation Phases

| Phase | Components | MVP Priority |
|-------|-----------|-------------|
| **Phase 1 (MVP)** | Context Vault (SQLCipher), basic extension entitlements, domain exclusion list | Essential |
| **Phase 2 (Beta)** | Context TCC (per-resource consent), Context Sandbox (per-tab graph isolation), Privacy Labels | High |
| **Phase 3 (v1.0)** | Context Gatekeeper (full trust chain), Context XProtect (threat detection), CIP (Merkle integrity) | High |
| **Phase 4 (v1.x)** | Hardware-backed keys (SEP/TPM), Context Lockdown Mode, Rapid Context Response | Medium |
| **Phase 5 (v2.0)** | AI-powered anomaly detection, Context Exfiltration Detection, community threat rules | Future |

### 4.6 Competitive Positioning

| Feature | Chrome | Firefox | Brave | Arc | Safari | **Quira** |
|---------|--------|---------|-------|-----|--------|-----------|
| Site isolation | Yes | Yes (Fission) | Yes | Yes | Yes | Yes (Gecko) |
| Extension permissions | Binary grant | Binary grant | Binary grant | Binary grant | Binary grant | **Per-resource TCC** |
| History encryption at rest | No | No | No | No | No | **SQLCipher + HSM** |
| Embedding/vector encryption | N/A | N/A | N/A | N/A | N/A | **Separate encrypted vault** |
| Knowledge exfiltration detection | No | No | No | No | No | **Context XProtect CED** |
| Integrity verification of user data | No | No | No | No | No | **Merkle tree CIP** |
| Lockdown mode | No | No | No | No | No | **Context Lockdown** |
| Per-workspace security scoping | No | No | No | No | No | **Space-scoped TCC** |
| AI model signing | N/A | N/A | No | No | N/A | **Full trust chain** |
| Privacy labels (enforced) | No | No | No | No | No | **Machine-enforced labels** |
| Panic wipe | No | No | No | No | No | **Lockdown rapid wipe** |
| Hardware-bound encryption | No | No | No | No | Partial (Keychain) | **Full graph encryption** |

### 4.7 Marketing Narrative

> "Your browser knows more about you than your therapist. Chrome doesn't protect that knowledge. Quira does."

> "macOS protects your apps from each other. Quira protects your *knowledge* from everything — including the browser itself."

> "Context Security: because your intellectual life deserves the same protection as your bank account."

---

## Appendix A: Key Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Database encryption | SQLCipher (open-source SQLite encryption) | Battle-tested, compatible with SQLite ecosystem, FIPS 140-2 validated |
| KDF for master password | Argon2id | Memory-hard, resists GPU/ASIC attacks, OWASP recommendation |
| Embedding encryption | Separate AES-256-GCM encrypted file | Embeddings are semantically richer than plaintext; warrant separate protection |
| Extension entitlement format | JSON manifest signed with Ed25519 | Compact, fast verification, quantum-resistant migration path to ML-DSA |
| Merkle tree for integrity | SHA-256 binary tree over permission + audit tables | Standard, well-understood, efficient incremental updates |
| Hardware key interface | Platform abstraction layer (CryptoKit / TPM PKCS#11 / WinCNG) | Same API regardless of platform hardware |

## Appendix B: Open Questions

1. **Key recovery:** If the user loses their master password and has hardware-bound keys, how do they recover their Context Graph? Options: recovery key generated at setup (like FileVault), or social recovery (split key among trusted contacts).

2. **Multi-device sync:** End-to-end encrypted sync of the Context Graph is architecturally desired but introduces key management complexity. The Keychain model (device-specific keys wrapping a shared graph key) is the likely approach, but this needs detailed protocol design.

3. **Legal compliance:** In jurisdictions requiring data access by law enforcement (e.g., UK Investigatory Powers Act), hardware-bound encryption with no recovery may create legal exposure. Quira's default should be maximum protection, but the architecture should not prevent users from choosing weaker protection if legally required.

4. **Performance impact:** SQLCipher adds approximately 5-15% overhead to database operations. Merkle tree verification adds latency on database open. These need benchmarking against the performance targets in the PRD (< 100ms FTS5, < 500ms k-NN).

5. **Threat definition governance:** Community-contributed threat rules (like uBlock filter lists) need a governance model to prevent abuse (e.g., rules that flag legitimate extensions as threats to reduce competition).

---

*This document establishes the theoretical foundation for Quira's security architecture. Implementation specifications for each component will be developed as separate technical design documents during the corresponding implementation phase.*
