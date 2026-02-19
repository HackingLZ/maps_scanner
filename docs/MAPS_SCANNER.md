# MAPS Scanner — Windows Defender Cloud Lookup Tool

A Python tool for interacting with Microsoft's MAPS (Microsoft Active Protection
Service) cloud. Sends file reputation queries using the same Bond binary protocol
as Windows Defender and parses the response into human-readable verdicts.

Built through reverse engineering of `mpengine.dll`, `MpCommu.dll`, `MpSvc.dll`,
and live wire capture (ETW) of real Defender traffic.

---

## Quick Start

```bash
# Scan a file
python -m tools.maps_scanner --no-verify scan /path/to/suspicious.exe

# Scan by hash (no local file needed)
python -m tools.maps_scanner --no-verify scan-hash \
    275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

# Trigger FASTPATH signature delivery (requires threat_id + fresh GUID)
python -m tools.maps_scanner --no-verify \
    --machine-guid "$(python3 -c 'import uuid; print(uuid.uuid4())')" \
    scan /tmp/eicar_test.com --threat-id 2147519003

# URL reputation check
python -m tools.maps_scanner --no-verify url https://example.com

# Heartbeat (connectivity test)
python -m tools.maps_scanner --no-verify heartbeat

# Enhanced heartbeat (specific type)
python -m tools.maps_scanner --no-verify heartbeat --type 1   # Setup heartbeat
python -m tools.maps_scanner --no-verify heartbeat --type 8   # Signature update

# Block at First Sight (BAFS) scan
python -m tools.maps_scanner --no-verify bafs suspicious.exe

# Upload sample for cloud detonation
python -m tools.maps_scanner --no-verify upload suspicious.exe

# Scan with auto-upload if cloud requests the file
python -m tools.maps_scanner --no-verify scan suspicious.exe --auto-upload

# Windows Defender Offline (WDO) scan report
python -m tools.maps_scanner --no-verify wdo suspicious.exe

# AMSI script submission (PowerShell, cscript, etc.)
python -m tools.maps_scanner --no-verify amsi script.ps1
python -m tools.maps_scanner --no-verify amsi script.vbs --app-id cscript.exe
echo 'Write-Host "test"' | python -m tools.maps_scanner --no-verify amsi -

# Enterprise mode with Bearer token
python -m tools.maps_scanner --no-verify --bearer-token "eyJ..." scan suspicious.exe

# Verbose output with full hex dump
python -m tools.maps_scanner --no-verify --verbose scan file.exe

# JSON output
python -m tools.maps_scanner --no-verify --json scan file.exe
```

## CLI Reference

```
python -m tools.maps_scanner [global-options] <command> [command-options]
```

### Global Options

| Flag | Description |
|------|-------------|
| `-v, --verbose` | Show decoded Bond fields and hex dump |
| `-q, --quiet` | Suppress informational messages |
| `-j, --json` | JSON output format |
| `--endpoint URL` | Override MAPS endpoint |
| `--ppe` | Use pre-production endpoint |
| `--geo REGION` | Geo-affinity endpoint (us, eu, uk, au) |
| `--proxy URL` | HTTP proxy (e.g. `http://127.0.0.1:8080` for mitmproxy) |
| `--no-verify` | Disable TLS certificate verification |
| `--timeout SECS` | Request timeout (default: 30) |
| `--machine-guid UUID` | Override machine GUID (fresh = new FASTPATH) |
| `--block-level N` | Cloud block level (0=off, 2=high, 6=zero-tolerance) |
| `--bearer-token TOKEN` | Enterprise AAD Bearer token for authenticated access |
| `--customer-type TYPE` | Customer type: Consumer (default) or Enterprise |

### Commands

| Command | Description |
|---------|-------------|
| `scan <file>` | Scan a local file through MAPS cloud |
| `scan-hash <sha256>` | Query file reputation by hash |
| `url <url>` | Check URL reputation |
| `heartbeat` | MAPS connectivity health check |
| `bafs <file>` | Block at First Sight scan (aggressive cloud check) |
| `upload <file>` | Upload file sample to MAPS cloud for detonation |
| `wdo <file>` | Windows Defender Offline (boot-time) scan report |
| `amsi <file>` | Submit script content via AMSI protocol for cloud analysis |
| `analyze <file>` | Local-only file analysis (no cloud) |
| `build <file>` | Build SpynetReport payload without sending |
| `decode <file>` | Decode Bond binary data |
| `replay <file>` | Replay a captured MAPS payload |
| `batch <file_list>` | Scan multiple files from a list |
| `config` | Show/edit persistent configuration |

### Examples

```bash
# Scan with verbose output
python -m tools.maps_scanner --no-verify -v scan malware.exe

# Scan EICAR with threat_id to get FASTPATH signature delivery
python -m tools.maps_scanner --no-verify \
    --machine-guid "$(python3 -c 'import uuid; print(uuid.uuid4())')" \
    scan /tmp/eicar_test.com --threat-id 2147519003

# Build payload to file for later replay
python -m tools.maps_scanner build suspicious.exe -o /tmp/payload.bin
python -m tools.maps_scanner replay /tmp/payload.bin --confirm

# Use with Fiddler/mitmproxy
python -m tools.maps_scanner --proxy http://127.0.0.1:8080 --no-verify scan file.exe

# Use pre-production environment
python -m tools.maps_scanner --ppe --no-verify heartbeat

# Geo-affinity endpoint (EU)
python -m tools.maps_scanner --geo eu --no-verify scan file.exe
```

---

## Protocol Overview

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  MAPS Scanner (Python)                                          │
│                                                                 │
│  scan_file() ──→ hash file ──→ build SpynetReport ──→ Bond     │
│                                  (372 fields)        serialize  │
│                                                         │       │
│  parse_response() ←── Bond deserialize ←── HTTP 200 ←───┘      │
│       │                                                         │
│  MAPSVerdict { is_malicious, threat_name, detection_name,       │
│                severity, signature_data, sample_requested }     │
└─────────────────────────────────────────────────────────────────┘
                              │
                    HTTPS POST (TLS 1.2+)
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Microsoft MAPS Cloud                                           │
│  Endpoint: wdcp.microsoft.com/wdcp.svc/bond/submitreport       │
│  Server: Kestrel (ASP.NET Core)                                │
│  Protocol: Bond CompactBinaryV1                                │
│  Auth: None (consumer) / Bearer token (enterprise)              │
└─────────────────────────────────────────────────────────────────┘
```

### HTTP Request (exact match with real Defender, from ETW capture)

```http
POST /wdcp.svc/bond/submitreport HTTP/1.1
Content-Type: application/bond
Accept: application/bond
Accept-Charset: utf-8
User-Agent: MpCommunication
X-MS-MAPS-CUSTOMERTYPE: Consumer
X-MS-MAPS-OSVERSION: a0000000065f4
X-MS-MAPS-PLATFORMVERSION: 40012659a0005
X-MS-MAPS-ENGINEVERSION: 10001659a0001
Content-Length: <body-size>
Host: wdcp.microsoft.com

<Bond CompactBinaryV1 serialized SpynetReport>
```

### Version Header Encoding

Version strings are packed as 64-bit hex:
`(major << 48) | (minor << 32) | (build << 16) | revision`

| Version String | Hex Encoding |
|---------------|-------------|
| `10.0.26100` (OS) | `a0000000065f4` |
| `1.1.26010.1` (Engine) | `10001659a0001` |
| `4.18.26010.5` (Platform) | `40012659a0005` |

### Bond Serialization

The request and response use Microsoft Bond CompactBinaryV1 format, wrapped in a
`Bonded<T>` marshal envelope:

```
43 42 01 00              CB marshal header ("CB" + version 1)
[varint] schema_name     Schema name as length-prefixed string
BT_STOP_BASE             Base class terminator
BT_STOP_BASE
[field data...]          Actual struct fields
BT_STOP                  End of struct
```

Field headers use a single byte: `(ordinal_delta << 5) | bond_type`. Values are
type-specific (varints for integers, length-prefixed for strings, nested for
structs/lists).

---

## Response Schema

### SubmitSpynetReportResult (outer envelope)

| Ordinal | Field | Type | Description |
|---------|-------|------|-------------|
| F5 | Schema | string | `Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult` |
| F6 | SpynetReportResponse | LIST\<STRUCT\>[1] | Main response body (single-element list) |
| F10 | RuntimeType | STRUCT | Empty (runtime type info placeholder) |

### SpynetReportResponse (F6, inner struct)

| Ordinal | Field | Type | Observed Values |
|---------|-------|------|----------------|
| F3 | Revision | UINT8 | `5` (current protocol revision) |
| F6 | SampleRate | INT32 | `1` (normal sampling) |
| F9 | SampleRequests | LIST\<STRUCT\> | Cloud requesting file upload |
| F12 | **SignaturePatches** | LIST\<STRUCT\> | **FASTPATH dynamic signatures** |
| F15 | UrlResponse | STRUCT | URL reputation result |
| F18 | ThreatDetailElements | LIST\<STRUCT\> | Threat verdict (name, ID, severity) |
| F21 | CertificateResponse | STRUCT | Certificate trust data |
| F24 | OnboardingResponse | STRUCT | Client onboarding info |

### CertificateResponse (F21, inner struct)

| Ordinal | Field | Type | Description |
|---------|-------|------|-------------|
| F3 | CertificateReportGuid | STRING | Certificate report correlation ID |
| F6 | Scenario | UINT8 | Certificate scenario type |
| F9 | CertificateResults | LIST\<STRUCT\> | Certificate verification results |

### UrlResponse (F15, inner struct)

| Ordinal | Field | Type | Description |
|---------|-------|------|-------------|
| F3 | UrlReportGuid | STRING | URL report correlation ID |
| F6 | UrlResults | LIST\<STRUCT\> | URL reputation results |

### OnboardingResponse (F24, inner struct)

| Ordinal | Field | Type | Description |
|---------|-------|------|-------------|
| F3 | OnboardingBlob | STRING | Onboarding configuration blob |

### SignatureGenerationMetadata (nested in response)

| Ordinal | Field | Type | Description |
|---------|-------|------|-------------|
| F3 | PartialCrc1 | STRING | Partial CRC hash 1 |
| F6 | PartialCrc2 | STRING | Partial CRC hash 2 |
| F9 | PartialCrc3 | STRING | Partial CRC hash 3 |
| F12 | FileSize | INT64 | Original file size |
| F15 | Sha1 | STRING | File SHA1 |
| F18 | Sha256 | STRING | File SHA256 |

### UrlResult (inside UrlResponse.UrlResults)

| Ordinal | Field | Type | Description |
|---------|-------|------|-------------|
| F3 | Url | STRING | URL that was checked |
| F6 | Determination | UINT8 | URL verdict (0=unknown, 1=safe, 2=malicious) |
| F9 | Confidence | UINT8 | Confidence score |
| F12 | TTL | UINT8 | Time-to-live (short) |
| F15 | UrlResponseContext | LIST\<STRUCT\> | Additional context |
| F18 | TTLlong | UINT64 | Extended TTL |

### UrlElement (inside UrlList.Urls) — Request Schema

| Ordinal | Field | Type | Description |
|---------|-------|------|-------------|
| F10 | Order | INT32 | Sort order index (not set by engine) |
| F20 | Url | STRING | URL being queried (**only field set by engine**) |
| F21 | Url_Scrubbed | STRING | Scrubbed/sanitized URL (not set by engine) |

### UrlReport Full Request Schema (RE'd from mpengine.dll 0x105251b2 by a5f83eb agent)

| Ordinal | Field | Type | Description |
|---------|-------|------|-------------|
| F3 | UrlReportGuid | STRING | **Mandatory** — report correlation GUID |
| F6 | UrlList | STRUCT | **Mandatory** — contains LIST\<UrlElement\> |
| F9 | UrlContext | STRUCT | Optional — LIST\<UrlContextElement\> with key/value pairs |
| F12 | SigSeq | STRING | **Mandatory** — sig sequence number (formatted via "%llu") |
| F15 | SigSha | STRING | **Mandatory** — sig SHA hash |
| F18 | ReportOnly | BOOL | Omitted when querying; only set to 1 for fire-and-forget reports |

**Key Findings from RE (a5f83eb agent)**:
- UrlReport (ordinal 1542) must be encoded as `LIST<STRUCT>` (not `BT_STRUCT` or
  `LIST<LIST<STRUCT>>`). Using the wrong encoding causes HTTP 500.
- Engine only sets UrlElement.F20 (`url`). Order and Url_Scrubbed are never written.
- SigSeq and SigSha are mandatory fields — always set by the engine.
- ReportOnly is **omitted** (not set to false) when querying for reputation.
- Cloud protection level must be > 5 for URL reputation queries to proceed.
- The UrlReport object allocates 0x850 (2128) bytes; Bond payload at offset +0x830.

### AMSI CoreReport Fields (RE'd from mpengine.dll by aae86e9 agent)

| Ordinal | Field | Type | Schema Table | Description |
|---------|-------|------|-------------|-------------|
| 1325 | AmsiAppId | STRING | CoreReport | AMSI host application (e.g. powershell.exe) |
| 1328 | AmsiSessionId | UINT32 | CoreReport | AMSI session correlation ID |
| 1364 | AmsiUacIdentifier | STRING | CoreReport | UAC identifier for AMSI |
| 1370 | AmsiContentName | STRING | CoreReport | Content name/path being scanned |
| 1371 | AmsiContentName_Scrubbed | STRING | CoreReport | Scrubbed content name |
| 1415 | AmsiRedirectChain | STRING | CoreReport | Web redirect chain data |
| 390 | AmsiContext | STRING | BehaviorEvent | AMSI context in behavior reports |
| 393 | AmsiAction | STRING | BehaviorEvent | AMSI action in behavior reports |
| 50 | Script | STRING | StartupListElement | Raw script content |
| 51 | Script_Scrubbed | STRING | StartupListElement | Scrubbed script content |

### Verdict Logic

- **CLEAN**: Response has Revision + SampleRate but NO SignaturePatches or ThreatDetails
- **MALICIOUS**: SignaturePatches present (FASTPATH delivery) OR ThreatDetails with threat name/ID
- **SAMPLE_REQUESTED**: SampleRequests present (cloud wants the file)

### Response Sizes

| Scenario | Size | Content |
|----------|------|---------|
| Clean/unknown file | 88 bytes | Revision=5, SampleRate=1 |
| Known threat + threat_id + fresh GUID | 488 bytes | 385-byte FASTPATH signature blob |
| Known threat (cached GUID) | 88 bytes | Already delivered to this GUID |

---

## FASTPATH Dynamic Signatures

When MAPS confirms a threat, it delivers a binary **FASTPATH signature** — a
miniature VDM (Virus Definition Module) containing everything the local engine
needs to detect the threat without further cloud lookups.

### FASTPATH Blob Structure (VDM TLV Format)

The signature blob uses the same TLV (Type-Length-Value) format as VDM database
files: `sig_type(1) + size_low(1) + size_high(2) + payload(size)`.

Example: EICAR test file (385 bytes, 5 TLV entries):

```
┌─────────────────────────────────────────────────────────────┐
│ Entry 1: type=0xEC (ENVELOPE), 256 bytes                    │
│   Encrypted/compressed detection logic                      │
│   (AES-encrypted pattern matching bytecode)                 │
├─────────────────────────────────────────────────────────────┤
│ Entry 2: type=0xAA (FASTPATH_DATA), 20 bytes                │
│   Metadata:                                                 │
│     Bytes 0-3:  Config flags (0x09 0x30 0x01 0x01)          │
│     Bytes 4-11: Reserved                                    │
│     Bytes 12-19: FILETIME compilation timestamp              │
│                  e.g. 2026-02-19 00:46:45 UTC               │
├─────────────────────────────────────────────────────────────┤
│ Entry 3: type=0x5C (THREAT_BEGIN), 47 bytes                  │
│   Threat group header:                                       │
│     Bytes 0-3:  Threat ID (uint32 LE)                        │
│                  e.g. 2147519003 = EICAR                     │
│     Bytes 4-7:  Flags (0x00010000)                           │
│     Bytes 8-9:  Category/severity (0x002A = 42)              │
│     Byte 10:    Detection name length (25)                   │
│     Bytes 12+:  "Virus:DOS/EICAR_Test_File\0"               │
│     Tail:       Remediation metadata                         │
├─────────────────────────────────────────────────────────────┤
│ Entry 4: type=0x67 (STATIC), 38 bytes                        │
│   Static hash-based detection:                               │
│     Prefix:     CRC32 + MD5 hash of target file              │
│     Last 20B:   SHA1 hash (3395856ce81f2b7382dee72602f798    │
│                  b642f14140 = EICAR SHA1)                    │
├─────────────────────────────────────────────────────────────┤
│ Entry 5: type=0x5D (THREAT_END), 4 bytes                     │
│   Threat group footer:                                       │
│     Bytes 0-3: Threat ID (matches THREAT_BEGIN)              │
└─────────────────────────────────────────────────────────────┘
```

### Signature Type Constants

| Type | Hex | Name | Purpose |
|------|-----|------|---------|
| 0x5C | 92 | THREAT_BEGIN | Threat group start with ID + name |
| 0x5D | 93 | THREAT_END | Threat group end marker |
| 0x67 | 103 | STATIC | Static hash-based detection (SHA1/MD5) |
| 0x80 | 128 | KCRCE | CRC-based detection (most common in VDM) |
| 0xAA | 170 | FASTPATH_DATA | FastPath metadata (timestamp, config) |
| 0xAB | 171 | FASTPATH_SDN | Static Detection Name |
| 0xD8 | 216 | FASTPATH_TDN | Threat Detection Name |
| 0xDA | 218 | FASTPATH_SDN_EX | Extended SDN with extra metadata |
| 0xEC | 236 | (envelope) | Encrypted detection logic blob |

### Key Observations

- **GUID deduplication**: MAPS delivers FASTPATH only once per machine GUID + file
  hash combination. Use a fresh `--machine-guid` to get a new delivery.
- **Compilation timestamp**: The FASTPATH_DATA entry contains a FILETIME showing when
  the signature was compiled — typically seconds before delivery (real-time generation).
- **Complete threat group**: The blob is a self-contained VDM threat group with
  THREAT_BEGIN → detection sigs → THREAT_END, identical to what's in mpavbase.vdm.
- **The 0xEC envelope** (256 bytes) contains encrypted detection logic. The engine
  decrypts this at runtime for behavioral/pattern matching. The cleartext entries
  (THREAT_BEGIN, STATIC) provide hash-based detection and metadata.

### FASTPATH Wire Format (RE'd from mpengine.dll by af843a1 agent)

The engine's FASTPATH blob handler (`fcn.1036dd82`) dispatches based on outer TLV type:

**TLV Header** (4 bytes): `[type:1][size_lo:1][size_mid:1][size_hi:1]`
Size = `(size_hi << 16) | (size_mid << 8) | size_lo` (24-bit LE)

| Outer Type | Path | Handler |
|------------|------|---------|
| `0xEE` | V3 FASTPATH | `fcn.1036e09c` (4729-byte parser) |
| Any other | Legacy | `fcn.1036f35e` (RSA signature verification) |

**V3 Format (0xEE outer type):**
```
[4B TLV header: type=0xEE, size]
[1B version (must be 1)]
[2B status (must be 0)]
[2B L1_stream_ver: 0→32B, 1→48B, 2→64B records]
[2B L2_stream_ver: 0→32B, 1→48B, 2→64B records]
[1B L1_stream_count (max 8)]
[1B L2_stream_count (max 8, ≤ L1)]
[L1 streams: sub-TLV detection containers]
[L2 streams: [4B size][payload] threat records]
[Detection body: cert chain verification + sig application]
```

**Legacy Format (non-0xEE outer type):**
Signed payload verified against RSA-2048 public keys:
- 2 production keys at 0x10a0aac8, 0x10a0ad18
- 3 test keys at 0x10a0ae50, 0x10a0a9b0, 0x10a0abe0 (require `MpFastpathEnableTestCert=1`)

**Inner Envelope Types** (within legacy `fcn.1036f35e`):
| Type | Crypto | Description |
|------|--------|-------------|
| `0xEB` | WinTrust | Signed via CryptCATOpen + WinVerifyTrust |
| `0xAC` | SHA-1 + RSA | 20-byte hash, 0x70-byte context |
| `0xEC` | SHA-256 + RSA | 32-byte hash, 0x78-byte context |
| `0xEE` | Rejected | Nested V3 not allowed in legacy path |

**Registry Controls:**
- `MpDisableFastpathV3` → force legacy path for 0xEE blobs
- `MpDisableFastpathCertCheck` → skip certificate verification
- `MpFastpathEnableTestCert` → allow test RSA keys
- `MpDisableFastpathV3ExpirationChecks` → skip timestamp validation
- `MpDisableBlobCache` → disable blob caching

---

## Request Schema (SpynetReport)

The SpynetReport entity has 372+ Bond fields organized hierarchically:

### Key Request Fields

| Ordinal | Field | Type | Description |
|---------|-------|------|-------------|
| 3 | ReportGuid | string | Unique report identifier (UUID) |
| 6 | ReportType | uint32 | 1=AsyncLowfi, 2=SyncLowfi, 3=Telemetry, 4=Heartbeat |
| 9 | EngineVersion | string | e.g. "1.1.26010.1" |
| 12 | SigVersion | string | e.g. "1.445.126.0" |
| 15 | AppVersion | string | e.g. "4.18.26010.5" |
| 18 | OSType | uint32 | 1=Workstation, 2=Server, 3=DC |
| 21 | MachineGuid | string | Persistent machine identifier |
| 24 | ScanReason | uint32 | Why scan was initiated |
| 190 | FileReportElements | LIST\<STRUCT\> | File metadata + hashes |
| 1542 | UrlReport | STRUCT | URL reputation query |

### FileReport / CoreReport Fields

| Ordinal | Field | Type | Description |
|---------|-------|------|-------------|
| 3 | FileName | string | Original filename |
| 6 | FileSHA256 | string | SHA-256 hash (hex) |
| 9 | FileSHA1 | string | SHA-1 hash (hex) |
| 12 | FileMD5 | string | MD5 hash (hex) |
| 15 | FileSize | uint64 | File size in bytes |
| 18 | ThreatID | uint32 | Lowfi threat ID to confirm |
| 21 | ThreatName | string | Lowfi detection name |

### Report Types

| Value | Name | Description |
|-------|------|-------------|
| 1 | ASYNC_LOWFI | Async lowfi detection (background verdict) |
| 2 | SYNC_LOWFI | Sync lowfi / cloud block (real-time, blocks file) |
| 3 | TELEMETRY_ONLY | Telemetry collection (no verdict needed) |
| 4 | HEARTBEAT | Health check / connectivity test |
| 5 | URL_REPUTATION | URL reputation query |
| 6 | SAMPLE_REQUEST | File upload for analysis |
| 7 | WDO_REPORT | Windows Defender Offline report |

---

## Identity and Authentication

### Machine GUID

A random UUID that identifies the client to MAPS. On real Defender, generated once
via `UuidCreate()` and stored persistently. Our tool generates one on first run and
saves it to `~/.maps_scanner/machine_guid` (or uses `--machine-guid` override).

The server accepts any valid UUID — no registration required.

### Consumer vs Enterprise

| Mode | Auth | Header |
|------|------|--------|
| Consumer | None (no Authorization header) | `X-MS-MAPS-CUSTOMERTYPE: Consumer` |
| Enterprise | `Authorization: Bearer <AAD token>` | `X-MS-MAPS-CUSTOMERTYPE: Enterprise` |

Enterprise mode requires an Azure AD token from client ID
`cab96880-db5b-4e15-90a7-f3f1d62ffe39` (Microsoft's registered app for Defender
Graph API access). This is NOT needed for basic MAPS lookups.

### SOAP Path (Legacy, Deprecated)

The SOAP endpoint (`/WdCpSrvc.asmx`) returns HTTP 404 — Microsoft has fully
migrated to the Bond REST protocol. The SOAP path used WS-Security UsernameToken
with hardcoded credentials:
- Username: `k8CLF3BX69dC0bge9PcDEtAa5cebEfkEEqXdve4BjK8=`
- PasswordDigest: SHA1(nonce + timestamp + password)

---

## Endpoints

| Endpoint | URL | Purpose |
|----------|-----|---------|
| Production | `https://wdcp.microsoft.com` | Main MAPS cloud |
| Alternative | `https://wdcpalt.microsoft.com` | Failover |
| Pre-Production | `https://fastpath.wdcpppe.microsoft.com` | Testing/PPE |
| US Geo | `https://unitedstates.cp.wd.microsoft.com` | US data residency |
| EU Geo | `https://europe.cp.wd.microsoft.com` | EU data residency |
| UK Geo | `https://unitedkingdom.cp.wd.microsoft.com` | UK data residency |
| AU Geo | `https://australia.cp.wd.microsoft.com` | AU data residency |
| Entra | `/wdcp.svc/entraReport` | Entra ID reports |

All use the path `/wdcp.svc/bond/submitreport` for Bond REST requests.

---

## Implemented Features

| Feature | Status | Notes |
|---------|--------|-------|
| File scanning (local file) | Done | Full PE analysis, hashing, metadata extraction |
| Hash-only queries | Done | SHA256/SHA1/MD5 without local file |
| URL reputation | Done | Via Bond_UrlReport |
| Heartbeat | Done | Connectivity health check |
| Enhanced heartbeat types (12) | Done | Setup, Uninstall, Error, PolicyChange, Browser, Exclusion, Cleanup, SigUpdate, PlatformUpdate, TamperProtect, Reboot |
| Block at First Sight (BAFS) | Done | SyncLowfi + zero-tolerance block level, `bafs` CLI command |
| Sample upload (Azure Blob) | Done | HTTP PUT to SAS URI, gzip/deflate compression, `upload` CLI command |
| Batch scanning | Done | Multiple files from list/stdin |
| FASTPATH signature extraction | Done | SDN/TDN/DATA types, detection name parsing |
| FASTPATH VDM TLV parsing | Done | Full decode of threat group entries |
| Sample request detection | Done | Parses upload URIs and TTL |
| Bond CompactBinaryV1 | Done | Full marshal/unmarshal with schema envelope |
| Response verdict parsing | Done | Threat name, ID, severity, category |
| Payload build/decode/replay | Done | Offline analysis and replay tools |
| Geo-affinity endpoints | Done | US, EU, UK, AU |
| Proxy support | Done | mitmproxy/Fiddler compatible |
| Wire-compatible headers | Done | Exact match with ETW capture of real Defender |
| Version hex encoding | Done | Verified against live traffic |
| JSON output mode | Done | Machine-readable output |
| Test file generation | Done | 9 types: EICAR, minimal PE, random binary, PowerShell, unique PE, versioned PE, DLL, batch script, large PE |
| Enterprise Bearer auth | Done | `--bearer-token` for enterprise MAPS, `--customer-type Enterprise` |
| WDO (Defender Offline) report | Done | Report type 7, `wdo` CLI command |
| Certificate response parsing | Done | RE'd CertificateReportGuid, Scenario, CertificateResults |
| Onboarding response parsing | Done | RE'd OnboardingBlob |
| Signature generation metadata | Done | RE'd PartialCrc, FileSize, SHA1, SHA256 |
| AMSI script submission | Done | `amsi` CLI command, CoreReport AMSI fields (1325, 1328, 1364, 1370, 1371, 1415) |
| UrlElement schema (RE'd) | Done | Order=10, Url=20, Url_Scrubbed=21 (from aa9e6ee agent) |
| BehaviorEvent schema fields | Done | AmsiContext(390), AmsiAction(393) (from aae86e9 agent) |
| StartupListElement script fields | Done | Script(50), Script_Scrubbed(51) (from aae86e9 agent) |
| CertificateResult nested schema | Done | Sha1=3, Determination=6, Confidence=9, Ttl=12, IsSelfSigned=15 (from ac80320 agent) |
| SignaturePatch schema | Done | Enable=3, Disable=6, SignatureMatches=9, EnableBlob=12, DisableBlob=15 (from ac80320 agent) |
| HeartbeatError schema | Done | FeatureError=10, FunctionError=20, ErrorHresult=30, ErrorDetails=40 (from ac80320 agent) |
| Heartbeat SF fields (900-1210+) | Done | 40+ fields: IsBeta, RtpState, HeartbeatErrors, Exclusions, DeviceId, MapsLatency, etc. (from ac80320 agent) |

## Cloud Detonation / Sample Upload

MAPS supports full file upload for cloud sandbox analysis ("cloud detonation").
When the cloud needs a file for deeper analysis, it responds with a
`Bond_SampleRequest` containing an Azure Blob Storage upload URL.

### Sample Upload Flow

```
1. Client sends SpynetReport with file hash
           │
2. MAPS responds with SampleRequest (F9):
   ├── REQUEST_GUID:  Unique request ID
   ├── SHA1:          File SHA1 hash
   ├── BLOB_SAS_URI:  Azure Blob upload URL with SAS token
   │                  e.g. https://ussus1eastprod.blob.core.windows.net/container/blob?SAS
   ├── TTL:           Request expiration time
   ├── COMPRESSION:   Compression method
   └── USE_QUARANTINE: Use quarantine storage
           │
3. Client uploads entire file to Azure Blob via HTTPS PUT
   (handled by MpAzSubmit.dll on real Defender)
           │
4. Cloud sandbox detonates file:
   - Behavioral analysis (API calls, file/registry changes, network)
   - Machine learning classification
   - Unpacking / deobfuscation
           │
5. Results delivered as FASTPATH signatures on next query
```

### Sample Submission Consent

Controlled by `SubmitSamplesConsent` registry setting:

| Value | Meaning |
|-------|---------|
| 0 | Always prompt user |
| 1 | Send safe samples automatically (default) |
| 2 | Never send |
| 3 | Send all samples automatically |

### Implementation

Fully implemented. The `upload` CLI command supports:
- Automatic SAS URI request from MAPS cloud
- Direct upload to a provided SAS URI (`--sas-uri`)
- Optional gzip/deflate compression (`--compression`)
- Auto-upload on scan via `scan --auto-upload`

```bash
# Upload a file (request SAS URI from MAPS, then upload)
python -m tools.maps_scanner --no-verify upload suspicious.exe

# Upload directly to a known SAS URI
python -m tools.maps_scanner --no-verify upload file.exe --sas-uri "https://..."

# Scan + auto-upload if MAPS requests it
python -m tools.maps_scanner --no-verify scan file.exe --auto-upload
```

---

## All MAPS Cloud Features

### Response Features (what the cloud sends back)

| Feature | Response Field | Status | Notes |
|---------|---------------|--------|-------|
| **Verdict (threat details)** | F18 ThreatDetailElements | Done | Name, ID, severity, category |
| **FASTPATH signatures** | F12 SignaturePatches | Done | Full VDM TLV parse |
| **Sample upload request** | F9 SampleRequests | Done | Upload URI extracted + Azure Blob PUT upload |
| **URL reputation** | F15 UrlResponse | Done | URL verdict via Bond_UrlReport |
| **Certificate reputation** | F21 CertificateResponse | Done | RE'd schema: CertificateReportGuid, Scenario, CertificateResults |
| **Onboarding** | F24 OnboardingResponse | Done | RE'd schema: OnboardingBlob |
| **Protocol revision** | F3 Revision | Done | Currently version 5 |
| **Sampling rate** | F6 SampleRate | Done | Telemetry throttle |

### Request Features (what we can send)

| Feature | Report Type | Status | Notes |
|---------|------------|--------|-------|
| **File scan (async lowfi)** | 1 | Done | Background cloud verdict |
| **File scan (sync/cloud block)** | 2 | Done | Real-time BAFS blocking |
| **Telemetry only** | 3 | Done | Data collection, no verdict |
| **Heartbeat** | 4 | Done | Connectivity + config sync |
| **URL reputation query** | 5 | Done | UrlReport as LIST\<STRUCT\>; UrlElement(Url=20), SigSeq, SigSha mandatory (RE'd from 0x105251b2) |
| **Sample upload trigger** | 6 | Done | SAS URI request + Azure Blob upload |
| **WDO (Defender Offline)** | 7 | Done | Offline scan report, `wdo` CLI command |
| **AMSI script content** | Via CoreReport AMSI fields | Done | `amsi` CLI command, pre-execution script analysis |
| **Network connection reports V1** | F1190 NetworkConnectionReportElements | Done | `netconn` CLI: 10-field Bond_NetworkConnectionReport (Timestamp, DestinationIp, SourceIp, DestinationPort, SourcePort, Protocol, Uri) |
| **Network connection reports V2** | F1191 NetworkConnectionReportV2Elements | Done | NCRV2 class: 21-field schema with UINT32 IPv4, split UINT64 IPv6, Direction, InboundBytes, OutboundBytes |
| **AMSI UAC info** | F1275 AmsiUacInfos | Done | `uac` CLI: 30-field Bond_AmsiUacInfo (Type discriminant: 0=Exe, 1=COM, 2=MSI, 3=ActiveX, 4=PackagedApp) |
| **Behavior reports** | 49 Bond classes | Not done | Process/network/memory telemetry |
| **Prevalent file reports** | Bond_PrevalentFileReport | Not done | ML prevalence data |
| **Remediation status** | Bond_RemediationStatusReport | Not done | Post-cleanup reporting |

### Configuration Features

| Feature | Status | Notes |
|---------|--------|-------|
| Cloud block level (0-6) | Done | Off, Default, Moderate, High, High+, Zero Tolerance |
| SpyNet reporting level (0-2) | Done | Disabled, Basic, Advanced |
| Geo-affinity endpoints | Done | US, EU, UK, AU |
| Enhanced heartbeat types (12) | Done | All 12 types: StillAlive, Setup, Uninstall, Error, PolicyChange, Browser, Exclusion, Cleanup, SigUpdate, PlatformUpdate, TamperProtect, Reboot |
| Enterprise auth (Bearer token) | Done | `--bearer-token` flag, AAD client ID cab96880-db5b-4e15-90a7-f3f1d62ffe39 |
| Organization ID | Not done | For enterprise policy features |
| Timeout configuration | Partial | Custom timeout supported, no fallback logic |

## Not Yet Implemented (Detailed)

| Feature | Difficulty | Notes |
|---------|------------|-------|
| FASTPATH 0xEC blob decryption | Hard | RSA-2048 + SHA-256 encrypted envelope; 5 RSA public keys in mpengine.dll (2 prod + 3 test); see af843a1 RE findings |
| FASTPATH V3 inner parsing | Hard | 0xEE outer type: version/status/stream counts header, L1/L2 stream decode, detection body; see af843a1 wire format |
| Behavior report submission | Hard | 49 Bond classes for behavioral telemetry; AmsiContext(390), AmsiAction(393) |
| Org-specific features | Medium | Organization ID, partner-specific endpoints |
| Network connection V2 builder | Low | NCRV2 schema class complete (21 fields); needs build_network_connection_report_v2() builder + CLI |
See [MAPS_SAMPLE_IO.md](MAPS_SAMPLE_IO.md) for comprehensive sample input/output for all file types and commands.

---

## AMSI Script Submission Architecture (RE'd)

AMSI (Antimalware Scan Interface) content is submitted through the standard
SpynetReport pipeline, not as a separate schema. Script content is embedded
within the CoreReport using STREAM_ATTRIBUTE metadata.

### Flow

```
AMSI Host App → amsistream (eSCT_AMSI) → VFZ Plugin + Stream Buffer
  → SetAmsiReportPath() attaches to SCAN_REPLY
    → Bond_CoreReport serialization (AMSI fields + Script content)
      → Bond_SpynetReport wrapper → MAPS cloud
        → Cloud may respond with Bond_SampleRequest
          → MemorySampleReader + CSampleSubmission
            → Chunked upload to Azure Blob via BlobSasUri
```

### CoreReport AMSI Fields (RE'd ordinals)

| Ordinal | Field | Type | Description |
|---------|-------|------|-------------|
| 1325 | AmsiAppId | STRING | Host app identifier (e.g. powershell.exe) |
| 1328 | AmsiSessionId | UINT32 | Session correlation ID |
| 1364 | AmsiUacIdentifier | STRING | UAC elevation identifier |
| 1370 | AmsiContentName | STRING | Content name/path being scanned |
| 1371 | AmsiContentName_Scrubbed | STRING | Sanitized content name |
| 1415 | AmsiRedirectChain | STRING | Web redirect chain data |

### STREAM_ATTRIBUTE Metadata (8 AMSI-specific, 72 total)

| Attribute | Purpose |
|-----------|---------|
| `STREAM_ATTRIBUTE_AMSI_SESSION_ID` | Correlates multiple AMSI calls |
| `STREAM_ATTRIBUTE_AMSI_APP_ID` | Host application identifier |
| `STREAM_ATTRIBUTE_AMSI_CONTENT_NAME` | Name/path of scanned content |
| `STREAM_ATTRIBUTE_AMSI_UAC_REQUEST_CONTEXT` | UAC elevation request blob |
| `STREAM_ATTRIBUTE_AMSI_REDIRECT_CHAIN` | Web redirect chain |
| `STREAM_ATTRIBUTE_AMSI_ALL` | Aggregated AMSI attribute blob |
| `STREAM_ATTRIBUTE_AMSI_OPERATION_PPID` | Parent process ID |
| `STREAM_ATTRIBUTE_AMSI_IS_EXCLUDED_PROCESS` | Exclusion flag |

### Script Content Fields

Script content goes in dedicated fields (likely in StringReport nested struct):
- `Script` (ordinal 50 in StringReport) — Raw script content
- `Script_Scrubbed` (ordinal 51) — Sanitized/scrubbed version

### Sample Upload for AMSI Content

Uses `MemorySampleReader` (vs `FileSampleReader` for files), controlled by
`AllowedAmsiAppIdSampleSubmissions` config — whitelists which AMSI host apps
can trigger sample uploads.

See [reports/amsi_maps_protocol_analysis.md](../../reports/amsi_maps_protocol_analysis.md) for full RE analysis.

---

## Response Schemas (RE'd by ac80320 agent)

### Bond_CertificateResponse (F21)

| Ordinal | Field | Type | Description |
|---------|-------|------|-------------|
| 3 | CertificateReportGuid | STRING | Report correlation GUID |
| 6 | Scenario | UINT8 | Certificate scenario |
| 9 | CertificateResults | LIST\<STRUCT\> | List of CertificateResult |

### Bond_CertificateResult (nested in CertificateResults)

| Ordinal | Field | Type | Description |
|---------|-------|------|-------------|
| 3 | Sha1 | STRING | Certificate SHA1 hash |
| 6 | Determination | UINT8 | Trust determination |
| 9 | Confidence | UINT8 | Confidence score |
| 12 | Ttl | UINT64 | Time-to-live |
| 15 | IsSelfSigned | BOOL | Self-signed flag |

### Bond_UrlResponse (F15)

| Ordinal | Field | Type | Description |
|---------|-------|------|-------------|
| 3 | UrlReportGuid | STRING | Report correlation GUID |
| 6 | UrlResults | LIST\<STRUCT\> | List of UrlResult |

### Bond_UrlResult (nested in UrlResults)

| Ordinal | Field | Type | Description |
|---------|-------|------|-------------|
| 3 | Url | STRING | The URL being evaluated |
| 6 | Determination | UINT8 | URL determination |
| 9 | Confidence | UINT8 | Confidence score |
| 12 | TTL | UINT8 | Time-to-live (short) |
| 15 | UrlResponseContext | LIST\<STRUCT\> | Contextual data |
| 18 | TTLlong | UINT64 | Time-to-live (long) |

### Bond_SignaturePatch (F12 element)

| Ordinal | Field | Type | Description |
|---------|-------|------|-------------|
| 3 | Enable | STRING | Signatures to enable |
| 6 | Disable | STRING | Signatures to disable |
| 9 | SignatureMatches | LIST\<STRUCT\> | Matched signatures |
| 12 | EnableBlob | LIST | Raw enable blob |
| 15 | DisableBlob | LIST | Raw disable blob |

### Bond_SignatureGenerationMetadata

| Ordinal | Field | Type | Description |
|---------|-------|------|-------------|
| 3 | PartialCrc1 | STRING | First partial CRC |
| 6 | PartialCrc2 | STRING | Second partial CRC |
| 9 | PartialCrc3 | STRING | Third partial CRC |
| 12 | FileSize | INT64 | File size |
| 15 | Sha1 | STRING | SHA1 hash |
| 18 | Sha256 | STRING | SHA256 hash |

### Bond_HeartbeatError (nested in HeartbeatErrors)

| Ordinal | Field | Type | Description |
|---------|-------|------|-------------|
| 10 | HeartbeatFeatureError | STRING | Feature that errored |
| 20 | HeartbeatFunctionError | STRING | Function that errored |
| 30 | HeartbeatErrorHresult | STRING | HRESULT code |
| 40 | HeartbeatErrorDetails | STRING | Error details |

### SpynetReport Heartbeat Fields (ordinals 830-1210+)

The SpynetReport has **372 fields** total. Heartbeat-specific fields at high ordinals:

| Ordinal | Field | Type |
|---------|-------|------|
| 830 | MapsGenerateLatency | UINT64 |
| 840 | MapsSendLatency | UINT64 |
| 850 | MapsParseLatency | UINT64 |
| 860 | MapsHresult | STRING |
| 900 | RemediationCheckpointReports | LIST\<STRUCT\> |
| 910 | IsBeta | BOOL |
| 920 | StillAliveHeartbeat | UINT8 |
| 930 | HeartbeatControlGroup | UINT8 |
| 980 | HeartbeatErrors | LIST\<STRUCT\> |
| 990 | Exclusions | LIST\<STRUCT\> |
| 1010 | RtpStateBitfield | UINT16 |
| 1020 | RtpHresult | UINT32 |
| 1050 | EngineReportGuid | STRING |
| 1060 | MapsReportGuid | STRING |
| 1100 | EngineLoadFileTime | UINT64 |
| 1133 | DeviceId | STRING |
| 1140 | SignatureUpdateTime | UINT64 |
| 1183 | MpFilterHeartbeatFlags | UINT32 |
| 1189 | ScanConfigFlags | UINT32 |
| 1192 | RtpConfigFlags | UINT32 |
| 1195-1210 | MapsLatencyTimers (6 fields) | UINT32 |

---

## Architecture (Internal)

### DLL Responsibility Chain (from RE)

```
mpengine.dll          Bond SpynetReport generation (372+ fields)
      │                Bond serialization (CompactBinaryV1)
      ▼
MpSvc.dll             Orchestration, GUID management, config
      │                Loads MpCommu.dll, passes report blob
      ▼
MpCommu.dll           HTTP transport (WinHTTP)
      │                Headers, auth, retry logic, response parsing
      ▼
wdcp.microsoft.com    MAPS cloud backend (Kestrel/ASP.NET Core)
      │
      ▼
MpAzSubmit.dll        Sample upload only (Azure Blob Storage)
                       Separate from verdict lookup
```

### Python Module Structure

```
tools/maps_scanner/
├── __main__.py        CLI entry point (945 lines)
├── client.py          MAPS client, verdict parser (2687 lines)
│   ├── MAPSConfig     Configuration dataclass
│   ├── MAPSClient     High-level scan/heartbeat/url/upload/bafs/wdo/amsi API
│   ├── MAPSTransport  HTTP transport with headers + Azure Blob upload
│   ├── SpynetReportBuilder  Bond payload construction
│   ├── HeartbeatType  12 heartbeat subtypes enum
│   ├── parse_response()     Response → MAPSVerdict
│   └── _interpret_*()       Field-specific parsers
├── bond.py            Bond CompactBinaryV1 codec (900+ lines)
│   ├── CompactBinaryV1Writer  Serialization
│   ├── CompactBinaryV1Reader  Deserialization
│   ├── bond_marshal()         Bonded<T> envelope
│   └── bond_unmarshal_with_schema()  Schema-aware decode
├── tests/
│   ├── create_test_files.py   Generate test files (EICAR, PE, random, PS1, unique PE)
│   └── samples/               Generated test files directory
└── MAPS_SCANNER.md    This documentation
```

---

## Related Research

### VDM Format Tools

| Tool | Author | Description |
|------|--------|-------------|
| [WDExtract](https://github.com/hfiref0x/WDExtract) | hfiref0x | Extract/decompress VDM files, merge deltas |
| [defender2yara](https://github.com/t-tani/defender2yara) | t-tani | Convert VDM signatures to YARA rules |
| [defender_signature_parser](https://github.com/ZPetricusic/defender_signature_parser) | ZPetricusic | Python VDM parser |
| [commial/experiments](https://github.com/commial/experiments/tree/master/windows-defender) | commial | VDM format RE, Lua scripts, ASR rules |
| [wd-pretender](https://github.com/SafeBreach-Labs/wd-pretender) | SafeBreach | VDM manipulation (CVE-2023-24934) |
| [defender-recon24](https://github.com/t0-retooling/defender-recon24) | retooling | Trigger specific Defender detections |

### Key References

- VDM container: PE file with RMDX-compressed resource, zlib deflate (wbits=-15)
- VDM entries: TLV stream — `sig_type(1) + size_low(1) + size_high(2) + payload`
- 235+ signature types enumerated from mpengine.dll PDB symbols
- FASTPATH blobs use identical TLV format as VDM entries
- 2.5M+ signatures in base databases, ~30K Lua detection scripts

---

## Reverse Engineering Sources

All findings derived from static analysis of Windows Defender binaries:

| Binary | Size | Arch | Analysis |
|--------|------|------|----------|
| `mpengine.dll` | 14.3 MB | x86 | Bond schema, MAPS report generation, sig types |
| `MpCommu.dll` | 578 KB | ARM64 | HTTP transport, headers, auth, dispatch logic |
| `MpSvc.dll` | 6.2 MB | ARM64 | Service orchestration, GUID management, AAD tokens |
| `MpClient.dll` | 1.8 MB | ARM64 | ReportingGUID, config management |
| `MpAzSubmit.dll` | — | ARM64 | Azure Blob upload (sample submission only) |

Tools used: Ghidra 12.0.3 headless, radare2 4.2.1, ETW WinHTTP tracing, Fiddler.

Wire protocol verified against ETW capture of live Defender traffic on Windows 11.
