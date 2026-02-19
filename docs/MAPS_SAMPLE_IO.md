# MAPS Scanner — Sample Input/Output

Reference showing actual MAPS cloud responses for different file types and commands.
All outputs captured from live production MAPS endpoint (`wdcp.microsoft.com`).

---

## File Scan — EICAR Test File (Known Malware + FASTPATH)

The EICAR test file is universally detected. When a `--threat-id` is provided with
a fresh `--machine-guid`, MAPS delivers a FASTPATH dynamic signature.

### Command

```bash
./maps_scanner --no-verify \
    --machine-guid "$(python3 -c 'import uuid; print(uuid.uuid4())')" \
    scan /tmp/eicar_test.com --threat-id 2147519003
```

### Text Output

```
HTTP Status:    200
Latency:        663.2 ms
Schema:         Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult

  VERDICT:      MALICIOUS
  Threat:       Virus:DOS/EICAR_Test_File
  Threat ID:    2147519003
  Sig Data:     385 bytes (FASTPATH)

  FASTPATH Signature (VDM TLV):
    [0xEC ENVELOPE] 256B (encrypted detection logic)
    [0xAA FASTPATH_DATA] 20B Compiled=2026-02-19 01:33:29 UTC
    [0x5C THREAT_BEGIN] 47B ThreatID=2147519003 "Virus:DOS/EICAR_Test_File"
    [0x67 STATIC] 38B SHA1=3395856ce81f2b7382dee72602f798b642f14140
    [0x5D THREAT_END] 4B
  Revision:     5
  Sample Rate:  1
```

### JSON Output

```json
{
  "is_malicious": true,
  "clean": false,
  "threat_name": "Virus:DOS/EICAR_Test_File",
  "threat_id": 2147519003,
  "detection_name": "Virus:DOS/EICAR_Test_File",
  "sample_requested": false,
  "revision": 5,
  "sample_rate": 1,
  "http_status": 200,
  "latency_ms": 495.4,
  "schema": "Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult",
  "signature_data_size": 385,
  "fastpath_entries": [
    {"type": "0xEC", "name": "ENVELOPE", "size": 256},
    {"type": "0xAA", "name": "FASTPATH_DATA", "size": 20, "compiled": "2026-02-19 01:33:00 UTC"},
    {"type": "0x5C", "name": "THREAT_BEGIN", "size": 47, "threat_id": 2147519003, "detection": "Virus:DOS/EICAR_Test_File"},
    {"type": "0x67", "name": "STATIC", "size": 38, "sha1": "3395856ce81f2b7382dee72602f798b642f14140"},
    {"type": "0x5D", "name": "THREAT_END", "size": 4, "threat_id": 2147519003}
  ]
}
```

### Notes

- FASTPATH is only delivered once per machine GUID + file hash combination
- Use `--machine-guid` with a fresh UUID each time to get new deliveries
- Without `--threat-id`, EICAR returns CLEAN (no lowfi trigger = no cloud confirmation)
- Response is 488 bytes total (88-byte base + 385-byte FASTPATH + overhead)
- The 0xEC ENVELOPE (256 bytes) contains AES-encrypted detection logic
- The STATIC entry (0x67) contains CRC32 + MD5 + SHA1 hashes for the target file

---

## File Scan — Clean File (Random Binary)

Unknown/clean files get a minimal response with just protocol metadata.

### Command

```bash
./maps_scanner --no-verify scan random_data.bin
```

### JSON Output

```json
{
  "is_malicious": false,
  "clean": true,
  "sample_requested": false,
  "revision": 5,
  "sample_rate": 1,
  "http_status": 200,
  "latency_ms": 400.1,
  "schema": "Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult"
}
```

### Notes

- Response is always 88 bytes for clean/unknown files
- `revision: 5` is the current MAPS protocol version
- `sample_rate: 1` means normal telemetry sampling

---

## File Scan — Minimal PE Executable

A minimal valid PE (just `ret` instruction) is treated as unknown/clean.

### Command

```bash
./maps_scanner --no-verify scan minimal_test.exe
```

### Text Output

```
HTTP Status:    200
Latency:        430.5 ms
Schema:         Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult

  VERDICT:      CLEAN (no threats detected)
  Revision:     5
  Sample Rate:  1
```

---

## File Scan — PowerShell Script

Even scripts with suspicious-looking patterns (VirtualAlloc, WriteProcessMemory
in comments) are treated as clean by hash-based scanning. AMSI-style analysis
requires STREAM_ATTRIBUTE submission (not yet implemented).

### Command

```bash
./maps_scanner --no-verify scan test_script.ps1
```

### Text Output

```
HTTP Status:    200
Latency:        402.1 ms
Schema:         Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult

  VERDICT:      CLEAN (no threats detected)
  Revision:     5
  Sample Rate:  1
```

---

## Hash-Only Query

Query by SHA-256 without a local file. Same response format as file scan.

### Command

```bash
./maps_scanner --no-verify scan-hash \
    275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

### JSON Output

```json
{
  "is_malicious": false,
  "clean": true,
  "sample_requested": false,
  "revision": 5,
  "sample_rate": 1,
  "http_status": 200,
  "latency_ms": 410.0,
  "schema": "Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult"
}
```

### Notes

- Hash-only queries return CLEAN even for known threats (EICAR) because no
  threat_id is provided (no lowfi context for cloud to confirm)
- Hash queries are useful for reputation checks without uploading file content

---

## Block at First Sight (BAFS)

BAFS uses SyncLowfi (type 2) + zero-tolerance block level for maximum cloud
detection sensitivity.

### Command (Blocked)

```bash
./maps_scanner --no-verify \
    --machine-guid "$(python3 -c 'import uuid; print(uuid.uuid4())')" \
    bafs /tmp/eicar_test.com --threat-id 2147519003
```

### Text Output

```
BLOCKED by cloud (BAFS)
HTTP Status:    200
Latency:        457.7 ms
Schema:         Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult

  VERDICT:      MALICIOUS
  Threat:       Virus:DOS/EICAR_Test_File
  Threat ID:    2147519003
  Sig Data:     385 bytes (FASTPATH)

  FASTPATH Signature (VDM TLV):
    [0xEC ENVELOPE] 256B (encrypted detection logic)
    [0xAA FASTPATH_DATA] 20B Compiled=2026-02-19 01:33:37 UTC
    [0x5C THREAT_BEGIN] 47B ThreatID=2147519003 "Virus:DOS/EICAR_Test_File"
    [0x67 STATIC] 38B SHA1=3395856ce81f2b7382dee72602f798b642f14140
    [0x5D THREAT_END] 4B
  Revision:     5
  Sample Rate:  1
```

### Command (Allowed)

```bash
./maps_scanner --no-verify bafs random_data.bin
```

### Text Output

```
ALLOWED by cloud (no threats)
HTTP Status:    200
Latency:        446.1 ms

  VERDICT:      CLEAN (no threats detected)
  Revision:     5
  Sample Rate:  1
```

---

## Heartbeat

Tests MAPS connectivity and reports client configuration.

### Command

```bash
./maps_scanner --no-verify heartbeat
```

### Text Output

```
Sending heartbeat to https://wdcp.microsoft.com...
Type:           STILL_ALIVE (0)
Machine GUID:   39949d42-152b-4929-8aa6-00baf5a88f4d
Engine:         1.1.26010.1
Signatures:     1.445.126.0
Platform:       4.18.26010.5
OS:             10.0.26100 (build 26100)
Customer:       Consumer
Cloud Block:    2
SpyNet Level:   2
HTTP Status:    200
Latency:        387.6 ms
Schema:         Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult

  VERDICT:      CLEAN (no threats detected)
  Revision:     5
  Sample Rate:  1
```

### Enhanced Heartbeat Types

```bash
# Setup heartbeat (type 1)
./maps_scanner --no-verify heartbeat --type 1

# Signature update heartbeat (type 8)
./maps_scanner --no-verify heartbeat --type 8

# All supported types: 0=StillAlive, 1=Setup, 2=Uninstall, 3=Error,
# 4=PolicyChange, 5=Browser, 6=Exclusion, 7=Cleanup, 8=SigUpdate,
# 9=PlatformUpdate, 10=TamperProtect, 11=Reboot
```

### JSON Output

```json
{
  "is_malicious": false,
  "clean": true,
  "sample_requested": false,
  "revision": 5,
  "sample_rate": 1,
  "http_status": 200,
  "latency_ms": 387.6,
  "schema": "Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult"
}
```

---

## Local File Analysis

Compute file metadata without contacting the MAPS cloud.

### Command

```bash
./maps_scanner --no-verify analyze /tmp/eicar_test.com
```

### Output

```
File:           /tmp/eicar_test.com
Size:           68 bytes
SHA-256:        275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
SHA-1:          3395856ce81f2b7382dee72602f798b642f14140
MD5:            44d88612fea8a8f36de82e1278abb02f
CRC32:          6851cf3c
```

---

## Response Size Reference

| Scenario | Response Size | Content |
|----------|--------------|---------|
| Clean/unknown file | 88 bytes | Revision=5, SampleRate=1 |
| Known threat + threat_id + fresh GUID | 488 bytes | 385-byte FASTPATH signature blob |
| Known threat (cached GUID) | 88 bytes | Already delivered to this GUID |
| Heartbeat | 88 bytes | Revision=5, SampleRate=1 |
| URL reputation | 88 bytes | Revision=5, SampleRate=1 (UrlReport as LIST\<STRUCT\>) |
| AMSI script submission | 88 bytes | Revision=5, SampleRate=1 |
| WDO report | 88 bytes | Revision=5, SampleRate=1 |

---

## Windows Defender Offline (WDO) Scan

WDO reports use ReportType 7 for boot-time offline scan results.

### Command

```bash
./maps_scanner --no-verify wdo suspicious.exe --threat-id 2147519003
```

### Text Output

```
  Report Type:  WDO (Windows Defender Offline)
HTTP Status:    200
Latency:        534.7 ms
Schema:         Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult

  VERDICT:      CLEAN (no threats detected)
  Revision:     5
  Sample Rate:  1
```

---

## AMSI Script Submission

Submit script content for cloud analysis via AMSI protocol fields.

### Command

```bash
# Submit a PowerShell script
./maps_scanner --no-verify amsi script.ps1

# Pipe from stdin
echo 'Write-Host "Hello"' | ./maps_scanner --no-verify amsi -

# Specify host application
./maps_scanner --no-verify amsi script.vbs --app-id cscript.exe
```

### Text Output

```
AMSI scan: test_script.ps1
App ID: powershell.exe
Content size: 438 chars
Sending AMSI report to MAPS cloud...

  Report Type:  AMSI (powershell.exe)
HTTP Status:    200
Latency:        451.5 ms
Schema:         Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult

  VERDICT:      CLEAN (no threats detected)
  Revision:     5
  Sample Rate:  1
```

### JSON Output

```json
{
  "is_malicious": false,
  "clean": true,
  "sample_requested": false,
  "revision": 5,
  "sample_rate": 1,
  "http_status": 200,
  "latency_ms": 586.2,
  "schema": "Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult"
}
```

### Notes

- AMSI content is submitted via CoreReport fields (AmsiAppId=1325, AmsiSessionId=1328, etc.)
- Script content is hashed (SHA256/SHA1/MD5) like regular files
- Hash-only analysis; actual STREAM_ATTRIBUTE submission (content detonation) requires
  additional fields not yet implemented
- The cloud may request a sample upload for deeper analysis of novel scripts

---

## Network Connection Report

Submit network connection telemetry using Bond_NetworkConnectionReport V1 schema
(10 fields, RE'd from mpengine.dll schema table at 0x10A065F0).

### Command

```bash
# Report a TCP connection to example.com
./maps_scanner --no-verify netconn 93.184.216.34 443 --protocol TCP

# Report a UDP connection with source IP
./maps_scanner --no-verify netconn 8.8.8.8 53 --protocol UDP --source-ip 192.168.1.100

# Report with URI
./maps_scanner --no-verify netconn 93.184.216.34 443 --uri "https://example.com/path"
```

### Text Output

```
Network connection report: 93.184.216.34:443
Protocol: TCP (6), Source port: 0
Sending network connection report to MAPS cloud...

  Report Type:  NetworkConnectionReport V1 (TCP 93.184.216.34:443)
HTTP Status:    200
Latency:        106.5 ms
Schema:         Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult

  VERDICT:      CLEAN (no threats detected)
  Revision:     5
  Sample Rate:  1
```

### Notes

- V1 schema uses string IPs, UINT16 Protocol (IANA: 6=TCP, 17=UDP, 1=ICMP)
- Scrubbed fields auto-mask last IPv4 octet (e.g., "93.184.216.x")
- V2 schema class (NCRV2, 21 fields) is defined but builder not yet implemented
- V2 uses UINT32 packed IPs, split UINT64 IPv6, Direction, InboundBytes, OutboundBytes

---

## AMSI UAC Info

Submit UAC elevation telemetry using Bond_AmsiUacInfo schema
(30 fields, RE'd from mpengine.dll schema table at 0x10a055f0).

### Command

```bash
# Report a UAC elevation for cmd.exe
./maps_scanner --no-verify uac --exe cmd.exe --uac-type 0

# Report with full details
./maps_scanner --no-verify uac --exe powershell.exe --cmdline "powershell -ep bypass" --uac-type 0 --blocked

# Report COM-type UAC (type 1)
./maps_scanner --no-verify uac --uac-type 1 --identifier "{some-clsid}"
```

### Text Output

```
UAC info report: type=Exe
  Executable: cmd.exe
  AutoElevate=False, Blocked=False
Sending UAC info report to MAPS cloud...

  Report Type:  AmsiUacInfo (Exe)
HTTP Status:    200
Latency:        424.3 ms
Schema:         Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult

  VERDICT:      CLEAN (no threats detected)
  Revision:     5
  Sample Rate:  1
```

### Notes

- Type discriminant: 0=Exe, 1=COM, 2=MSI, 3=ActiveX, 4=PackagedApp
- Type field controls which sub-fields are populated (e.g., COM fields only for type=1)
- 30-field schema includes requestor info, exe info, COM server, MSI action, ActiveX URL, PackagedApp details
- SHA1 fields (RequestorSha1, ExeAppSha1) use STRING type for binary blob data

---

## URL Reputation (Fixed)

URL reputation queries now return HTTP 200 after fixing the UrlReport encoding.

### Command

```bash
./maps_scanner --no-verify url https://example.com
```

### JSON Output

```json
{
  "is_malicious": false,
  "clean": true,
  "sample_requested": false,
  "revision": 5,
  "sample_rate": 1,
  "http_status": 200,
  "latency_ms": 153.5,
  "schema": "Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult"
}
```

### Notes

- **Key fix**: UrlReport (ordinal 1542) must be encoded as `LIST<STRUCT>`, not `BT_STRUCT`
- UrlElement fields use ordinals 10/20/21 (not 3/6/9 pattern): Order=10, Url=20, Url_Scrubbed=21
- The server returns 88-byte clean response for known safe URLs
- URL determination (malicious/safe/unknown) would appear in UrlResponse.UrlResults

---

## Enterprise Mode

Enterprise mode adds Bearer token authentication for organizational MAPS access.

### Command

```bash
./maps_scanner --no-verify \
    --bearer-token "eyJ..." \
    --customer-type Enterprise \
    scan suspicious.exe
```

### Notes

- Enterprise mode uses AAD client ID `cab96880-db5b-4e15-90a7-f3f1d62ffe39`
- The `--bearer-token` flag automatically sets `--customer-type Enterprise`
- Tokens must be obtained from Azure AD (Microsoft Entra ID) separately

---

## Test File Generation

Generate test files for exercising different scan scenarios.

### Command

```bash
python tests/create_test_files.py
```

### Output

```
Creating test files in tools/maps_scanner/tests/samples/

[+] EICAR (known malware):
  eicar_test.com: 68B sha256=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

[+] Minimal PE (triggers PE analysis):
  minimal_test.exe: 1024B sha256=<varies>

[+] Random binary (clean/unknown):
  random_data.bin: 4096B sha256=<varies per run>

[+] PowerShell script (AMSI patterns):
  test_script.ps1: <size>B sha256=<varies>

[+] Unique PE (never-seen, may trigger sample request):
  unique_test.exe: 1024B sha256=<unique per run>

[+] PE with version info (certificate/metadata):
  versioned_test.exe: 1536B sha256=<varies>

[+] DLL (different PE characteristics):
  test_library.dll: 1024B sha256=<varies>

[+] Batch script (non-PE suspicious):
  test_batch.cmd: 281B sha256=<varies>

[+] Large unique PE (more likely to trigger sample upload):
  large_unique_test.exe: 33280B sha256=<unique per run>

Created 9 test files in tools/maps_scanner/tests/samples/
```

### File Descriptions

| File | Type | Purpose | Expected MAPS Result |
|------|------|---------|---------------------|
| `eicar_test.com` | EICAR | Standard AV test file | MALICIOUS (with threat_id) |
| `minimal_test.exe` | PE32 | Minimal valid executable | CLEAN |
| `random_data.bin` | Binary | 4096 random bytes | CLEAN |
| `test_script.ps1` | PowerShell | AMSI-triggerable patterns | CLEAN (hash-only scan) |
| `unique_test.exe` | PE32 | UUID-embedded, unique hash | CLEAN (may trigger sample request) |
| `versioned_test.exe` | PE32 | PE with .rsrc section | CLEAN |
| `test_library.dll` | DLL | Minimal DLL (IMAGE_FILE_DLL flag) | CLEAN |
| `test_batch.cmd` | Batch | Non-PE suspicious patterns | CLEAN |
| `large_unique_test.exe` | PE32 | Large PE, high entropy code | CLEAN (may trigger sample upload) |
| `test_script.vbs` | VBScript | AMSI test with cscript.exe app-id | CLEAN (hash-only) |
| `test_script.js` | JavaScript | AMSI test with wscript.exe app-id | CLEAN (hash-only) |
| `pe_with_imports.exe` | PE32 | PE importing kernel32!ExitProcess | CLEAN (deeper analysis) |
| `test_x64.exe` | PE32+ | x64 PE executable | CLEAN |
| `dotnet_test.exe` | PE32/.NET | .NET assembly with CLR header | CLEAN |
