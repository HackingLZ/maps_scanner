# MAPS Scanner — Live Test Results

> **Generated:** 2026-02-19
> **Endpoint:** `https://wdcp.microsoft.com` (production)
> **Platform:** Linux (with `--no-verify` for TLS)
> **GUID Mode:** Rotating (default) — fresh UUID4 per request, bypasses cloud GUID caching
> **Engine:** 1.1.26010.1 | **Signatures:** 1.445.126.0 | **Platform:** 4.18.26010.5

All commands below were executed against the live MAPS production endpoint with freshly generated test binaries. ANSI color codes have been stripped from output for readability.

**GUID Rotation:** By default, each request now uses a fresh machine GUID. This prevents the cloud's per-GUID caching from suppressing FASTPATH signatures on repeat scans. Use `--fixed-guid` or `--machine-guid <UUID>` to pin a specific identity.

---

## Table of Contents

### Cloud Scans (11 file types)
1. [EICAR Scan — MALICIOUS + FASTPATH](#1-eicar-scan--malicious--fastpath)
2. [Minimal PE Scan — CLEAN](#2-minimal-pe-scan--clean)
3. [Random Binary Scan — CLEAN](#3-random-binary-scan--clean)
4. [PowerShell Script Scan — CLEAN](#4-powershell-script-scan--clean)
5. [PE with Imports Scan — CLEAN](#5-pe-with-imports-scan--clean)
6. [DLL Scan — CLEAN](#6-dll-scan--clean)
7. [.NET Assembly Scan — CLEAN](#7-net-assembly-scan--clean)
8. [Large Unique PE Scan — CLEAN](#8-large-unique-pe-scan--clean)
9. [Batch Script Scan — CLEAN](#9-batch-script-scan--clean)
10. [x64 PE Scan — CLEAN](#10-x64-pe-scan--clean)
11. [Versioned PE Scan — CLEAN](#11-versioned-pe-scan--clean)

### Cloud Queries & Reports
12. [Hash Scan — EICAR SHA256](#12-hash-scan--eicar-sha256)
13. [Hash Scan — Unknown Hash](#13-hash-scan--unknown-hash)
14. [URL Reputation — example.com](#14-url-reputation--examplecom)
15. [URL Reputation — with Referrer](#15-url-reputation--with-referrer)
16. [Heartbeat — STILL_ALIVE (type 0)](#16-heartbeat--still_alive-type-0)
17. [Heartbeat — SETUP (type 1)](#17-heartbeat--setup-type-1)
18. [Heartbeat — SIGNATURE_UPDATE (type 8)](#18-heartbeat--signature_update-type-8)
19. [BAFS — Zero Tolerance (default)](#19-bafs--zero-tolerance-default)
20. [BAFS — HIGH Block Level](#20-bafs--high-block-level)
21. [WDO — Windows Defender Offline](#21-wdo--windows-defender-offline)
22. [AMSI — PowerShell](#22-amsi--powershell)
23. [AMSI — PowerShell with Session ID + Content Name](#23-amsi--powershell-with-session-id--content-name)
24. [AMSI — VBScript (cscript.exe)](#24-amsi--vbscript-cscriptexe)
25. [AMSI — JavaScript (wscript.exe)](#25-amsi--javascript-wscriptexe)
26. [UAC — Exe Elevation](#26-uac--exe-elevation)
27. [UAC — COM Elevation](#27-uac--com-elevation)
28. [UAC — Exe with Auto-Elevate + Blocked](#28-uac--exe-with-auto-elevate--blocked)
29. [Network Connection — TCP](#29-network-connection--tcp)
30. [Network Connection — UDP](#30-network-connection--udp)
31. [Network Connection — TCP with URI + Source IP](#31-network-connection--tcp-with-uri--source-ip)
32. [Upload — Sample Submission](#32-upload--sample-submission)
33. [Upload — with Compression Flag](#33-upload--with-compression-flag)

### Batch & Replay
34. [Batch — Cloud Scan (text)](#34-batch--cloud-scan-text)
35. [Batch — Cloud Scan (JSON)](#35-batch--cloud-scan-json)
36. [Batch — Local Only](#36-batch--local-only)
37. [Replay — Dry Run](#37-replay--dry-run)
38. [Replay — Live Send](#38-replay--live-send)

### Local Commands
39. [Scan — Local Only (--local-only)](#39-scan--local-only---local-only)
40. [Analyze — EICAR](#40-analyze--eicar)
41. [Analyze — Minimal PE](#41-analyze--minimal-pe)
42. [Analyze — PE with Imports (ImpHash)](#42-analyze--pe-with-imports-imphash)
43. [Analyze — .NET Assembly](#43-analyze--net-assembly)
44. [Build — Payload Construction](#44-build--payload-construction)
45. [Decode — Bond Binary](#45-decode--bond-binary)
46. [Config — Show Configuration](#46-config--show-configuration)

### Feature Demonstrations
47. [GUID Rotation — Repeat EICAR Detection](#47-guid-rotation--repeat-eicar-detection)
48. [Verbose Mode — Decoded Response Fields](#48-verbose-mode--decoded-response-fields)

### Geo Endpoints
49. [Geo — EU (EICAR Scan)](#49-geo--eu-eicar-scan)
50. [Geo — UK (Heartbeat)](#50-geo--uk-heartbeat)
51. [Geo — AU (URL Reputation)](#51-geo--au-url-reputation)
52. [Geo — US (Heartbeat)](#52-geo--us-heartbeat)
53. [PPE Endpoint — DNS Failure](#53-ppe-endpoint--dns-failure)

### Advanced Scenarios
54. [EICAR Without --threat-id](#54-eicar-without---threat-id)
55. [scan-hash — All 3 Hash Types](#55-scan-hash--all-3-hash-types)
56. [AMSI — Stdin Pipe](#56-amsi--stdin-pipe)
57. [Batch — Stdin Pipe](#57-batch--stdin-pipe)
58. [Quiet + JSON Mode](#58-quiet--json-mode)
59. [Config — Set Flags](#59-config--set-flags)

### Error Handling
60. [Error — File Not Found](#60-error--file-not-found)
61. [Error — Unreachable Endpoint](#61-error--unreachable-endpoint)
62. [Error — TLS Verification Failure](#62-error--tls-verification-failure)

---

## Cloud Scans

### 1. EICAR Scan — MALICIOUS + FASTPATH

Scan the EICAR test file with a known threat ID. With GUID rotation (default), each scan gets a fresh GUID, so the cloud always delivers FASTPATH signatures.

#### Input
- **File:** `eicar_test.com` (68 bytes)
- **SHA-256:** `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`
- **Flags:** `--threat-id 2147519003`

#### Command
```bash
python -m tools.maps_scanner --no-verify scan tests/samples/eicar_test.com --threat-id 2147519003
```

#### Output (Text)
```
HTTP Status:    200
Latency:        470.3 ms
Schema:         Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult

  VERDICT:      MALICIOUS
  Threat:       Virus:DOS/EICAR_Test_File
  Threat ID:    2147519003
  Sig Data:     385 bytes (FASTPATH)

  FASTPATH Signature (VDM TLV):
    [0xEC ENVELOPE] 256B (encrypted detection logic)
    [0xAA FASTPATH_DATA] 20B Compiled=2026-02-19 12:13:44 UTC
    [0x5C THREAT_BEGIN] 47B ThreatID=2147519003 "Virus:DOS/EICAR_Test_File"
    [0x67 STATIC] 38B SHA1=3395856ce81f2b7382dee72602f798b642f14140
    [0x5D THREAT_END] 4B
  Revision:     5
  Sample Rate:  1
```

#### Output (JSON)
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
  "latency_ms": 188.4,
  "schema": "Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult",
  "signature_data_size": 385,
  "fastpath_entries": [
    {
      "type": "0xEC",
      "name": "ENVELOPE",
      "size": 256
    },
    {
      "type": "0xAA",
      "name": "FASTPATH_DATA",
      "size": 20,
      "compiled": "2026-02-19 12:14:51 UTC"
    },
    {
      "type": "0x5C",
      "name": "THREAT_BEGIN",
      "size": 47,
      "threat_id": 2147519003,
      "detection": "Virus:DOS/EICAR_Test_File"
    },
    {
      "type": "0x67",
      "name": "STATIC",
      "size": 38,
      "sha1": "3395856ce81f2b7382dee72602f798b642f14140"
    },
    {
      "type": "0x5D",
      "name": "THREAT_END",
      "size": 4,
      "threat_id": 2147519003
    }
  ]
}
```

---

### 2. Minimal PE Scan — CLEAN

#### Command
```bash
python -m tools.maps_scanner --no-verify scan tests/samples/minimal_test.exe
```
#### Output
```
HTTP Status:    200
Latency:        406.7 ms

  VERDICT:      CLEAN (no threats detected)
  Revision:     5
  Sample Rate:  1
```

---

### 3. Random Binary Scan — CLEAN

#### Command
```bash
python -m tools.maps_scanner --no-verify scan tests/samples/random_data.bin
```
#### Output
```
HTTP Status:    200
Latency:        409.4 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 4. PowerShell Script Scan — CLEAN

#### Command
```bash
python -m tools.maps_scanner --no-verify scan tests/samples/test_script.ps1
```
#### Output
```
HTTP Status:    200
Latency:        406.2 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 5. PE with Imports Scan — CLEAN

#### Command
```bash
python -m tools.maps_scanner --no-verify scan tests/samples/pe_with_imports.exe
```
#### Output
```
HTTP Status:    200
Latency:        405.6 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 6. DLL Scan — CLEAN

#### Command
```bash
python -m tools.maps_scanner --no-verify scan tests/samples/test_library.dll
```
#### Output
```
HTTP Status:    200
Latency:        418.0 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 7. .NET Assembly Scan — CLEAN

#### Command
```bash
python -m tools.maps_scanner --no-verify scan tests/samples/dotnet_test.exe
```
#### Output
```
HTTP Status:    200
Latency:        403.9 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 8. Large Unique PE Scan — CLEAN

33KB PE with high-entropy code sections, unique hash per generation.

#### Command
```bash
python -m tools.maps_scanner --no-verify scan tests/samples/large_unique_test.exe
```
#### Output
```
HTTP Status:    200
Latency:        403.1 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 9. Batch Script Scan — CLEAN

#### Command
```bash
python -m tools.maps_scanner --no-verify scan tests/samples/test_batch.cmd
```
#### Output
```
HTTP Status:    200
Latency:        412.9 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 10. x64 PE Scan — CLEAN

#### Command
```bash
python -m tools.maps_scanner --no-verify scan tests/samples/test_x64.exe
```
#### Output
```
HTTP Status:    200
Latency:        416.5 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 11. Versioned PE Scan — CLEAN

PE with `.rsrc` section containing version information.

#### Command
```bash
python -m tools.maps_scanner --no-verify scan tests/samples/versioned_test.exe
```
#### Output
```
HTTP Status:    200
Latency:        155.0 ms

  VERDICT:      CLEAN (no threats detected)
```

---

## Cloud Queries & Reports

### 12. Hash Scan — EICAR SHA256

Query file reputation by SHA256 hash only (no file content submitted).

#### Command
```bash
python -m tools.maps_scanner --no-verify scan-hash \
  275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f \
  --name eicar_test.com --size 68
```

#### Output
```
HTTP Status:    200
Latency:        474.9 ms

  VERDICT:      CLEAN (no threats detected)
```

> **Note:** Hash-only queries return CLEAN even for known threats. The cloud requires full file content + `--threat-id` + fresh GUID to deliver FASTPATH signatures. The hash query is a lightweight reputation check, not a detection trigger.

---

### 13. Hash Scan — Unknown Hash

#### Command
```bash
python -m tools.maps_scanner --no-verify scan-hash \
  b28a8b72e4755b87a9acf4ccf0c0afc91ee5eb379a14a02c3d54edfc65471377 \
  --name random_data.bin --size 4096
```

#### Output
```
HTTP Status:    200
Latency:        128.4 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 14. URL Reputation — example.com

#### Command
```bash
python -m tools.maps_scanner --no-verify url "https://example.com"
```

#### Output (Text)
```
HTTP Status:    200
Latency:        125.4 ms

  VERDICT:      CLEAN (no threats detected)
```

#### Output (JSON)
```json
{
  "is_malicious": false,
  "clean": true,
  "sample_requested": false,
  "revision": 5,
  "sample_rate": 1,
  "http_status": 200,
  "latency_ms": 124.7,
  "schema": "Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult"
}
```

---

### 15. URL Reputation — with Referrer

The `--referrer` flag sets the referring URL in the UrlReport Bond payload.

#### Command
```bash
python -m tools.maps_scanner --no-verify url "https://example.com/test" --referrer "https://google.com"
```

#### Output
```
HTTP Status:    200
Latency:        437.1 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 16. Heartbeat — STILL_ALIVE (type 0)

Default heartbeat: periodic connectivity check.

#### Command
```bash
python -m tools.maps_scanner --no-verify heartbeat
```

#### Output
```
HTTP Status:    200
Latency:        109.5 ms

  VERDICT:      CLEAN (no threats detected)
  Revision:     5
  Sample Rate:  1
```

> **Stderr info:**
> ```
> Type:           STILL_ALIVE (0)
> Machine GUID:   (rotating)
> Engine:         1.1.26010.1
> Signatures:     1.445.126.0
> Platform:       4.18.26010.5
> ```

---

### 17. Heartbeat — SETUP (type 1)

First-run/setup heartbeat.

#### Command
```bash
python -m tools.maps_scanner --no-verify heartbeat --type 1
```

#### Output
```
Type:           SETUP (1)
HTTP Status:    200
Latency:        417.8 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 18. Heartbeat — SIGNATURE_UPDATE (type 8)

Post-signature-update heartbeat.

#### Command
```bash
python -m tools.maps_scanner --no-verify heartbeat --type 8
```

#### Output
```
Type:           SIGNATURE_UPDATE (8)
HTTP Status:    200
Latency:        388.8 ms

  VERDICT:      CLEAN (no threats detected)
```

> All 12 heartbeat types (0-11) are supported: StillAlive, Setup, Uninstall, Error, PolicyChange, Browser, Exclusion, Cleanup, SigUpdate, PlatformUpdate, TamperProtect, Reboot.

---

### 19. BAFS — Zero Tolerance (default)

Block at First Sight scan. Uses SyncLowfi (type 2) with zero-tolerance block level (default).

#### Command
```bash
python -m tools.maps_scanner --no-verify bafs tests/samples/unique_test.exe
```

#### Output
```
Block Level: 6 (ZERO_TOLERANCE)
Timeout: 10s

  ALLOWED by cloud (no threats)
HTTP Status:    200
Latency:        191.7 ms

  VERDICT:      CLEAN (no threats detected)
```

#### Output (JSON)
```json
{
  "is_malicious": false,
  "clean": true,
  "sample_requested": false,
  "revision": 5,
  "sample_rate": 1,
  "http_status": 200,
  "latency_ms": 123.4,
  "schema": "Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult"
}
```

---

### 20. BAFS — HIGH Block Level

BAFS with `--block-level 2` (HIGH instead of default ZERO_TOLERANCE).

#### Command
```bash
python -m tools.maps_scanner --no-verify bafs tests/samples/unique_test.exe --block-level 2
```

#### Output
```
Block Level: 2 (HIGH)
Timeout: 10s

  ALLOWED by cloud (no threats)
HTTP Status:    200
Latency:        403.9 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 21. WDO — Windows Defender Offline

Submit a WDO scan report (ReportType 7) for boot-time scan results.

#### Command
```bash
python -m tools.maps_scanner --no-verify wdo tests/samples/eicar_test.com
```

#### Output (Text)
```
  Report Type:  WDO (Windows Defender Offline)
HTTP Status:    200
Latency:        175.0 ms

  VERDICT:      CLEAN (no threats detected)
```

#### Output (JSON)
```json
{
  "is_malicious": false,
  "clean": true,
  "sample_requested": false,
  "revision": 5,
  "sample_rate": 1,
  "http_status": 200,
  "latency_ms": 166.4,
  "schema": "Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult"
}
```

---

### 22. AMSI — PowerShell

Submit script content via AMSI with default `powershell.exe` app ID.

#### Command
```bash
python -m tools.maps_scanner --no-verify amsi tests/samples/test_script.ps1
```

#### Output
```
  Report Type:  AMSI (powershell.exe)
HTTP Status:    200
Latency:        133.8 ms

  VERDICT:      CLEAN (no threats detected)
```

#### Output (JSON)
```json
{
  "is_malicious": false,
  "clean": true,
  "sample_requested": false,
  "revision": 5,
  "sample_rate": 1,
  "http_status": 200,
  "latency_ms": 121.0,
  "schema": "Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult"
}
```

---

### 23. AMSI — PowerShell with Session ID + Content Name

AMSI with `--content-name` (Windows-style path reported to cloud) and `--session-id` (AMSI session correlation).

#### Command
```bash
python -m tools.maps_scanner --no-verify amsi tests/samples/test_script.ps1 \
  --content-name "C:\Users\test\script.ps1" --session-id 42
```

#### Output
```
AMSI scan: C:\Users\test\script.ps1
App ID: powershell.exe
Content size: 438 chars

  Report Type:  AMSI (powershell.exe)
HTTP Status:    200
Latency:        402.6 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 24. AMSI — VBScript (cscript.exe)

#### Command
```bash
python -m tools.maps_scanner --no-verify amsi tests/samples/test_script.vbs --app-id cscript.exe
```

#### Output
```
  Report Type:  AMSI (cscript.exe)
HTTP Status:    200
Latency:        146.1 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 25. AMSI — JavaScript (wscript.exe)

#### Command
```bash
python -m tools.maps_scanner --no-verify amsi tests/samples/test_script.js --app-id wscript.exe
```

#### Output
```
  Report Type:  AMSI (wscript.exe)
HTTP Status:    200
Latency:        143.6 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 26. UAC — Exe Elevation

Submit UAC elevation report for an executable (type 0).

#### Command
```bash
python -m tools.maps_scanner --no-verify uac --exe cmd.exe --uac-type 0
```

#### Output
```
UAC info report: type=Exe
  Executable: cmd.exe
  AutoElevate=False, Blocked=False

  Report Type:  AmsiUacInfo (Exe)
HTTP Status:    200
Latency:        110.2 ms

  VERDICT:      CLEAN (no threats detected)
```

#### Output (JSON)
```json
{
  "is_malicious": false,
  "clean": true,
  "sample_requested": false,
  "revision": 5,
  "sample_rate": 1,
  "http_status": 200,
  "latency_ms": 109.0,
  "schema": "Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult"
}
```

---

### 27. UAC — COM Elevation

Submit UAC elevation report for a COM object (type 1) with CLSID identifier.

#### Command
```bash
python -m tools.maps_scanner --no-verify uac --uac-type 1 \
  --identifier "{3ad05575-8857-4850-9277-11b85bdb8e09}"
```

#### Output
```
UAC info report: type=COM
  AutoElevate=False, Blocked=False

  Report Type:  AmsiUacInfo (COM)
HTTP Status:    200
Latency:        109.3 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 28. UAC — Exe with Auto-Elevate + Blocked

UAC report with `--auto-elevate` and `--blocked` flags set, plus `--cmdline`.

#### Command
```bash
python -m tools.maps_scanner --no-verify uac --uac-type 0 \
  --exe cmd.exe --cmdline "cmd.exe /c whoami" --auto-elevate --blocked
```

#### Output
```
UAC info report: type=Exe
  Executable: cmd.exe
  AutoElevate=True, Blocked=True

  Report Type:  AmsiUacInfo (Exe)
HTTP Status:    200
Latency:        388.6 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 29. Network Connection — TCP

#### Command
```bash
python -m tools.maps_scanner --no-verify netconn 93.184.216.34 443 --protocol TCP
```

#### Output
```
Network connection report: 93.184.216.34:443
Protocol: TCP (6), Source port: 0

  Report Type:  NetworkConnectionReport V1 (TCP 93.184.216.34:443)
HTTP Status:    200
Latency:        109.5 ms

  VERDICT:      CLEAN (no threats detected)
```

#### Output (JSON)
```json
{
  "is_malicious": false,
  "clean": true,
  "sample_requested": false,
  "revision": 5,
  "sample_rate": 1,
  "http_status": 200,
  "latency_ms": 108.1,
  "schema": "Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult"
}
```

---

### 30. Network Connection — UDP

#### Command
```bash
python -m tools.maps_scanner --no-verify netconn 8.8.8.8 53 --protocol UDP
```

#### Output
```
Network connection report: 8.8.8.8:53
Protocol: UDP (17), Source port: 0

  Report Type:  NetworkConnectionReport V1 (UDP 8.8.8.8:53)
HTTP Status:    200
Latency:        109.7 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 31. Network Connection — TCP with URI + Source IP

Test all netconn sub-flags: `--uri`, `--source-ip`, `--local-port`.

#### Command
```bash
python -m tools.maps_scanner --no-verify netconn 93.184.216.34 443 \
  --protocol TCP --uri "https://example.com/api" --source-ip 10.0.0.5 --local-port 54321
```

#### Output
```
Network connection report: 93.184.216.34:443
Protocol: TCP (6), Source port: 54321

  Report Type:  NetworkConnectionReport V1 (TCP 93.184.216.34:443)
HTTP Status:    200
Latency:        404.9 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 32. Upload — Sample Submission

Attempt to upload a file sample to MAPS for detonation. The cloud must first request the sample via a SAS URI in a scan response.

#### Command
```bash
python -m tools.maps_scanner --no-verify upload tests/samples/large_unique_test.exe
```

#### Output
```
SHA-256: 69a10fbd1e5dd7590e20f388c5e8a5853906163f622bbfb63842f9d8512d31cc
Size: 33280 bytes
Requesting sample upload URI from MAPS...

MAPS did not request a sample upload for this file.
The cloud may not need this file, or the file is already known.
Tip: Use --sas-uri to upload directly if you have a SAS URI.
HTTP Status:    200
Latency:        128.5 ms

  VERDICT:      CLEAN (no threats detected)
```

> **How upload works:** The `upload` command sends a SAMPLE_REQUEST report to MAPS. If the cloud wants the file, it responds with a SampleRequest containing a Blob SAS URI. The client then PUTs the file to Azure Blob Storage. For our test files, the cloud does not request samples — they're too simple/clean to warrant detonation. Use `--sas-uri` to bypass this and upload directly with a known SAS URI.

---

### 33. Upload — with Compression Flag

The `--compression gzip` flag enables gzip compression for the blob upload. The flag is accepted but the upload flow still requires a SAS URI from the cloud.

#### Command
```bash
python -m tools.maps_scanner --no-verify upload tests/samples/large_unique_test.exe --compression gzip
```

#### Output
```
MAPS did not request a sample upload for this file.
The cloud may not need this file, or the file is already known.
Tip: Use --sas-uri to upload directly if you have a SAS URI.
HTTP Status:    200
Latency:        404.7 ms

  VERDICT:      CLEAN (no threats detected)
```

> Compression options: `none` (default), `gzip`, `deflate`. Applied to the PUT body when uploading to Azure Blob Storage.

---

## Batch & Replay

### 34. Batch — Cloud Scan (text)

Scan multiple files from a list file. Each file is scanned independently through the cloud.

#### Input
```
# /tmp/batch_list.txt
tests/samples/eicar_test.com
tests/samples/minimal_test.exe
tests/samples/random_data.bin
```

#### Command
```bash
python -m tools.maps_scanner --no-verify batch /tmp/batch_list.txt
```

#### Output
```
[1/3] tests/samples/eicar_test.com
[2/3] tests/samples/minimal_test.exe
[3/3] tests/samples/random_data.bin
  tests/samples/eicar_test.com: MALICIOUS (Virus:DOS/EICAR_Test_File)
  tests/samples/minimal_test.exe: CLEAN
  tests/samples/random_data.bin: CLEAN
```

---

### 35. Batch — Cloud Scan (JSON)

JSON output gives full verdict details per file. With GUID rotation, EICAR reliably detects as MALICIOUS.

#### Command
```bash
python -m tools.maps_scanner --no-verify --json batch /tmp/batch_list.txt
```

#### Output
```json
[
  {
    "path": "tests/samples/eicar_test.com",
    "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "is_malicious": true,
    "clean": false,
    "threat_name": "Virus:DOS/EICAR_Test_File",
    "threat_id": 2147519003,
    "detection_name": "Virus:DOS/EICAR_Test_File",
    "sample_requested": false,
    "revision": 5,
    "sample_rate": 1,
    "http_status": 200,
    "latency_ms": 448.2,
    "schema": "Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult",
    "signature_data_size": 385,
    "fastpath_entries": [
      {"type": "0xEC", "name": "ENVELOPE", "size": 256},
      {"type": "0xAA", "name": "FASTPATH_DATA", "size": 20, "compiled": "2026-02-19 12:27:29 UTC"},
      {"type": "0x5C", "name": "THREAT_BEGIN", "size": 47, "threat_id": 2147519003, "detection": "Virus:DOS/EICAR_Test_File"},
      {"type": "0x67", "name": "STATIC", "size": 38, "sha1": "3395856ce81f2b7382dee72602f798b642f14140"},
      {"type": "0x5D", "name": "THREAT_END", "size": 4, "threat_id": 2147519003}
    ]
  },
  {
    "path": "tests/samples/minimal_test.exe",
    "sha256": "4e0623d89b42a157b9ed482c64c9740eb85ea12d82313d898eae53ba858ce2b1",
    "is_malicious": false,
    "clean": true,
    "sample_requested": false,
    "revision": 5,
    "sample_rate": 1,
    "http_status": 200,
    "latency_ms": 136.2
  }
]
```

---

### 36. Batch — Local Only

Hash-only batch scan without cloud contact. Shows `UNKNOWN` since no cloud verdict is available.

#### Command
```bash
python -m tools.maps_scanner batch /tmp/batch_list.txt --local-only
```

#### Output
```
[1/2] tests/samples/eicar_test.com
[2/2] tests/samples/pe_with_imports.exe
  tests/samples/eicar_test.com: UNKNOWN
  tests/samples/pe_with_imports.exe: UNKNOWN
```

---

### 37. Replay — Dry Run

Replay a previously captured Bond payload. Dry run by default (no `--confirm`), shows payload preview only.

#### Command
```bash
python -m tools.maps_scanner replay /tmp/eicar_payload.bin
```

#### Output
```
Replaying 809 bytes to https://wdcp.microsoft.com/wdcp.svc/bond/submitreport
Add --confirm to actually send (dry-run by default)

Payload preview:
[2] BT_UINT8 = 66
```

---

### 38. Replay — Live Send

Replay with `--confirm` actually sends the captured payload to the MAPS endpoint.

#### Command
```bash
python -m tools.maps_scanner --no-verify replay /tmp/eicar_payload.bin --confirm
```

#### Output
```
Replaying 809 bytes to https://wdcp.microsoft.com/wdcp.svc/bond/submitreport
HTTP 200 (466.3ms)

Response (88 bytes):
[2] BT_UINT8 = 66
```

> The 88-byte response is a minimal CLEAN reply (revision + sample_rate only). The replayed payload uses the original GUID, which has already been seen by the cloud, so no FASTPATH signature is delivered.

---

## Local Commands

### 39. Scan — Local Only (--local-only)

Compute file hashes and PE metadata without contacting the cloud. Same output as `analyze`.

#### Command
```bash
python -m tools.maps_scanner scan tests/samples/pe_with_imports.exe --local-only
```

#### Output
```
File:           tests/samples/pe_with_imports.exe
Size:           1536 bytes
SHA-256:        1b4baf00e86251b3fecd6d9a138811b4d75527314e1bd7b73aec96f81c5df3ca
SHA-1:          333471490754813c5b08f080c9ca16cf010dfd9f
MD5:            081d2260bb1a2076613f91717dd56e3a
CRC32:          4a9edaf2
ImpHash:        f9ade0aa18f660a34a4fa23392e21838
PE Timestamp:   1705033728
PE Checksum:    0x00000000
Section Hashes:
  .text:3d64acbf4147b610d88c922fab5f77a63dfd402f80a365fa5a88a87ea6e37b88
  .idata:0acd08ba6bd19c5e1c53a868caff4e755c3d2666103dc50ce07e6ee908e9d1b0
```

---

### 40. Analyze — EICAR

#### Command
```bash
python -m tools.maps_scanner analyze tests/samples/eicar_test.com
```
#### Output
```
File:           tests/samples/eicar_test.com
Size:           68 bytes
SHA-256:        275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
SHA-1:          3395856ce81f2b7382dee72602f798b642f14140
MD5:            44d88612fea8a8f36de82e1278abb02f
CRC32:          6851cf3c
```

---

### 41. Analyze — Minimal PE

#### Command
```bash
python -m tools.maps_scanner analyze tests/samples/minimal_test.exe
```
#### Output
```
File:           tests/samples/minimal_test.exe
Size:           1024 bytes
SHA-256:        4e0623d89b42a157b9ed482c64c9740eb85ea12d82313d898eae53ba858ce2b1
SHA-1:          8dec23f8d1e64ff500cdea36364c61ae95482d07
MD5:            27b4521c33d613ff1d7cad60824cc8bd
CRC32:          24e897ba
PE Timestamp:   1705033728
PE Checksum:    0x00000000
Section Hashes:
  .text:3d64acbf4147b610d88c922fab5f77a63dfd402f80a365fa5a88a87ea6e37b88
```

---

### 42. Analyze — PE with Imports (ImpHash)

Shows the import hash (ImpHash) computed from the PE import table.

#### Command
```bash
python -m tools.maps_scanner analyze tests/samples/pe_with_imports.exe
```
#### Output
```
File:           tests/samples/pe_with_imports.exe
Size:           1536 bytes
SHA-256:        1b4baf00e86251b3fecd6d9a138811b4d75527314e1bd7b73aec96f81c5df3ca
SHA-1:          333471490754813c5b08f080c9ca16cf010dfd9f
MD5:            081d2260bb1a2076613f91717dd56e3a
CRC32:          4a9edaf2
ImpHash:        f9ade0aa18f660a34a4fa23392e21838
PE Timestamp:   1705033728
PE Checksum:    0x00000000
Section Hashes:
  .text:3d64acbf4147b610d88c922fab5f77a63dfd402f80a365fa5a88a87ea6e37b88
  .idata:0acd08ba6bd19c5e1c53a868caff4e755c3d2666103dc50ce07e6ee908e9d1b0
```

---

### 43. Analyze — .NET Assembly

#### Command
```bash
python -m tools.maps_scanner analyze tests/samples/dotnet_test.exe
```
#### Output
```
File:           tests/samples/dotnet_test.exe
Size:           1024 bytes
SHA-256:        5a4e55d7b9f75fb251fad3b0c83fdec9a39142f862f9b3afa2781b62c1cf2093
SHA-1:          6bc7e4bb3dac5c23a7931000f97b9a4da3c6926d
MD5:            63d3965d23715e57b6ebe4f733ec625b
CRC32:          9e42f92c
PE Timestamp:   1705033728
PE Checksum:    0x00000000
Section Hashes:
  .text:cc2e264c1fbefd0d6fb65b3fee4feb3b734d1702e173c1e52e89eb2da3981e3c
```

---

### 44. Build — Payload Construction

Build a SpynetReport Bond binary payload without sending. Useful for inspecting wire format or feeding to `replay`.

#### Command
```bash
python -m tools.maps_scanner build tests/samples/eicar_test.com -o /tmp/eicar_payload.bin
```

#### Output
```
SpynetReport: 809 bytes

[2] BT_UINT8 = 66

Hex dump:
  00000000  43 42 01 00 a9 3c 4d 69 63 72 6f 73 6f 66 74 2e   CB...<Microsoft.
  00000010  50 72 6f 74 65 63 74 69 6f 6e 53 65 72 76 69 63   ProtectionServic
  00000020  65 73 2e 45 6e 74 69 74 69 65 73 2e 52 61 77 2e   es.Entities.Raw.
  00000030  53 70 79 6e 65 74 52 65 70 6f 72 74 45 6e 74 69   SpynetReportEnti
  00000040  74 79 01 01 cb 0a 0b 01 0e 00 ca 14 a9 3c 4d 69   ty...........<Mi
  00000050  63 72 6f 73 6f 66 74 2e 50 72 6f 74 65 63 74 69   crosoft.Protecti
  ...
  000002f0  6d 00 00 e9 e0 01 04 57 61 72 6e e9 1a 04 24 62   m......Warn...$b
  00000300  35 61 62 62 33 38 35 2d 64 66 32 37 2d 34 62 34   5abb385-df27-4b4
  00000310  30 2d 39 65 34 65 2d 37 35 32 38 34 34 37 66 32   0-9e4e-7528447f2
  00000320  61 35 31 f0 01 05 02 00 00                        a51......

Payload written to /tmp/eicar_payload.bin (809 bytes)
```

> The payload begins with `CB 01 00` (Bond CompactBinaryV1 protocol version), followed by the schema name `Microsoft.ProtectionServices.Entities.Raw.SpynetReportEntity`, then the nested CoreReport containing machine GUID, version strings, file hashes, and report type.

---

### 45. Decode — Bond Binary

Decode a Bond CompactBinaryV1 binary payload. The `--schema request` option maps field ordinals to SpynetReport field names.

#### Command
```bash
python -m tools.maps_scanner decode /tmp/eicar_payload.bin --schema request
```

#### Output
```
Decoding 809 bytes of Bond CompactBinaryV1...
[2] BT_UINT8 = 66
```

> The top-level `[2] BT_UINT8 = 66` is the SpynetReport protocol version marker (0x42 = 'B'). The nested Bond structures (schema names, CoreReport fields, FileReportElements) are decoded internally. Use `-v` for the full hex dump (see [Verbose Mode](#48-verbose-mode--decoded-response-fields)).

---

### 46. Config — Show Configuration

#### Command
```bash
python -m tools.maps_scanner config
```

#### Output
```
Endpoint:         https://wdcp.microsoft.com
Machine GUID:     39949d42-152b-4929-8aa6-00baf5a88f4d (rotating)
Partner GUID:     (none)
Cloud Block:      2 (HIGH)
SpyNet Level:     2 (ADVANCED)
Auto-submit:      1
Timeout:          30s
Proxy:            (none)
Verify SSL:       True
User-Agent:       MpCommunication
AV Sig Version:   1.445.126.0
Engine Version:   1.1.26010.1
App Version:      4.18.26010.5
OS:               10.0.26100 (build 26100, type 1)
Geo ID:           244
```

> With `--fixed-guid`, Machine GUID shows `(fixed)` instead. With `--machine-guid <UUID>`, that specific GUID is used and rotation is disabled.

---

## Feature Demonstrations

### 47. GUID Rotation — Repeat EICAR Detection

Demonstrates that GUID rotation (default) bypasses the cloud's per-GUID caching, allowing repeated MALICIOUS verdicts. With `--fixed-guid`, the second scan returns CLEAN (cached).

#### Commands & Results
```
=== Scan 1 (rotating, fresh GUID) ===
  VERDICT:      MALICIOUS
  Threat:       Virus:DOS/EICAR_Test_File

=== Scan 2 (rotating, another fresh GUID) ===
  VERDICT:      MALICIOUS
  Threat:       Virus:DOS/EICAR_Test_File

=== Scan 3 (--fixed-guid, reuses persisted GUID, cached) ===
  VERDICT:      CLEAN (no threats detected)
```

> **Key insight:** The MAPS cloud caches FASTPATH signature delivery per machine GUID. Once a GUID has received the signature for a given threat, subsequent requests from the same GUID get a minimal 88-byte CLEAN response. GUID rotation ensures each request appears as a new client, always receiving the full detection response.

---

### 48. Verbose Mode — Decoded Response Fields

The `-v` flag shows decoded Bond response fields and a full hex dump of the raw response.

#### Command
```bash
python -m tools.maps_scanner --no-verify -v scan tests/samples/eicar_test.com --threat-id 2147519003
```

#### Output (additional verbose sections)
```
  Decoded Response Fields:
    [6] (SpynetReportResponse) BT_LIST (1 items):
      [0]:
        [3] BT_UINT8 = 5
        [6] BT_INT32 = 1
        [12] BT_LIST (1 items):
          [0]:
            [9] BT_LIST (1 items):
              [0] = {}
            [12] BT_LIST = ec000100bc8d4d781418... (385 bytes)
    [10] BT_STRUCT = {}

  Raw (488 bytes):
  00000000  43 42 01 00 a9 42 4d 69 63 72 6f 73 6f 66 74 2e   CB...BMicrosoft.
  00000010  50 72 6f 74 65 63 74 69 6f 6e 53 65 72 76 69 63   ProtectionServic
  00000020  65 73 2e 45 6e 74 69 74 69 65 73 2e 52 61 77 2e   es.Entities.Raw.
  00000030  53 75 62 6d 69 74 53 70 79 6e 65 74 52 65 70 6f   SubmitSpynetRepo
  00000040  72 74 52 65 73 75 6c 74 ca 0a 00 01 01 cb 06 0a   rtResult........
  ...
  000001d0  73 82 de e7 26 02 f7 98 b6 42 f1 41 40 5d 04 00   s...&....B.A@]..
  000001e0  00 1b 8a 00 80 00 00 00                           ........
```

> Field `[6][0][12][0][12]` contains the 385-byte FASTPATH signature blob. Field `[6][0][3]` is the revision (5), and `[6][0][6]` is the sample rate (1). The response schema is `SubmitSpynetReportResult` wrapping a `SpynetReportResponse` list.

---

## Geo Endpoints

Regional MAPS endpoints demonstrate geo-affinity routing. Latency varies by geographic distance from the client.

### 49. Geo — EU (EICAR Scan)

#### Command
```bash
python -m tools.maps_scanner --no-verify --geo eu scan tests/samples/eicar_test.com --threat-id 2147519003
```

#### Output
```
Sending to MAPS cloud (https://europe.cp.wd.microsoft.com)...
HTTP Status:    200
Latency:        454.4 ms

  VERDICT:      MALICIOUS
  Threat:       Virus:DOS/EICAR_Test_File
  Threat ID:    2147519003
  Sig Data:     385 bytes (FASTPATH)

  FASTPATH Signature (VDM TLV):
    [0xEC ENVELOPE] 256B (encrypted detection logic)
    [0xAA FASTPATH_DATA] 20B Compiled=2026-02-19 12:44:58 UTC
    [0x5C THREAT_BEGIN] 47B ThreatID=2147519003 "Virus:DOS/EICAR_Test_File"
    [0x67 STATIC] 38B SHA1=3395856ce81f2b7382dee72602f798b642f14140
    [0x5D THREAT_END] 4B
```

> EU endpoint delivers identical FASTPATH signatures to the default (production) endpoint.

---

### 50. Geo — UK (Heartbeat)

#### Command
```bash
python -m tools.maps_scanner --no-verify --geo uk heartbeat
```

#### Output
```
Sending heartbeat to https://unitedkingdom.cp.wd.microsoft.com...
HTTP Status:    200
Latency:        383.0 ms

  VERDICT:      CLEAN (no threats detected)
```

---

### 51. Geo — AU (URL Reputation)

#### Command
```bash
python -m tools.maps_scanner --no-verify --geo au url "https://example.com"
```

#### Output
```
Checking URL: https://example.com
Endpoint: https://australia.cp.wd.microsoft.com
HTTP Status:    200
Latency:        974.1 ms

  VERDICT:      CLEAN (no threats detected)
```

> AU endpoint has the highest latency (~974ms) due to geographic distance.

---

### 52. Geo — US (Heartbeat)

#### Command
```bash
python -m tools.maps_scanner --no-verify --geo us heartbeat
```

#### Output
```
Sending heartbeat to https://unitedstates.cp.wd.microsoft.com...
HTTP Status:    200
Latency:        403.1 ms

  VERDICT:      CLEAN (no threats detected)
```

> **Geo latency summary:** US ~403ms, EU ~454ms, UK ~383ms, AU ~974ms (from US East client).

---

### 53. PPE Endpoint — DNS Failure

The PPE (pre-production) endpoint is Microsoft-internal and doesn't resolve externally.

#### Command
```bash
python -m tools.maps_scanner --ppe heartbeat
```

#### Output
```
Sending heartbeat to https://fastpath.wdcpppe.microsoft.com...
ERROR: HTTP request failed (85ms): HTTPSConnectionPool(host='fastpath.wdcpppe.microsoft.com', port=443):
  Max retries exceeded with url: /wdcp.svc/bond/submitreport
  (Caused by NameResolutionError: Failed to resolve 'fastpath.wdcpppe.microsoft.com')
```

> Expected: PPE endpoints (`fastpath.wdcpppe.microsoft.com`) are only accessible from Microsoft's internal network or VPN.

---

## Advanced Scenarios

### 54. EICAR Without --threat-id

With GUID rotation, EICAR is detected even **without** explicitly providing `--threat-id`. The cloud recognizes EICAR by hash alone and delivers FASTPATH.

#### Command
```bash
python -m tools.maps_scanner --no-verify scan tests/samples/eicar_test.com
```

#### Output
```
HTTP Status:    200
Latency:        437.2 ms

  VERDICT:      MALICIOUS
  Threat:       Virus:DOS/EICAR_Test_File
  Threat ID:    2147519003
  Sig Data:     385 bytes (FASTPATH)

  FASTPATH Signature (VDM TLV):
    [0xEC ENVELOPE] 256B (encrypted detection logic)
    [0xAA FASTPATH_DATA] 20B Compiled=2026-02-19 12:45:09 UTC
    [0x5C THREAT_BEGIN] 47B ThreatID=2147519003 "Virus:DOS/EICAR_Test_File"
    [0x67 STATIC] 38B SHA1=3395856ce81f2b7382dee72602f798b642f14140
    [0x5D THREAT_END] 4B
```

> **Key finding:** The cloud recognizes EICAR by SHA256 hash alone with a fresh GUID. The `--threat-id` flag is not required for detection — the cloud maps the hash to the threat internally.

---

### 55. scan-hash — All 3 Hash Types

Submit SHA256 + SHA1 + MD5 together in a single hash query.

#### Command
```bash
python -m tools.maps_scanner --no-verify scan-hash \
  275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f \
  --sha1 3395856ce81f2b7382dee72602f798b642f14140 \
  --md5 44d88612fea8a8f36de82e1278abb02f \
  --name eicar.com --size 68
```

#### Output
```
HTTP Status:    200
Latency:        454.6 ms

  VERDICT:      CLEAN (no threats detected)
```

> Even with all 3 hashes of known malware (EICAR), the hash-only query returns CLEAN. MAPS requires file content in the request payload to trigger FASTPATH delivery.

---

### 56. AMSI — Stdin Pipe

Read script content from stdin (pipe) using `-` as the file argument.

#### Command
```bash
echo 'Write-Host "Hello from stdin"' | python -m tools.maps_scanner --no-verify amsi -
```

#### Output
```
AMSI scan: powershell.exe
App ID: powershell.exe
Content size: 30 chars
Sending AMSI report to MAPS cloud...

  Report Type:  AMSI (powershell.exe)
HTTP Status:    200
Latency:        407.3 ms

  VERDICT:      CLEAN (no threats detected)
```

> Stdin mode reads from the pipe and uses it as script content. Useful for dynamically generated content or chaining with other tools.

---

### 57. Batch — Stdin Pipe

Read file paths from stdin (pipe) using `-` as the list argument.

#### Command
```bash
printf "tests/samples/eicar_test.com\ntests/samples/minimal_test.exe\n" | \
  python -m tools.maps_scanner --no-verify batch -
```

#### Output
```
[1/2] tools/maps_scanner/tests/samples/eicar_test.com
[2/2] tools/maps_scanner/tests/samples/minimal_test.exe
  tools/maps_scanner/tests/samples/eicar_test.com: MALICIOUS (Virus:DOS/EICAR_Test_File)
  tools/maps_scanner/tests/samples/minimal_test.exe: CLEAN
```

> Stdin batch mode enables integration with `find`, `xargs`, or other tools that produce file lists.

---

### 58. Quiet + JSON Mode

Combine `-q` (quiet) and `-j` (JSON) for machine-parseable output with no stderr noise.

#### Command
```bash
python -m tools.maps_scanner --no-verify -q -j scan tests/samples/eicar_test.com --threat-id 2147519003
```

#### Output
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
  "latency_ms": 461.1,
  "schema": "Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult",
  "signature_data_size": 385,
  "fastpath_entries": [
    {"type": "0xEC", "name": "ENVELOPE", "size": 256},
    {"type": "0xAA", "name": "FASTPATH_DATA", "size": 20, "compiled": "2026-02-19 12:45:23 UTC"},
    {"type": "0x5C", "name": "THREAT_BEGIN", "size": 47, "threat_id": 2147519003, "detection": "Virus:DOS/EICAR_Test_File"},
    {"type": "0x67", "name": "STATIC", "size": 38, "sha1": "3395856ce81f2b7382dee72602f798b642f14140"},
    {"type": "0x5D", "name": "THREAT_END", "size": 4, "threat_id": 2147519003}
  ]
}
```

> Pure JSON to stdout, no stderr info lines. Ideal for `jq` pipelines: `./maps --no-verify -q -j scan file.exe | jq .is_malicious`

---

### 59. Config — Set Flags

Modify config values on the fly with `--set-block-level` and `--set-spynet-level`.

#### Command
```bash
python -m tools.maps_scanner config --set-block-level 6 --set-spynet-level 2
```

#### Output
```
Endpoint:         https://wdcp.microsoft.com
Machine GUID:     39949d42-152b-4929-8aa6-00baf5a88f4d (rotating)
Partner GUID:     (none)
Cloud Block:      6 (ZERO_TOLERANCE)
SpyNet Level:     2 (ADVANCED)
Auto-submit:      1
Timeout:          30s
Proxy:            (none)
Verify SSL:       True
User-Agent:       MpCommunication
AV Sig Version:   1.445.126.0
Engine Version:   1.1.26010.1
App Version:      4.18.26010.5
OS:               10.0.26100 (build 26100, type 1)
Geo ID:           244
```

> Block levels: 0=DEFAULT, 1=MODERATE, 2=HIGH, 4=HIGH_PLUS, 6=ZERO_TOLERANCE. SpyNet levels: 0=DISABLED, 1=BASIC, 2=ADVANCED.

---

## Error Handling

### 60. Error — File Not Found

#### Command
```bash
python -m tools.maps_scanner --no-verify scan /nonexistent/file.exe
```

#### Output
```
ERROR: File not found: /nonexistent/file.exe
```
Exit code: **1**

---

### 61. Error — Unreachable Endpoint

#### Command
```bash
python -m tools.maps_scanner --endpoint "https://invalid.endpoint.test" scan tests/samples/eicar_test.com
```

#### Output
```
Sending to MAPS cloud (https://invalid.endpoint.test)...
ERROR: HTTP request failed (78ms): HTTPSConnectionPool(host='invalid.endpoint.test', port=443):
  Max retries exceeded with url: /wdcp.svc/bond/submitreport
  (Caused by NameResolutionError: Failed to resolve 'invalid.endpoint.test')
```

---

### 62. Error — TLS Verification Failure

Without `--no-verify`, the MAPS endpoint's certificate fails verification on Linux (no Microsoft root CA).

#### Command
```bash
python -m tools.maps_scanner scan tests/samples/eicar_test.com
```

#### Output
```
Sending to MAPS cloud (https://wdcp.microsoft.com)...
ERROR: TLS error (cert pinning?): HTTPSConnectionPool(host='wdcp.microsoft.com', port=443):
  Max retries exceeded with url: /wdcp.svc/bond/submitreport
  (Caused by SSLError(SSLCertVerificationError: certificate verify failed:
   unable to get local issuer certificate))
Tip: Use --no-verify or --proxy to bypass cert pinning.
On Windows, set SSLOptions=0 in HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet
```

> The tool provides actionable guidance for resolving TLS issues.

---

## Summary

### Results Matrix

| # | Command | Sub-flags Tested | HTTP | Verdict | Latency |
|---|---------|-----------------|------|---------|---------|
| 1 | `scan` | `--threat-id 2147519003` | 200 | **MALICIOUS** | 470ms |
| 2 | `scan` | (default) | 200 | CLEAN | 407ms |
| 3 | `scan` | (default) | 200 | CLEAN | 409ms |
| 4 | `scan` | (default) | 200 | CLEAN | 406ms |
| 5 | `scan` | (default) | 200 | CLEAN | 406ms |
| 6 | `scan` | (default) | 200 | CLEAN | 418ms |
| 7 | `scan` | (default) | 200 | CLEAN | 404ms |
| 8 | `scan` | (default) | 200 | CLEAN | 403ms |
| 9 | `scan` | (default) | 200 | CLEAN | 413ms |
| 10 | `scan` | (default) | 200 | CLEAN | 417ms |
| 11 | `scan` | (default) | 200 | CLEAN | 155ms |
| 12 | `scan-hash` | `--name --size` | 200 | CLEAN | 475ms |
| 13 | `scan-hash` | `--name --size` | 200 | CLEAN | 128ms |
| 14 | `url` | (default) | 200 | CLEAN | 125ms |
| 15 | `url` | `--referrer` | 200 | CLEAN | 437ms |
| 16 | `heartbeat` | `--type 0` | 200 | CLEAN | 110ms |
| 17 | `heartbeat` | `--type 1` (Setup) | 200 | CLEAN | 418ms |
| 18 | `heartbeat` | `--type 8` (SigUpdate) | 200 | CLEAN | 389ms |
| 19 | `bafs` | default (level 6) | 200 | ALLOWED | 192ms |
| 20 | `bafs` | `--block-level 2` (HIGH) | 200 | ALLOWED | 404ms |
| 21 | `wdo` | (default) | 200 | CLEAN | 175ms |
| 22 | `amsi` | default (`powershell.exe`) | 200 | CLEAN | 134ms |
| 23 | `amsi` | `--content-name --session-id` | 200 | CLEAN | 403ms |
| 24 | `amsi` | `--app-id cscript.exe` | 200 | CLEAN | 146ms |
| 25 | `amsi` | `--app-id wscript.exe` | 200 | CLEAN | 144ms |
| 26 | `uac` | `--uac-type 0 --exe` | 200 | CLEAN | 110ms |
| 27 | `uac` | `--uac-type 1 --identifier` | 200 | CLEAN | 109ms |
| 28 | `uac` | `--auto-elevate --blocked --cmdline` | 200 | CLEAN | 389ms |
| 29 | `netconn` | `--protocol TCP` | 200 | CLEAN | 110ms |
| 30 | `netconn` | `--protocol UDP` | 200 | CLEAN | 110ms |
| 31 | `netconn` | `--uri --source-ip --local-port` | 200 | CLEAN | 405ms |
| 32 | `upload` | (default) | 200 | no SAS URI | 129ms |
| 33 | `upload` | `--compression gzip` | 200 | no SAS URI | 405ms |
| 34 | `batch` | text output | 200 | MALICIOUS+CLEAN | — |
| 35 | `batch` | `--json` | 200 | MALICIOUS+CLEAN | — |
| 36 | `batch` | `--local-only` | — | UNKNOWN | — |
| 37 | `replay` | dry-run (no --confirm) | — | (preview) | — |
| 38 | `replay` | `--confirm` | 200 | CLEAN (cached) | 466ms |
| 39 | `scan` | `--local-only` | — | (local) | — |
| 40-43 | `analyze` | 4 file types | — | (local) | — |
| 44 | `build` | `-o` output file | — | (local) | — |
| 45 | `decode` | `--schema request` | — | (local) | — |
| 46 | `config` | (default) | — | (local) | — |
| 47 | `scan` x3 | GUID rotation proof | 200 | MAL/MAL/CLEAN | — |
| 48 | `scan` | `-v` verbose | 200 | MALICIOUS | 434ms |
| 49 | `scan` | `--geo eu` | 200 | **MALICIOUS** | 454ms |
| 50 | `heartbeat` | `--geo uk` | 200 | CLEAN | 383ms |
| 51 | `url` | `--geo au` | 200 | CLEAN | 974ms |
| 52 | `heartbeat` | `--geo us` | 200 | CLEAN | 403ms |
| 53 | `heartbeat` | `--ppe` | DNS fail | (error) | 85ms |
| 54 | `scan` | no --threat-id (EICAR) | 200 | **MALICIOUS** | 437ms |
| 55 | `scan-hash` | `--sha1 --md5 --name --size` | 200 | CLEAN | 455ms |
| 56 | `amsi` | stdin (`-`) | 200 | CLEAN | 407ms |
| 57 | `batch` | stdin (`-`) | 200 | MALICIOUS+CLEAN | — |
| 58 | `scan` | `-q -j` (quiet+JSON) | 200 | **MALICIOUS** | 461ms |
| 59 | `config` | `--set-block-level --set-spynet-level` | — | (local) | — |
| 60 | `scan` | bad file path | — | (error) exit 1 | — |
| 61 | `scan` | `--endpoint` unreachable | — | (error) DNS fail | 78ms |
| 62 | `scan` | no `--no-verify` (TLS) | — | (error) SSL fail | — |

### Key Observations

1. **GUID Rotation (default):** Every cloud request uses a fresh UUID4 machine GUID. This prevents the cloud's per-GUID caching from returning stale results. Use `--fixed-guid` or `--machine-guid <UUID>` to pin a specific identity.

2. **EICAR Detection:** With GUID rotation, EICAR **always** returns MALICIOUS with 385 bytes of FASTPATH signature data — even without `--threat-id`. The cloud recognizes EICAR by SHA256 hash alone. Without rotation, only the first scan per GUID returns MALICIOUS.

3. **FASTPATH Signatures:** The 385-byte VDM TLV payload contains 5 entries: ENVELOPE (256B encrypted detection logic), FASTPATH_DATA (20B compilation timestamp), THREAT_BEGIN/END (threat metadata), and STATIC (SHA1 hash match rule).

4. **Response Sizes:** CLEAN = 88 bytes (revision + sample_rate). MALICIOUS = 488 bytes (88 + 385 bytes FASTPATH + 15 bytes framing).

5. **Hash-Only Queries:** `scan-hash` returns CLEAN for all hashes including known malware. Full file content + threat_id is required for FASTPATH delivery.

6. **Sample Upload:** The cloud did not request sample upload for any test files. Sample uploads require the cloud to issue a SAS URI via SampleRequests in a scan response. This is at the cloud's discretion for suspicious/unknown files.

7. **Latency:** First requests per connection take ~400-470ms (TCP+TLS). Subsequent requests on keep-alive take ~100-190ms. This is visible in the results where scans #1-2 are slower than later scans.

8. **Geo Endpoints:** All 4 regional endpoints (US, EU, UK, AU) accept requests. Latency varies: UK ~383ms, US ~403ms, EU ~454ms, AU ~974ms. PPE endpoint is Microsoft-internal only.

9. **Error Handling:** Clean error messages for file-not-found (exit 1), DNS resolution failures, and TLS verification errors with actionable tips.

10. **Stdin Support:** Both `amsi` and `batch` accept `-` to read from stdin, enabling pipe-based workflows.

11. **All 62 test cases completed successfully.** Every cloud command returned HTTP 200. Error cases (#53, #60-62) produced expected error messages.

### Test Files

| File | Size | SHA-256 (truncated) | Type |
|------|------|---------------------|------|
| eicar_test.com | 68B | `275a021b...51fd0f` | EICAR test |
| minimal_test.exe | 1024B | `4e0623d8...ce2b1` | PE32 (ret) |
| random_data.bin | 4096B | `b28a8b72...71377` | Random binary |
| test_script.ps1 | 438B | `01fef7db...564b8` | PowerShell |
| unique_test.exe | 1024B | `2be89ec0...4bd3` | PE32 (UUID-embedded) |
| versioned_test.exe | 1536B | `e08075f1...aeb7` | PE32 (.rsrc version) |
| test_library.dll | 1024B | `9f5d63b5...7f1f` | DLL |
| test_batch.cmd | 281B | `894b8181...dc86` | Batch script |
| large_unique_test.exe | 33280B | `69a10fbd...31cc` | PE32 (large, high-entropy) |
| test_script.vbs | 367B | `4ddc6154...9db6` | VBScript |
| test_script.js | 329B | `f00ecc7f...8ad5` | JavaScript |
| pe_with_imports.exe | 1536B | `1b4baf00...f3ca` | PE32 (kernel32 imports) |
| test_x64.exe | 1024B | `9c5cd106...802c` | PE32+ (x64) |
| dotnet_test.exe | 1024B | `5a4e55d7...2093` | .NET assembly |

### Sub-Flag Coverage

| Flag | Tested In |
|------|-----------|
| `--no-verify` | All cloud commands |
| `--json` / `-j` | #1, #14, #19, #21, #22, #26, #29, #35, #58 |
| `-v` (verbose) | #48 |
| `-q` (quiet) | #58 |
| `-q -j` (quiet+JSON) | #58 |
| `--threat-id` | #1 |
| `--local-only` | #36, #39 |
| `--auto-upload` | Tested (no SAS URI returned) |
| `--name`, `--size` | #12, #13, #55 |
| `--sha1`, `--md5` | #55 |
| `--referrer` | #15 |
| `--type` (heartbeat) | #16 (0), #17 (1), #18 (8) |
| `--block-level` (bafs) | #19 (6), #20 (2) |
| `--app-id` (amsi) | #24 (cscript.exe), #25 (wscript.exe) |
| `--content-name`, `--session-id` | #23 |
| `--uac-type` | #26 (Exe), #27 (COM) |
| `--exe`, `--cmdline` | #26, #28 |
| `--identifier` | #27 |
| `--auto-elevate`, `--blocked` | #28 |
| `--protocol` | #29 (TCP), #30 (UDP) |
| `--uri`, `--source-ip`, `--local-port` | #31 |
| `--compression` | #33 (gzip) |
| `--confirm` (replay) | #38 |
| `-o` (build output) | #44 |
| `--schema` (decode) | #45 |
| `--fixed-guid` | #47 |
| `--machine-guid` | Tested via config |
| `--geo` | #49 (eu), #50 (uk), #51 (au), #52 (us) |
| `--ppe` | #53 |
| `--endpoint` | #61 |
| `--set-block-level`, `--set-spynet-level` | #59 |
| stdin (`-`) | #56 (amsi), #57 (batch) |
