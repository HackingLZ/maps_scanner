# MAPS Cloud Scanner

A research tool for interacting with **Windows Defender's MAPS** (Microsoft Active Protection Service) cloud-based file reputation and dynamic signature delivery system.

MAPS is the cloud backend that powers Defender's real-time protection verdicts, sample submission pipeline, and dynamic signature (SDN/DSS) delivery. This tool speaks the same **Bond CompactBinaryV1** protocol that the Defender client uses on the wire, enabling direct interaction with MAPS endpoints for security research purposes.

## Features

- **File Scanning** - Submit files to MAPS and receive cloud verdicts (clean, malware, PUA, unknown)
- **Hash Lookups** - Query file reputation by SHA-256 without submitting the file
- **URL Reputation** - Check URLs against Defender's cloud reputation service
- **Heartbeat / Connectivity** - Test connectivity to MAPS endpoints
- **Local Analysis** - Analyze PE metadata, imports, sections, and authenticode signatures offline
- **Bond Protocol** - Full CompactBinaryV1 serializer/deserializer matching Defender's wire format
- **Payload Inspection** - Build, decode, and replay raw Bond payloads for protocol research
- **API Fuzzing** - Enumerate undocumented endpoints, hidden fields, report types, and server behavior

## Installation

```bash
pip install -r requirements.txt
```

The only required dependency is `requests`. Optional dependencies for enhanced analysis:

| Package  | Purpose                    |
|----------|----------------------------|
| `pefile` | Deep PE structure analysis |
| `ssdeep` | Fuzzy hash computation     |

## Usage

```bash
# Scan a local file
python -m maps_scanner scan <file>

# Query reputation by hash
python -m maps_scanner scan-hash <sha256>

# URL reputation check
python -m maps_scanner url <url>

# Connectivity test
python -m maps_scanner heartbeat

# Local-only PE analysis
python -m maps_scanner analyze <file>

# Build a Bond payload without sending
python -m maps_scanner build <file>

# Decode a captured Bond binary
python -m maps_scanner decode <file>

# Replay a previously captured payload
python -m maps_scanner replay <file>

# Show or edit configuration
python -m maps_scanner config
```

Add `--json` to any command for machine-readable output. Use `-v` for verbose protocol details.

## Project Structure

```
maps_scanner/
  __init__.py        # Package metadata
  __main__.py        # CLI entry point and command routing
  client.py          # MAPS protocol client, config, and file analysis
  bond.py            # Microsoft Bond CompactBinaryV1 serializer/deserializer
  fuzz_maps.py       # API fuzzer for endpoint and field discovery
  maps_scanner       # Python wrapper script
  requirements.txt   # Dependencies
  docs/              # Protocol documentation and test results
  tests/             # Test samples and utilities
```

## Documentation

Detailed protocol documentation is available in [`docs/`](docs/):

- **MAPS_SCANNER.md** - Full technical reference
- **MAPS_SAMPLE_IO.md** - Example request/response payloads
- **MAPS_LIVE_TEST_RESULTS.md** - Live endpoint test results
- **maps_protocol_guide.html** - Visual protocol guide

## Disclaimer

This tool is provided for **authorized security research only**. It interacts with live Microsoft services. Use responsibly and in compliance with all applicable laws and Microsoft's terms of service. The authors assume no liability for misuse.

## License

For authorized security research use only.
