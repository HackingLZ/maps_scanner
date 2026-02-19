#!/usr/bin/env python3
"""
MAPS Cloud Scanner CLI

Interact with Microsoft's MAPS (Microsoft Active Protection Service) cloud
for file reputation queries, URL reputation, and dynamic signature delivery.

For authorized security research use only.

Usage:
    python -m maps_scanner scan <file>              # Scan a local file
    python -m maps_scanner scan-hash <sha256>       # Query by hash
    python -m maps_scanner url <url>                # URL reputation check
    python -m maps_scanner heartbeat                # Connectivity test
    python -m maps_scanner analyze <file>           # Local analysis only
    python -m maps_scanner build <file>             # Build payload (no send)
    python -m maps_scanner decode <file>            # Decode Bond binary
    python -m maps_scanner replay <file>            # Replay captured payload
    python -m maps_scanner config                   # Show/edit config
"""

import warnings
# Suppress noisy warnings before any imports that trigger them
warnings.filterwarnings("ignore", category=DeprecationWarning, module="urllib3")
warnings.filterwarnings("ignore", message="urllib3.*")
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

import argparse
import json
import sys
import os
from pathlib import Path
from typing import Optional

from .bond import (
    BondType,
    bond_deserialize,
    bond_hexdump,
    bond_pretty_print,
)
from .client import (
    MAPS_BOND_PATH,
    MAPS_ENDPOINT_ALT,
    MAPS_ENDPOINT_PPE,
    MAPS_ENDPOINT_PROD,
    MAPS_GEO_ENDPOINTS,
    MAPSClient,
    MAPSConfig,
    MAPSVerdict,
    RESPONSE_NAMES,
    SEVERITY_NAMES,
    SPYNET_REPORT_NAMES,
    SPYNET_RESPONSE_NAMES,
    THREAT_CATEGORY_NAMES,
    THREAT_DETAIL_NAMES,
    CloudBlockLevel,
    HeartbeatType,
    ReportType,
    SpynetLevel,
    analyze_file,
    load_config,
    parse_fastpath_blob,
    save_config,
)


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

class Output:
    """Handle output formatting."""

    def __init__(self, json_mode: bool = False, verbose: bool = False, quiet: bool = False):
        self.json_mode = json_mode
        self.verbose = verbose
        self.quiet = quiet

    def info(self, msg: str):
        if not self.quiet:
            print(msg, file=sys.stderr)

    def error(self, msg: str):
        print(f"ERROR: {msg}", file=sys.stderr)

    def verdict(self, v: MAPSVerdict):
        if self.json_mode:
            result = v.to_dict()
            if self.verbose and v.raw_fields:
                result["raw_fields"] = _fields_to_json(v.raw_fields)
            print(json.dumps(result, indent=2, default=str))
            return

        if v.error:
            self.error(v.error)
            if v.http_status:
                print(f"  HTTP Status: {v.http_status}")
            if self.verbose and v.raw_bytes:
                print(f"\n  Raw response ({len(v.raw_bytes)} bytes):")
                print(bond_hexdump(v.raw_bytes))
            return

        # Header
        if v.http_status:
            print(f"HTTP Status:    {v.http_status}")
        if v.latency_ms is not None:
            print(f"Latency:        {v.latency_ms:.1f} ms")
        if v.schema_name:
            print(f"Schema:         {v.schema_name}")
        print()

        # Verdict
        if v.is_malicious:
            print("  VERDICT:      \033[91mMALICIOUS\033[0m")
            if v.threat_name:
                print(f"  Threat:       {v.threat_name}")
            if v.detection_name and v.detection_name != v.threat_name:
                print(f"  Detection:    {v.detection_name}")
            if v.threat_family:
                print(f"  Family:       {v.threat_family}")
            if v.threat_id is not None:
                print(f"  Threat ID:    {v.threat_id}")
            if v.severity is not None:
                sev_name = SEVERITY_NAMES.get(v.severity, f"Unknown({v.severity})")
                print(f"  Severity:     {v.severity} ({sev_name})")
            if v.signature_data:
                print(f"  Sig Data:     {len(v.signature_data)} bytes (FASTPATH)")

            # Show parsed FASTPATH VDM TLV entries
            if v.fastpath_entries:
                print()
                print("  \033[1mFASTPATH Signature (VDM TLV):\033[0m")
                for e in v.fastpath_entries:
                    label = f"0x{e.sig_type:02X} {e.sig_type_name}"
                    size_str = f"{len(e.data)}B"
                    if e.sig_type == 0x5C:  # THREAT_BEGIN
                        tid = f"ThreatID={e.threat_id}" if e.threat_id else ""
                        det = f'"{e.detection_name}"' if e.detection_name else ""
                        print(f"    [{label}] {size_str} {tid} {det}")
                    elif e.sig_type == 0x67:  # STATIC
                        sha = f"SHA1={e.sha1}" if e.sha1 else ""
                        print(f"    [{label}] {size_str} {sha}")
                    elif e.sig_type == 0xAA:  # FASTPATH_DATA
                        ts = e.compilation_time or ""
                        print(f"    [{label}] {size_str} Compiled={ts}")
                    elif e.sig_type == 0xEC:  # ENVELOPE
                        print(f"    [{label}] {size_str} (encrypted detection logic)")
                    elif e.sig_type == 0x5D:  # THREAT_END
                        print(f"    [{label}] {size_str}")
                    else:
                        print(f"    [{label}] {size_str}")
        elif v.clean:
            print("  VERDICT:      \033[92mCLEAN\033[0m (no threats detected)")
        else:
            print("  VERDICT:      \033[93mUNKNOWN\033[0m (no definitive result)")

        # Response metadata
        if v.revision is not None:
            print(f"  Revision:     {v.revision}")
        if v.sample_rate is not None:
            print(f"  Sample Rate:  {v.sample_rate}")

        if v.sample_requested:
            print(f"  Sample:       \033[93mREQUESTED by cloud\033[0m")
            if v.sample_requests:
                for i, sr in enumerate(v.sample_requests):
                    print(f"    Request {i+1}:")
                    for k, val in sr.items():
                        print(f"      {k}: {val}")

        # CertificateResponse
        if v.certificate_response:
            print(f"  Certificate:  {v.certificate_response}")

        # OnboardingResponse
        if v.onboarding_blob:
            blob_preview = v.onboarding_blob[:80] + "..." if len(v.onboarding_blob) > 80 else v.onboarding_blob
            print(f"  Onboarding:   {blob_preview}")

        # UrlResponse
        if v.url_response_data:
            print(f"  URL Response: {v.url_response_data}")

        # Verbose: show all decoded fields
        if self.verbose and v.raw_fields:
            print("\n  Decoded Response Fields:")
            print(bond_pretty_print(v.raw_fields, schema=RESPONSE_NAMES, indent=2))

        if self.verbose and v.raw_bytes:
            print(f"\n  Raw ({len(v.raw_bytes)} bytes):")
            print(bond_hexdump(v.raw_bytes))

    def file_info(self, info):
        if self.json_mode:
            d = {
                "path": info.path,
                "size": info.size,
                "sha256": info.sha256,
                "sha1": info.sha1,
                "md5": info.md5,
                "crc32": f"{info.crc32:08x}",
            }
            if info.imphash:
                d["imphash"] = info.imphash
            if info.ssdeep_hash:
                d["ssdeep"] = info.ssdeep_hash
            if info.pe_timestamp is not None:
                d["pe_timestamp"] = info.pe_timestamp
            if info.pe_checksum is not None:
                d["pe_checksum"] = info.pe_checksum
            if info.file_description:
                d["file_description"] = info.file_description
            if info.file_version:
                d["file_version"] = info.file_version
            if info.product_name:
                d["product_name"] = info.product_name
            if info.original_filename:
                d["original_filename"] = info.original_filename
            if info.signer:
                d["signer"] = info.signer
            if info.section_hashes:
                d["section_hashes"] = info.section_hashes
            print(json.dumps(d, indent=2))
            return

        print(f"File:           {info.path}")
        print(f"Size:           {info.size} bytes")
        print(f"SHA-256:        {info.sha256}")
        print(f"SHA-1:          {info.sha1}")
        print(f"MD5:            {info.md5}")
        print(f"CRC32:          {info.crc32:08x}")
        if info.imphash:
            print(f"ImpHash:        {info.imphash}")
        if info.ssdeep_hash:
            print(f"SSDEEP:         {info.ssdeep_hash}")
        if info.pe_timestamp is not None:
            print(f"PE Timestamp:   {info.pe_timestamp}")
        if info.pe_checksum is not None:
            print(f"PE Checksum:    {info.pe_checksum:#010x}")
        if info.file_description:
            print(f"Description:    {info.file_description}")
        if info.file_version:
            print(f"Version:        {info.file_version}")
        if info.product_name:
            print(f"Product:        {info.product_name}")
        if info.original_filename:
            print(f"Original Name:  {info.original_filename}")
        if info.signer:
            print(f"Signer:         {info.signer}")
        if info.section_hashes:
            print(f"Section Hashes:")
            for sh in info.section_hashes:
                print(f"  {sh}")

    def decoded_bond(self, fields, schema=None, raw_bytes=None):
        if self.json_mode:
            print(json.dumps(_fields_to_json(fields), indent=2, default=str))
        else:
            print(bond_pretty_print(fields, schema=schema))

        if self.verbose and raw_bytes:
            print(f"\nHex dump ({len(raw_bytes)} bytes):")
            print(bond_hexdump(raw_bytes))

    def payload_info(self, payload: bytes, label: str = "Payload"):
        if self.json_mode:
            try:
                fields = bond_deserialize(payload)
                result = {
                    "size": len(payload),
                    "fields": _fields_to_json(fields),
                }
                print(json.dumps(result, indent=2, default=str))
            except Exception:
                print(json.dumps({"size": len(payload), "hex": payload.hex()}, indent=2))
        else:
            print(f"{label}: {len(payload)} bytes")
            print()
            try:
                fields = bond_deserialize(payload)
                print(bond_pretty_print(fields, schema=SPYNET_REPORT_NAMES))
            except Exception as e:
                print(f"  (Could not decode as Bond: {e})")
            print()
            print("Hex dump:")
            print(bond_hexdump(payload))


def _fields_to_json(fields) -> dict:
    """Convert decoded Bond fields to JSON-serializable dict."""
    result = {}
    for fid, (type_name, value) in fields.items():
        key = str(fid)
        if isinstance(value, dict) and value:
            first_val = next(iter(value.values()), None)
            if isinstance(first_val, tuple):
                value = _fields_to_json(value)
        if isinstance(value, bytes):
            value = value.hex()
        if isinstance(value, list):
            value = [
                _fields_to_json(v) if isinstance(v, dict) and v and isinstance(next(iter(v.values()), None), tuple)
                else v.hex() if isinstance(v, bytes)
                else v
                for v in value
            ]
        result[key] = {"type": type_name, "value": value}
    return result


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

def cmd_scan(args, config: MAPSConfig, out: Output):
    """Scan a local file through MAPS cloud."""
    client = MAPSClient(config)

    out.info(f"Analyzing file: {args.file}")
    file_info = client.analyze_file_local(args.file)

    if args.local_only:
        out.file_info(file_info)
        return

    out.info(f"SHA-256: {file_info.sha256}")
    out.info(f"Size: {file_info.size} bytes")
    out.info(f"Sending to MAPS cloud ({config.endpoint})...")

    auto_upload = getattr(args, 'auto_upload', False)

    if auto_upload:
        verdict, upload_result = client.scan_and_upload(
            args.file, threat_id=args.threat_id, auto_upload=True,
        )
        out.verdict(verdict)
        if upload_result:
            _print_upload_result(out, upload_result)
    else:
        verdict = client.scan_file(args.file, threat_id=args.threat_id)
        out.verdict(verdict)
        if verdict.sample_requested and verdict.sample_requests:
            out.info("\nTip: Use --auto-upload to automatically upload when MAPS requests a sample.")


def cmd_scan_hash(args, config: MAPSConfig, out: Output):
    """Query MAPS cloud by file hash."""
    client = MAPSClient(config)

    out.info(f"Querying hash: {args.sha256}")
    out.info(f"Endpoint: {config.endpoint}")

    verdict = client.scan_hash(
        sha256=args.sha256,
        sha1=args.sha1 or "",
        md5=args.md5 or "",
        file_name=args.name or "unknown",
        file_size=args.size or 0,
    )
    out.verdict(verdict)


def cmd_url(args, config: MAPSConfig, out: Output):
    """Check URL reputation through MAPS."""
    client = MAPSClient(config)

    out.info(f"Checking URL: {args.url}")
    out.info(f"Endpoint: {config.endpoint}")

    verdict = client.check_url(args.url, referrer=args.referrer or "")
    out.verdict(verdict)


def cmd_heartbeat(args, config: MAPSConfig, out: Output):
    """Send MAPS heartbeat (connectivity test)."""
    client = MAPSClient(config)

    hb_type = getattr(args, 'hb_type', HeartbeatType.STILL_ALIVE) or HeartbeatType.STILL_ALIVE
    hb_name = HeartbeatType(hb_type).name if hb_type in HeartbeatType.__members__.values() else f"TYPE_{hb_type}"

    out.info(f"Sending heartbeat to {config.endpoint}...")
    out.info(f"Type:           {hb_name} ({hb_type})")
    guid_label = "(rotating)" if config.rotate_guid else config.machine_guid
    out.info(f"Machine GUID:   {guid_label}")
    out.info(f"Engine:         {config.engine_version}")
    out.info(f"Signatures:     {config.av_sig_version}")
    out.info(f"Platform:       {config.app_version}")
    out.info(f"OS:             {config.os_ver} (build {config.os_build})")
    out.info(f"Customer:       {config.customer_type}")
    out.info(f"Cloud Block:    {config.cloud_block_level}")
    out.info(f"SpyNet Level:   {config.spynet_level}")
    verdict = client.heartbeat(hb_type=hb_type)
    out.verdict(verdict)


def _print_upload_result(out: Output, result: dict):
    """Print sample upload result."""
    if result.get("success"):
        out.info(f"\n  Sample Upload:  \033[92mSUCCESS\033[0m")
        out.info(f"  HTTP Status:    {result.get('http_status')}")
        out.info(f"  Bytes Uploaded: {result.get('bytes_uploaded')}")
        out.info(f"  Latency:        {result.get('latency_ms', 0):.1f} ms")
    else:
        out.info(f"\n  Sample Upload:  \033[91mFAILED\033[0m")
        if result.get("http_status"):
            out.info(f"  HTTP Status:    {result['http_status']}")
        if result.get("error"):
            out.info(f"  Error:          {result['error']}")


def cmd_upload(args, config: MAPSConfig, out: Output):
    """Upload a file sample to MAPS cloud for detonation analysis."""
    client = MAPSClient(config)

    out.info(f"Analyzing file: {args.file}")
    file_info = client.analyze_file_local(args.file)
    out.info(f"SHA-256: {file_info.sha256}")
    out.info(f"Size: {file_info.size} bytes")

    if args.sas_uri:
        # Direct upload with provided SAS URI
        out.info(f"Uploading to provided SAS URI...")
        result = client.upload_sample(
            path=args.file,
            sas_uri=args.sas_uri,
            compression=args.compression or "",
        )
        _print_upload_result(out, result)
    else:
        # Request SAS URI from MAPS first
        out.info(f"Requesting sample upload URI from MAPS ({config.endpoint})...")
        verdict = client.request_sample_upload(args.file, threat_id=args.threat_id)
        out.verdict(verdict)

        if verdict.sample_requested and verdict.sample_requests:
            out.verdict(verdict)
            for sr in verdict.sample_requests:
                uri = sr.get("upload_uri")
                if uri:
                    out.info(f"\nMAPS provided upload URI. Uploading sample...")
                    compression = sr.get("compression", "")
                    result = client.upload_sample(
                        path=args.file,
                        sas_uri=uri,
                        compression=compression,
                    )
                    _print_upload_result(out, result)
                    break
        else:
            out.verdict(verdict)
            out.info("\nMAPS did not request a sample upload for this file.")
            out.info("The cloud may not need this file, or the file is already known.")
            out.info("Tip: Use --sas-uri to upload directly if you have a SAS URI.")


def cmd_bafs(args, config: MAPSConfig, out: Output):
    """Block at First Sight (BAFS) scan - aggressive cloud check.

    Uses SyncLowfi (type 2) with high/zero-tolerance block level and
    tight timeout to simulate real Defender BAFS behavior. This is
    the highest-confidence cloud scan mode.
    """
    # Override config for maximum BAFS sensitivity
    original_block = config.cloud_block_level
    config.cloud_block_level = args.block_level or 6  # Zero Tolerance by default

    client = MAPSClient(config)

    out.info(f"BAFS scan: {args.file}")
    file_info = client.analyze_file_local(args.file)
    out.info(f"SHA-256: {file_info.sha256}")
    out.info(f"Size: {file_info.size} bytes")
    block_name = CloudBlockLevel(config.cloud_block_level).name if config.cloud_block_level in CloudBlockLevel.__members__.values() else str(config.cloud_block_level)
    out.info(f"Block Level: {config.cloud_block_level} ({block_name})")
    out.info(f"Timeout: {args.bafs_timeout}s")
    out.info(f"Sending sync lowfi query to MAPS cloud...")

    # Use scan with no threat_id (pure cloud-block mode)
    verdict = client.scan_file(args.file, threat_id=args.threat_id)

    if not out.json_mode:
        if verdict.is_malicious:
            print(f"\n  \033[91mBLOCKED\033[0m by cloud (BAFS)")
        elif verdict.clean:
            print(f"\n  \033[92mALLOWED\033[0m by cloud (no threats)")
        else:
            print(f"\n  \033[93mINDETERMINATE\033[0m (timeout or error)")

    out.verdict(verdict)

    # Restore
    config.cloud_block_level = original_block


def cmd_wdo(args, config: MAPSConfig, out: Output):
    """Windows Defender Offline (WDO) scan - boot-time offline scan report.

    Sends a WDO report (type 7) for files found during offline boot scans.
    WDO scans are used to detect rootkits and persistent threats that hide
    from the running OS.
    """
    client = MAPSClient(config)

    out.info(f"WDO scan: {args.file}")
    file_info = client.analyze_file_local(args.file)
    out.info(f"SHA-256: {file_info.sha256}")
    out.info(f"Size: {file_info.size} bytes")
    out.info(f"Sending WDO report (type 7) to MAPS cloud...")

    verdict = client.wdo_scan(args.file, threat_id=args.threat_id)

    if not out.json_mode:
        print(f"\n  Report Type:  WDO (Windows Defender Offline)")
    out.verdict(verdict)


def cmd_amsi(args, config: MAPSConfig, out: Output):
    """Submit script content via AMSI protocol for cloud analysis.

    Sends script content embedded in CoreReport AMSI fields, similar to
    how Windows Defender handles AMSI content from PowerShell, cscript, etc.
    Can read from a file or stdin.
    """
    client = MAPSClient(config)

    # Read script content
    if args.file == "-":
        import sys
        script_content = sys.stdin.read()
        content_name = args.content_name or args.app_id
    else:
        with open(args.file, 'r', errors='replace') as f:
            script_content = f.read()
        content_name = args.content_name or args.file

    out.info(f"AMSI scan: {content_name}")
    out.info(f"App ID: {args.app_id}")
    out.info(f"Content size: {len(script_content)} chars")
    out.info(f"Sending AMSI report to MAPS cloud...")

    verdict = client.amsi_scan(
        script_content,
        app_id=args.app_id,
        content_name=content_name,
        session_id=args.session_id,
    )

    if not out.json_mode:
        print(f"\n  Report Type:  AMSI ({args.app_id})")
    out.verdict(verdict)


def cmd_uac(args, config: MAPSConfig, out: Output):
    """Submit AMSI UAC elevation info report to MAPS cloud.

    Reports UAC elevation telemetry using Bond_AmsiUacInfo schema
    (30 fields, RE'd from mpengine.dll at 0x10a055f0 by a9c5bd1 agent).
    """
    client = MAPSClient(config)

    type_names = {0: "Exe", 1: "COM", 2: "MSI", 3: "ActiveX", 4: "PackagedApp"}
    type_name = type_names.get(args.uac_type, f"Unknown({args.uac_type})")

    out.info(f"UAC info report: type={type_name}")
    if args.exe:
        out.info(f"  Executable: {args.exe}")
    if args.requestor:
        out.info(f"  Requestor: {args.requestor}")
    out.info(f"  AutoElevate={args.auto_elevate}, Blocked={args.blocked}")
    out.info(f"Sending UAC info report to MAPS cloud...")

    verdict = client.amsi_uac_report(
        uac_type=args.uac_type,
        exe_app_name=args.exe or "",
        exe_command_line=args.cmdline or "",
        identifier=args.identifier or "",
        auto_elevate=args.auto_elevate,
        blocked=args.blocked,
        trusted_state=args.trusted_state,
        requestor_name=args.requestor or "",
    )

    if not out.json_mode:
        print(f"\n  Report Type:  AmsiUacInfo ({type_name})")
    out.verdict(verdict)


def cmd_netconn(args, config: MAPSConfig, out: Output):
    """Submit a network connection report to MAPS cloud.

    Reports network connection telemetry using Bond_NetworkConnectionReport V1
    schema (10 fields, RE'd from mpengine.dll at 0x10A065F0).
    """
    PROTO_MAP = {"tcp": 6, "udp": 17, "icmp": 1}
    proto = args.protocol
    if isinstance(proto, str):
        proto = PROTO_MAP.get(proto.lower(), 6)

    client = MAPSClient(config)

    proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))
    out.info(f"Network connection report: {args.remote_ip}:{args.remote_port}")
    out.info(f"Protocol: {proto_name} ({proto}), Source port: {args.local_port}")
    out.info(f"Sending network connection report to MAPS cloud...")

    verdict = client.network_conn_report(
        remote_ip=args.remote_ip,
        remote_port=args.remote_port,
        local_port=args.local_port,
        protocol=proto,
        source_ip=args.source_ip,
        uri=args.uri,
    )

    if not out.json_mode:
        print(f"\n  Report Type:  NetworkConnectionReport V1 ({proto_name} {args.remote_ip}:{args.remote_port})")
    out.verdict(verdict)


def cmd_analyze(args, config: MAPSConfig, out: Output):
    """Analyze a file locally (no cloud contact)."""
    file_info = analyze_file(args.file)
    out.file_info(file_info)


def cmd_build(args, config: MAPSConfig, out: Output):
    """Build a SpynetReport payload without sending it."""
    client = MAPSClient(config)
    payload = client.build_report_bytes(args.file, threat_id=args.threat_id)

    if args.output:
        Path(args.output).write_bytes(payload)
        out.info(f"Payload written to {args.output} ({len(payload)} bytes)")
    else:
        out.payload_info(payload, label="SpynetReport")


def cmd_decode(args, config: MAPSConfig, out: Output):
    """Decode a Bond binary file."""
    data = Path(args.file).read_bytes()

    # Auto-detect if it's hex-encoded
    try:
        text = data.decode('ascii').strip()
        if all(c in '0123456789abcdefABCDEF \n\r\t' for c in text):
            data = bytes.fromhex(text.replace(' ', '').replace('\n', '').replace('\r', ''))
            out.info("Detected hex-encoded input, converted to binary")
    except (UnicodeDecodeError, ValueError):
        pass

    out.info(f"Decoding {len(data)} bytes of Bond CompactBinaryV1...")

    schema = None
    if args.schema == "request":
        schema = SPYNET_REPORT_NAMES
    elif args.schema == "response":
        schema = RESPONSE_NAMES

    try:
        fields = bond_deserialize(data)
        out.decoded_bond(fields, schema=schema, raw_bytes=data)
    except Exception as e:
        out.error(f"Failed to decode: {e}")
        print("\nHex dump:")
        print(bond_hexdump(data))
        sys.exit(1)


def cmd_replay(args, config: MAPSConfig, out: Output):
    """Replay a captured MAPS payload."""
    data = Path(args.file).read_bytes()

    # Auto-detect hex encoding
    try:
        text = data.decode('ascii').strip()
        if all(c in '0123456789abcdefABCDEF \n\r\t' for c in text):
            data = bytes.fromhex(text.replace(' ', '').replace('\n', '').replace('\r', ''))
    except (UnicodeDecodeError, ValueError):
        pass

    out.info(f"Replaying {len(data)} bytes to {config.endpoint}{args.path}")

    if not args.confirm:
        out.info("Add --confirm to actually send (dry-run by default)")
        out.info("\nPayload preview:")
        try:
            fields = bond_deserialize(data)
            print(bond_pretty_print(fields, schema=SPYNET_REPORT_NAMES))
        except Exception:
            print(bond_hexdump(data))
        return

    client = MAPSClient(config)
    try:
        status, body, latency = client.send_raw(data, path=args.path)
        out.info(f"HTTP {status} ({latency:.1f}ms)")

        if body:
            out.info(f"\nResponse ({len(body)} bytes):")
            try:
                fields = bond_deserialize(body)
                out.decoded_bond(fields, schema=RESPONSE_NAMES, raw_bytes=body)
            except Exception:
                print(bond_hexdump(body))
    except ConnectionError as e:
        out.error(str(e))
        sys.exit(1)


def cmd_config(args, config: MAPSConfig, out: Output):
    """Show or update configuration."""
    if args.set_endpoint:
        config.endpoint = args.set_endpoint
    if args.set_machine_guid:
        config.machine_guid = args.set_machine_guid
    if args.set_proxy:
        config.proxy = args.set_proxy if args.set_proxy != "none" else None
    if args.set_block_level is not None:
        config.cloud_block_level = args.set_block_level
    if args.set_spynet_level is not None:
        config.spynet_level = args.set_spynet_level

    if args.save:
        save_config(config)
        out.info(f"Config saved to {config.__class__.__name__}")

    if out.json_mode:
        d = {
            "endpoint": config.endpoint,
            "machine_guid": config.machine_guid,
            "partner_guid": config.partner_guid,
            "cloud_block_level": config.cloud_block_level,
            "spynet_level": config.spynet_level,
            "auto_submit": config.auto_submit,
            "timeout": config.timeout,
            "proxy": config.proxy,
            "verify_ssl": config.verify_ssl,
            "user_agent": config.user_agent,
            "av_sig_version": config.av_sig_version,
            "engine_version": config.engine_version,
            "app_version": config.app_version,
            "os_ver": config.os_ver,
            "os_build": config.os_build,
            "os_type": config.os_type,
            "geo_id": config.geo_id,
        }
        print(json.dumps(d, indent=2))
    else:
        print(f"Endpoint:         {config.endpoint}")
        guid_display = f"{config.machine_guid} (rotating)" if config.rotate_guid else f"{config.machine_guid} (fixed)"
        print(f"Machine GUID:     {guid_display}")
        print(f"Partner GUID:     {config.partner_guid or '(none)'}")
        print(f"Cloud Block:      {config.cloud_block_level} ({CloudBlockLevel(config.cloud_block_level).name})")
        print(f"SpyNet Level:     {config.spynet_level} ({SpynetLevel(config.spynet_level).name})")
        print(f"Auto-submit:      {config.auto_submit}")
        print(f"Timeout:          {config.timeout}s")
        print(f"Proxy:            {config.proxy or '(none)'}")
        print(f"Verify SSL:       {config.verify_ssl}")
        print(f"User-Agent:       {config.user_agent}")
        print(f"AV Sig Version:   {config.av_sig_version}")
        print(f"Engine Version:   {config.engine_version}")
        print(f"App Version:      {config.app_version}")
        print(f"OS:               {config.os_ver} (build {config.os_build}, type {config.os_type})")
        print(f"Geo ID:           {config.geo_id}")


def cmd_scan_batch(args, config: MAPSConfig, out: Output):
    """Scan multiple files from a list."""
    client = MAPSClient(config)

    # Read file list
    if args.file_list == "-":
        paths = [line.strip() for line in sys.stdin if line.strip()]
    else:
        paths = [line.strip() for line in Path(args.file_list).read_text().splitlines() if line.strip()]

    results = []
    for i, path in enumerate(paths):
        out.info(f"[{i+1}/{len(paths)}] {path}")
        try:
            file_info = client.analyze_file_local(path)
            if args.local_only:
                results.append({"path": path, "sha256": file_info.sha256, "size": file_info.size})
                continue

            verdict = client.scan_file(path)
            results.append({
                "path": path,
                "sha256": file_info.sha256,
                **verdict.to_dict(),
            })
        except Exception as e:
            results.append({"path": path, "error": str(e)})

    if out.json_mode:
        print(json.dumps(results, indent=2, default=str))
    else:
        for r in results:
            status = "MALICIOUS" if r.get("is_malicious") else "CLEAN" if r.get("clean") else "UNKNOWN"
            threat = r.get("threat_name", "")
            err = r.get("error", "")
            line = f"  {r['path']}: {status}"
            if threat:
                line += f" ({threat})"
            if err:
                line += f" [ERROR: {err}]"
            print(line)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="maps_scanner",
        description="MAPS Cloud Scanner - Windows Defender cloud reputation tool",
        epilog="For authorized research only.",
    )

    # Global options
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress info messages")
    parser.add_argument("-j", "--json", action="store_true", help="JSON output")
    parser.add_argument("--endpoint", help=f"MAPS endpoint URL (default: {MAPS_ENDPOINT_PROD})")
    parser.add_argument("--ppe", action="store_true", help="Use PPE (pre-production) endpoint")
    parser.add_argument("--geo", choices=list(MAPS_GEO_ENDPOINTS.keys()), help="Use geo-affinity endpoint")
    parser.add_argument("--proxy", help="HTTP proxy (e.g., http://127.0.0.1:8080 for mitmproxy)")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--timeout", type=int, help="Request timeout in seconds")
    parser.add_argument("--machine-guid", help="Use a fixed machine GUID (disables default rotation)")
    parser.add_argument("--fixed-guid", action="store_true",
                        help="Use the persisted machine GUID instead of rotating per-request "
                             "(shows cloud GUID caching behavior — repeat scans return cached results)")
    parser.add_argument("--block-level", type=int, choices=[0, 1, 2, 4, 6],
                        help="Cloud block level (0=off, 2=high, 6=zero-tolerance)")
    parser.add_argument("--bearer-token", help="Enterprise AAD Bearer token for authenticated MAPS access")
    parser.add_argument("--customer-type", choices=["Consumer", "Enterprise"],
                        help="MAPS customer type (default: Consumer)")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan a local file through MAPS cloud")
    p_scan.add_argument("file", help="File to scan")
    p_scan.add_argument("--threat-id", type=int, help="Lowfi threat ID (triggers cloud confirmation, e.g. 2147519003)")
    p_scan.add_argument("--local-only", action="store_true", help="Only compute hashes, don't contact cloud")
    p_scan.add_argument("--auto-upload", action="store_true", help="Auto-upload if MAPS requests a sample")

    # scan-hash
    p_hash = subparsers.add_parser("scan-hash", help="Query MAPS by file hash")
    p_hash.add_argument("sha256", help="SHA-256 hash to query")
    p_hash.add_argument("--sha1", help="SHA-1 hash")
    p_hash.add_argument("--md5", help="MD5 hash")
    p_hash.add_argument("--name", help="File name")
    p_hash.add_argument("--size", type=int, help="File size in bytes")

    # url
    p_url = subparsers.add_parser("url", help="Check URL reputation")
    p_url.add_argument("url", help="URL to check")
    p_url.add_argument("--referrer", help="Referrer URL")

    # heartbeat
    p_hb = subparsers.add_parser("heartbeat", help="Send MAPS heartbeat (connectivity test)")
    p_hb.add_argument("--type", dest="hb_type", type=int, default=0,
                       choices=[e.value for e in HeartbeatType],
                       help="Heartbeat subtype: 0=StillAlive, 1=Setup, 2=Uninstall, "
                            "3=Error, 4=PolicyChange, 5=Browser, 6=Exclusion, "
                            "7=Cleanup, 8=SigUpdate, 9=PlatformUpdate, "
                            "10=TamperProtect, 11=Reboot")

    # bafs
    p_bafs = subparsers.add_parser("bafs", help="Block at First Sight scan (aggressive cloud check)")
    p_bafs.add_argument("file", help="File to scan")
    p_bafs.add_argument("--threat-id", type=int, help="Lowfi threat ID")
    p_bafs.add_argument("--block-level", type=int, default=6, choices=[2, 4, 6],
                         help="Block level (2=High, 4=High+, 6=ZeroTolerance, default: 6)")
    p_bafs.add_argument("--bafs-timeout", type=int, default=10, help="BAFS timeout in seconds (default: 10)")

    # wdo
    p_wdo = subparsers.add_parser("wdo", help="Windows Defender Offline (WDO) scan report")
    p_wdo.add_argument("file", help="File to report")
    p_wdo.add_argument("--threat-id", type=int, help="Lowfi threat ID")

    # amsi
    p_amsi = subparsers.add_parser("amsi", help="Submit script content via AMSI protocol")
    p_amsi.add_argument("file", help="Script file to submit (use '-' for stdin)")
    p_amsi.add_argument("--app-id", default="powershell.exe",
                         help="AMSI host application (default: powershell.exe)")
    p_amsi.add_argument("--content-name", help="Content name/path (default: filename)")
    p_amsi.add_argument("--session-id", type=int, default=0, help="AMSI session ID")

    # uac
    p_uac = subparsers.add_parser("uac", help="Submit AMSI UAC elevation info report")
    p_uac.add_argument("--uac-type", type=int, default=0, choices=[0, 1, 2, 3, 4],
                        help="UAC type: 0=Exe, 1=COM, 2=MSI, 3=ActiveX, 4=PkApp (default: 0)")
    p_uac.add_argument("--exe", help="Executable requesting elevation")
    p_uac.add_argument("--cmdline", help="Command line of requestor")
    p_uac.add_argument("--requestor", help="Process name requesting elevation")
    p_uac.add_argument("--identifier", help="UAC request identifier")
    p_uac.add_argument("--auto-elevate", action="store_true", help="Auto-elevation requested")
    p_uac.add_argument("--blocked", action="store_true", help="Elevation was blocked")
    p_uac.add_argument("--trusted-state", type=int, default=0, help="Trust state (default: 0)")

    # netconn
    p_netconn = subparsers.add_parser("netconn", help="Submit network connection report (V1)")
    p_netconn.add_argument("remote_ip", help="Destination IP address")
    p_netconn.add_argument("remote_port", type=int, help="Destination port number")
    p_netconn.add_argument("--local-port", type=int, default=0, help="Source port (default: 0)")
    p_netconn.add_argument("--protocol", default="TCP",
                           help="Protocol: TCP, UDP, ICMP or IANA number (default: TCP)")
    p_netconn.add_argument("--source-ip", default="0.0.0.0", help="Source IP (default: 0.0.0.0)")
    p_netconn.add_argument("--uri", default="", help="Optional URI associated with connection")

    # analyze
    p_analyze = subparsers.add_parser("analyze", help="Analyze file locally (no cloud)")
    p_analyze.add_argument("file", help="File to analyze")

    # build
    p_build = subparsers.add_parser("build", help="Build SpynetReport payload (no send)")
    p_build.add_argument("file", help="File to build report for")
    p_build.add_argument("--threat-id", help="Lowfi threat ID")
    p_build.add_argument("-o", "--output", help="Write payload to file")

    # decode
    p_decode = subparsers.add_parser("decode", help="Decode Bond binary data")
    p_decode.add_argument("file", help="Bond binary file to decode (or hex-encoded)")
    p_decode.add_argument("--schema", choices=["request", "response", "none"],
                          default="none", help="Schema to use for field names")

    # replay
    p_replay = subparsers.add_parser("replay", help="Replay a captured MAPS payload")
    p_replay.add_argument("file", help="Payload file to replay")
    p_replay.add_argument("--path", default=MAPS_BOND_PATH, help=f"URL path (default: {MAPS_BOND_PATH})")
    p_replay.add_argument("--confirm", action="store_true", help="Actually send (dry-run by default)")

    # upload
    p_upload = subparsers.add_parser("upload", help="Upload file sample to MAPS cloud for detonation")
    p_upload.add_argument("file", help="File to upload")
    p_upload.add_argument("--sas-uri", help="Azure Blob SAS URI (skip MAPS request, upload directly)")
    p_upload.add_argument("--threat-id", type=int, help="Lowfi threat ID for sample request")
    p_upload.add_argument("--compression", choices=["none", "gzip", "deflate"], default="none",
                          help="Compression for upload (default: none)")

    # batch
    p_batch = subparsers.add_parser("batch", help="Scan multiple files")
    p_batch.add_argument("file_list", help="File containing paths to scan (or - for stdin)")
    p_batch.add_argument("--local-only", action="store_true", help="Only compute hashes")

    # config
    p_config = subparsers.add_parser("config", help="Show/edit configuration")
    p_config.add_argument("--set-endpoint", help="Set MAPS endpoint")
    p_config.add_argument("--set-machine-guid", help="Set machine GUID")
    p_config.add_argument("--set-proxy", help="Set proxy (or 'none' to clear)")
    p_config.add_argument("--set-block-level", type=int, choices=[0, 1, 2, 4, 6])
    p_config.add_argument("--set-spynet-level", type=int, choices=[0, 1, 2])
    p_config.add_argument("--save", action="store_true", help="Persist to disk")

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Load/build config
    config = load_config()

    # Apply CLI overrides
    if args.endpoint:
        config.endpoint = args.endpoint
    elif args.ppe:
        config.endpoint = MAPS_ENDPOINT_PPE
    elif args.geo:
        config.endpoint = MAPS_GEO_ENDPOINTS[args.geo]

    if args.proxy:
        config.proxy = args.proxy
    if args.no_verify:
        config.verify_ssl = False
    if args.timeout:
        config.timeout = args.timeout
    if args.machine_guid:
        config.machine_guid = args.machine_guid
        config.rotate_guid = False  # Explicit GUID disables rotation
    if args.fixed_guid:
        config.rotate_guid = False
    if args.block_level is not None:
        config.cloud_block_level = args.block_level
    if args.bearer_token:
        config.bearer_token = args.bearer_token
        if not args.customer_type:
            config.customer_type = "Enterprise"
    if args.customer_type:
        config.customer_type = args.customer_type

    # Output handler
    out = Output(json_mode=args.json, verbose=args.verbose, quiet=args.quiet)

    # Dispatch
    commands = {
        "scan": cmd_scan,
        "scan-hash": cmd_scan_hash,
        "url": cmd_url,
        "heartbeat": cmd_heartbeat,
        "bafs": cmd_bafs,
        "wdo": cmd_wdo,
        "amsi": cmd_amsi,
        "netconn": cmd_netconn,
        "uac": cmd_uac,
        "analyze": cmd_analyze,
        "build": cmd_build,
        "decode": cmd_decode,
        "replay": cmd_replay,
        "upload": cmd_upload,
        "batch": cmd_scan_batch,
        "config": cmd_config,
    }

    handler = commands.get(args.command)
    if handler:
        try:
            handler(args, config, out)
        except FileNotFoundError as e:
            out.error(str(e))
            sys.exit(1)
        except KeyboardInterrupt:
            out.info("\nInterrupted")
            sys.exit(130)
        except Exception as e:
            out.error(f"Unexpected error: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
