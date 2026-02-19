#!/usr/bin/env python3
"""
MAPS API Fuzzer — Feature Discovery & Attack Surface Enumeration

Probes Microsoft's MAPS (Microsoft Active Protection Service) web API to
discover undocumented endpoints, hidden Bond fields, alternative report types,
and differential server behavior.

Uses the existing maps_scanner client/bond libraries without modification.

For authorized security research use only.

Usage:
    python fuzz_maps.py [options] <module>

Modules:
    paths           Fuzz URL paths for undiscovered endpoints
    report-types    Try report type values beyond known 1-7
    headers         Enumerate custom HTTP headers and values
    fields          Probe unknown Bond field ordinals in SpynetReport
    response-fields Probe unknown response field ordinals
    schemas         Try alternative Bond schema names
    endpoints       Discover endpoint hostname variations
    versions        Fuzz version strings for behavior changes
    customer-types  Enumerate customer type header values
    block-levels    Sweep all cloud block level values
    heartbeat-types Enumerate heartbeat subtypes beyond known 0-11
    bond-types      Send fields with unexpected Bond wire types
    all             Run all modules sequentially
"""

import argparse
import hashlib
import json
import os
import random
import string
import struct
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Add parent to path so we can import maps_scanner
_HERE = Path(__file__).resolve().parent
if str(_HERE.parent) not in sys.path:
    sys.path.insert(0, str(_HERE.parent))

from maps_scanner.bond import (
    BOND_CB1_MARSHAL_HEADER,
    BondType,
    CompactBinaryV1Writer,
    bond_deserialize,
    bond_hexdump,
    bond_marshal,
    bond_marshal_with_schema,
    bond_pretty_print,
    bond_wrap_with_schema,
)
from maps_scanner.client import (
    MAPS_BOND_PATH,
    MAPS_ENDPOINT_ALT,
    MAPS_ENDPOINT_PPE,
    MAPS_ENDPOINT_PROD,
    MAPS_ENTRA_PATH,
    MAPS_FASTPATH_PPE,
    MAPS_FASTPATH_PROD,
    MAPS_GEO_ENDPOINTS,
    MAPS_REST_PATH,
    SPYNET_REPORT_SCHEMA,
    CRF,
    FRF,
    MAPSConfig,
    MAPSTransport,
    ReportType,
    SF,
    SpynetReportBuilder,
    bond_deserialize as client_bond_deserialize,
    parse_response,
)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

@dataclass
class FuzzResult:
    """Single fuzz probe result."""
    module: str
    probe_id: str
    description: str
    http_status: int = 0
    response_size: int = 0
    latency_ms: float = 0.0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body_hex: str = ""
    decoded_fields: Optional[Dict] = None
    error: str = ""
    interesting: bool = False
    notes: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        d = {
            "module": self.module,
            "probe_id": self.probe_id,
            "description": self.description,
            "http_status": self.http_status,
            "response_size": self.response_size,
            "latency_ms": round(self.latency_ms, 1),
            "interesting": self.interesting,
            "timestamp": self.timestamp,
        }
        if self.error:
            d["error"] = self.error
        if self.notes:
            d["notes"] = self.notes
        if self.response_headers:
            d["response_headers"] = self.response_headers
        if self.decoded_fields:
            d["decoded_fields"] = str(self.decoded_fields)[:2000]
        if self.response_body_hex and self.interesting:
            d["response_body_hex"] = self.response_body_hex[:500]
        return d


class FuzzLogger:
    """Structured logging for fuzz results."""

    def __init__(self, output_dir: str = "fuzz_results", verbose: bool = False):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        self.results: List[FuzzResult] = []
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._baseline_size: Optional[int] = None
        self._baseline_status: Optional[int] = None

    def set_baseline(self, status: int, size: int):
        self._baseline_size = size
        self._baseline_status = status

    def is_interesting(self, result: FuzzResult) -> bool:
        """Determine if a result differs from baseline."""
        if result.error:
            return False
        # Any non-standard status is interesting
        if result.http_status not in (200, 400, 404, 500):
            return True
        # Response size differs from baseline
        if self._baseline_size is not None and result.response_size != self._baseline_size:
            if result.http_status == 200:
                return True
        # Got 200 on a path/feature that might not exist
        if result.http_status == 200 and result.response_size > 0:
            return True
        return False

    def log(self, result: FuzzResult):
        result.timestamp = datetime.now().isoformat()
        if not result.interesting:
            result.interesting = self.is_interesting(result)
        self.results.append(result)

        marker = " *** INTERESTING ***" if result.interesting else ""
        status_str = f"HTTP {result.http_status}" if result.http_status else "ERROR"
        size_str = f"{result.response_size}B" if result.response_size else "0B"

        if result.error:
            print(f"  [{result.probe_id}] {result.description}: ERROR - {result.error}")
        elif self.verbose or result.interesting:
            print(f"  [{result.probe_id}] {result.description}: "
                  f"{status_str} {size_str} ({result.latency_ms:.0f}ms){marker}")
            if result.notes:
                print(f"    -> {result.notes}")
        else:
            print(f"  [{result.probe_id}] {status_str} {size_str} ({result.latency_ms:.0f}ms)")

    def save(self, module_name: str):
        """Save results for a module to JSON."""
        outfile = self.output_dir / f"{self.session_id}_{module_name}.json"
        data = {
            "session_id": self.session_id,
            "module": module_name,
            "total_probes": len(self.results),
            "interesting_count": sum(1 for r in self.results if r.interesting),
            "results": [r.to_dict() for r in self.results],
        }
        outfile.write_text(json.dumps(data, indent=2, default=str))
        print(f"\n  Saved {len(self.results)} results to {outfile}")

    def save_summary(self):
        """Save combined summary of all modules."""
        interesting = [r for r in self.results if r.interesting]
        summary_file = self.output_dir / f"{self.session_id}_SUMMARY.json"
        data = {
            "session_id": self.session_id,
            "total_probes": len(self.results),
            "interesting_count": len(interesting),
            "interesting_results": [r.to_dict() for r in interesting],
            "status_distribution": {},
        }
        for r in self.results:
            key = str(r.http_status) if r.http_status else "error"
            data["status_distribution"][key] = data["status_distribution"].get(key, 0) + 1
        summary_file.write_text(json.dumps(data, indent=2, default=str))
        print(f"\nSummary: {len(interesting)}/{len(self.results)} interesting results")
        print(f"Saved to {summary_file}")


# ---------------------------------------------------------------------------
# Transport helpers
# ---------------------------------------------------------------------------

class FuzzTransport:
    """Thin HTTP transport for fuzzing — more flexible than MAPSTransport."""

    def __init__(self, config: MAPSConfig):
        self.config = config
        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        if config.proxy:
            self.session.proxies = {"http": config.proxy, "https": config.proxy}

    def send(
        self,
        payload: bytes,
        path: str = MAPS_BOND_PATH,
        endpoint: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        method: str = "POST",
    ) -> Tuple[int, bytes, Dict[str, str], float]:
        """Send raw payload, return (status, body, response_headers, latency_ms)."""
        base = endpoint or self.config.endpoint
        url = base.rstrip("/") + path

        hdrs = {
            "Content-Type": "application/bond",
            "Accept": "application/bond",
            "Accept-Charset": "utf-8",
            "User-Agent": self.config.user_agent,
            "Connection": "Keep-Alive",
            "X-MS-MAPS-CUSTOMERTYPE": self.config.customer_type,
            "X-MS-MAPS-OSVERSION": self.config.os_version_hex,
            "X-MS-MAPS-PLATFORMVERSION": self.config.platform_version_hex,
            "X-MS-MAPS-ENGINEVERSION": self.config.engine_version_hex,
        }
        if self.config.bearer_token:
            hdrs["Authorization"] = f"Bearer {self.config.bearer_token}"
        if headers:
            hdrs.update(headers)

        start = time.monotonic()
        try:
            if method.upper() == "GET":
                resp = self.session.get(url, headers=hdrs, timeout=self.config.timeout)
            elif method.upper() == "PUT":
                resp = self.session.put(url, data=payload, headers=hdrs, timeout=self.config.timeout)
            elif method.upper() == "OPTIONS":
                resp = self.session.options(url, headers=hdrs, timeout=self.config.timeout)
            elif method.upper() == "HEAD":
                resp = self.session.head(url, headers=hdrs, timeout=self.config.timeout)
            else:
                resp = self.session.post(url, data=payload, headers=hdrs, timeout=self.config.timeout)
            latency = (time.monotonic() - start) * 1000
            resp_headers = dict(resp.headers)
            return resp.status_code, resp.content, resp_headers, latency
        except requests.exceptions.ConnectionError as e:
            latency = (time.monotonic() - start) * 1000
            raise ConnectionError(f"Connection failed ({latency:.0f}ms): {e}") from e
        except requests.exceptions.Timeout as e:
            latency = (time.monotonic() - start) * 1000
            raise ConnectionError(f"Timeout ({latency:.0f}ms): {e}") from e
        except requests.exceptions.RequestException as e:
            latency = (time.monotonic() - start) * 1000
            raise ConnectionError(f"Request error ({latency:.0f}ms): {e}") from e


def build_minimal_heartbeat(config: MAPSConfig) -> bytes:
    """Build a minimal valid heartbeat payload for baseline measurements."""
    builder = SpynetReportBuilder(config)
    return builder.build_heartbeat()


def build_minimal_scan(config: MAPSConfig) -> bytes:
    """Build a minimal file scan payload (random file hash)."""
    builder = SpynetReportBuilder(config)
    rand_hash = hashlib.sha256(os.urandom(32)).hexdigest()
    return builder.build_hash_query(sha256=rand_hash)


def try_decode_response(body: bytes) -> Optional[Dict]:
    """Best-effort decode of a Bond response body."""
    if not body or len(body) < 4:
        return None
    try:
        # Skip CB marshal header if present
        data = body
        if len(data) >= 4:
            magic = struct.unpack_from('<H', data, 0)[0]
            if magic == 0x4243:
                data = data[4:]
        return bond_deserialize(data)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Fuzz modules
# ---------------------------------------------------------------------------

def fuzz_paths(transport: FuzzTransport, config: MAPSConfig, logger: FuzzLogger, delay: float):
    """Probe URL paths for undiscovered WCF/REST endpoints."""
    print("\n[PATH FUZZING] Probing URL paths...")

    payload = build_minimal_heartbeat(config)

    # Known paths plus speculative variations
    paths = [
        # Known working
        "/wdcp.svc/bond/submitreport",
        # Known legacy/documented
        "/wdcp.svc/submitReport",
        "/wdcp.svc/entraReport",
        # WCF WSDL/metadata probing
        "/wdcp.svc",
        "/wdcp.svc?wsdl",
        "/wdcp.svc?singleWsdl",
        "/wdcp.svc/mex",
        "/wdcp.svc/metadata",
        # Bond endpoint variations
        "/wdcp.svc/bond",
        "/wdcp.svc/bond/submitReport",  # case variation
        "/wdcp.svc/bond/SubmitReport",
        "/wdcp.svc/bond/submit",
        "/wdcp.svc/bond/query",
        "/wdcp.svc/bond/getreport",
        "/wdcp.svc/bond/heartbeat",
        "/wdcp.svc/bond/signature",
        "/wdcp.svc/bond/fastpath",
        "/wdcp.svc/bond/sample",
        "/wdcp.svc/bond/upload",
        "/wdcp.svc/bond/config",
        "/wdcp.svc/bond/status",
        "/wdcp.svc/bond/version",
        "/wdcp.svc/bond/enroll",
        "/wdcp.svc/bond/register",
        "/wdcp.svc/bond/onboard",
        "/wdcp.svc/bond/telemetry",
        "/wdcp.svc/bond/behavior",
        "/wdcp.svc/bond/remediation",
        "/wdcp.svc/bond/certificate",
        "/wdcp.svc/bond/policy",
        # REST variations
        "/wdcp.svc/rest/submitreport",
        "/wdcp.svc/json/submitreport",
        "/wdcp.svc/xml/submitreport",
        # Service alternative names
        "/WdCpSrvc.asmx",
        "/WdCpSrvc.svc",
        "/wdcp.asmx",
        "/maps.svc",
        "/maps.svc/bond/submitreport",
        "/defender.svc",
        "/defender.svc/bond/submitreport",
        "/spynet.svc",
        "/spynet.svc/bond/submitreport",
        # API version prefixes
        "/v1/wdcp.svc/bond/submitreport",
        "/v2/wdcp.svc/bond/submitreport",
        "/api/wdcp.svc/bond/submitreport",
        # Entra/Enterprise variations
        "/wdcp.svc/entra",
        "/wdcp.svc/entraReport/bond",
        "/wdcp.svc/bond/entraReport",
        "/wdcp.svc/enterprise",
        "/wdcp.svc/bond/enterprise",
        # Fastpath-specific
        "/wdcp.svc/fastpath",
        "/wdcp.svc/bond/fastpath/signature",
        "/wdcp.svc/dss",
        "/wdcp.svc/sdn",
        # Health/diagnostics
        "/health",
        "/healthcheck",
        "/status",
        "/ready",
        "/ping",
        "/robots.txt",
        "/.well-known/openid-configuration",
        # Root
        "/",
    ]

    for i, path in enumerate(paths):
        probe_id = f"PATH-{i:03d}"
        try:
            status, body, resp_hdrs, latency = transport.send(payload, path=path)
            result = FuzzResult(
                module="paths",
                probe_id=probe_id,
                description=f"POST {path}",
                http_status=status,
                response_size=len(body),
                latency_ms=latency,
                response_headers=resp_hdrs,
                response_body_hex=body.hex()[:500] if body else "",
                decoded_fields=try_decode_response(body),
            )
            # Anything returning 200 or non-standard codes on speculative paths
            if status == 200 and path != "/wdcp.svc/bond/submitreport":
                result.interesting = True
                result.notes = f"Got 200 on non-standard path!"
            elif status not in (400, 404, 405, 500, 503):
                result.interesting = True
                result.notes = f"Unexpected status {status}"
            logger.log(result)
        except ConnectionError as e:
            logger.log(FuzzResult(
                module="paths", probe_id=probe_id,
                description=f"POST {path}", error=str(e),
            ))
        time.sleep(delay)

    # Also try GET/OPTIONS/HEAD on the known bond path
    for method in ["GET", "OPTIONS", "HEAD", "PUT"]:
        probe_id = f"PATH-M-{method}"
        try:
            status, body, resp_hdrs, latency = transport.send(
                payload, path=MAPS_BOND_PATH, method=method
            )
            result = FuzzResult(
                module="paths",
                probe_id=probe_id,
                description=f"{method} {MAPS_BOND_PATH}",
                http_status=status,
                response_size=len(body),
                latency_ms=latency,
                response_headers=resp_hdrs,
                response_body_hex=body.hex()[:500] if body else "",
            )
            if status == 200:
                result.interesting = True
                result.notes = f"{method} accepted!"
            elif method == "OPTIONS" and "Allow" in resp_hdrs:
                result.interesting = True
                result.notes = f"Allow: {resp_hdrs.get('Allow', '')}"
            logger.log(result)
        except ConnectionError as e:
            logger.log(FuzzResult(
                module="paths", probe_id=probe_id,
                description=f"{method} {MAPS_BOND_PATH}", error=str(e),
            ))
        time.sleep(delay)


def fuzz_report_types(transport: FuzzTransport, config: MAPSConfig, logger: FuzzLogger, delay: float):
    """Enumerate report type values beyond known 1-7."""
    print("\n[REPORT TYPE FUZZING] Trying report types 0-20 + edge cases...")

    builder = SpynetReportBuilder(config)
    rand_hash = hashlib.sha256(os.urandom(32)).hexdigest()

    # Known: 1=ASYNC_LOWFI, 2=SYNC_LOWFI, 3=TELEMETRY, 4=HB, 5=URL, 6=SAMPLE, 7=WDO
    # Probe 0-20 and some large values
    test_values = list(range(0, 21)) + [32, 64, 100, 128, 255, 256, 1000, 65535]

    for report_type in test_values:
        probe_id = f"RT-{report_type}"
        try:
            # Build payload with custom report type
            w = CompactBinaryV1Writer()
            report_guid = str(uuid.uuid4())
            builder._write_top_level(w, report_guid)

            # FileReportElements with the custom report type
            w.write_field_begin(BondType.BT_LIST, SF.FILE_REPORT_ELEMENTS)
            w._write_byte(BondType.BT_LIST)
            w._write_varint(1)
            w._write_byte(BondType.BT_STRUCT)
            w._write_varint(1)
            w._field_stack.append(0)
            w.write_list_begin(FRF.REVISION, BondType.BT_INT16, 1)
            w._write_varint(2)
            w.write_list_begin(FRF.INDEX, BondType.BT_INT16, 1)
            w._write_varint(2)
            w.write_list_begin(FRF.CORE_REPORT, BondType.BT_STRUCT, 1)
            w._field_stack.append(0)
            w.write_list_begin(CRF.REVISION, BondType.BT_INT16, 1)
            w._write_varint(2)
            w.write_string(CRF.FILE_NAME, "fuzz_test.exe")
            w.write_string(CRF.SHA256, rand_hash)
            # ReportType as string (field 330)
            w.write_string(CRF.REPORT_TYPE - 10, str(report_type))
            w._write_byte(BondType.BT_STOP)  # end CoreReport
            w._field_stack.pop()
            w._write_byte(BondType.BT_STOP)  # end FileReport
            w._field_stack.pop()

            w.write_string(SF.ENGINE_REPORT_GUID, str(uuid.uuid4()))
            w._write_byte(BondType.BT_STOP)
            payload = bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())

            status, body, resp_hdrs, latency = transport.send(payload)

            known_type = report_type in range(1, 8)
            result = FuzzResult(
                module="report_types",
                probe_id=probe_id,
                description=f"ReportType={report_type}{'(known)' if known_type else ''}",
                http_status=status,
                response_size=len(body),
                latency_ms=latency,
                response_headers=resp_hdrs,
                response_body_hex=body.hex()[:500] if body else "",
                decoded_fields=try_decode_response(body),
            )
            # Interesting if an unknown type gets a 200 with substantial response
            if not known_type and status == 200 and len(body) > 0:
                result.interesting = True
                result.notes = f"Unknown report type {report_type} got valid response!"
            logger.log(result)
        except ConnectionError as e:
            logger.log(FuzzResult(
                module="report_types", probe_id=probe_id,
                description=f"ReportType={report_type}", error=str(e),
            ))
        time.sleep(delay)


def fuzz_headers(transport: FuzzTransport, config: MAPSConfig, logger: FuzzLogger, delay: float):
    """Enumerate HTTP request headers for hidden features."""
    print("\n[HEADER FUZZING] Probing custom HTTP headers...")

    payload = build_minimal_heartbeat(config)

    # Headers to probe — based on Microsoft patterns and WCF conventions
    header_tests = [
        # Customer type variations
        ("X-MS-MAPS-CUSTOMERTYPE", "Enterprise"),
        ("X-MS-MAPS-CUSTOMERTYPE", "Government"),
        ("X-MS-MAPS-CUSTOMERTYPE", "Education"),
        ("X-MS-MAPS-CUSTOMERTYPE", "Partner"),
        ("X-MS-MAPS-CUSTOMERTYPE", "Internal"),
        ("X-MS-MAPS-CUSTOMERTYPE", "Preview"),
        ("X-MS-MAPS-CUSTOMERTYPE", "Insider"),
        ("X-MS-MAPS-CUSTOMERTYPE", "MSFT"),
        # Potential hidden MAPS headers
        ("X-MS-MAPS-PARTNERID", str(uuid.uuid4())),
        ("X-MS-MAPS-TENANTID", str(uuid.uuid4())),
        ("X-MS-MAPS-DEVICEID", str(uuid.uuid4())),
        ("X-MS-MAPS-MACHINEID", str(uuid.uuid4())),
        ("X-MS-MAPS-CLIENTID", str(uuid.uuid4())),
        ("X-MS-MAPS-SESSIONID", str(uuid.uuid4())),
        ("X-MS-MAPS-REQUESTID", str(uuid.uuid4())),
        ("X-MS-MAPS-CORRELATIONID", str(uuid.uuid4())),
        ("X-MS-MAPS-DIAGNOSTIC", "true"),
        ("X-MS-MAPS-DEBUG", "true"),
        ("X-MS-MAPS-VERBOSE", "true"),
        ("X-MS-MAPS-TRACE", "true"),
        ("X-MS-MAPS-BETA", "true"),
        ("X-MS-MAPS-PREVIEW", "true"),
        ("X-MS-MAPS-INSIDER", "true"),
        ("X-MS-MAPS-FLIGHTING", "AllFeatures"),
        ("X-MS-MAPS-RING", "insider"),
        ("X-MS-MAPS-RING", "canary"),
        ("X-MS-MAPS-SIGVERSION", config.av_sig_version),
        ("X-MS-MAPS-ASIMOV", "true"),
        ("X-MS-MAPS-REGION", "US"),
        ("X-MS-MAPS-REGION", "EU"),
        ("X-MS-MAPS-DATACENTER", "westus2"),
        # Content-Type variations
        ("Content-Type", "application/json"),
        ("Content-Type", "application/xml"),
        ("Content-Type", "application/octet-stream"),
        ("Content-Type", "application/bond-compact-binary"),
        ("Content-Type", "application/bond; protocol=compact_v1"),
        # Accept variations
        ("Accept", "application/json"),
        ("Accept", "application/xml"),
        ("Accept", "*/*"),
        # Microsoft identity headers
        ("X-MS-DeviceId", str(uuid.uuid4())),
        ("X-MS-TokenId", str(uuid.uuid4())),
        ("X-AnchorMailbox", "test@test.com"),
        ("X-MS-Client-Request-Id", str(uuid.uuid4())),
        ("client-request-id", str(uuid.uuid4())),
        # Compression
        ("Accept-Encoding", "gzip, deflate"),
        ("Accept-Encoding", "br"),
        ("Content-Encoding", "gzip"),
        # WCF specific
        ("SOAPAction", "http://tempuri.org/IWdCpSrvc/SubmitReport"),
        ("SOAPAction", "SubmitReport"),
    ]

    # First, get a baseline
    try:
        status, body, resp_hdrs, latency = transport.send(payload)
        baseline_size = len(body)
        baseline_status = status
        logger.set_baseline(baseline_status, baseline_size)
        print(f"  Baseline: HTTP {baseline_status}, {baseline_size}B")
    except ConnectionError as e:
        print(f"  Baseline failed: {e}")
        return

    for i, (header, value) in enumerate(header_tests):
        probe_id = f"HDR-{i:03d}"
        try:
            status, body, resp_hdrs, latency = transport.send(
                payload, headers={header: value}
            )
            result = FuzzResult(
                module="headers",
                probe_id=probe_id,
                description=f"{header}: {value[:50]}",
                http_status=status,
                response_size=len(body),
                latency_ms=latency,
                response_headers=resp_hdrs,
                response_body_hex=body.hex()[:500] if body else "",
                decoded_fields=try_decode_response(body),
            )
            # Interesting if response differs from baseline
            if status == 200 and len(body) != baseline_size:
                result.interesting = True
                result.notes = f"Response size {len(body)}B differs from baseline {baseline_size}B"
            elif status != baseline_status:
                result.interesting = True
                result.notes = f"Status {status} differs from baseline {baseline_status}"
            # Check for new response headers
            for rh in resp_hdrs:
                rh_lower = rh.lower()
                if "maps" in rh_lower or "defender" in rh_lower or "debug" in rh_lower:
                    result.interesting = True
                    result.notes = f"Interesting response header: {rh}: {resp_hdrs[rh]}"
            logger.log(result)
        except ConnectionError as e:
            logger.log(FuzzResult(
                module="headers", probe_id=probe_id,
                description=f"{header}: {value[:50]}", error=str(e),
            ))
        time.sleep(delay)


def fuzz_spynet_fields(transport: FuzzTransport, config: MAPSConfig, logger: FuzzLogger, delay: float):
    """Probe unknown field ordinals in SpynetReport for server reactions."""
    print("\n[FIELD FUZZING] Probing unknown SpynetReport field ordinals...")

    builder = SpynetReportBuilder(config)

    # Known field ordinals from SF class — we want to test gaps and beyond
    known_ordinals = {
        10, 20, 30, 31, 32, 40, 43, 50, 60, 70, 80, 90, 100, 110, 120,
        130, 150, 160, 170, 180, 190, 200, 210, 220, 280, 290, 300, 310,
        320, 330, 340, 350, 360, 370, 380, 390, 400, 410, 470, 480, 490,
        530, 560, 580, 590, 600, 690, 700, 730, 830, 840, 850, 860, 870,
        880, 900, 910, 920, 930, 940, 960, 970, 980, 990, 1000, 1010,
        1020, 1030, 1040, 1050, 1060, 1070, 1080, 1090, 1100, 1110,
        1120, 1130, 1133, 1134, 1140, 1150, 1160, 1170, 1180, 1183,
        1189, 1190, 1191, 1192, 1195, 1198, 1201, 1204, 1207, 1210,
        1275, 1281, 1284, 1340, 1373, 1400, 1424, 1542,
    }

    # Probe fields in the gaps and beyond known max
    test_ordinals = []
    # Fill gaps between known ordinals
    for i in range(0, 1600, 10):
        if i not in known_ordinals:
            test_ordinals.append(i)
    # Beyond max known
    for i in range(1550, 2000, 10):
        test_ordinals.append(i)
    # Some specific interesting candidates
    test_ordinals.extend([1543, 1544, 1545, 1550, 1555, 1560, 1600, 1700, 1800, 1900, 2000])
    test_ordinals = sorted(set(test_ordinals))

    # Get baseline
    baseline_payload = build_minimal_heartbeat(config)
    try:
        bstatus, bbody, _, _ = transport.send(baseline_payload)
        baseline_size = len(bbody)
        logger.set_baseline(bstatus, baseline_size)
        print(f"  Baseline: HTTP {bstatus}, {baseline_size}B")
    except ConnectionError as e:
        print(f"  Baseline failed: {e}")
        return

    for ordinal in test_ordinals:
        probe_id = f"FLD-{ordinal}"
        try:
            # Build heartbeat with an extra unknown field injected
            w = CompactBinaryV1Writer()
            report_guid = str(uuid.uuid4())
            builder._write_top_level(w, report_guid)

            # Inject the unknown field as a STRING with a marker value
            w.write_string(ordinal, f"fuzz_probe_{ordinal}")

            w._write_byte(BondType.BT_STOP)
            payload = bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())

            status, body, resp_hdrs, latency = transport.send(payload)

            result = FuzzResult(
                module="fields",
                probe_id=probe_id,
                description=f"SpynetReport.F{ordinal} = STRING",
                http_status=status,
                response_size=len(body),
                latency_ms=latency,
                response_headers=resp_hdrs,
                decoded_fields=try_decode_response(body),
            )
            if status == 200 and len(body) != baseline_size:
                result.interesting = True
                result.notes = f"Response {len(body)}B differs from baseline {baseline_size}B — field F{ordinal} may be processed"
            elif status != bstatus:
                result.interesting = True
                result.notes = f"Status changed to {status} — field F{ordinal} caused different behavior"
            logger.log(result)
        except ConnectionError as e:
            logger.log(FuzzResult(
                module="fields", probe_id=probe_id,
                description=f"SpynetReport.F{ordinal}", error=str(e),
            ))
        time.sleep(delay)


def fuzz_response_fields(transport: FuzzTransport, config: MAPSConfig, logger: FuzzLogger, delay: float):
    """Analyze responses for undocumented fields by varying input."""
    print("\n[RESPONSE FIELD ANALYSIS] Probing for hidden response fields...")

    builder = SpynetReportBuilder(config)

    # Send various well-formed requests and analyze response field ordinals
    probes = [
        ("clean-file", lambda: builder.build_hash_query(sha256=hashlib.sha256(os.urandom(32)).hexdigest())),
        ("eicar-hash", lambda: builder.build_hash_query(
            sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            sha1="3395856ce81f2b7382dee72602f798b642f14140",
            md5="44d88612fea8a8f36de82e1278abb02f",
        )),
        ("heartbeat-0", lambda: builder.build_heartbeat(hb_type=0)),
        ("heartbeat-1", lambda: builder.build_heartbeat(hb_type=1)),
        ("url-google", lambda: builder.build_url_reputation_query("https://www.google.com")),
        ("url-malware", lambda: builder.build_url_reputation_query("http://malware.testing.google.test/testing/malware/")),
    ]

    all_seen_fields = {}

    for name, build_fn in probes:
        probe_id = f"RESP-{name}"
        try:
            payload = build_fn()
            status, body, resp_hdrs, latency = transport.send(payload)

            decoded = try_decode_response(body)
            result = FuzzResult(
                module="response_fields",
                probe_id=probe_id,
                description=f"Probe '{name}' response analysis",
                http_status=status,
                response_size=len(body),
                latency_ms=latency,
                response_headers=resp_hdrs,
                decoded_fields=decoded,
                response_body_hex=body.hex() if body else "",
            )

            # Track which field ordinals appear in responses
            if decoded:
                field_ids = set()
                _collect_field_ids(decoded, field_ids)
                for fid in field_ids:
                    if fid not in all_seen_fields:
                        all_seen_fields[fid] = []
                    all_seen_fields[fid].append(name)
                result.notes = f"Response fields: {sorted(field_ids)}"
                result.interesting = True  # Always log response analysis

            logger.log(result)
        except ConnectionError as e:
            logger.log(FuzzResult(
                module="response_fields", probe_id=probe_id,
                description=f"Probe '{name}'", error=str(e),
            ))
        time.sleep(delay)

    # Summary of all seen response fields
    if all_seen_fields:
        print(f"\n  Response field summary ({len(all_seen_fields)} unique ordinals):")
        for fid in sorted(all_seen_fields.keys()):
            probes_seen = all_seen_fields[fid]
            print(f"    F{fid}: seen in {len(probes_seen)} probes — {probes_seen}")


def _collect_field_ids(fields: dict, result: set, prefix: str = ""):
    """Recursively collect all field IDs from decoded Bond struct."""
    if not isinstance(fields, dict):
        return
    for fid, val in fields.items():
        if isinstance(fid, int):
            result.add(fid)
        if isinstance(val, tuple) and len(val) == 2:
            _, inner = val
            if isinstance(inner, dict):
                _collect_field_ids(inner, result)
            elif isinstance(inner, list):
                for item in inner:
                    if isinstance(item, dict):
                        _collect_field_ids(item, result)


def fuzz_schemas(transport: FuzzTransport, config: MAPSConfig, logger: FuzzLogger, delay: float):
    """Try alternative Bond schema names in the Bonded<T> envelope."""
    print("\n[SCHEMA FUZZING] Probing Bond schema name variations...")

    # Build a heartbeat payload body (without schema wrapping)
    w = CompactBinaryV1Writer()
    builder = SpynetReportBuilder(config)
    builder._write_top_level(w, str(uuid.uuid4()))
    w._write_byte(BondType.BT_STOP)
    inner_data = w.get_data()

    schemas = [
        # Known working
        SPYNET_REPORT_SCHEMA,
        # Variations
        "Microsoft.ProtectionServices.Entities.Raw.SpynetReportEntity",
        "Microsoft.ProtectionServices.Entities.SpynetReportEntity",
        "Microsoft.ProtectionServices.SpynetReportEntity",
        "Microsoft.ProtectionServices.Entities.Raw.SpynetReport",
        "Microsoft.ProtectionServices.Entities.Raw.HeartbeatReportEntity",
        "Microsoft.ProtectionServices.Entities.Raw.FileReportEntity",
        "Microsoft.ProtectionServices.Entities.Raw.UrlReportEntity",
        "Microsoft.ProtectionServices.Entities.Raw.SampleReportEntity",
        "Microsoft.ProtectionServices.Entities.Raw.BehaviorReportEntity",
        "Microsoft.ProtectionServices.Entities.Raw.TelemetryReportEntity",
        "Microsoft.ProtectionServices.Entities.Raw.RemediationReportEntity",
        "Microsoft.ProtectionServices.Entities.Raw.ConfigReportEntity",
        "Microsoft.ProtectionServices.Entities.Raw.EnrollmentEntity",
        "Microsoft.ProtectionServices.Entities.Raw.OnboardingEntity",
        "Microsoft.ProtectionServices.Entities.Raw.PolicyEntity",
        "Microsoft.ProtectionServices.Entities.Raw.SubmitSpynetReportResult",
        # Windows Defender namespace guesses
        "Microsoft.Windows.Defender.SpynetReport",
        "Microsoft.Windows.Defender.Entities.SpynetReport",
        "Microsoft.Antimalware.Entities.SpynetReport",
        # Empty/minimal
        "",
        "SpynetReportEntity",
        "SpynetReport",
    ]

    for i, schema in enumerate(schemas):
        probe_id = f"SCH-{i:03d}"
        try:
            payload = bond_wrap_with_schema(schema, inner_data)
            status, body, resp_hdrs, latency = transport.send(payload)

            result = FuzzResult(
                module="schemas",
                probe_id=probe_id,
                description=f"Schema: {schema[:70]}",
                http_status=status,
                response_size=len(body),
                latency_ms=latency,
                response_headers=resp_hdrs,
                decoded_fields=try_decode_response(body),
            )
            if status == 200 and schema != SPYNET_REPORT_SCHEMA:
                result.interesting = True
                result.notes = f"Alternative schema accepted!"
            logger.log(result)
        except ConnectionError as e:
            logger.log(FuzzResult(
                module="schemas", probe_id=probe_id,
                description=f"Schema: {schema[:70]}", error=str(e),
            ))
        time.sleep(delay)


def fuzz_endpoints(transport: FuzzTransport, config: MAPSConfig, logger: FuzzLogger, delay: float):
    """Discover endpoint hostname variations and geo endpoints."""
    print("\n[ENDPOINT FUZZING] Probing endpoint hostname variations...")

    payload = build_minimal_heartbeat(config)

    endpoints = [
        # Known
        MAPS_ENDPOINT_PROD,
        MAPS_ENDPOINT_ALT,
        MAPS_ENDPOINT_PPE,
        MAPS_FASTPATH_PROD,
        MAPS_FASTPATH_PPE,
        # Geo endpoints
        *MAPS_GEO_ENDPOINTS.values(),
        # Speculative variations
        "https://wdcp2.microsoft.com",
        "https://wdcp-v2.microsoft.com",
        "https://maps.microsoft.com",
        "https://defender.microsoft.com",
        "https://protection.microsoft.com",
        "https://spynet.microsoft.com",
        "https://cp.wd.microsoft.com",
        "https://wdcp.wd.microsoft.com",
        # Regional variations
        "https://eastus.cp.wd.microsoft.com",
        "https://westus.cp.wd.microsoft.com",
        "https://centralus.cp.wd.microsoft.com",
        "https://northeurope.cp.wd.microsoft.com",
        "https://westeurope.cp.wd.microsoft.com",
        "https://japan.cp.wd.microsoft.com",
        "https://india.cp.wd.microsoft.com",
        "https://brazil.cp.wd.microsoft.com",
        "https://canada.cp.wd.microsoft.com",
        "https://korea.cp.wd.microsoft.com",
        # Defender for Endpoint
        "https://winatp-gw-cus.microsoft.com",
        "https://winatp-gw-eus.microsoft.com",
    ]

    for i, endpoint in enumerate(endpoints):
        probe_id = f"EP-{i:03d}"
        try:
            status, body, resp_hdrs, latency = transport.send(
                payload, endpoint=endpoint
            )
            result = FuzzResult(
                module="endpoints",
                probe_id=probe_id,
                description=f"Endpoint: {endpoint}",
                http_status=status,
                response_size=len(body),
                latency_ms=latency,
                response_headers=resp_hdrs,
            )
            if status == 200:
                result.interesting = True
                result.notes = f"Endpoint reachable and accepted payload!"
            elif status in (301, 302, 307, 308):
                loc = resp_hdrs.get("Location", "")
                result.interesting = True
                result.notes = f"Redirect to: {loc}"
            logger.log(result)
        except ConnectionError as e:
            logger.log(FuzzResult(
                module="endpoints", probe_id=probe_id,
                description=f"Endpoint: {endpoint}", error=str(e)[:200],
            ))
        time.sleep(delay)


def fuzz_versions(transport: FuzzTransport, config: MAPSConfig, logger: FuzzLogger, delay: float):
    """Fuzz version strings to trigger different server behavior."""
    print("\n[VERSION FUZZING] Probing version string variations...")

    # Get baseline first
    payload = build_minimal_heartbeat(config)
    try:
        bstatus, bbody, _, _ = transport.send(payload)
        baseline_size = len(bbody)
        logger.set_baseline(bstatus, baseline_size)
        print(f"  Baseline: HTTP {bstatus}, {baseline_size}B")
    except ConnectionError as e:
        print(f"  Baseline failed: {e}")
        return

    version_tests = [
        # Very old platform versions
        ("platform", "4.1.0.0", "old_platform"),
        ("platform", "4.10.0.0", "legacy_platform"),
        ("platform", "4.18.0.0", "early_18_platform"),
        # Future/preview versions
        ("platform", "4.19.0.0", "future_platform_19"),
        ("platform", "5.0.0.0", "future_platform_5"),
        ("platform", "99.0.0.0", "absurd_platform"),
        # Engine variations
        ("engine", "1.0.0.0", "old_engine"),
        ("engine", "1.1.0.0", "early_engine"),
        ("engine", "1.1.99999.1", "future_engine"),
        ("engine", "2.0.0.0", "next_gen_engine"),
        # OS variations
        ("os", "6.1.7601", "win7"),
        ("os", "6.3.9600", "win81"),
        ("os", "10.0.14393", "win10_1607"),
        ("os", "10.0.17763", "win10_1809"),
        ("os", "10.0.19041", "win10_2004"),
        ("os", "10.0.22000", "win11_21h2"),
        ("os", "10.0.22621", "win11_22h2"),
        ("os", "10.0.22631", "win11_23h2"),
        ("os", "10.0.26100", "win11_24h2"),
        ("os", "10.0.99999", "future_os"),
        ("os", "11.0.0", "win12"),
        # Sig version variations
        ("sig", "1.0.0.0", "ancient_sigs"),
        ("sig", "1.445.0.0", "current_sigs"),
        ("sig", "1.999.0.0", "future_sigs"),
    ]

    for version_type, version_val, tag in version_tests:
        probe_id = f"VER-{tag}"
        try:
            # Clone config with modified version
            test_config = MAPSConfig(
                endpoint=config.endpoint,
                machine_guid=config.machine_guid,
                proxy=config.proxy,
                verify_ssl=config.verify_ssl,
                rotate_guid=True,
            )
            if version_type == "platform":
                test_config.app_version = version_val
            elif version_type == "engine":
                test_config.engine_version = version_val
            elif version_type == "os":
                test_config.os_ver = version_val
                parts = version_val.split(".")
                test_config.os_build = int(parts[-1]) if len(parts) >= 3 else 0
            elif version_type == "sig":
                test_config.av_sig_version = version_val

            test_builder = SpynetReportBuilder(test_config)
            test_payload = test_builder.build_heartbeat()

            # Use custom headers matching the version
            custom_headers = {}
            if version_type == "platform":
                from maps_scanner.client import encode_maps_version
                custom_headers["X-MS-MAPS-PLATFORMVERSION"] = encode_maps_version(version_val)
            elif version_type == "engine":
                from maps_scanner.client import encode_maps_version
                custom_headers["X-MS-MAPS-ENGINEVERSION"] = encode_maps_version(version_val)
            elif version_type == "os":
                from maps_scanner.client import encode_maps_version
                custom_headers["X-MS-MAPS-OSVERSION"] = encode_maps_version(version_val)

            status, body, resp_hdrs, latency = transport.send(
                test_payload, headers=custom_headers
            )

            result = FuzzResult(
                module="versions",
                probe_id=probe_id,
                description=f"{version_type}={version_val}",
                http_status=status,
                response_size=len(body),
                latency_ms=latency,
                response_headers=resp_hdrs,
                decoded_fields=try_decode_response(body),
            )
            if status == 200 and len(body) != baseline_size:
                result.interesting = True
                result.notes = f"Response {len(body)}B differs from baseline {baseline_size}B"
            elif status != bstatus:
                result.interesting = True
                result.notes = f"Status {status} differs from baseline {bstatus}"
            logger.log(result)
        except Exception as e:
            logger.log(FuzzResult(
                module="versions", probe_id=probe_id,
                description=f"{version_type}={version_val}", error=str(e)[:200],
            ))
        time.sleep(delay)


def fuzz_customer_types(transport: FuzzTransport, config: MAPSConfig, logger: FuzzLogger, delay: float):
    """Enumerate customer type header values."""
    print("\n[CUSTOMER TYPE FUZZING] Probing X-MS-MAPS-CUSTOMERTYPE values...")

    payload = build_minimal_heartbeat(config)

    types = [
        "Consumer", "Enterprise", "Government", "Education",
        "Partner", "OEM", "Trial", "Developer", "Internal",
        "Preview", "Insider", "MSFT", "Microsoft", "Server",
        "IoT", "HoloLens", "Xbox", "Surface", "Azure",
        "Intune", "SCCM", "MDATP", "MDE", "M365",
        "", "0", "1", "2", "3", "test", "debug",
    ]

    for i, ctype in enumerate(types):
        probe_id = f"CT-{i:03d}"
        try:
            status, body, resp_hdrs, latency = transport.send(
                payload, headers={"X-MS-MAPS-CUSTOMERTYPE": ctype}
            )
            result = FuzzResult(
                module="customer_types",
                probe_id=probe_id,
                description=f"CustomerType: {ctype!r}",
                http_status=status,
                response_size=len(body),
                latency_ms=latency,
                response_headers=resp_hdrs,
            )
            if status == 200 and ctype not in ("Consumer", "Enterprise"):
                result.interesting = True
                result.notes = f"Non-standard customer type accepted!"
            logger.log(result)
        except ConnectionError as e:
            logger.log(FuzzResult(
                module="customer_types", probe_id=probe_id,
                description=f"CustomerType: {ctype!r}", error=str(e)[:200],
            ))
        time.sleep(delay)


def fuzz_block_levels(transport: FuzzTransport, config: MAPSConfig, logger: FuzzLogger, delay: float):
    """Sweep all cloud block level values in payload."""
    print("\n[BLOCK LEVEL FUZZING] Sweeping CloudBlockLevel values...")

    # Known: 0=OFF, 1=MOD, 2=HIGH, 4=HIGH+, 6=ZERO_TOL
    # Test all values 0-10 plus some edge cases
    levels = list(range(0, 11)) + [16, 32, 64, 128, 255]

    for level in levels:
        probe_id = f"BL-{level}"
        try:
            test_config = MAPSConfig(
                endpoint=config.endpoint,
                machine_guid=config.machine_guid,
                proxy=config.proxy,
                verify_ssl=config.verify_ssl,
                cloud_block_level=level,
                rotate_guid=True,
            )
            builder = SpynetReportBuilder(test_config)
            # Use EICAR hash with different block levels to see if response differs
            payload = builder.build_hash_query(
                sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                sha1="3395856ce81f2b7382dee72602f798b642f14140",
                md5="44d88612fea8a8f36de82e1278abb02f",
            )

            status, body, resp_hdrs, latency = transport.send(payload)

            known = level in (0, 1, 2, 4, 6)
            result = FuzzResult(
                module="block_levels",
                probe_id=probe_id,
                description=f"CloudBlockLevel={level}{'(known)' if known else ''}",
                http_status=status,
                response_size=len(body),
                latency_ms=latency,
                response_headers=resp_hdrs,
                decoded_fields=try_decode_response(body),
            )
            if not known and status == 200:
                result.interesting = True
                result.notes = f"Unknown block level {level} accepted"
            logger.log(result)
        except Exception as e:
            logger.log(FuzzResult(
                module="block_levels", probe_id=probe_id,
                description=f"CloudBlockLevel={level}", error=str(e)[:200],
            ))
        time.sleep(delay)


def fuzz_heartbeat_types(transport: FuzzTransport, config: MAPSConfig, logger: FuzzLogger, delay: float):
    """Enumerate heartbeat subtypes beyond known 0-11."""
    print("\n[HEARTBEAT TYPE FUZZING] Probing heartbeat subtypes 0-30+...")

    builder = SpynetReportBuilder(config)

    # Known: 0-11. Probe up to 50 + edge cases
    types = list(range(0, 51)) + [64, 100, 128, 200, 255]

    # Get baseline (type 0)
    try:
        payload = builder.build_heartbeat(hb_type=0)
        bstatus, bbody, _, _ = transport.send(payload)
        baseline_size = len(bbody)
        logger.set_baseline(bstatus, baseline_size)
        print(f"  Baseline (type=0): HTTP {bstatus}, {baseline_size}B")
    except ConnectionError as e:
        print(f"  Baseline failed: {e}")
        return

    for hb_type in types:
        probe_id = f"HB-{hb_type:03d}"
        try:
            payload = builder.build_heartbeat(hb_type=hb_type)
            status, body, resp_hdrs, latency = transport.send(payload)

            known = hb_type <= 11
            result = FuzzResult(
                module="heartbeat_types",
                probe_id=probe_id,
                description=f"HeartbeatType={hb_type}{'(known)' if known else ''}",
                http_status=status,
                response_size=len(body),
                latency_ms=latency,
                response_headers=resp_hdrs,
                decoded_fields=try_decode_response(body),
            )
            if status == 200 and len(body) != baseline_size:
                result.interesting = True
                result.notes = f"Response {len(body)}B differs from baseline {baseline_size}B"
            elif not known and status == 200:
                result.notes = f"Unknown type {hb_type} accepted (same response size)"
            logger.log(result)
        except ConnectionError as e:
            logger.log(FuzzResult(
                module="heartbeat_types", probe_id=probe_id,
                description=f"HeartbeatType={hb_type}", error=str(e)[:200],
            ))
        time.sleep(delay)


def fuzz_hidden_features(transport: FuzzTransport, config: MAPSConfig, logger: FuzzLogger, delay: float):
    """Targeted probes designed to surface hidden/undocumented API features.

    Strategy: craft payloads that combine unusual but valid field combinations
    that real Defender wouldn't normally send together, then watch for
    differential responses (new fields, different sizes, new behavior).
    """
    print("\n[HIDDEN FEATURE DISCOVERY] Targeted combination probes...")

    builder = SpynetReportBuilder(config)
    eicar_sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    eicar_sha1 = "3395856ce81f2b7382dee72602f798b642f14140"
    eicar_md5 = "44d88612fea8a8f36de82e1278abb02f"

    # Get baseline for comparison
    try:
        bp = builder.build_hash_query(sha256=eicar_sha, sha1=eicar_sha1, md5=eicar_md5)
        bstatus, bbody, _, _ = transport.send(bp)
        baseline_eicar_size = len(bbody)
        bp2 = builder.build_heartbeat()
        _, bbody2, _, _ = transport.send(bp2)
        baseline_hb_size = len(bbody2)
        print(f"  Baseline EICAR: {baseline_eicar_size}B, Heartbeat: {baseline_hb_size}B")
    except ConnectionError as e:
        print(f"  Baseline failed: {e}")
        return

    probes: List[Tuple[str, str, callable]] = []

    # --- 1. IsMsftInternal=1: Does the server return extra data for internal clients? ---
    def _probe_msft_internal():
        w = CompactBinaryV1Writer()
        builder._write_top_level(w, str(uuid.uuid4()))
        w.write_list_begin(SF.IS_MSFT_INTERNAL, BondType.BT_UINT16, 1)
        w._write_varint(1)
        w.write_field_begin(BondType.BT_LIST, SF.FILE_REPORT_ELEMENTS)
        w._write_byte(BondType.BT_LIST); w._write_varint(1)
        w._write_byte(BondType.BT_STRUCT); w._write_varint(1)
        w._field_stack.append(0)
        w.write_list_begin(FRF.REVISION, BondType.BT_INT16, 1); w._write_varint(2)
        w.write_list_begin(FRF.INDEX, BondType.BT_INT16, 1); w._write_varint(2)
        w.write_list_begin(FRF.CORE_REPORT, BondType.BT_STRUCT, 1)
        w._field_stack.append(0)
        w.write_list_begin(CRF.REVISION, BondType.BT_INT16, 1); w._write_varint(2)
        w.write_string(CRF.FILE_NAME, "test.exe")
        w.write_string(CRF.SHA256, eicar_sha)
        w.write_string(CRF.SHA1, eicar_sha1)
        w.write_string(CRF.MD5, eicar_md5)
        w._write_byte(BondType.BT_STOP); w._field_stack.pop()
        w._write_byte(BondType.BT_STOP); w._field_stack.pop()
        w._write_byte(BondType.BT_STOP)
        return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())
    probes.append(("HF-msft-internal", "IsMsftInternal=1 with EICAR hash", _probe_msft_internal))

    # --- 2. TestHook field: Does server recognize test hooks? ---
    for hook_val in ["enabled", "debug", "verbose", "trace", "all", "1", "true",
                     "AllFeatures", "beta", "preview", "internal", "diag"]:
        def _probe_testhook(v=hook_val):
            w = CompactBinaryV1Writer()
            builder._write_top_level(w, str(uuid.uuid4()))
            w.write_string(SF.TEST_HOOK, v)
            w._write_byte(BondType.BT_STOP)
            return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())
        probes.append((f"HF-testhook-{hook_val}", f"TestHook='{hook_val}'", _probe_testhook))

    # --- 3. IsBeta=true: Different handling for beta clients? ---
    def _probe_beta():
        w = CompactBinaryV1Writer()
        builder._write_top_level(w, str(uuid.uuid4()))
        w.write_list_begin(SF.IS_BETA, BondType.BT_UINT8, 1)
        w._write_byte(1)
        w._write_byte(BondType.BT_STOP)
        return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())
    probes.append(("HF-beta", "IsBeta=true heartbeat", _probe_beta))

    # --- 4. QueryOnly field: Does this toggle a query-only mode? ---
    for qval in ["1", "true", "yes", "query", "readonly"]:
        def _probe_queryonly(v=qval):
            w = CompactBinaryV1Writer()
            builder._write_top_level(w, str(uuid.uuid4()))
            w.write_string(SF.QUERY_ONLY, v)
            w.write_field_begin(BondType.BT_LIST, SF.FILE_REPORT_ELEMENTS)
            w._write_byte(BondType.BT_LIST); w._write_varint(1)
            w._write_byte(BondType.BT_STRUCT); w._write_varint(1)
            w._field_stack.append(0)
            w.write_list_begin(FRF.REVISION, BondType.BT_INT16, 1); w._write_varint(2)
            w.write_list_begin(FRF.INDEX, BondType.BT_INT16, 1); w._write_varint(2)
            w.write_list_begin(FRF.CORE_REPORT, BondType.BT_STRUCT, 1)
            w._field_stack.append(0)
            w.write_list_begin(CRF.REVISION, BondType.BT_INT16, 1); w._write_varint(2)
            w.write_string(CRF.FILE_NAME, "test.exe")
            w.write_string(CRF.SHA256, eicar_sha)
            w._write_byte(BondType.BT_STOP); w._field_stack.pop()
            w._write_byte(BondType.BT_STOP); w._field_stack.pop()
            w._write_byte(BondType.BT_STOP)
            return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())
        probes.append((f"HF-queryonly-{qval}", f"QueryOnly='{qval}'", _probe_queryonly))

    # --- 5. MAPS_ORIGIN variations: Does origin affect routing/features? ---
    for origin in ["consumer", "enterprise", "mdatp", "mde", "intune", "sccm",
                    "wdav", "scep", "epp", "ioav", "smartscreen", "defender"]:
        def _probe_origin(v=origin):
            w = CompactBinaryV1Writer()
            builder._write_top_level(w, str(uuid.uuid4()))
            w.write_string(SF.MAPS_ORIGIN, v)
            w._write_byte(BondType.BT_STOP)
            return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())
        probes.append((f"HF-origin-{origin}", f"MapsOrigin='{origin}'", _probe_origin))

    # --- 6. Partner GUID: Does having a partner ID unlock features? ---
    def _probe_partner():
        w = CompactBinaryV1Writer()
        builder._write_top_level(w, str(uuid.uuid4()))
        w.write_string(SF.PARTNER_GUID, str(uuid.uuid4()))
        w._write_byte(BondType.BT_STOP)
        return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())
    probes.append(("HF-partner", "PartnerGuid set", _probe_partner))

    # --- 7. Entra path with consumer payload: Does it handle differently? ---
    def _probe_entra_path():
        return builder.build_heartbeat()
    probes.append(("HF-entra-path", "Heartbeat via /wdcp.svc/entraReport", _probe_entra_path))

    # --- 8. Supported compression field: Does declaring compression change response? ---
    for comp in ["gzip", "deflate", "br", "zstd", "lz4", "snappy"]:
        def _probe_compress(v=comp):
            w = CompactBinaryV1Writer()
            builder._write_top_level(w, str(uuid.uuid4()))
            w.write_string(SF.SUPPORTED_COMPRESS, v)
            w._write_byte(BondType.BT_STOP)
            return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())
        probes.append((f"HF-compress-{comp}", f"SupportedCompress='{comp}'", _probe_compress))

    # --- 9. VDI_TYPE: Virtual desktop infrastructure type ---
    for vdi in [0, 1, 2, 3, 4, 5, 10, 100]:
        def _probe_vdi(v=vdi):
            w = CompactBinaryV1Writer()
            builder._write_top_level(w, str(uuid.uuid4()))
            w.write_int32(SF.VDI_TYPE, v)
            w._write_byte(BondType.BT_STOP)
            return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())
        probes.append((f"HF-vdi-{vdi}", f"VdiType={vdi}", _probe_vdi))

    # --- 10. IsPassiveMode: Passive mode scanning ---
    def _probe_passive():
        w = CompactBinaryV1Writer()
        builder._write_top_level(w, str(uuid.uuid4()))
        w.write_bool(SF.IS_PASSIVE_MODE, True)
        w.write_field_begin(BondType.BT_LIST, SF.FILE_REPORT_ELEMENTS)
        w._write_byte(BondType.BT_LIST); w._write_varint(1)
        w._write_byte(BondType.BT_STRUCT); w._write_varint(1)
        w._field_stack.append(0)
        w.write_list_begin(FRF.REVISION, BondType.BT_INT16, 1); w._write_varint(2)
        w.write_list_begin(FRF.INDEX, BondType.BT_INT16, 1); w._write_varint(2)
        w.write_list_begin(FRF.CORE_REPORT, BondType.BT_STRUCT, 1)
        w._field_stack.append(0)
        w.write_list_begin(CRF.REVISION, BondType.BT_INT16, 1); w._write_varint(2)
        w.write_string(CRF.FILE_NAME, "test.exe")
        w.write_string(CRF.SHA256, eicar_sha)
        w._write_byte(BondType.BT_STOP); w._field_stack.pop()
        w._write_byte(BondType.BT_STOP); w._field_stack.pop()
        w._write_byte(BondType.BT_STOP)
        return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())
    probes.append(("HF-passive", "IsPassiveMode=true with EICAR", _probe_passive))

    # --- 11. AsimovDeviceTicket: Does an Asimov token unlock telemetry features? ---
    def _probe_asimov():
        w = CompactBinaryV1Writer()
        builder._write_top_level(w, str(uuid.uuid4()))
        w.write_string(SF.ASIMOV_DEVICE_TICKET, "test-asimov-ticket-" + str(uuid.uuid4()))
        w.write_string(SF.DEVICE_ID, str(uuid.uuid4()))
        w._write_byte(BondType.BT_STOP)
        return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())
    probes.append(("HF-asimov", "AsimovDeviceTicket + DeviceId set", _probe_asimov))

    # --- 12. Multiple file reports: Does server handle >1 file differently? ---
    def _probe_multi_file():
        w = CompactBinaryV1Writer()
        builder._write_top_level(w, str(uuid.uuid4()))
        w.write_field_begin(BondType.BT_LIST, SF.FILE_REPORT_ELEMENTS)
        w._write_byte(BondType.BT_LIST); w._write_varint(1)
        w._write_byte(BondType.BT_STRUCT); w._write_varint(3)  # 3 files
        for idx in range(3):
            w._field_stack.append(0)
            w.write_list_begin(FRF.REVISION, BondType.BT_INT16, 1); w._write_varint(2)
            w.write_list_begin(FRF.INDEX, BondType.BT_INT16, 1)
            w._write_varint((idx + 1) * 2)
            w.write_list_begin(FRF.CORE_REPORT, BondType.BT_STRUCT, 1)
            w._field_stack.append(0)
            w.write_list_begin(CRF.REVISION, BondType.BT_INT16, 1); w._write_varint(2)
            w.write_string(CRF.FILE_NAME, f"file{idx}.exe")
            h = hashlib.sha256(f"fuzz-multi-{idx}".encode()).hexdigest()
            w.write_string(CRF.SHA256, h)
            w._write_byte(BondType.BT_STOP); w._field_stack.pop()
            w._write_byte(BondType.BT_STOP); w._field_stack.pop()
        w._write_byte(BondType.BT_STOP)
        return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())
    probes.append(("HF-multifile", "3 FileReports in single request", _probe_multi_file))

    # --- 13. CloudBlockLevel in payload body: Sweep non-standard values ---
    for lvl in [3, 5, 7, 8, 10, 15, 16, 32, 50, 100]:
        def _probe_cbl(v=lvl):
            w = CompactBinaryV1Writer()
            builder._write_top_level(w, str(uuid.uuid4()))
            w.write_uint32(SF.CLOUD_BLOCK_LEVEL, v)
            w.write_field_begin(BondType.BT_LIST, SF.FILE_REPORT_ELEMENTS)
            w._write_byte(BondType.BT_LIST); w._write_varint(1)
            w._write_byte(BondType.BT_STRUCT); w._write_varint(1)
            w._field_stack.append(0)
            w.write_list_begin(FRF.REVISION, BondType.BT_INT16, 1); w._write_varint(2)
            w.write_list_begin(FRF.INDEX, BondType.BT_INT16, 1); w._write_varint(2)
            w.write_list_begin(FRF.CORE_REPORT, BondType.BT_STRUCT, 1)
            w._field_stack.append(0)
            w.write_list_begin(CRF.REVISION, BondType.BT_INT16, 1); w._write_varint(2)
            w.write_string(CRF.FILE_NAME, "test.exe")
            w.write_string(CRF.SHA256, eicar_sha)
            w._write_byte(BondType.BT_STOP); w._field_stack.pop()
            w._write_byte(BondType.BT_STOP); w._field_stack.pop()
            w._write_byte(BondType.BT_STOP)
            return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())
        probes.append((f"HF-cbl-{lvl}", f"CloudBlockLevel={lvl} with EICAR", _probe_cbl))

    # Run all probes
    for probe_id, desc, build_fn in probes:
        try:
            payload = build_fn()
            # Use entra path for the entra probe
            path = MAPS_ENTRA_PATH if "entra-path" in probe_id else MAPS_BOND_PATH
            status, body, resp_hdrs, latency = transport.send(payload, path=path)

            decoded = try_decode_response(body)
            result = FuzzResult(
                module="hidden_features",
                probe_id=probe_id,
                description=desc,
                http_status=status,
                response_size=len(body),
                latency_ms=latency,
                response_headers=resp_hdrs,
                decoded_fields=decoded,
                response_body_hex=body.hex()[:500] if body else "",
            )

            # Check for interesting differential
            is_hb_probe = "heartbeat" in desc.lower() or "Beta" in desc or "Origin" in desc
            compare_size = baseline_hb_size if is_hb_probe else baseline_eicar_size

            if status == 200 and len(body) != compare_size:
                result.interesting = True
                result.notes = f"Response {len(body)}B vs baseline {compare_size}B — DIFFERENT!"
            elif status != 200:
                result.interesting = True
                result.notes = f"Non-200 status: {status}"

            # Check for new response fields not in standard set
            if decoded:
                field_ids = set()
                _collect_field_ids(decoded, field_ids)
                known_resp = {3, 5, 6, 10, 20}  # standard response ordinals
                novel = field_ids - known_resp
                if novel:
                    result.interesting = True
                    result.notes = (result.notes or "") + f" Novel response fields: {sorted(novel)}"

            logger.log(result)
        except Exception as e:
            logger.log(FuzzResult(
                module="hidden_features", probe_id=probe_id,
                description=desc, error=str(e)[:200],
            ))
        time.sleep(delay)


def fuzz_bond_wire_types(transport: FuzzTransport, config: MAPSConfig, logger: FuzzLogger, delay: float):
    """Send known fields with unexpected Bond wire types to probe parsing."""
    print("\n[BOND TYPE FUZZING] Sending fields with unexpected wire types...")

    builder = SpynetReportBuilder(config)

    # For each test, we'll build a heartbeat-like payload but override
    # one field with a different Bond wire type
    wire_type_tests = [
        # (field_ordinal, wire_type, value_bytes, description)
        # Send MACHINE_GUID (normally STRING) as different types
        (30, BondType.BT_UINT32, b'\x01', "MachineGuid as UINT32"),
        (30, BondType.BT_LIST, bytes([BondType.BT_STRING, 1]) + b'\x24' + str(uuid.uuid4()).encode(), "MachineGuid as LIST<STRING>"),
        (30, BondType.BT_WSTRING, b'\x24' + str(uuid.uuid4()).encode('utf-16-le'), "MachineGuid as WSTRING"),
        # Send REVISION (normally LIST<INT16>) as different types
        (20, BondType.BT_INT16, b'\x06', "Revision as INT16 directly"),
        (20, BondType.BT_STRING, b'\x01\x33', "Revision as STRING '3'"),
        (20, BondType.BT_UINT32, b'\x03', "Revision as UINT32"),
        # Send OS_BUILD (normally LIST<UINT32>) as INT32
        (170, BondType.BT_INT32, b'\x80\x82\x03', "OsBuild as INT32"),
        (170, BondType.BT_STRING, b'\x05\x32\x36\x31\x30\x30', "OsBuild as STRING"),
        # Send IS_HEARTBEAT with different values
        (90, BondType.BT_UINT8, b'\x00', "IsHeartbeat=0"),
        (90, BondType.BT_UINT8, b'\x01', "IsHeartbeat=1"),
        (90, BondType.BT_UINT8, b'\x02', "IsHeartbeat=2"),
        (90, BondType.BT_UINT8, b'\xFF', "IsHeartbeat=255"),
        # IS_MSFT_INTERNAL flag (LIST<UINT16> on wire)
        (580, BondType.BT_LIST, b'\x04\x01\x01', "IsMsftInternal=1 LIST<UINT16>"),
        (580, BondType.BT_LIST, b'\x04\x01\x00', "IsMsftInternal=0 LIST<UINT16>"),
        # TEST_HOOK (STRING field 590)
        (590, BondType.BT_STRING, b'\x04test', "TestHook='test'"),
        (590, BondType.BT_STRING, b'\x05debug', "TestHook='debug'"),
        (590, BondType.BT_STRING, b'\x08internal', "TestHook='internal'"),
        # IS_BETA flag (LIST<UINT8> on wire)
        (910, BondType.BT_LIST, b'\x03\x01\x01', "IsBeta=1 LIST<UINT8>"),
        (910, BondType.BT_LIST, b'\x03\x01\x00', "IsBeta=0 LIST<UINT8>"),
    ]

    # Get baseline
    baseline_payload = build_minimal_heartbeat(config)
    try:
        bstatus, bbody, _, _ = transport.send(baseline_payload)
        baseline_size = len(bbody)
        logger.set_baseline(bstatus, baseline_size)
        print(f"  Baseline: HTTP {bstatus}, {baseline_size}B")
    except ConnectionError as e:
        print(f"  Baseline failed: {e}")
        return

    for i, (ordinal, btype, value_bytes, desc) in enumerate(wire_type_tests):
        probe_id = f"BWT-{i:03d}"
        try:
            # Build minimal payload manually with the injected field
            w = CompactBinaryV1Writer()

            # Write minimal top-level fields
            w.write_string(SF.MACHINE_GUID, str(uuid.uuid4()))
            w.write_string(SF.AV_SIG_VERSION, config.av_sig_version)
            w.write_string(SF.ENGINE_VERSION, config.engine_version)
            w.write_string(SF.OS_VER, "10.0.0.0")
            w.write_string(SF.APP_VERSION, config.app_version)

            # Inject the test field
            w.write_field_begin(btype, ordinal)
            w._write(value_bytes)

            w._write_byte(BondType.BT_STOP)
            payload = bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())

            status, body, resp_hdrs, latency = transport.send(payload)

            result = FuzzResult(
                module="bond_types",
                probe_id=probe_id,
                description=desc,
                http_status=status,
                response_size=len(body),
                latency_ms=latency,
                response_headers=resp_hdrs,
                decoded_fields=try_decode_response(body),
            )
            if status == 200 and len(body) != baseline_size:
                result.interesting = True
                result.notes = f"Response {len(body)}B differs from baseline {baseline_size}B"
            elif status != bstatus:
                result.interesting = True
                result.notes = f"Status changed from {bstatus} to {status}"
            logger.log(result)
        except Exception as e:
            logger.log(FuzzResult(
                module="bond_types", probe_id=probe_id,
                description=desc, error=str(e)[:200],
            ))
        time.sleep(delay)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

MODULES = {
    "paths": fuzz_paths,
    "report-types": fuzz_report_types,
    "headers": fuzz_headers,
    "fields": fuzz_spynet_fields,
    "response-fields": fuzz_response_fields,
    "schemas": fuzz_schemas,
    "endpoints": fuzz_endpoints,
    "versions": fuzz_versions,
    "customer-types": fuzz_customer_types,
    "block-levels": fuzz_block_levels,
    "heartbeat-types": fuzz_heartbeat_types,
    "bond-types": fuzz_bond_wire_types,
    "hidden": fuzz_hidden_features,
}


def main():
    parser = argparse.ArgumentParser(
        description="MAPS API Fuzzer — Feature Discovery & Attack Surface Enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modules:
  paths             Fuzz URL paths for undiscovered endpoints
  report-types      Try report type values beyond known 1-7
  headers           Enumerate custom HTTP headers and values
  fields            Probe unknown Bond field ordinals in SpynetReport
  response-fields   Analyze response fields across different request types
  schemas           Try alternative Bond schema names
  endpoints         Discover endpoint hostname variations
  versions          Fuzz version strings for behavior changes
  customer-types    Enumerate customer type header values
  block-levels      Sweep all cloud block level values
  heartbeat-types   Enumerate heartbeat subtypes beyond known 0-11
  bond-types        Send fields with unexpected Bond wire types
  all               Run all modules sequentially

Examples:
  python fuzz_maps.py paths
  python fuzz_maps.py --delay 2.0 --verbose all
  python fuzz_maps.py --proxy http://127.0.0.1:8080 --no-verify headers
  python fuzz_maps.py --ppe report-types
  python fuzz_maps.py --endpoint https://custom.endpoint.com fields
""")

    parser.add_argument("module", choices=list(MODULES.keys()) + ["all"],
                        help="Fuzz module to run")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show all probe results (not just interesting)")
    parser.add_argument("-d", "--delay", type=float, default=1.0,
                        help="Delay between requests in seconds (default: 1.0)")
    parser.add_argument("-o", "--output", default="fuzz_results",
                        help="Output directory for results (default: fuzz_results)")
    parser.add_argument("--endpoint", default=MAPS_ENDPOINT_PROD,
                        help="MAPS endpoint URL")
    parser.add_argument("--ppe", action="store_true",
                        help="Use pre-production endpoint")
    parser.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable TLS certificate verification")
    parser.add_argument("--timeout", type=int, default=15,
                        help="Request timeout in seconds (default: 15)")
    parser.add_argument("--machine-guid", help="Override machine GUID")
    parser.add_argument("--bearer-token", help="Enterprise AAD Bearer token")
    parser.add_argument("--customer-type", default="Consumer",
                        help="Customer type header (default: Consumer)")

    args = parser.parse_args()

    if not HAS_REQUESTS:
        print("ERROR: 'requests' library required. Install with: pip install requests")
        sys.exit(1)

    # Build config
    endpoint = MAPS_ENDPOINT_PPE if args.ppe else args.endpoint
    config = MAPSConfig(
        endpoint=endpoint,
        proxy=args.proxy,
        verify_ssl=not args.no_verify,
        timeout=args.timeout,
        customer_type=args.customer_type,
        rotate_guid=True,
    )
    if args.machine_guid:
        config.machine_guid = args.machine_guid
    if args.bearer_token:
        config.bearer_token = args.bearer_token

    transport = FuzzTransport(config)
    logger = FuzzLogger(output_dir=args.output, verbose=args.verbose)

    print(f"MAPS API Fuzzer")
    print(f"  Endpoint: {config.endpoint}")
    print(f"  Delay: {args.delay}s between probes")
    print(f"  Output: {args.output}/")
    if args.proxy:
        print(f"  Proxy: {args.proxy}")

    if args.module == "all":
        for name, func in MODULES.items():
            print(f"\n{'='*60}")
            print(f"Running module: {name}")
            print(f"{'='*60}")
            module_logger = FuzzLogger(output_dir=args.output, verbose=args.verbose)
            try:
                func(transport, config, module_logger, args.delay)
            except KeyboardInterrupt:
                print("\n  Interrupted!")
            except Exception as e:
                print(f"  Module error: {e}")
            module_logger.save(name)
            logger.results.extend(module_logger.results)
        logger.save_summary()
    else:
        try:
            MODULES[args.module](transport, config, logger, args.delay)
        except KeyboardInterrupt:
            print("\n  Interrupted!")
        logger.save(args.module)
        logger.save_summary()


if __name__ == "__main__":
    main()
