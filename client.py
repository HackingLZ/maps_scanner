"""
MAPS Cloud Client - Windows Defender Active Protection Service

Implements the SpynetReport protocol for querying Microsoft's MAPS cloud
for file reputation, dynamic signature delivery, and URL reputation.

Bond field ordinals extracted from mpengine.dll via RTTI vtable analysis.
Bond wire types verified against raw schema descriptor tables.
"""

import hashlib
import json
import os
import struct
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from .bond import (
    BOND_CB1_MARSHAL_HEADER,
    BondType,
    CompactBinaryV1Reader,
    CompactBinaryV1Writer,
    bond_deserialize,
    bond_marshal,
    bond_marshal_with_schema,
    bond_unmarshal_with_schema,
    bond_wrap_with_schema,
    bond_pretty_print,
    bond_serialize,
)

# Try optional dependencies
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import ssdeep
    HAS_SSDEEP = True
except ImportError:
    HAS_SSDEEP = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# MAPS endpoints (from Windows registry SpyNetReportingLocation)
MAPS_ENDPOINT_PROD = "https://wdcp.microsoft.com"
MAPS_ENDPOINT_ALT = "https://wdcpalt.microsoft.com"
MAPS_ENDPOINT_PPE = "https://fastpath.wdcpppe.microsoft.com"

# Bond protocol URL path
MAPS_BOND_PATH = "/wdcp.svc/bond/submitreport"
MAPS_REST_PATH = "/wdcp.svc/submitReport"
MAPS_ENTRA_PATH = "/wdcp.svc/entraReport"

# Fastpath (DSS/SDN signature delivery) - separate from report submission
MAPS_FASTPATH_PROD = "https://fastpath.wdcp.microsoft.com"
MAPS_FASTPATH_PPE = "https://fastpath.wdcpppe.microsoft.com"

# Geo-affinity endpoints
MAPS_GEO_ENDPOINTS = {
    "us": "https://unitedstates.cp.wd.microsoft.com",
    "eu": "https://europe.cp.wd.microsoft.com",
    "uk": "https://unitedkingdom.cp.wd.microsoft.com",
    "au": "https://australia.cp.wd.microsoft.com",
}

# Bond schema name for the Bonded<T> envelope
SPYNET_REPORT_SCHEMA = "Microsoft.ProtectionServices.Entities.Raw.SpynetReportEntity"

# Report types (CoreReport.ReportType)
class ReportType(IntEnum):
    ASYNC_LOWFI = 1
    SYNC_LOWFI = 2
    TELEMETRY_ONLY = 3
    HEARTBEAT = 4
    URL_REPUTATION = 5
    SAMPLE_REQUEST = 6
    WDO_REPORT = 7

# Heartbeat subtypes (inferred from MpClient.dll exports + MpSvc.dll CHeartbeatManager)
class HeartbeatType(IntEnum):
    STILL_ALIVE = 0      # Standard periodic heartbeat (default)
    SETUP = 1            # Initial setup/first-run heartbeat
    UNINSTALL = 2        # Triggered by MpTriggerHeartbeatOnUninstall
    ERROR = 3            # Triggered by MpTriggerErrorHeartbeatReport
    POLICY_CHANGE = 4    # Configuration/policy update
    BROWSER = 5          # Browser protection (MpSendBrowserHeartbeat)
    EXCLUSION = 6        # Exclusion list change
    CLEANUP = 7          # Post-remediation cleanup
    SIGNATURE_UPDATE = 8 # After signature update
    PLATFORM_UPDATE = 9  # After platform/engine update
    TAMPER_PROTECT = 10  # Tamper protection event
    REBOOT = 11          # Post-reboot heartbeat


# Cloud block levels
class CloudBlockLevel(IntEnum):
    OFF = 0
    DEFAULT = 0
    MODERATE = 1
    HIGH = 2
    HIGH_PLUS = 4
    ZERO_TOLERANCE = 6

# SpyNet reporting levels
class SpynetLevel(IntEnum):
    DISABLED = 0
    BASIC = 1
    ADVANCED = 2


# ---------------------------------------------------------------------------
# Schema definitions — Bond field ordinals & wire types
#
# Extracted from mpengine.dll via RTTI + vtable[0] schema descriptor tables.
# Wire types verified against raw packed values in the binary.
#
# Type_raw=266 (0x10A) = nested struct reference:
#   extra1="List" → BT_LIST of BT_STRUCT
#   extra1=<ClassName> → BT_STRUCT (single nested struct)
# ---------------------------------------------------------------------------

class SF:
    """SpynetReport field ordinals (from RE - 372 fields total).

    Wire types: STRING=9, INT16=15, INT32=16, INT64=17, UINT8=3,
    UINT32=5, UINT64=6, BOOL=2, 266=nested struct ref.
    """
    # --- Core identity & timestamps ---
    REPORT_TIME          = 10    # INT64  (DateTime ticks)
    REVISION             = 20    # INT16
    MACHINE_GUID         = 30    # STRING (GUID format)
    MACHINE_GUID_SCRUB   = 31    # STRING
    RAW_MACHINE_GUID     = 32    # STRING (GUID)
    AV_SIG_VERSION       = 40    # STRING
    AS_SIG_VERSION       = 43    # STRING
    SIG_VERSION          = 50    # STRING
    ENGINE_VERSION       = 60    # STRING
    NRI_SIG_VERSION      = 70    # STRING
    NRI_ENGINE_VERSION   = 80    # STRING

    # --- Flags ---
    IS_HEARTBEAT         = 90    # UINT8  (byte)

    # --- Nested reports ---
    BEHAVIOR_REPORT      = 100   # 266 (BehaviorReport)
    MEMORY_REPORT        = 110   # 266 (MemoryReport)
    STRING_REPORT        = 120   # 266 (List)

    # --- System info ---
    DEP                  = 130   # UINT8
    OS_VER               = 150   # STRING
    IE_VER               = 160   # STRING
    OS_BUILD             = 170   # UINT32 (uint)
    OS_SUITE             = 180   # INT32
    OS_TYPE              = 190   # INT16  (short)
    GEO_ID               = 200   # INT32  (int)
    LC_ID                = 210   # UINT32
    PROCESSOR            = 220   # UINT16

    # --- Identity ---
    PRODUCT_GUID         = 280   # STRING (GUID)
    MEMBERSHIP           = 290   # STRING
    APP_VERSION          = 300   # STRING
    SYS_MARKER           = 310   # STRING
    SYS_MFG              = 320   # STRING
    SYS_MODEL            = 330   # STRING
    QUERY_ONLY           = 340   # STRING
    SPYNET_REPORT_GUID   = 350   # STRING (GUID)
    LOCATION             = 360   # INT32
    IP_ADDRESS           = 370   # STRING
    VIA                  = 380   # STRING

    # --- File & signature reports ---
    FILE_REPORT_ELEMENTS = 390   # 266 (List<FileReport>)
    SIGNATURE_REQUESTS   = 400   # 266 (List)
    HARDWARE_ELEMENT     = 410   # 266 (HardwareElement)

    # --- Additional identity ---
    NONCE                = 470   # STRING
    SMART_SCREEN         = 480   # STRING
    FIREWALL             = 490   # BOOL
    UNIQUE_ID            = 530   # STRING (GUID)
    USERS                = 560   # 266 (List)
    IS_MSFT_INTERNAL     = 580   # UINT16 (LIST-wrapped on wire)
    TEST_HOOK            = 590   # STRING
    DRIVER_DATA          = 600   # 266 (DriverData)

    # --- Partner ---
    PARTNER_GUID         = 730   # STRING (GUID)

    # --- MAPS origin ---
    MAPS_ORIGIN          = 690   # STRING
    OS_PRODUCT_TYPE      = 700   # UINT64

    # --- Remediation & diagnostics ---
    REMEDIATION_REPORTS  = 900   # 266 (List<RemediationCheckpointReport>)
    IS_BETA              = 910   # UINT8 (LIST-wrapped on wire)

    # --- MAPS latency (RE'd by ac80320 agent) ---
    MAPS_GENERATE_LATENCY = 830  # UINT64
    MAPS_SEND_LATENCY    = 840   # UINT64
    MAPS_PARSE_LATENCY   = 850   # UINT64
    MAPS_HRESULT         = 860   # STRING
    BM_NOTIFICATION_COUNT = 870  # STRING
    BM_START_TIME        = 880   # UINT64

    # --- Heartbeat (RE'd by ac80320 agent: ordinals 900-1210+) ---
    REMEDIATION_CKPT_RPT = 900   # 266 (RemediationCheckpointReports)
    # IS_BETA already defined above at ordinal 910
    STILL_ALIVE_HB       = 920   # UINT8
    HB_CONTROL_GROUP     = 930   # UINT8
    HB_SUBTYPE           = 940   # UINT8

    # --- Telemetry ---
    SPYNET_COL_ERRORS    = 960   # 266 (SpynetCollectionErrors)
    SAMPLES              = 970   # 266 (Samples)
    HEARTBEAT_ERRORS     = 980   # 266 (HeartbeatErrors)
    EXCLUSIONS           = 990   # 266 (Exclusions)
    DEPRECATED_RTP_STATE = 1000  # STRING
    RTP_STATE_BITFIELD   = 1010  # UINT16
    RTP_HRESULT          = 1020  # UINT32
    OA_HRESULT           = 1030  # UINT32
    BM_HRESULT           = 1040  # UINT32

    # --- Engine report ---
    ENGINE_REPORT_GUID   = 1050  # STRING (GUID)
    MAPS_REPORT_GUID     = 1060  # STRING (GUID)
    REMEDIATION_STATUS   = 1070  # 266 (RemediationStatusReportElements)
    DEFAULT_BROWSERS     = 1080  # 266 (DefaultBrowsers)
    BACKEND_METADATA     = 1090  # 266 (BackendMetadata)
    ENGINE_LOAD_FILETIME = 1100  # UINT64
    THREAD_THREAT_RPTS   = 1110  # 266 (ThreadThreatReports)
    SIG_BACKUP_DISABLED  = 1120  # UINT32
    ASIMOV_DEVICE_TICKET = 1130  # STRING
    DEVICE_ID            = 1133  # STRING
    DEVICE_ID_SCRUBBED   = 1134  # STRING
    SIG_UPDATE_TIME      = 1140  # UINT64
    BM_PROCESS_ARG_COUNT = 1150  # UINT64
    MPUT_DATA            = 1160  # 266 (MputData)
    FILE_ASSOCIATIONS    = 1170  # 266 (FileAssociations)
    WINDOWS_UPDATE_STATUS = 1180 # 266 (WindowsUpdateStatus)
    MP_FILTER_HB_FLAGS   = 1183  # UINT32
    SCAN_CONFIG_FLAGS    = 1189  # UINT32
    NETWORK_CONN_ELEMENTS = 1190 # 266 (LIST<STRUCT> NetworkConnectionReport)
    NETWORK_CONN_V2      = 1191  # 266 (LIST<STRUCT> NetworkConnectionReportV2)
    RTP_CONFIG_FLAGS     = 1192  # UINT32
    MAPS_CONN_CREATE_TIME = 1195 # UINT32
    MAPS_SEND_REQ_TIME   = 1198  # UINT32
    MAPS_SEND_OVERHEAD   = 1201  # UINT32
    MAPS_SEND_URL_ATTEMPTS = 1204 # UINT32
    MAPS_RECV_RESP_TIME  = 1207  # UINT32
    MAPS_SEND_START_TICK = 1210  # UINT32

    # --- AMSI UAC & Config ---
    AMSI_UAC_INFOS       = 1275  # 266 (LIST<STRUCT> AmsiUacInfo, 30 fields)
    AUTO_SAMPLE_OPT_IN   = 1281  # INT32
    SIG_UPDATES_SINCE_HB = 1284  # STRING
    SUPPORTED_COMPRESS   = 1340  # STRING
    CLOUD_BLOCK_LEVEL    = 1373  # UINT32
    IS_PASSIVE_MODE      = 1400  # BOOL
    VDI_TYPE             = 1424  # INT32

    # --- URL report ---
    URL_REPORT           = 1542  # 266 (UrlReport)


class FRF:
    """Bond_FileReport field ordinals (12 fields)."""
    REVISION             = 10    # INT16
    INDEX                = 20    # INT16
    CORE_REPORT          = 30    # 266 (CoreReportElement - single struct)
    PREVALENT_FILE_RPT   = 40    # 266 (PrevalentFileReport)
    RELATED_TO           = 50    # INT32
    PERSISTED_INFO       = 60    # 266 (PersistedInfo)
    PREVALENT_URL_RPT    = 70    # 266 (PrevalentUrlReport)
    PARENT_INDICES       = 80    # STRING
    CHILD_INDICES        = 90    # STRING
    PREVALENT_STATS      = 100   # 266 (List)
    ASSOCIATED_FILE_RPT  = 103   # INT16
    COLLECT_REASON       = 106   # INT32


class CRF:
    """Bond_CoreReport field ordinals (239 fields - key fields shown).

    All hash fields are STRING type. Sizes are INT64.
    """
    REVISION             = 10    # INT16
    FILE_NAME            = 20    # STRING
    FILE_NAME_SCRUB      = 21    # STRING
    FILE_SYSTEM          = 30    # STRING
    SIZE                 = 40    # INT64
    HASHES_SIZE          = 43    # INT64
    FUZZY_HASHES_SIZE    = 46    # INT64
    PARTIAL_CRC2         = 50    # STRING
    PARTIAL_CRC1         = 60    # STRING
    PARTIAL_CRC3         = 70    # STRING
    PARTIAL_CRC3F        = 73    # STRING
    MD5                  = 80    # STRING
    SHA1                 = 90    # STRING
    SHA256               = 100   # STRING
    LSHASH               = 110   # STRING
    LSHASHS              = 120   # STRING
    VERSION              = 130   # STRING
    TYPE                 = 140   # STRING
    PUBLISHER            = 150   # STRING
    SIGNER               = 160   # STRING
    SIGNER_HASH          = 170   # STRING
    ISSUER               = 180   # STRING
    ISSUER_HASH          = 190   # STRING
    DESC                 = 200   # STRING (FileDescription)
    ORIGINAL_NAME        = 210   # STRING
    ORIGINAL_NAME_SCRUB  = 211   # STRING
    NAME                 = 220   # STRING (ProductName)
    NAME_SCRUB           = 221   # STRING
    THREAT_ID            = 230   # UINT32
    THREAT_NAME          = 233   # STRING
    CHECKSUM             = 270   # STRING
    KCRC1                = 290   # STRING
    KCRC2                = 300   # STRING
    KCRC3                = 310   # STRING
    KCRC3N               = 320   # STRING
    REPORT_TYPE          = 340   # UINT32 (ReportType enum)
    DETERMINATION        = 370   # INT16 (via extraction)
    ACTION_STATUS        = 380   # STRING
    SIG_SEQ              = 410   # STRING
    SIG_SHA              = 411   # STRING
    PATH                 = 420   # STRING
    PATH_SCRUB           = 421   # STRING
    WEB_FILE_URL         = 430   # STRING
    WEB_FILE_URL_SCRUB   = 431   # STRING
    SUBTYPE              = 440   # STRING
    REAL_PATH            = 640   # STRING
    SHA512               = 650   # STRING
    VPATH                = 660   # STRING
    CTPH                 = 1070  # STRING (fuzzy hash)
    SCAN_REASON          = 950   # UINT32
    IS_CLOUD_SIGNATURE   = 1140  # UINT32
    AUTHENTICODE_HASH    = 1220  # STRING
    IMP_HASH             = 1334  # STRING
    CRC16                = 620   # STRING
    CRC32                = 1331  # STRING
    HASHED_FULL_PATH     = 1322  # STRING
    CLUSTER_HASH         = 1403  # STRING
    AUTHENTICODE_HASH256 = 1313  # STRING

    # --- AMSI script submission fields (RE'd from mpengine.dll schema tables by aae86e9) ---
    AMSI_APP_ID              = 1325  # STRING  (packed 0x0009052d)
    AMSI_SESSION_ID          = 1328  # UINT32  (packed 0x00060530)
    AMSI_UAC_IDENTIFIER      = 1364  # STRING  (packed 0x00090554)
    AMSI_CONTENT_NAME        = 1370  # STRING  (packed 0x0009055a)
    AMSI_CONTENT_NAME_SCRUB  = 1371  # STRING  (packed 0x0009055b)
    AMSI_REDIRECT_CHAIN      = 1415  # STRING  (packed 0x00090587)


class URF:
    """Bond_UrlReport field ordinals (6 fields)."""
    URL_REPORT_GUID      = 3     # STRING
    URL_LIST             = 6     # 266 (UrlList - struct)
    URL_CONTEXT          = 9     # 266 (UrlContext - struct)
    SIG_SEQ              = 12    # STRING
    SIG_SHA              = 15    # STRING
    REPORT_ONLY          = 18    # BOOL


class TDF:
    """Bond_ThreatDetails field ordinals (11 fields)."""
    THREAT_ID            = 3     # UINT32
    THREAT_CATEGORY      = 6     # UINT32
    THREAT_NAME          = 9     # STRING
    THREAT_SEVERITY      = 12    # UINT32
    THREAT_ADVICE        = 15    # UINT32
    SHORT_DESC_ID        = 18    # UINT32
    THREAT_ADVICE_INFO   = 21    # UINT32
    SIG_INFO_ELEMENTS    = 24    # 266 (List<SignatureInfo>)
    DROP_TYPE            = 27    # INT32
    TTL                  = 30    # UINT64
    SIG_MATCHES          = 33    # 266 (List<SignatureMatch>)


class SRR:
    """Bond_SpynetReportResponse field ordinals (8 fields)."""
    REVISION             = 3     # UINT8
    SAMPLE_RATE          = 6     # INT32
    SAMPLE_REQUESTS      = 9     # 266 (List<SampleRequest>)
    SIGNATURE_PATCHES    = 12    # 266 (SignaturePatch)
    URL_RESPONSE         = 15    # 266 (UrlResponse)
    THREAT_DETAIL_ELEMS  = 18    # 266 (List<ThreatDetails>)
    CERTIFICATE_RESPONSE = 21    # 266 (CertificateResponse)
    ONBOARDING_RESPONSE  = 24    # 266 (OnboardingResponse)


class SSRR:
    """Bond_SubmitSpynetReportResult field ordinals (2 fields)."""
    XMLNS                = 3     # STRING
    SPYNET_REPORT_RESP   = 6     # 266 (SpynetReportResponse - struct)


class SRQ:
    """Bond_SampleRequest field ordinals (7 fields)."""
    REQUEST_GUID         = 3     # STRING
    SHA1                 = 6     # STRING
    HOLD                 = 9     # UINT8
    BLOB_SAS_URI         = 12    # STRING
    TTL                  = 15    # UINT64
    COMPRESSION          = 18    # STRING
    USE_QUARANTINE       = 21    # BOOL


class SIF:
    """Bond_SignatureInfo field ordinals (5 fields)."""
    PARTIAL_CRC2         = 3     # STRING
    PARTIAL_CRC1         = 6     # STRING
    PARTIAL_CRC3         = 9     # STRING
    SHA1                 = 12    # STRING
    SHA256               = 15    # STRING


class CRF_CERT:
    """Bond_CertificateResponse field ordinals (3 fields).
    RE'd from mpengine.dll schema table at 0x109dac08."""
    CERT_REPORT_GUID     = 3     # STRING
    SCENARIO             = 6     # UINT8
    CERT_RESULTS         = 9     # LIST<STRUCT> (CertificateResult)


class CRF_URL:
    """Bond_UrlResponse field ordinals (2 fields).
    RE'd from mpengine.dll schema table at 0x109da928."""
    URL_REPORT_GUID      = 3     # STRING
    URL_RESULTS          = 6     # LIST<STRUCT> (UrlResult)


class ORF:
    """Bond_OnboardingResponse field ordinals (1 field).
    RE'd from mpengine.dll schema table at 0x109db1e0."""
    ONBOARDING_BLOB      = 3     # STRING


class ULR:
    """Bond_UrlResult field ordinals (6 fields).
    RE'd from mpengine.dll schema table."""
    URL                  = 3     # STRING
    DETERMINATION        = 6     # UINT8
    CONFIDENCE           = 9     # UINT8
    TTL                  = 12    # UINT8
    URL_RESPONSE_CONTEXT = 15    # LIST<STRUCT> (UrlResponseContext)
    TTL_LONG             = 18    # UINT64


class UEF:
    """Bond_UrlElement field ordinals (3 fields).
    RE'd from mpengine.dll schema table at 0x10a064f0 by aa9e6ee agent.
    Calibrated: Order=10, Url=20, Url_Scrubbed=21."""
    ORDER                = 10    # INT32   (sort order index)
    URL                  = 20    # STRING  (the URL being queried)
    URL_SCRUBBED         = 21    # STRING  (scrubbed/sanitized URL)


class ULF:
    """Bond_UrlList field ordinals.
    RE'd from mpengine.dll schema table."""
    URLS                 = 3     # LIST<STRUCT> (UrlElement)


class UCF:
    """Bond_UrlContext field ordinals.
    RE'd from mpengine.dll schema table."""
    URL_CONTEXTS         = 3     # LIST<STRUCT> (UrlContextElement)


class UCEF:
    """Bond_UrlContextElement field ordinals (2 fields).
    RE'd from mpengine.dll constructor at 0x1052593a by aa9e6ee agent.
    Confirmed via UrlResponseContextElement data table at 0x109dafc0."""
    KEY                  = 3     # STRING  (context key)
    VALUE                = 6     # STRING  (context value)


class BEF:
    """Bond_BehaviorEvent field ordinals (50+ fields).
    Descriptor table @ 0x109F8238.
    Extracted from mpengine.dll schema table."""
    ETW_ID                        = 10    # INT16
    CALLBACK_ADDRESS              = 13    # UINT32
    API_RESULTS                   = 16    # INT32
    THREAD_ID                     = 19    # INT32
    ACCESS_RIGHTS                 = 22    # INT32
    DRIVER_NAME                   = 25    # STRING
    DRIVER_PATH                   = 28    # STRING
    IMAGE_NAME                    = 31    # STRING
    SOURCE                        = 34    # STRING
    TARGET                        = 37    # STRING
    TARGET_SCRUBBED               = 38    # STRING
    EVENT_MIN                     = 40    # INT32
    EVENT_MAX                     = 43    # INT32
    FLAGS                         = 46    # INT32
    HANDLE                        = 49    # UINT32
    CVE_ID                        = 52    # STRING
    EXPLOIT_MODE                  = 55    # STRING
    EXPLOIT_INFO                  = 58    # STRING
    INJECTION_TYPE                = 61    # STRING
    MODULE_NAME                   = 64    # STRING
    HOOK_TYPE                     = 68    # STRING
    LOG_TYPE                      = 72    # STRING
    OPERATION_METHOD_NAME         = 76    # STRING
    WMI_CALLER                    = 80    # STRING
    LOCAL_VM_ALLOC_REGIONSIZE     = 83    # STRING
    CURRENT                       = 86    # STRING
    ORIGINAL                      = 89    # STRING
    INTEGRITY_LEVEL               = 92    # STRING
    TOKEN_TAMPERING_TYPE          = 95    # STRING
    TARGET_NAME                   = 98    # STRING
    TARGET_NAME_SCRUBBED          = 99    # STRING
    CREDENTIAL_TYPE               = 101   # INT32
    COUNT_OF_CREDENTIALS_RETURNED = 104   # INT32
    RETURN_CODE                   = 107   # INT32
    BACKUP_FILE_NAME              = 110   # STRING
    BACKUP_FILE_NAME_SCRUBBED     = 111   # STRING
    SEARCH_STRING                 = 113   # STRING
    SEARCH_STRING_SCRUBBED        = 114   # STRING
    VAULT_SVC_SCHEMA              = 119   # STRING
    RESOURCE                      = 122   # STRING
    IDENTITY                      = 125   # STRING
    IDENTITY_SCRUBBED             = 126   # STRING
    PACKAGE_SID                   = 128   # STRING
    VAULT_FLAGS                   = 131   # INT32
    SCOPE_OF_SEARCH               = 134   # INT32
    ATTRIBUTE_LIST                = 137   # STRING
    LAST_PROTECTION_MASK          = 140   # INT32
    PROTECTION_MASK               = 143   # INT32
    ACCOUNT_EXPIRES               = 146   # STRING
    AUTH_PACKAGE                  = 149   # STRING
    AMSI_CONTEXT                  = 390   # STRING  (beyond descriptor table range)
    AMSI_ACTION                   = 393   # STRING  (beyond descriptor table range)


class SLEF:
    """Bond_StartupListElement field ordinals (script-related fields).
    RE'd from mpengine.dll schema table at 0x109fcb58 by aae86e9 agent.
    Calibrated against: Exec=10, Guid=20, MenuText=30, RegHive=40."""
    EXEC                 = 10    # STRING
    GUID                 = 20    # STRING
    MENU_TEXT            = 30    # STRING
    REG_HIVE             = 40    # STRING
    SCRIPT               = 50    # STRING  (raw script content for AMSI)
    SCRIPT_SCRUBBED      = 51    # STRING  (sanitized script content)


class SGMF:
    """Bond_SignatureGenerationMetadata field ordinals (6 fields).
    RE'd from mpengine.dll schema table at 0x109fe750."""
    PARTIAL_CRC1         = 3     # STRING
    PARTIAL_CRC2         = 6     # STRING
    PARTIAL_CRC3         = 9     # STRING
    FILE_SIZE            = 12    # INT64
    SHA1                 = 15    # STRING
    SHA256               = 18    # STRING


class CRF_CERT_RESULT:
    """Bond_CertificateResult field ordinals (5 fields).
    Nested inside CertificateResponse.CertificateResults (LIST<STRUCT>).
    RE'd from mpengine.dll schema table at 0x109dad50 by ac80320 agent."""
    SHA1                 = 3     # STRING
    DETERMINATION        = 6     # UINT8
    CONFIDENCE           = 9     # UINT8
    TTL                  = 12    # UINT64
    IS_SELF_SIGNED       = 15    # BOOL


class SPF:
    """Bond_SignaturePatch field ordinals (5 fields).
    RE'd from mpengine.dll schema table at 0x109dadf8 by ac80320 agent."""
    ENABLE               = 3     # STRING
    DISABLE              = 6     # STRING
    SIGNATURE_MATCHES    = 9     # LIST<STRUCT>
    ENABLE_BLOB          = 12    # LIST
    DISABLE_BLOB         = 15    # LIST


class HEF:
    """Bond_HeartbeatError field ordinals (4 fields).
    RE'd from mpengine.dll schema table at 0x109fcf78 by ac80320 agent."""
    FEATURE_ERROR        = 10    # STRING
    FUNCTION_ERROR       = 20    # STRING
    ERROR_HRESULT        = 30    # STRING
    ERROR_DETAILS        = 40    # STRING


class AUIF:
    """Bond_AmsiUacInfo field ordinals (30 fields).
    RE'd from mpengine.dll schema table at 0x10a055f0 by a9c5bd1 agent.
    Inner struct for SpynetReport.AmsiUacInfos (1275).

    GetSchema function at 0x103498f0 returns field_count=30, table=0x10a055f0.
    Type field acts as discriminant (0=Exe, 1=COM, 2=MSI, 3=ActiveX, 4=PackagedApp).
    Three "byte" metadata fields (RequestorSha1, ExeAppSha1, BlockingTriggerSigseq)
    use BT_STRING for binary blob data.
    """
    TYPE                         = 0     # INT32   (packed 0x00100000) - discriminant
    IDENTIFIER                   = 3     # STRING  (packed 0x00090003)
    BLOCKED                      = 6     # BOOL    (packed 0x00020006)
    TRUSTED_STATE                = 9     # INT32   (packed 0x00100009)
    REQUESTOR_NAME               = 12    # STRING  (packed 0x0009000c)
    REQUESTOR_NAME_SCRUBBED      = 13    # STRING  (packed 0x0009000d)
    REQUESTOR_SHA1               = 15    # STRING  (packed 0x0009000f) - binary blob
    REQUESTOR_IL                 = 18    # UINT32  (packed 0x00050012)
    AUTO_ELEVATE                 = 21    # BOOL    (packed 0x00020015)
    EXE_APP_NAME                 = 24    # STRING  (packed 0x00090018)
    EXE_APP_NAME_SCRUBBED        = 25    # STRING  (packed 0x00090019)
    EXE_APP_SHA1                 = 27    # STRING  (packed 0x0009001b) - binary blob
    EXE_COMMAND_LINE             = 30    # STRING  (packed 0x0009001e)
    EXE_COMMAND_LINE_SCRUBBED    = 31    # STRING  (packed 0x0009001f)
    EXE_DLL_PARAMETER            = 33    # STRING  (packed 0x00090021)
    COM_REQUESTOR                = 36    # STRING  (packed 0x00090024)
    COM_SERVER_BINARY            = 39    # STRING  (packed 0x00090027)
    COM_CLSID                    = 42    # STRING  (packed 0x0009002a)
    MSI_ACTION                   = 45    # INT32   (packed 0x0010002d)
    MSI_PACKAGE_PATH             = 48    # STRING  (packed 0x00090030)
    MSI_PACKAGE_PATH_SCRUBBED    = 49    # STRING  (packed 0x00090031)
    AX_URL                       = 51    # STRING  (packed 0x00090033)
    AX_URL_SCRUBBED              = 52    # STRING  (packed 0x00090034)
    BLOCKING_TRIGGER_SIGSEQ      = 54    # STRING  (packed 0x00090036) - binary blob
    BLOCKING_TRIGGER_SIGSHA      = 55    # STRING  (packed 0x00090037)
    PK_APP_APP_NAME              = 57    # STRING  (packed 0x00090039)
    PK_APP_COMMAND_LINE          = 60    # STRING  (packed 0x0009003c)
    PK_APP_COMMAND_LINE_SCRUBBED = 61    # STRING  (packed 0x0009003d)
    PK_APP_FAMILY_NAME           = 63    # STRING  (packed 0x0009003f)
    PK_APP_APP_ID                = 66    # STRING  (packed 0x00090042)


class NCRF:
    """Bond_NetworkConnectionReport V1 field ordinals (10 fields).
    RE'd from mpengine.dll schema table at 0x10A065F0 via GetSchema at 0x1034A550.
    RTTI: .?AVBond_NetworkConnectionReport@@
    Inner struct for SpynetReport.NetworkConnectionReportElements (1190).
    """
    TIMESTAMP              = 10    # UINT64  (packed 0x0006000a) - FILETIME
    DESTINATION_IP         = 20    # STRING  (packed 0x00090014)
    DESTINATION_IP_SCRUB   = 21    # STRING  (packed 0x00090015)
    SOURCE_IP              = 30    # STRING  (packed 0x0009001e)
    SOURCE_IP_SCRUBBED     = 31    # STRING  (packed 0x0009001f)
    DESTINATION_PORT       = 40    # UINT16  (packed 0x00040028)
    SOURCE_PORT            = 50    # UINT16  (packed 0x00040032)
    PROTOCOL               = 60    # UINT16  (packed 0x0004003c) - 6=TCP, 17=UDP
    URI                    = 70    # STRING  (packed 0x00090046)
    URI_SCRUBBED           = 71    # STRING  (packed 0x00090047)


class NCRV2:
    """Bond_NetworkConnectionReportV2 field ordinals (21 fields).
    RE'd from mpengine.dll schema table at 0x109FF9D8 via GetSchema at 0x1034A570.
    RTTI: .?AVBond_NetworkConnectionReportV2@@
    Inner struct for SpynetReport.NetworkConnectionReportV2Elements (1191).
    """
    RAW_TIMESTAMP              = 1      # UINT64
    IPV4_DESTINATION           = 2      # UINT32
    IPV4_DESTINATION_SCRUBBED  = 102    # UINT32
    DEPRECATED_IPV6_DEST       = 3      # BLOB (0x000B)
    IPV4_SOURCE                = 4      # UINT32
    IPV4_SOURCE_SCRUBBED       = 104    # UINT32
    DEPRECATED_IPV6_SRC        = 5      # BLOB (0x000B)
    DESTINATION_PORT           = 6      # UINT16
    SOURCE_PORT                = 7      # UINT16
    PROTOCOL_ID                = 8      # UINT8  - 6=TCP, 17=UDP
    URI                        = 9      # STRING
    URI_SCRUBBED               = 109    # STRING
    IPV6_DEST_LOW              = 10     # UINT64
    IPV6_DEST_LOW_SCRUBBED     = 110    # UINT64
    IPV6_DEST_HIGH             = 11     # UINT64
    IPV6_SRC_LOW               = 12     # UINT64
    IPV6_SRC_LOW_SCRUBBED      = 112    # UINT64
    IPV6_SRC_HIGH              = 13     # UINT64
    DIRECTION                  = 14     # UINT8  - inbound/outbound
    INBOUND_BYTES              = 15     # UINT64
    OUTBOUND_BYTES             = 16     # UINT64


# ===========================================================================
# BehaviorReport Bond sub-schema field ordinal classes
# Extracted from mpengine.dll descriptor tables via extract_behavior_direct.py
# ===========================================================================

class BRF:
    """Bond_BehaviorReport field ordinals (21 fields).
    Descriptor table @ 0x109F48F8."""
    BEHAVIORS                  = 10    # LIST<STRUCT> (Bond_Behavior)
    PARTICIPATING_MODULES      = 20    # LIST<STRUCT> (Bond_ParticipatingModule)
    FILE_INDEX                 = 30    # MAP
    ENFORCE_RESTRICTION_POLICY = 40    # UINT8
    LEVEL                      = 50    # UINT16
    SCORE                      = 60    # UINT16
    SIGNATURE                  = 70    # FLOAT
    MODULE_LIST                = 80    # STRING
    PROCESS_STARTUP_DETAILS    = 83    # LIST<STRUCT> (Bond_ProcessStartupDetails)
    THREAT_TRACKING_ID         = 86    # STRING
    PROCESS_TAINTED            = 89    # UINT8
    BM_EVENT_IDS               = 92    # STRING
    MULTI_PROCESSS             = 95    # UINT8
    PROCESS_TAINT_INFO         = 98    # STRING
    PROCESS_PPID               = 101   # STRING
    PROCESS_INFOS              = 104   # LIST<STRUCT> (Bond_ProcessInfo)
    RELATED_STRINGS            = 107   # LIST<STRUCT>
    PROCESS_TAINT_INFO_EX      = 110   # STRING
    RESEARCH_DATA_EX           = 113   # LIST<STRUCT>
    THREAT_LEVEL               = 116   # MAP
    PROCESS_FLAGS              = 119   # MAP


class BF:
    """Bond_Behavior field ordinals (20 fields).
    Descriptor table @ 0x10A068D8."""
    DEVIATIONS                 = 10    # LIST<STRUCT> (Bond_Deviation)
    NETWORK_ACCESS_ELEMENTS    = 20    # LIST<STRUCT> (uses NCRF schema @ 0x10A065F0)
    PROCESS_MODIFIERS          = 30    # LIST<STRUCT>
    REGISTRY_MANIPULATIONS     = 40    # LIST<STRUCT>
    TABLE_HOOKS                = 50    # LIST<STRUCT> (Bond_TableHook)
    THREAT_FILE_MANIPULATIONS  = 60    # LIST<STRUCT>
    UNKNOWN_FILE_MANIPULATIONS = 70    # LIST<STRUCT>
    PARTIAL_SIGNATURE          = 80    # FLOAT
    ORDER                      = 90    # MAP
    ANTI_ROOTKITS              = 100   # LIST<STRUCT> (Bond_AntiRootkit)
    INTERNAL_INFOS             = 110   # LIST<STRUCT> (Bond_InternalInfo)
    INTERNAL_BEHAVIORS         = 120   # LIST<STRUCT>
    ETW_BEHAVIORS              = 123   # LIST<STRUCT>
    VOLUME_MOUNT_BEHAVIORS     = 126   # LIST<STRUCT>
    DESKTOP_BEHAVIORS          = 129   # LIST<STRUCT> (Bond_DesktopBehavior)
    OPEN_PROCESS_BEHAVIORS     = 132   # LIST<STRUCT> (Bond_OpenProcessBehavior)
    FILE_INDEX                 = 135   # MAP
    BEHAVIOR_TIME              = 138   # UINT32
    SIGNATURE_MATCH            = 141   # UINT8
    MEMORY_EVENT_BEHAVIORS     = 144   # LIST<STRUCT>


class DEVF:
    """Bond_Deviation field ordinals (45 fields).
    Descriptor table @ 0x10A07940."""
    PERSISTED_TIME                           = 10    # UINT32
    ENGINE_VERSION                           = 20    # STRING
    SIG_VERSION                              = 30    # STRING
    AV_SIG_VERSION                           = 40    # STRING
    MODIFICATIONS                            = 50    # MAP
    PERSIST_EVENT                            = 60    # UINT16
    PROCESS_ID                               = 70    # INT32
    PROCESS_START_TIME                       = 80    # UINT32
    PROCESS_START_PARAMETERS                 = 90    # STRING
    PROCESS_START_PARAMETERS_SCRUBBED        = 91    # STRING
    PROCESS_FILE_NAME                        = 100   # STRING
    PERSIST_EVENT_STATE                      = 110   # INT32
    PARENT_EVENT                             = 113   # MAP
    PARENT_FILE_FULL_PATH                    = 116   # STRING
    PARENT_FILE_FULL_PATH_SCRUBBED           = 117   # STRING
    PARENT_FILE_NAME                         = 119   # STRING
    PARENT_FILE_PATH                         = 122   # STRING
    PARENT_FILE_PATH_SCRUBBED                = 123   # STRING
    REMOTE_PROCESS_FILE_FULL_PATH            = 125   # STRING
    REMOTE_PROCESS_FILE_FULL_PATH_SCRUBBED   = 126   # STRING
    REMOTE_PROCESS_FILE_NAME                 = 128   # STRING
    REMOTE_PROCESS_FILE_PATH                 = 131   # STRING
    REMOTE_PROCESS_FILE_PATH_SCRUBBED        = 132   # STRING
    REMOTE_PROCESS_START_PARAMETERS          = 134   # STRING
    REMOTE_PROCESS_START_PARAMETERS_SCRUBBED = 135   # STRING
    REMOTE_PROCESS_ELEVATION                 = 137   # MAP
    PROCESS_FILE_FULL_PATH                   = 140   # STRING
    PROCESS_FILE_FULL_PATH_SCRUBBED          = 141   # STRING
    PROCESS_FILE_PATH                        = 143   # STRING
    PROCESS_FILE_PATH_SCRUBBED               = 144   # STRING
    PROCESS_ELEVATION                        = 146   # MAP
    PERSIST_GUID                             = 149   # STRING
    PROGENITOR_PERSIST_SIG_SEQ               = 152   # STRING
    PROGENITOR_PERSIST_SIG_SHA               = 153   # STRING
    PERSIST_SCAN_REASON                      = 155   # MAP
    PROCESS_TOKEN_ELEVATION_TYPE             = 158   # MAP
    PROCESS_TOKEN_ELEVATION                  = 161   # UINT8
    PROCESS_INTEGRITY_LEVEL                  = 164   # MAP
    REMOTE_PROCESS_TOKEN_ELEVATION_TYPE      = 167   # MAP
    REMOTE_PROCESS_TOKEN_ELEVATION           = 170   # UINT8
    REMOTE_PROCESS_INTEGRITY_LEVEL           = 173   # MAP
    ALL_SHA1                                 = 176   # STRING
    ALL_ANCESTRY_SHA1                        = 179   # STRING
    ALL_SIBLING_SHA1                         = 182   # STRING
    ALL_CHILDRENG_SHA1                       = 185   # STRING


class THF:
    """Bond_TableHook field ordinals (6 fields).
    Descriptor table @ 0x10A03008."""
    FUNCTION_INDEX = 20    # MAP
    FUNCTION_NAME  = 30    # STRING
    TABLE_ID       = 40    # MAP
    TABLE_NAME     = 50    # STRING
    TYPE           = 60    # UINT16
    SENSOR_ID      = 70    # MAP


class ARKF:
    """Bond_AntiRootkit field ordinals (6 fields).
    Descriptor table @ 0x10A060F0."""
    AR_SIG_ID      = 10    # UINT32
    MODULE_NAME    = 20    # STRING
    AR_DATA        = 30    # STRING
    DETECTION_NAME = 40    # STRING
    AR_SCORE       = 50    # MAP
    AR_TRIGGER     = 53    # UINT32


class IIF:
    """Bond_InternalInfo field ordinals (3 fields).
    Descriptor table @ 0x109FA940."""
    FEATURE_ID     = 10    # UINT32
    SIGNATURE_ID   = 20    # STRING
    DETECTION_NAME = 30    # STRING


class DBF:
    """Bond_DesktopBehavior field ordinals (5 fields).
    Descriptor table @ 0x109FD320."""
    DESKTOP_NAME          = 10    # STRING
    DESKTOP_NAME_SCRUBBED = 11    # STRING
    IS_DUPLICATE          = 13    # UINT8
    IS_KERNEL             = 16    # UINT8
    DESKTOP_ACCESS        = 19    # MAP


class OPBF:
    """Bond_OpenProcessBehavior field ordinals (4 fields).
    Descriptor table @ 0x10A033D8."""
    TARGET_IMAGE          = 3     # STRING
    TARGET_IMAGE_SCRUBBED = 4     # STRING
    ACCESS_MASK           = 6     # INT32
    VM_ACCESS_REMOVED     = 9     # UINT8


class PARTF:
    """Bond_ParticipatingModule field ordinals (3 fields).
    Descriptor table @ 0x10A05590."""
    MODULE = 10    # STRING
    NAME   = 20    # STRING
    VA     = 30    # FLOAT


class PSDF:
    """Bond_ProcessStartupDetails field ordinals (4 fields).
    Descriptor table @ 0x109F6E38."""
    PROCESS_INFO_ID   = 3     # INT32
    PROCESS_PPID      = 6     # STRING
    TRIGGER_SIG_SEQ   = 9     # STRING
    MEM_QUERY_REGIONS = 12    # LIST<STRUCT>


class PRINF:
    """Bond_ProcessInfo field ordinals (8 fields).
    Descriptor table @ 0x10A06B70."""
    ID                              = 3     # INT32
    PARENT_PROCESSES_IDS            = 6     # STRING
    REAL_PATH                       = 9     # STRING
    REAL_PATH_SCRUBBED              = 10    # STRING
    COMMAND_LINE_ARGUMENTS          = 12    # STRING
    COMMAND_LINE_ARGUMENTS_SCRUBBED = 13    # STRING
    BEHAVIORS                       = 15    # LIST<STRUCT> (Bond_Behavior)
    PROCESS_PPID                    = 18    # STRING


# Schema name mappings for pretty-printing
SPYNET_REPORT_NAMES = {
    SF.REPORT_TIME: "ReportTime",
    SF.REVISION: "Revision",
    SF.MACHINE_GUID: "MachineGuid",
    SF.AV_SIG_VERSION: "AvSigVersion",
    SF.SIG_VERSION: "SigVersion",
    SF.ENGINE_VERSION: "EngineVersion",
    SF.IS_HEARTBEAT: "IsHeartBeat",
    SF.OS_VER: "OsVer",
    SF.OS_BUILD: "OsBuild",
    SF.OS_TYPE: "OsType",
    SF.GEO_ID: "GeoId",
    SF.PRODUCT_GUID: "ProductGuid",
    SF.APP_VERSION: "AppVersion",
    SF.SPYNET_REPORT_GUID: "SpynetReportGuid",
    SF.FILE_REPORT_ELEMENTS: "FileReportElements",
    SF.PARTNER_GUID: "PartnerGuid",
    SF.MAPS_GENERATE_LATENCY: "MapsGenerateLatency",
    SF.MAPS_SEND_LATENCY: "MapsSendLatency",
    SF.MAPS_PARSE_LATENCY: "MapsParseLatency",
    SF.MAPS_HRESULT: "MapsHresult",
    SF.REMEDIATION_CKPT_RPT: "RemediationCheckpointReports",
    SF.IS_BETA: "IsBeta",
    SF.STILL_ALIVE_HB: "StillAliveHeartbeat",
    SF.HB_CONTROL_GROUP: "HeartbeatControlGroup",
    SF.HB_SUBTYPE: "UEFISecureBootStatus",
    SF.SPYNET_COL_ERRORS: "SpynetCollectionErrors",
    SF.SAMPLES: "Samples",
    SF.HEARTBEAT_ERRORS: "HeartbeatErrors",
    SF.EXCLUSIONS: "Exclusions",
    SF.RTP_STATE_BITFIELD: "RtpStateBitfield",
    SF.RTP_HRESULT: "RtpHresult",
    SF.ENGINE_REPORT_GUID: "EngineReportGuid",
    SF.MAPS_REPORT_GUID: "MapsReportGuid",
    SF.REMEDIATION_STATUS: "RemediationStatusReportElements",
    SF.BACKEND_METADATA: "BackendMetadata",
    SF.ENGINE_LOAD_FILETIME: "EngineLoadFileTime",
    SF.DEVICE_ID: "DeviceId",
    SF.SIG_UPDATE_TIME: "SignatureUpdateTime",
    SF.MP_FILTER_HB_FLAGS: "MpFilterHeartbeatFlags",
    SF.SCAN_CONFIG_FLAGS: "ScanConfigFlags",
    SF.NETWORK_CONN_ELEMENTS: "NetworkConnectionReportElements",
    SF.NETWORK_CONN_V2: "NetworkConnectionReportV2Elements",
    SF.RTP_CONFIG_FLAGS: "RtpConfigFlags",
    SF.MAPS_CONN_CREATE_TIME: "MapsCreateConnectionTime",
    SF.MAPS_SEND_REQ_TIME: "MapsSendRequestTime",
    SF.MAPS_RECV_RESP_TIME: "MapsReceiveResponseTime",
    SF.CLOUD_BLOCK_LEVEL: "CloudBlockLevel",
    SF.URL_REPORT: "UrlReport",
    SF.AUTO_SAMPLE_OPT_IN: "AutoSampleOptInValue",
    SF.SIG_UPDATES_SINCE_HB: "SigUpdatesSinceLastHb",
    SF.IS_PASSIVE_MODE: "IsPassiveMode",
}

RESPONSE_NAMES = {
    SSRR.XMLNS: "Xmlns",
    SSRR.SPYNET_REPORT_RESP: "SpynetReportResponse",
}

SPYNET_RESPONSE_NAMES = {
    SRR.REVISION: "Revision",
    SRR.SAMPLE_RATE: "SampleRate",
    SRR.SAMPLE_REQUESTS: "SampleRequests",
    SRR.SIGNATURE_PATCHES: "SignaturePatches",
    SRR.URL_RESPONSE: "UrlResponse",
    SRR.THREAT_DETAIL_ELEMS: "ThreatDetailElements",
    SRR.CERTIFICATE_RESPONSE: "CertificateResponse",
    SRR.ONBOARDING_RESPONSE: "OnboardingResponse",
}

THREAT_DETAIL_NAMES = {
    TDF.THREAT_ID: "ThreatId",
    TDF.THREAT_CATEGORY: "ThreatCategory",
    TDF.THREAT_NAME: "ThreatName",
    TDF.THREAT_SEVERITY: "ThreatSeverity",
    TDF.THREAT_ADVICE: "ThreatAdvice",
    TDF.SHORT_DESC_ID: "ShortDescId",
    TDF.THREAT_ADVICE_INFO: "ThreatAdviceInfo",
    TDF.SIG_INFO_ELEMENTS: "SigInfoElements",
    TDF.DROP_TYPE: "DropType",
    TDF.TTL: "TTL",
    TDF.SIG_MATCHES: "SigMatches",
}

CERTIFICATE_RESPONSE_NAMES = {
    CRF_CERT.CERT_REPORT_GUID: "CertificateReportGuid",
    CRF_CERT.SCENARIO: "Scenario",
    CRF_CERT.CERT_RESULTS: "CertificateResults",
}

URL_RESPONSE_NAMES = {
    CRF_URL.URL_REPORT_GUID: "UrlReportGuid",
    CRF_URL.URL_RESULTS: "UrlResults",
}

ONBOARDING_RESPONSE_NAMES = {
    ORF.ONBOARDING_BLOB: "OnboardingBlob",
}

URL_RESULT_NAMES = {
    ULR.URL: "Url",
    ULR.DETERMINATION: "Determination",
    ULR.CONFIDENCE: "Confidence",
    ULR.TTL: "TTL",
    ULR.URL_RESPONSE_CONTEXT: "UrlResponseContext",
    ULR.TTL_LONG: "TTLlong",
}

SIGGEN_METADATA_NAMES = {
    SGMF.PARTIAL_CRC1: "PartialCrc1",
    SGMF.PARTIAL_CRC2: "PartialCrc2",
    SGMF.PARTIAL_CRC3: "PartialCrc3",
    SGMF.FILE_SIZE: "FileSize",
    SGMF.SHA1: "Sha1",
    SGMF.SHA256: "Sha256",
}

SEVERITY_NAMES = {
    0: "Unknown",
    1: "Low",
    2: "Medium",
    4: "High",
    5: "Severe",
}

THREAT_CATEGORY_NAMES = {
    0: "Invalid",
    1: "Adware",
    2: "Spyware",
    3: "PasswordStealer",
    4: "Trojan_Downloader",
    5: "Worm",
    6: "Backdoor",
    7: "RemoteAccessTrojan",
    8: "Trojan",
    9: "Email_Flooder",
    10: "Keylogger",
    11: "Dialer",
    12: "MonitoringSoftware",
    13: "BrowserModifier",
    14: "Cookie",
    19: "Browser_Plugin",
    21: "Aol_Exploit",
    23: "Nuker",
    27: "SecurityDisabler",
    30: "JokeProgram",
    32: "HostileActiveXControl",
    33: "SoftwareBundler",
    34: "StealthNotifier",
    36: "SettingsModifier",
    37: "Toolbar",
    38: "RemoteControlSoftware",
    39: "TrojanFTP",
    40: "PotentialUnwantedSoftware",
    42: "Virus",
    43: "Known",
    44: "Unknown",
    45: "SPP",
    46: "Behavior",
    47: "Vulnerability",
    48: "Policy",
    49: "EUS",
    50: "Ransomware",
    51: "ASR",
}


# ---------------------------------------------------------------------------
# File analysis
# ---------------------------------------------------------------------------

@dataclass
class FileInfo:
    """Computed metadata for a scanned file."""
    path: str
    size: int
    sha256: str
    sha1: str
    md5: str
    crc32: int
    imphash: Optional[str] = None
    ssdeep_hash: Optional[str] = None
    pe_timestamp: Optional[int] = None
    pe_checksum: Optional[int] = None
    file_description: Optional[str] = None
    file_version: Optional[str] = None
    product_name: Optional[str] = None
    original_filename: Optional[str] = None
    signer: Optional[str] = None
    section_hashes: Optional[List[str]] = None


def analyze_file(path: str) -> FileInfo:
    """Compute hashes and extract metadata from a file."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    data = file_path.read_bytes()

    # Core hashes
    sha256 = hashlib.sha256(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()

    # CRC32
    import binascii
    crc32 = binascii.crc32(data) & 0xFFFFFFFF

    info = FileInfo(
        path=str(file_path.resolve()),
        size=len(data),
        sha256=sha256,
        sha1=sha1,
        md5=md5,
        crc32=crc32,
    )

    # ssdeep fuzzy hash
    if HAS_SSDEEP:
        try:
            info.ssdeep_hash = ssdeep.hash(data)
        except Exception:
            pass

    # PE analysis
    if HAS_PEFILE and len(data) > 2 and data[:2] == b'MZ':
        try:
            pe = pefile.PE(data=data, fast_load=False)
            info.imphash = pe.get_imphash()
            info.pe_timestamp = pe.FILE_HEADER.TimeDateStamp
            info.pe_checksum = pe.OPTIONAL_HEADER.CheckSum

            # PE version info
            if hasattr(pe, 'FileInfo') and pe.FileInfo:
                for fi_list in pe.FileInfo:
                    for entry in fi_list:
                        if hasattr(entry, 'StringTable'):
                            for st in entry.StringTable:
                                strings = {
                                    k.decode('utf-8', errors='replace'): v.decode('utf-8', errors='replace').rstrip('\x00')
                                    for k, v in st.entries.items()
                                }
                                info.file_description = strings.get('FileDescription')
                                info.file_version = strings.get('FileVersion')
                                info.product_name = strings.get('ProductName')
                                info.original_filename = strings.get('OriginalFilename')

            # Section hashes
            info.section_hashes = []
            for section in pe.sections:
                section_data = section.get_data()
                sh = hashlib.sha256(section_data).hexdigest()
                name = section.Name.rstrip(b'\x00').decode('utf-8', errors='replace')
                info.section_hashes.append(f"{name}:{sh}")

            pe.close()
        except Exception:
            pass

    return info


def compute_hashes_from_bytes(data: bytes) -> Dict[str, str]:
    """Compute basic hashes from raw bytes."""
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


# ---------------------------------------------------------------------------
# SpynetReport builder
# ---------------------------------------------------------------------------

def encode_maps_version(version_str: str) -> str:
    """Encode a dotted version string into MAPS hex format.

    MAPS encodes versions as packed 64-bit integers rendered as hex:
      (major << 48) | (minor << 32) | (build << 16) | revision

    For 3-part versions (e.g. OS "10.0.26100"), revision is 0 and build
    goes into the low 16 bits directly (no << 16 shift):
      (major << 48) | (minor << 32) | build

    Examples (from ETW capture of real Defender traffic):
      "4.18.26010.5"  -> "40012659a0005"   (platform)
      "1.1.26010.1"   -> "10001659a0001"   (engine)
      "10.0.26100"    -> "a0000000065f4"   (OS)
    """
    parts = [int(p) for p in version_str.split('.')]
    if len(parts) == 4:
        val = (parts[0] << 48) | (parts[1] << 32) | (parts[2] << 16) | parts[3]
    elif len(parts) == 3:
        val = (parts[0] << 48) | (parts[1] << 32) | parts[2]
    elif len(parts) == 2:
        val = (parts[0] << 48) | (parts[1] << 32)
    else:
        val = parts[0] << 48
    return format(val, 'x')


@dataclass
class MAPSConfig:
    """Configuration for MAPS client.

    The machine_guid is a persistent random UUID that identifies this client
    to MAPS, equivalent to Windows Defender's ComputerID (accessible via
    Get-MpComputerStatus). On real Defender, it's generated once via
    UuidCreate() and stored in MpConfig. Here we persist it to a state file
    so it remains stable across sessions.

    Format: lowercase dashed GUID (e.g. "d0c07775-f139-454d-ad86-e7c4e7765f40")
    """
    endpoint: str = MAPS_ENDPOINT_PROD
    machine_guid: str = ""
    partner_guid: str = ""
    cloud_block_level: int = CloudBlockLevel.HIGH
    spynet_level: int = SpynetLevel.ADVANCED
    auto_submit: int = 1
    timeout: int = 30
    proxy: Optional[str] = None
    verify_ssl: bool = True
    user_agent: str = "MpCommunication"
    # Version strings for Bond payload fields (human-readable)
    av_sig_version: str = "1.445.126.0"
    engine_version: str = "1.1.26010.1"
    app_version: str = "4.18.26010.5"
    os_ver: str = "10.0.26100"
    os_build: int = 26100
    os_type: int = 1   # 1=Workstation
    geo_id: int = 244  # US
    customer_type: str = "Consumer"
    bearer_token: Optional[str] = None  # Enterprise AAD token (client ID: cab96880-db5b-4e15-90a7-f3f1d62ffe39)
    state_dir: str = ""
    rotate_guid: bool = True  # Generate a fresh machine GUID for each request (default on)

    def __post_init__(self):
        if not self.machine_guid:
            self.machine_guid = self._load_or_generate_guid()

    def _load_or_generate_guid(self) -> str:
        """Load persisted machine GUID or generate and save a new one."""
        state_dir = self.state_dir or str(Path(__file__).parent / ".state")
        state_file = Path(state_dir) / "machine_guid"
        try:
            if state_file.exists():
                guid = state_file.read_text().strip()
                if guid:
                    return guid
        except OSError:
            pass
        guid = str(uuid.uuid4())
        try:
            Path(state_dir).mkdir(parents=True, exist_ok=True)
            state_file.write_text(guid + "\n")
        except OSError:
            pass
        return guid

    def get_guid(self) -> str:
        """Return the machine GUID, rotating to a fresh UUID4 if rotate_guid is set."""
        if self.rotate_guid:
            return str(uuid.uuid4())
        return self.machine_guid

    @property
    def os_version_hex(self) -> str:
        """OS version encoded as MAPS hex (for HTTP header)."""
        return encode_maps_version(self.os_ver)

    @property
    def platform_version_hex(self) -> str:
        """Platform/app version encoded as MAPS hex (for HTTP header)."""
        return encode_maps_version(self.app_version)

    @property
    def engine_version_hex(self) -> str:
        """Engine version encoded as MAPS hex (for HTTP header)."""
        return encode_maps_version(self.engine_version)


def _dotnet_datetime_now() -> int:
    """Return current time as .NET DateTime ticks (100ns intervals since 0001-01-01)."""
    # Unix epoch in .NET ticks: 621355968000000000
    unix_ts = time.time()
    return int(unix_ts * 10_000_000) + 621355968000000000


class SpynetReportBuilder:
    """Construct Bond-serialized SpynetReport payloads.

    Report structure (Bond CompactBinaryV1):
      SpynetReport {
        ...top-level metadata fields...
        390: FileReportElements = List<FileReport> {
          FileReport {
            10: Revision
            20: Index
            30: CoreReportElement = CoreReport {
              ...file hashes, metadata, threat info...
            }
          }
        }
        1542: UrlReport { ...url fields... }
      }
    """

    def __init__(self, config: MAPSConfig):
        self.config = config

    def _write_top_level(self, w: CompactBinaryV1Writer, report_guid: str):
        """Write common SpynetReport top-level fields.

        Uses field types matching real Defender traffic (LIST wrappers
        for scalar system info fields).
        """
        os_parts = self.config.os_ver.split('.')
        os_ver_short = f"{os_parts[0]}.0.0.0"
        os_build_info = f"11.0.{self.config.os_build}.0"

        # F20: Schema version marker
        w.write_list_begin(SF.REVISION, BondType.BT_INT16, 1)
        w._write_varint(6)  # zigzag(3) = 6
        # F30: Machine GUID
        w.write_string(SF.MACHINE_GUID, self.config.get_guid())
        # Version strings
        w.write_string(SF.AV_SIG_VERSION, self.config.av_sig_version)
        w.write_string(SF.AS_SIG_VERSION, self.config.av_sig_version)
        w.write_string(SF.SIG_VERSION, self.config.av_sig_version)
        w.write_string(SF.ENGINE_VERSION, self.config.engine_version)
        w.write_string(SF.NRI_SIG_VERSION, self.config.av_sig_version)
        w.write_string(SF.NRI_ENGINE_VERSION, self.config.engine_version)
        # System info
        w.write_string(SF.OS_VER, os_ver_short)
        w.write_string(SF.IE_VER, os_build_info)
        w.write_list_begin(SF.OS_BUILD, BondType.BT_UINT32, 1)
        w._write_varint(self.config.os_build)
        w.write_list_begin(SF.OS_SUITE, BondType.BT_INT32, 1)
        w._write_varint(512)  # zigzag(256) = 512
        w.write_list_begin(SF.OS_TYPE, BondType.BT_INT16, 1)
        w._write_varint(2)  # zigzag(1) = 2
        w.write_list_begin(SF.GEO_ID, BondType.BT_INT32, 1)
        w._write_varint(self.config.geo_id << 1)  # zigzag
        w.write_list_begin(SF.LC_ID, BondType.BT_UINT32, 1)
        w._write_varint(1033)
        w.write_list_begin(SF.PROCESSOR, BondType.BT_UINT16, 1)
        w._write_varint(12)
        # F230-F270: Config values
        w.write_list_begin(230, BondType.BT_INT32, 1)
        w._write_varint(2)  # zigzag(1) = 2
        w.write_list_begin(240, BondType.BT_INT64, 1)
        w._write_varint(2)
        w.write_list_begin(250, BondType.BT_INT64, 1)
        w._write_varint(self.config.cloud_block_level << 1)
        w.write_list_begin(260, BondType.BT_INT64, 1)
        w._write_varint(self.config.spynet_level << 1)
        w.write_list_begin(270, BondType.BT_INT64, 1)
        w._write_varint(0)
        # Identity
        w.write_string(SF.PRODUCT_GUID, str(uuid.uuid4()))
        w.write_string(SF.MEMBERSHIP, "2")
        w.write_string(SF.APP_VERSION, self.config.app_version)

    def _write_core_report(
        self,
        w: CompactBinaryV1Writer,
        file_info: FileInfo,
        report_type: int,
        threat_id: Optional[int] = None,
    ):
        """Write a CoreReport struct (nested inside FileReport)."""
        w.write_int16(CRF.REVISION, 1)
        w.write_string(CRF.FILE_NAME, Path(file_info.path).name)
        w.write_int64(CRF.SIZE, file_info.size)

        # Hashes (all STRING type)
        w.write_string(CRF.MD5, file_info.md5)
        w.write_string(CRF.SHA1, file_info.sha1)
        w.write_string(CRF.SHA256, file_info.sha256)

        # PE metadata
        if file_info.file_description:
            w.write_string(CRF.DESC, file_info.file_description)
        if file_info.original_filename:
            w.write_string(CRF.ORIGINAL_NAME, file_info.original_filename)
        if file_info.product_name:
            w.write_string(CRF.NAME, file_info.product_name)
        if file_info.signer:
            w.write_string(CRF.SIGNER, file_info.signer)
        if file_info.imphash:
            w.write_string(CRF.IMP_HASH, file_info.imphash)
        if file_info.ssdeep_hash:
            w.write_string(CRF.CTPH, file_info.ssdeep_hash)

        # Threat info
        if threat_id is not None:
            w.write_uint32(CRF.THREAT_ID, threat_id)

        # ReportType (UINT32)
        w.write_uint32(CRF.REPORT_TYPE, report_type)

        # SigSeq and SigSha (lowfi trigger signature)
        w.write_string(CRF.SIG_SEQ, "")
        w.write_string(CRF.SIG_SHA, "")

        # Path
        w.write_string(CRF.PATH, file_info.path)

    def _write_core_report_from_hashes(
        self,
        w: CompactBinaryV1Writer,
        sha256: str,
        sha1: str = "",
        md5: str = "",
        file_name: str = "unknown",
        file_size: int = 0,
        report_type: int = ReportType.SYNC_LOWFI,
    ):
        """Write a CoreReport from hash values only."""
        w.write_int16(CRF.REVISION, 1)
        w.write_string(CRF.FILE_NAME, file_name)
        if file_size > 0:
            w.write_int64(CRF.SIZE, file_size)
        if md5:
            w.write_string(CRF.MD5, md5.lower())
        if sha1:
            w.write_string(CRF.SHA1, sha1.lower())
        w.write_string(CRF.SHA256, sha256.lower())
        w.write_uint32(CRF.REPORT_TYPE, report_type)

    def build_file_scan_report(
        self,
        file_info: FileInfo,
        report_type: int = ReportType.SYNC_LOWFI,
        threat_id: Optional[int] = None,
    ) -> bytes:
        """Build a SpynetReport for a file scan query.

        Uses the Bonded<T> envelope and correct wire format matching
        real Defender MAPS traffic.
        """
        w = CompactBinaryV1Writer()
        report_guid = str(uuid.uuid4())

        # -- Top-level SpynetReport fields --
        self._write_top_level(w, report_guid)

        # -- FileReportElements (F390): nested in LIST<LIST<STRUCT>> --
        # Real format: LIST<LIST<STRUCT>> where outer list has 1 element
        # which is LIST<STRUCT> with the file reports
        w.write_field_begin(BondType.BT_LIST, SF.FILE_REPORT_ELEMENTS)
        w._write_byte(BondType.BT_LIST)   # outer elem type: LIST
        w._write_varint(1)                 # outer count: 1
        w._write_byte(BondType.BT_STRUCT)  # inner elem type: STRUCT
        w._write_varint(1)                 # inner count: 1

        # --- FileReport struct ---
        w._field_stack.append(0)  # push struct context
        w.write_list_begin(FRF.REVISION, BondType.BT_INT16, 1)
        w._write_varint(2)  # zigzag(1) = 2
        w.write_list_begin(FRF.INDEX, BondType.BT_INT16, 1)
        w._write_varint(2)  # zigzag(1) = 2

        # CoreReportElement (F30): LIST<STRUCT>[1]
        w.write_list_begin(FRF.CORE_REPORT, BondType.BT_STRUCT, 1)

        # --- CoreReport struct ---
        w._field_stack.append(0)
        # Revision
        w.write_list_begin(CRF.REVISION, BondType.BT_INT16, 1)
        w._write_varint(2)  # zigzag(1) = 2
        # File name
        w.write_string(CRF.FILE_NAME, Path(file_info.path).name)
        # File system
        w.write_string(CRF.FILE_SYSTEM, "NTFS")
        # Size
        w.write_list_begin(CRF.SIZE, BondType.BT_INT64, 1)
        w._write_varint(file_info.size << 1)  # zigzag encode

        # Hashes (all STRING)
        w.write_string(CRF.PARTIAL_CRC2, file_info.md5[:8])
        w.write_string(CRF.PARTIAL_CRC1, file_info.md5[8:16])
        w.write_string(CRF.PARTIAL_CRC3, file_info.md5[16:24])
        w.write_string(CRF.MD5, file_info.md5)
        w.write_string(CRF.SHA1, file_info.sha1)
        w.write_string(CRF.SHA256, file_info.sha256)

        # Threat info
        if threat_id is not None:
            w.write_list_begin(CRF.THREAT_ID, BondType.BT_UINT32, 1)
            w._write_varint(threat_id)

        # ReportType (STRING, not UINT32)
        w.write_string(CRF.REPORT_TYPE - 10, str(report_type))  # F330

        # Path
        w.write_string(CRF.PATH, file_info.path)

        # ssdeep/CTPH
        if file_info.ssdeep_hash:
            w.write_string(CRF.CTPH, file_info.ssdeep_hash)

        w._write_byte(BondType.BT_STOP)  # end CoreReport
        w._field_stack.pop()

        w._write_byte(BondType.BT_STOP)  # end FileReport
        w._field_stack.pop()

        # -- Additional SpynetReport fields --
        w.write_string(SF.SMART_SCREEN, "Warn")

        if self.config.partner_guid:
            w.write_string(SF.PARTNER_GUID, self.config.partner_guid)

        w.write_string(SF.ENGINE_REPORT_GUID, str(uuid.uuid4()))
        w.write_int32(SF.AUTO_SAMPLE_OPT_IN, self.config.auto_submit)

        w._write_byte(BondType.BT_STOP)  # end SpynetReport
        return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())

    def build_hash_query(
        self,
        sha256: str,
        sha1: str = "",
        md5: str = "",
        file_name: str = "unknown",
        file_size: int = 0,
        report_type: int = ReportType.SYNC_LOWFI,
    ) -> bytes:
        """Build a SpynetReport from hash values only (no local file).

        Uses Bonded<T> envelope matching real Defender wire format.
        """
        w = CompactBinaryV1Writer()
        report_guid = str(uuid.uuid4())

        self._write_top_level(w, report_guid)

        # FileReportElements (F390): LIST<LIST<STRUCT>>
        w.write_field_begin(BondType.BT_LIST, SF.FILE_REPORT_ELEMENTS)
        w._write_byte(BondType.BT_LIST)
        w._write_varint(1)
        w._write_byte(BondType.BT_STRUCT)
        w._write_varint(1)

        # FileReport struct
        w._field_stack.append(0)
        w.write_list_begin(FRF.REVISION, BondType.BT_INT16, 1)
        w._write_varint(2)  # zigzag(1)
        w.write_list_begin(FRF.INDEX, BondType.BT_INT16, 1)
        w._write_varint(2)  # zigzag(1)

        # CoreReport (F30): LIST<STRUCT>[1]
        w.write_list_begin(FRF.CORE_REPORT, BondType.BT_STRUCT, 1)
        w._field_stack.append(0)

        w.write_list_begin(CRF.REVISION, BondType.BT_INT16, 1)
        w._write_varint(2)
        w.write_string(CRF.FILE_NAME, file_name)
        if file_size > 0:
            w.write_list_begin(CRF.SIZE, BondType.BT_INT64, 1)
            w._write_varint(file_size << 1)
        if md5:
            w.write_string(CRF.MD5, md5.lower())
        if sha1:
            w.write_string(CRF.SHA1, sha1.lower())
        w.write_string(CRF.SHA256, sha256.lower())

        w._write_byte(BondType.BT_STOP)  # end CoreReport
        w._field_stack.pop()
        w._write_byte(BondType.BT_STOP)  # end FileReport
        w._field_stack.pop()

        # Trailing fields
        w.write_string(SF.ENGINE_REPORT_GUID, str(uuid.uuid4()))
        w.write_int32(SF.AUTO_SAMPLE_OPT_IN, self.config.auto_submit)

        w._write_byte(BondType.BT_STOP)
        return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())

    def build_sample_request_report(
        self,
        file_info: FileInfo,
        threat_id: Optional[int] = None,
    ) -> bytes:
        """Build a SpynetReport requesting a SAS URI for sample upload.

        Sends ReportType.SAMPLE_REQUEST (6) to ask MAPS for an Azure Blob
        upload URL. The response should contain a SampleRequest with
        BLOB_SAS_URI if the cloud wants the sample.
        """
        w = CompactBinaryV1Writer()
        report_guid = str(uuid.uuid4())

        self._write_top_level(w, report_guid)

        # FileReportElements (F390): LIST<LIST<STRUCT>>
        w.write_field_begin(BondType.BT_LIST, SF.FILE_REPORT_ELEMENTS)
        w._write_byte(BondType.BT_LIST)
        w._write_varint(1)
        w._write_byte(BondType.BT_STRUCT)
        w._write_varint(1)

        # FileReport struct
        w._field_stack.append(0)
        w.write_list_begin(FRF.REVISION, BondType.BT_INT16, 1)
        w._write_varint(2)
        w.write_list_begin(FRF.INDEX, BondType.BT_INT16, 1)
        w._write_varint(2)

        # CoreReport (F30): LIST<STRUCT>[1]
        w.write_list_begin(FRF.CORE_REPORT, BondType.BT_STRUCT, 1)
        w._field_stack.append(0)

        w.write_list_begin(CRF.REVISION, BondType.BT_INT16, 1)
        w._write_varint(2)
        w.write_string(CRF.FILE_NAME, Path(file_info.path).name)
        w.write_string(CRF.FILE_SYSTEM, "NTFS")
        w.write_list_begin(CRF.SIZE, BondType.BT_INT64, 1)
        w._write_varint(file_info.size << 1)

        # Hashes
        w.write_string(CRF.MD5, file_info.md5)
        w.write_string(CRF.SHA1, file_info.sha1)
        w.write_string(CRF.SHA256, file_info.sha256)

        if threat_id is not None:
            w.write_list_begin(CRF.THREAT_ID, BondType.BT_UINT32, 1)
            w._write_varint(threat_id)

        # ReportType = SAMPLE_REQUEST (6)
        w.write_string(CRF.REPORT_TYPE - 10, str(ReportType.SAMPLE_REQUEST))

        w.write_string(CRF.PATH, file_info.path)

        w._write_byte(BondType.BT_STOP)  # end CoreReport
        w._field_stack.pop()
        w._write_byte(BondType.BT_STOP)  # end FileReport
        w._field_stack.pop()

        # AutoSampleOptIn = 3 (send all samples automatically)
        w.write_int32(SF.AUTO_SAMPLE_OPT_IN, 3)
        w.write_string(SF.ENGINE_REPORT_GUID, str(uuid.uuid4()))

        w._write_byte(BondType.BT_STOP)
        return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())

    def build_wdo_report(
        self,
        file_info: FileInfo,
        threat_id: Optional[int] = None,
    ) -> bytes:
        """Build a Windows Defender Offline (WDO) report.

        WDO reports use ReportType 7 and are sent after offline scans
        (boot-time scans that run outside the OS to detect rootkits and
        persistent threats). The report structure is similar to a regular
        file scan but with the WDO report type.
        """
        w = CompactBinaryV1Writer()
        report_guid = str(uuid.uuid4())

        self._write_top_level(w, report_guid)

        # FileReportElements (F390): LIST<LIST<STRUCT>>
        w.write_field_begin(BondType.BT_LIST, SF.FILE_REPORT_ELEMENTS)
        w._write_byte(BondType.BT_LIST)
        w._write_varint(1)
        w._write_byte(BondType.BT_STRUCT)
        w._write_varint(1)

        # FileReport struct
        w._field_stack.append(0)
        w.write_list_begin(FRF.REVISION, BondType.BT_INT16, 1)
        w._write_varint(2)  # zigzag(1)
        w.write_list_begin(FRF.INDEX, BondType.BT_INT16, 1)
        w._write_varint(2)  # zigzag(1)

        # CoreReport (F30): LIST<STRUCT>[1]
        w.write_list_begin(FRF.CORE_REPORT, BondType.BT_STRUCT, 1)
        w._field_stack.append(0)

        w.write_list_begin(CRF.REVISION, BondType.BT_INT16, 1)
        w._write_varint(2)
        w.write_string(CRF.FILE_NAME, Path(file_info.path).name)
        w.write_string(CRF.FILE_SYSTEM, "NTFS")
        w.write_list_begin(CRF.SIZE, BondType.BT_INT64, 1)
        w._write_varint(file_info.size << 1)

        # Hashes
        w.write_string(CRF.MD5, file_info.md5)
        w.write_string(CRF.SHA1, file_info.sha1)
        w.write_string(CRF.SHA256, file_info.sha256)

        if threat_id is not None:
            w.write_list_begin(CRF.THREAT_ID, BondType.BT_UINT32, 1)
            w._write_varint(threat_id)

        # ReportType = WDO_REPORT (7)
        w.write_string(CRF.REPORT_TYPE - 10, str(ReportType.WDO_REPORT))

        w.write_string(CRF.PATH, file_info.path)

        w._write_byte(BondType.BT_STOP)  # end CoreReport
        w._field_stack.pop()
        w._write_byte(BondType.BT_STOP)  # end FileReport
        w._field_stack.pop()

        w.write_string(SF.ENGINE_REPORT_GUID, str(uuid.uuid4()))
        w.write_int32(SF.AUTO_SAMPLE_OPT_IN, self.config.auto_submit)

        w._write_byte(BondType.BT_STOP)
        return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())

    def build_amsi_report(
        self,
        script_content: str,
        app_id: str = "powershell.exe",
        content_name: str = "",
        session_id: int = 0,
    ) -> bytes:
        """Build a SpynetReport for AMSI script content analysis.

        AMSI (Antimalware Scan Interface) content is submitted through the
        standard SpynetReport pipeline. Script content is embedded within
        the CoreReport using AMSI-specific fields (RE'd from mpengine.dll
        by aae86e9 agent).

        Structure:
          SpynetReport {
            ...top-level fields...
            F190: FileReportElements [{
              FileReport {
                F30: CoreReport [{
                  F20: FileName (script name or app_id)
                  F340: ReportType = ASYNC_LOWFI (1)
                  F1325: AmsiAppId (e.g. "powershell.exe")
                  F1328: AmsiSessionId
                  F1370: AmsiContentName
                  F1371: AmsiContentName_Scrubbed
                }]
              }
            }]
          }

        Args:
            script_content: The script/content text to submit.
            app_id: AMSI host application (e.g. "powershell.exe", "cscript.exe").
            content_name: Content name/path (defaults to app_id).
            session_id: AMSI session correlation ID.
        """
        import zlib

        w = CompactBinaryV1Writer()
        report_guid = str(uuid.uuid4())

        if not content_name:
            content_name = app_id

        self._write_top_level(w, report_guid)

        # Hash the script content for file-like identification
        script_bytes = script_content.encode('utf-8')
        sha256 = hashlib.sha256(script_bytes).hexdigest()
        sha1 = hashlib.sha1(script_bytes).hexdigest()
        md5 = hashlib.md5(script_bytes).hexdigest()

        # FileReportElements (F190): LIST<LIST<STRUCT>>
        w.write_field_begin(BondType.BT_LIST, SF.FILE_REPORT_ELEMENTS)
        w._write_byte(BondType.BT_LIST)
        w._write_varint(1)
        w._write_byte(BondType.BT_STRUCT)
        w._write_varint(1)

        # FileReport struct
        w._field_stack.append(0)
        w.write_list_begin(FRF.REVISION, BondType.BT_INT16, 1)
        w._write_varint(2)  # zigzag(1)
        w.write_list_begin(FRF.INDEX, BondType.BT_INT16, 1)
        w._write_varint(2)  # zigzag(1)

        # CoreReport (F30): LIST<STRUCT>[1]
        w.write_list_begin(FRF.CORE_REPORT, BondType.BT_STRUCT, 1)
        w._field_stack.append(0)

        w.write_list_begin(CRF.REVISION, BondType.BT_INT16, 1)
        w._write_varint(2)
        w.write_string(CRF.FILE_NAME, content_name)

        # Script content hashes
        w.write_string(CRF.MD5, md5)
        w.write_string(CRF.SHA1, sha1)
        w.write_string(CRF.SHA256, sha256)

        # Report type: ASYNC_LOWFI for AMSI content
        w.write_string(CRF.REPORT_TYPE - 10, str(ReportType.ASYNC_LOWFI))

        # AMSI-specific fields (RE'd ordinals from CoreReport schema table)
        w.write_string(CRF.AMSI_APP_ID, app_id)
        w.write_uint32(CRF.AMSI_SESSION_ID, session_id)
        w.write_string(CRF.AMSI_CONTENT_NAME, content_name)
        w.write_string(CRF.AMSI_CONTENT_NAME_SCRUB, content_name)

        w._write_byte(BondType.BT_STOP)  # end CoreReport
        w._field_stack.pop()
        w._write_byte(BondType.BT_STOP)  # end FileReport
        w._field_stack.pop()

        w.write_string(SF.ENGINE_REPORT_GUID, str(uuid.uuid4()))
        w.write_int32(SF.AUTO_SAMPLE_OPT_IN, self.config.auto_submit)

        w._write_byte(BondType.BT_STOP)
        return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())

    def build_url_reputation_query(self, url: str, referrer: str = "") -> bytes:
        """Build a SpynetReport for URL reputation lookup.

        Structure (RE'd from mpengine.dll function at 0x105251b2 by a5f83eb agent):
          SpynetReport {
            ...top-level fields...
            F190: FileReportElements (with URL_REPUTATION report type)
            F1542: UrlReport {
              F3: UrlReportGuid (STRING) — mandatory
              F6: UrlList (STRUCT) {    — mandatory
                F3: Urls (LIST<STRUCT>) [
                  UrlElement {
                    F20: Url (STRING)   — only field set by engine
                  }
                ]
              }
              F9: UrlContext (STRUCT)    — optional, built from context data
              F12: SigSeq (STRING)      — mandatory, sig sequence number
              F15: SigSha (STRING)      — mandatory, sig SHA hash
              F18: ReportOnly (BOOL)    — omitted when querying (only set when report_only=true)
            }
          }

        Key findings from RE (a5f83eb agent):
        - UrlElement only needs F20 (url) — Order and Url_Scrubbed are never set by engine
        - SigSeq/SigSha are mandatory (sig definition version tracking)
        - ReportOnly is omitted (not set to false) when querying for reputation
        - UrlReport encoded as LIST<STRUCT> (not BT_STRUCT) — HTTP 500 otherwise
        """
        w = CompactBinaryV1Writer()
        report_guid = str(uuid.uuid4())

        self._write_top_level(w, report_guid)

        # FileReportElements with URL_REPUTATION report type
        w.write_field_begin(BondType.BT_LIST, SF.FILE_REPORT_ELEMENTS)
        w._write_byte(BondType.BT_LIST)
        w._write_varint(1)
        w._write_byte(BondType.BT_STRUCT)
        w._write_varint(1)

        # FileReport
        w._field_stack.append(0)
        w.write_list_begin(FRF.REVISION, BondType.BT_INT16, 1)
        w._write_varint(2)
        w.write_list_begin(FRF.INDEX, BondType.BT_INT16, 1)
        w._write_varint(2)

        # CoreReport
        w.write_list_begin(FRF.CORE_REPORT, BondType.BT_STRUCT, 1)
        w._field_stack.append(0)
        w.write_list_begin(CRF.REVISION, BondType.BT_INT16, 1)
        w._write_varint(2)
        w.write_string(CRF.FILE_NAME, url)
        w.write_string(CRF.WEB_FILE_URL, url)
        if referrer:
            w.write_string(CRF.PATH, referrer)
        w.write_string(CRF.REPORT_TYPE - 10, str(ReportType.URL_REPUTATION))
        w._write_byte(BondType.BT_STOP)  # end CoreReport
        w._field_stack.pop()
        w._write_byte(BondType.BT_STOP)  # end FileReport
        w._field_stack.pop()

        # UrlReport (ordinal 1542) — encoded as LIST<STRUCT>[1]
        # Note: type 266 in schema table = LIST<STRUCT>, NOT a plain STRUCT.
        # Using BT_STRUCT directly causes HTTP 500. Verified by testing:
        # LIST<STRUCT> → HTTP 200, BT_STRUCT → HTTP 500, LIST<LIST<STRUCT>> → HTTP 500.
        w.write_field_begin(BondType.BT_LIST, SF.URL_REPORT)
        w._write_byte(BondType.BT_STRUCT)   # element type: STRUCT
        w._write_varint(1)                   # count: 1

        # UrlReport struct fields
        w._field_stack.append(0)
        w.write_string(URF.URL_REPORT_GUID, str(uuid.uuid4()))

        # UrlList as nested struct
        w.write_field_begin(BondType.BT_STRUCT, URF.URL_LIST)
        w._field_stack.append(0)
        # Urls = LIST<STRUCT> of UrlElement
        w.write_field_begin(BondType.BT_LIST, ULF.URLS)
        w._write_byte(BondType.BT_STRUCT)
        w._write_varint(1)
        # UrlElement — engine only sets F20 (url), skips Order and Url_Scrubbed
        w._field_stack.append(0)
        w.write_string(UEF.URL, url)       # UrlElement.F20: URL (only field set by engine)
        w._write_byte(BondType.BT_STOP)    # end UrlElement
        w._field_stack.pop()
        w._write_byte(BondType.BT_STOP)    # end UrlList
        w._field_stack.pop()

        # SigSeq and SigSha — mandatory per RE of 0x105251b2
        w.write_string(URF.SIG_SEQ, "0")
        w.write_string(URF.SIG_SHA, "")
        # ReportOnly (F18) — omitted when querying (engine only sets it when report_only=true)
        w._write_byte(BondType.BT_STOP)    # end UrlReport
        w._field_stack.pop()

        w.write_string(SF.ENGINE_REPORT_GUID, str(uuid.uuid4()))

        w._write_byte(BondType.BT_STOP)
        return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())

    def build_heartbeat(self, hb_type: int = HeartbeatType.STILL_ALIVE) -> bytes:
        """Build a MAPS heartbeat report.

        Uses the Bonded<T> envelope wrapper and field types matching
        real Defender traffic (verified via ETW capture).

        Args:
            hb_type: Heartbeat subtype (HeartbeatType enum value).
                0=StillAlive, 1=Setup, 2=Uninstall, 3=Error, etc.
        """
        # OS version as "major.0.0.0" format used by Defender
        os_parts = self.config.os_ver.split('.')
        os_ver_short = f"{os_parts[0]}.0.0.0"

        # OS build info string: "major.minor.build.revision" or similar
        os_build_info = self.config.os_ver
        if len(os_parts) <= 3:
            os_build_info = f"11.0.{self.config.os_build}.0"

        os_parts = self.config.os_ver.split('.')
        os_ver_short = f"{os_parts[0]}.0.0.0"
        os_build_info = self.config.os_ver
        if len(os_parts) <= 3:
            os_build_info = f"11.0.{self.config.os_build}.0"

        fields = {
            # F20: Schema version marker
            20: (BondType.BT_LIST, (BondType.BT_INT16, [3])),
            # F30: Machine GUID
            30: (BondType.BT_STRING, self.config.get_guid()),
            # F40: AV signature version
            40: (BondType.BT_STRING, self.config.av_sig_version),
            # F43: AS signature version
            43: (BondType.BT_STRING, self.config.av_sig_version),
            # F50: Signature version
            50: (BondType.BT_STRING, self.config.av_sig_version),
            # F60: Engine version
            60: (BondType.BT_STRING, self.config.engine_version),
            # F70: NIS signature version
            70: (BondType.BT_STRING, self.config.av_sig_version),
            # F80: NIS engine version
            80: (BondType.BT_STRING, self.config.engine_version),
            # F150: OS version (short format)
            150: (BondType.BT_STRING, os_ver_short),
            # F160: OS build info (full)
            160: (BondType.BT_STRING, os_build_info),
            # F170-F270: System info as LIST wrappers
            170: (BondType.BT_LIST, (BondType.BT_UINT32, [self.config.os_build])),
            180: (BondType.BT_LIST, (BondType.BT_INT32, [256])),
            190: (BondType.BT_LIST, (BondType.BT_INT16, [self.config.os_type])),
            200: (BondType.BT_LIST, (BondType.BT_INT32, [self.config.geo_id])),
            210: (BondType.BT_LIST, (BondType.BT_UINT32, [1033])),
            220: (BondType.BT_LIST, (BondType.BT_UINT16, [12])),
            230: (BondType.BT_LIST, (BondType.BT_INT32, [1])),
            240: (BondType.BT_LIST, (BondType.BT_INT64, [1])),
            250: (BondType.BT_LIST, (BondType.BT_INT64, [self.config.cloud_block_level])),
            260: (BondType.BT_LIST, (BondType.BT_INT64, [self.config.spynet_level])),
            270: (BondType.BT_LIST, (BondType.BT_INT64, [0])),
            # F280: Session GUID
            280: (BondType.BT_STRING, str(uuid.uuid4())),
            # F290: Report type ("2" = heartbeat)
            290: (BondType.BT_STRING, "2"),
            # F300: App/platform version
            300: (BondType.BT_STRING, self.config.app_version),
            # F920: StillAliveHB - heartbeat subtype
            920: (BondType.BT_LIST, (BondType.BT_UINT8, [hb_type])),
            # F930: HBControlGroup
            930: (BondType.BT_LIST, (BondType.BT_UINT8, [0])),
        }

        return bond_marshal_with_schema(SPYNET_REPORT_SCHEMA, fields)

    def build_network_connection_report(
        self,
        remote_ip: str,
        remote_port: int,
        local_port: int = 0,
        protocol: int = 6,  # 6=TCP, 17=UDP
        source_ip: str = "0.0.0.0",
        uri: str = "",
    ) -> bytes:
        """Build a SpynetReport with NetworkConnectionReport V1 telemetry.

        Uses Bond_NetworkConnectionReport schema (10 fields) RE'd from
        mpengine.dll schema table at 0x10A065F0 via GetSchema at 0x1034A550.
        RTTI: .?AVBond_NetworkConnectionReport@@

        Args:
            remote_ip: Destination IP address.
            remote_port: Destination port number.
            local_port: Source port number (0 = ephemeral).
            protocol: IANA protocol number (6=TCP, 17=UDP, 1=ICMP).
            source_ip: Source IP address (default 0.0.0.0).
            uri: Optional URI associated with connection.
        """
        w = CompactBinaryV1Writer()
        report_guid = str(uuid.uuid4())

        self._write_top_level(w, report_guid)

        # FileReportElements (minimal, just revision/report type)
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
        w.write_string(CRF.FILE_NAME, f"netconn:{remote_ip}:{remote_port}")
        w.write_string(CRF.REPORT_TYPE - 10, str(ReportType.TELEMETRY_ONLY))
        w._write_byte(BondType.BT_STOP)  # end CoreReport
        w._field_stack.pop()
        w._write_byte(BondType.BT_STOP)  # end FileReport
        w._field_stack.pop()

        # NetworkConnectionReportElements (F1190): LIST<STRUCT>
        # Scrub IPs for _Scrubbed fields (mask last octet for IPv4)
        def _scrub_ip(ip: str) -> str:
            parts = ip.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.x"
            return ip

        # FILETIME: 100-ns intervals since 1601-01-01
        filetime = int((time.time() + 11644473600) * 10_000_000)

        w.write_field_begin(BondType.BT_LIST, SF.NETWORK_CONN_ELEMENTS)
        w._write_byte(BondType.BT_STRUCT)
        w._write_varint(1)
        w._field_stack.append(0)
        w.write_uint64(NCRF.TIMESTAMP, filetime)
        w.write_string(NCRF.DESTINATION_IP, remote_ip)
        w.write_string(NCRF.DESTINATION_IP_SCRUB, _scrub_ip(remote_ip))
        w.write_string(NCRF.SOURCE_IP, source_ip)
        w.write_string(NCRF.SOURCE_IP_SCRUBBED, _scrub_ip(source_ip))
        w.write_uint16(NCRF.DESTINATION_PORT, remote_port)
        w.write_uint16(NCRF.SOURCE_PORT, local_port)
        w.write_uint16(NCRF.PROTOCOL, protocol)
        if uri:
            w.write_string(NCRF.URI, uri)
            w.write_string(NCRF.URI_SCRUBBED, uri)
        w._write_byte(BondType.BT_STOP)  # end NetworkConnectionReport
        w._field_stack.pop()

        w.write_string(SF.ENGINE_REPORT_GUID, str(uuid.uuid4()))
        w.write_int32(SF.AUTO_SAMPLE_OPT_IN, self.config.auto_submit)

        w._write_byte(BondType.BT_STOP)
        return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())

    def build_amsi_uac_info_report(
        self,
        uac_type: int = 0,
        exe_app_name: str = "",
        exe_command_line: str = "",
        identifier: str = "",
        auto_elevate: bool = False,
        blocked: bool = False,
        trusted_state: int = 0,
        requestor_name: str = "",
    ) -> bytes:
        """Build a SpynetReport with AmsiUacInfo telemetry.

        Reports UAC elevation info to MAPS cloud for behavioral analysis.
        Uses the Bond_AmsiUacInfo schema (30 fields, RE'd from mpengine.dll
        schema table at 0x10a055f0 by a9c5bd1 agent).

        Structure:
          SpynetReport {
            ...top-level fields...
            F1275: AmsiUacInfos (LIST<STRUCT>) [
              AmsiUacInfo {
                F0:  Type (INT32) — 0=Exe, 1=COM, 2=MSI, 3=ActiveX, 4=PkApp
                F3:  Identifier (STRING)
                F6:  Blocked (BOOL)
                F9:  TrustedState (INT32)
                F12: RequestorName (STRING)
                F21: AutoElevate (BOOL)
                F24: ExeAppName (STRING) — populated when Type=0
                F30: ExeCommandLine (STRING) — populated when Type=0
                ...30 fields total...
              }
            ]
          }

        Args:
            uac_type: UAC request type (0=Exe, 1=COM, 2=MSI, 3=ActiveX, 4=PkApp).
            exe_app_name: Executable requesting elevation (for type=0).
            exe_command_line: Command line of requestor (for type=0).
            identifier: UAC request identifier.
            auto_elevate: Whether auto-elevation is requested.
            blocked: Whether the elevation was blocked.
            trusted_state: Trust state of the requestor.
            requestor_name: Name of the process requesting elevation.
        """
        w = CompactBinaryV1Writer()
        report_guid = str(uuid.uuid4())

        self._write_top_level(w, report_guid)

        # FileReportElements (minimal)
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
        w.write_string(CRF.FILE_NAME, exe_app_name or requestor_name or "uac_request")
        w.write_string(CRF.REPORT_TYPE - 10, str(ReportType.TELEMETRY_ONLY))

        # AMSI UAC identifier in CoreReport
        if identifier:
            w.write_string(CRF.AMSI_UAC_IDENTIFIER, identifier)

        w._write_byte(BondType.BT_STOP)  # end CoreReport
        w._field_stack.pop()
        w._write_byte(BondType.BT_STOP)  # end FileReport
        w._field_stack.pop()

        # AmsiUacInfos (F1275): LIST<STRUCT>
        w.write_field_begin(BondType.BT_LIST, SF.AMSI_UAC_INFOS)
        w._write_byte(BondType.BT_STRUCT)
        w._write_varint(1)
        w._field_stack.append(0)

        # Type discriminant (ordinal 0 — must use write_field_begin directly)
        w.write_int32(AUIF.TYPE, uac_type)
        if identifier:
            w.write_string(AUIF.IDENTIFIER, identifier)
        w.write_bool(AUIF.BLOCKED, blocked)
        w.write_int32(AUIF.TRUSTED_STATE, trusted_state)
        if requestor_name:
            w.write_string(AUIF.REQUESTOR_NAME, requestor_name)
            w.write_string(AUIF.REQUESTOR_NAME_SCRUBBED, requestor_name)
        w.write_bool(AUIF.AUTO_ELEVATE, auto_elevate)

        # Type-dependent fields
        if uac_type == 0 and exe_app_name:  # Exe type
            w.write_string(AUIF.EXE_APP_NAME, exe_app_name)
            w.write_string(AUIF.EXE_APP_NAME_SCRUBBED, exe_app_name)
            if exe_command_line:
                w.write_string(AUIF.EXE_COMMAND_LINE, exe_command_line)
                w.write_string(AUIF.EXE_COMMAND_LINE_SCRUBBED, exe_command_line)

        w._write_byte(BondType.BT_STOP)  # end AmsiUacInfo
        w._field_stack.pop()

        w.write_string(SF.ENGINE_REPORT_GUID, str(uuid.uuid4()))
        w.write_int32(SF.AUTO_SAMPLE_OPT_IN, self.config.auto_submit)

        w._write_byte(BondType.BT_STOP)
        return bond_wrap_with_schema(SPYNET_REPORT_SCHEMA, w.get_data())


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

@dataclass
class FastpathEntry:
    """A single TLV entry from a FASTPATH signature blob."""
    sig_type: int
    sig_type_name: str
    data: bytes

    # Parsed fields (populated for known types)
    threat_id: Optional[int] = None
    detection_name: Optional[str] = None
    sha1: Optional[str] = None
    md5_prefix: Optional[str] = None
    compilation_time: Optional[str] = None
    flags: Optional[int] = None


def parse_fastpath_blob(sig_bytes: bytes) -> List[FastpathEntry]:
    """Parse a FASTPATH signature blob as VDM TLV entries.

    FASTPATH blobs use the same TLV format as VDM database files:
      sig_type(1) + size_low(1) + size_high(2) + payload(size)

    Typical structure for a threat detection:
      0xEC  - Encrypted detection logic (256 bytes)
      0xAA  - FASTPATH_DATA metadata (20 bytes, includes compilation timestamp)
      0x5C  - THREAT_BEGIN (threat ID, detection name, severity)
      0x67  - STATIC (hash-based detection: CRC32 + MD5 + SHA1)
      0x5D  - THREAT_END (threat ID, closing bracket)
    """
    # VDM TLV sub-type names.
    # RE'd from mpengine.dll builder at 0x10366065 (sub-types 0x4A-0x61)
    # and response parser at 0x1036e09c (sub-types 0x43-0x67) by af843a1 agent.
    _SIG_NAMES = {
        0x43: "RESPONSE_HDR",       # Response parser entry (trace tag 0x43)
        0x44: "TLV_PARSE_FAIL",     # TLV header parse failed (trace 0x44)
        0x45: "BAD_OUTER_TYPE",     # Outer type != 0xEE (trace 0x45)
        0x46: "BAD_VERSION",        # Inner version != 1 (trace 0x46)
        0x47: "VERSION_1_ERR",      # Version field == 1 error (trace 0x47)
        0x48: "VERSION_UNK_ERR",    # Unknown version error (trace 0x48)
        0x49: "PARSE_COMPLETE",     # Response parse complete (trace 0x49)
        0x4A: "BUILDER_START",      # Builder entry (trace 0x4A)
        0x4B: "BLOB_LIMIT",        # Blob count > 0x20000 (trace 0x4B)
        0x4C: "STREAM_ALLOC",      # Stream allocation (trace 0x4C)
        0x4D: "HEADER_WRITE",      # Header write (trace 0x4D)
        0x4E: "THREAT_WRITE",      # Threat entry write (trace 0x4E)
        0x4F: "CERT_WRITE",        # Certificate write (trace 0x4F)
        0x50: "HASH_WRITE",        # Hash data write (trace 0x50)
        0x51: "PATTERN_WRITE",     # Pattern match write (trace 0x51)
        0x52: "NAME_WRITE",        # Name/string write (trace 0x52)
        0x53: "PATH_WRITE",        # Path write (trace 0x53)
        0x54: "FOLDER_WRITE",      # Folder write (trace 0x54)
        0x55: "PEHSTR_WRITE",      # PEHSTR write (trace 0x55)
        0x56: "LOCALHASH_WRITE",   # Local hash write (trace 0x56)
        0x57: "BEHAVIOR_WRITE",    # Behavior write (trace 0x57)
        0x58: "METADATA_WRITE",    # Metadata write (trace 0x58)
        0x59: "DELTA_WRITE",       # Delta blob write (trace 0x59)
        0x5A: "BLOOM_WRITE",       # Bloom filter write (trace 0x5A)
        0x5B: "ENCRYPT_WRITE",     # Encrypted data write (trace 0x5B)
        0x5C: "THREAT_BEGIN", 0x5D: "THREAT_END", 0x5E: "FILENAME",
        0x5F: "FILEPATH", 0x60: "FOLDERNAME", 0x61: "PEHSTR",
        0x62: "LOCALHASH", 0x64: "BEHAVIOR_SIG", 0x65: "MACRO_SIG",
        0x66: "SCRIPT_SIG", 0x67: "STATIC", 0x69: "LATENT_THREAT",
        0x73: "DELTA_BLOB", 0x77: "PATTMATCH_V2", 0x78: "PEHSTR_EXT",
        0x7E: "SNID", 0x80: "KCRCE", 0x85: "PEHSTR_EXT2",
        0x87: "PESTATIC", 0x8C: "ELFHSTR_EXT", 0x8D: "MACHOHSTR_EXT",
        0xA0: "FRIENDLYFILE_SHA256", 0xA3: "VDM_METADATA",
        0xAA: "FASTPATH_DATA", 0xAB: "FASTPATH_SDN",
        0xAC: "DATABASE_CERT", 0xBD: "LUASTANDALONE",
        0xD8: "FASTPATH_TDN", 0xDA: "FASTPATH_SDN_EX",
        0xDB: "BLOOM_FILTER", 0xEC: "ENVELOPE", 0xEE: "OUTER_WRAPPER",
    }

    entries: List[FastpathEntry] = []
    ptr = 0
    while ptr + 4 <= len(sig_bytes):
        sig_type = sig_bytes[ptr]
        size_low = sig_bytes[ptr + 1]
        size_high = int.from_bytes(sig_bytes[ptr + 2:ptr + 4], 'little')
        size = size_low | (size_high << 8)
        header_len = 4

        if size == 0xFFFFFF and ptr + 8 <= len(sig_bytes):
            size = int.from_bytes(sig_bytes[ptr + 4:ptr + 8], 'little')
            header_len = 8

        payload_start = ptr + header_len
        payload_end = min(payload_start + size, len(sig_bytes))
        data = sig_bytes[payload_start:payload_end]

        name = _SIG_NAMES.get(sig_type, f"UNKNOWN_0x{sig_type:02X}")
        entry = FastpathEntry(sig_type=sig_type, sig_type_name=name, data=data)

        # Parse known types
        if sig_type == 0x5C and len(data) >= 12:  # THREAT_BEGIN
            entry.threat_id = int.from_bytes(data[0:4], 'little')
            entry.flags = int.from_bytes(data[4:8], 'little')
            # Detection name: length at byte 10, string at byte 12
            if len(data) > 12:
                name_len = data[10]
                if 12 + name_len <= len(data):
                    try:
                        det = data[12:12 + name_len].decode('ascii').rstrip('\x00')
                        if det:
                            entry.detection_name = det
                    except UnicodeDecodeError:
                        pass

        elif sig_type == 0x5D and len(data) >= 4:  # THREAT_END
            entry.threat_id = int.from_bytes(data[0:4], 'little')

        elif sig_type == 0xAA and len(data) >= 20:  # FASTPATH_DATA
            # Bytes 12-19: FILETIME compilation timestamp
            ft = int.from_bytes(data[12:20], 'little')
            if ft > 116444736000000000:  # valid FILETIME range
                try:
                    import datetime
                    unix_ts = (ft - 116444736000000000) / 10000000
                    dt = datetime.datetime.utcfromtimestamp(unix_ts)
                    entry.compilation_time = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                except (OSError, OverflowError):
                    pass

        elif sig_type == 0x67 and len(data) >= 20:  # STATIC
            # Last 20 bytes = SHA1 hash
            sha1_bytes = data[-20:]
            entry.sha1 = sha1_bytes.hex()
            # MD5 may be in prefix (bytes 8-24 of prefix contain md5)
            if len(data) >= 34:
                md5_bytes = data[8:24]
                entry.md5_prefix = md5_bytes.hex()

        entries.append(entry)
        ptr = payload_end

    return entries


@dataclass
class MAPSVerdict:
    """Parsed MAPS cloud response."""
    raw_fields: Dict[int, Tuple[str, Any]]
    schema_name: str = ""
    is_malicious: bool = False
    threat_name: Optional[str] = None
    threat_id: Optional[int] = None
    severity: Optional[int] = None
    detection_name: Optional[str] = None    # FASTPATH SDN
    threat_family: Optional[str] = None     # FASTPATH TDN
    signature_data: Optional[bytes] = None  # FASTPATH DATA
    fastpath_entries: Optional[List[FastpathEntry]] = None  # Parsed TLV entries
    sample_requested: bool = False
    sample_requests: Optional[List[Dict]] = None
    clean: bool = False
    revision: Optional[int] = None          # Protocol revision (F3)
    sample_rate: Optional[int] = None       # Telemetry sample rate (F6)
    certificate_response: Optional[Dict[str, Any]] = None
    onboarding_blob: Optional[str] = None
    url_response_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    http_status: Optional[int] = None
    latency_ms: Optional[float] = None
    raw_bytes: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "is_malicious": self.is_malicious,
            "clean": self.clean,
            "threat_name": self.threat_name,
            "threat_id": self.threat_id,
            "severity": self.severity,
            "detection_name": self.detection_name,
            "threat_family": self.threat_family,
            "sample_requested": self.sample_requested,
            "revision": self.revision,
            "sample_rate": self.sample_rate,
            "http_status": self.http_status,
            "latency_ms": self.latency_ms,
        }
        if self.schema_name:
            result["schema"] = self.schema_name
        if self.error:
            result["error"] = self.error
        if self.signature_data:
            result["signature_data_size"] = len(self.signature_data)
        if self.fastpath_entries:
            result["fastpath_entries"] = [
                {
                    "type": f"0x{e.sig_type:02X}",
                    "name": e.sig_type_name,
                    "size": len(e.data),
                    **({"threat_id": e.threat_id} if e.threat_id else {}),
                    **({"detection": e.detection_name} if e.detection_name else {}),
                    **({"sha1": e.sha1} if e.sha1 else {}),
                    **({"compiled": e.compilation_time} if e.compilation_time else {}),
                }
                for e in self.fastpath_entries
            ]
        if self.sample_requests:
            result["sample_requests"] = self.sample_requests
        if self.certificate_response:
            result["certificate_response"] = self.certificate_response
        if self.onboarding_blob:
            result["onboarding_blob"] = self.onboarding_blob
        if self.url_response_data:
            result["url_response_data"] = self.url_response_data
        return {k: v for k, v in result.items() if v is not None}


def parse_response(data: bytes) -> MAPSVerdict:
    """Parse a Bond-encoded SubmitSpynetReportResult / SpynetReportResponse.

    Response envelope (Bonded<T>):
      F5: schema name ("...SubmitSpynetReportResult")
      F6: SpynetReportResponse - delivered as LIST<STRUCT>[1]
      F10: empty STRUCT

    SpynetReportResponse fields (inside the LIST wrapper):
      F3:  Revision (UINT8) - protocol revision (currently 5)
      F6:  SampleRate (INT32) - telemetry sampling rate (1=normal)
      F9:  SampleRequests (LIST<STRUCT>) - cloud requesting file upload
      F12: SignaturePatches (STRUCT) - dynamic signature delivery (FASTPATH)
      F15: UrlResponse (STRUCT) - URL reputation result
      F18: ThreatDetailElements (LIST<STRUCT>) - threat verdicts
      F21: CertificateResponse (STRUCT)
      F24: OnboardingResponse (STRUCT)
    """
    verdict = MAPSVerdict(raw_fields={}, raw_bytes=data)

    if not data:
        verdict.error = "Empty response"
        return verdict

    try:
        schema_name, fields = bond_unmarshal_with_schema(data)
        verdict.raw_fields = fields
        if schema_name:
            verdict.schema_name = schema_name
    except Exception as e:
        # Try XML fallback
        text = data.decode('utf-8', errors='replace')
        if '<SubmitSpynetReportResult>' in text:
            verdict = _parse_xml_response(text)
            verdict.raw_bytes = data
            return verdict
        verdict.error = f"Bond deserialization failed: {e}"
        return verdict

    # Navigate the response structure
    _interpret_response(verdict, fields)
    return verdict


def _interpret_response(verdict: MAPSVerdict, fields: Dict[int, Tuple[str, Any]]):
    """Interpret SubmitSpynetReportResult → SpynetReportResponse fields.

    F6 (SpynetReportResponse) is delivered as LIST<STRUCT>[1] in the
    Bond response - a single-element list containing the response struct.
    """
    # Check for SpynetReportResponse at ordinal 6
    if SSRR.SPYNET_REPORT_RESP in fields:
        _, resp_data = fields[SSRR.SPYNET_REPORT_RESP]

        # Handle LIST<STRUCT> wrapper (real response format)
        if isinstance(resp_data, list):
            for item in resp_data:
                if isinstance(item, dict):
                    _interpret_spynet_response(verdict, item)
            return

        # Handle plain STRUCT (fallback)
        if isinstance(resp_data, dict):
            _interpret_spynet_response(verdict, resp_data)
            return

    # Fallback: try interpreting fields directly as SpynetReportResponse
    _interpret_spynet_response(verdict, fields)


def _interpret_spynet_response(verdict: MAPSVerdict, fields: Dict[int, Tuple[str, Any]]):
    """Interpret SpynetReportResponse fields.

    Known field values:
      F3  Revision (UINT8):  Protocol revision, currently 5
      F6  SampleRate (INT32): Telemetry sampling rate
          1 = normal sampling, higher = more aggressive
      F9  SampleRequests:     Cloud wants file upload for analysis
      F12 SignaturePatches:   Dynamic signature delivery (FASTPATH/SDN)
      F15 UrlResponse:        URL reputation result
      F18 ThreatDetailElements: Threat verdict with name, ID, severity
      F21 CertificateResponse: Certificate trust data
      F24 OnboardingResponse:  Client onboarding info
    """
    # F3: Revision
    if SRR.REVISION in fields:
        _, rev = fields[SRR.REVISION]
        if isinstance(rev, int):
            verdict.revision = rev

    # F6: SampleRate
    if SRR.SAMPLE_RATE in fields:
        _, rate = fields[SRR.SAMPLE_RATE]
        if isinstance(rate, int):
            verdict.sample_rate = rate

    # F18: ThreatDetailElements
    if SRR.THREAT_DETAIL_ELEMS in fields:
        _, td_list = fields[SRR.THREAT_DETAIL_ELEMS]
        if isinstance(td_list, list):
            for item in td_list:
                if isinstance(item, dict):
                    _interpret_threat_details(verdict, item)
        elif isinstance(td_list, dict):
            _interpret_threat_details(verdict, td_list)

    # F9: SampleRequests
    if SRR.SAMPLE_REQUESTS in fields:
        _, sr_data = fields[SRR.SAMPLE_REQUESTS]
        if isinstance(sr_data, list) and sr_data:
            verdict.sample_requested = True
            verdict.sample_requests = []
            for item in sr_data:
                if isinstance(item, dict):
                    sr = {}
                    if SRQ.REQUEST_GUID in item:
                        sr["guid"] = item[SRQ.REQUEST_GUID][1]
                    if SRQ.SHA1 in item:
                        sr["sha1"] = item[SRQ.SHA1][1]
                    if SRQ.BLOB_SAS_URI in item:
                        sr["upload_uri"] = item[SRQ.BLOB_SAS_URI][1]
                    if SRQ.HOLD in item:
                        sr["hold"] = item[SRQ.HOLD][1]
                    if SRQ.TTL in item:
                        sr["ttl"] = item[SRQ.TTL][1]
                    verdict.sample_requests.append(sr)

    # F12: SignaturePatches (FASTPATH dynamic signatures)
    # Presence of SignaturePatches means MAPS confirmed the threat
    # and is sending back a dynamic detection signature.
    if SRR.SIGNATURE_PATCHES in fields:
        _, sig_data = fields[SRR.SIGNATURE_PATCHES]
        _interpret_signature_patches(verdict, sig_data)

    # F21: CertificateResponse
    if SRR.CERTIFICATE_RESPONSE in fields:
        _, cert_data = fields[SRR.CERTIFICATE_RESPONSE]
        if isinstance(cert_data, dict):
            cert_info = {}
            if CRF_CERT.CERT_REPORT_GUID in cert_data:
                cert_info["guid"] = cert_data[CRF_CERT.CERT_REPORT_GUID][1]
            if CRF_CERT.SCENARIO in cert_data:
                cert_info["scenario"] = cert_data[CRF_CERT.SCENARIO][1]
            if CRF_CERT.CERT_RESULTS in cert_data:
                cert_info["results"] = cert_data[CRF_CERT.CERT_RESULTS][1]
            if cert_info:
                verdict.certificate_response = cert_info

    # F24: OnboardingResponse
    if SRR.ONBOARDING_RESPONSE in fields:
        _, onboard_data = fields[SRR.ONBOARDING_RESPONSE]
        if isinstance(onboard_data, dict):
            if ORF.ONBOARDING_BLOB in onboard_data:
                verdict.onboarding_blob = onboard_data[ORF.ONBOARDING_BLOB][1]

    # F15: UrlResponse
    if SRR.URL_RESPONSE in fields:
        _, url_data = fields[SRR.URL_RESPONSE]
        if isinstance(url_data, dict):
            url_info = {}
            if CRF_URL.URL_REPORT_GUID in url_data:
                url_info["guid"] = url_data[CRF_URL.URL_REPORT_GUID][1]
            if CRF_URL.URL_RESULTS in url_data:
                _, url_results = url_data[CRF_URL.URL_RESULTS]
                parsed_results = []
                items = url_results if isinstance(url_results, list) else [url_results]
                for item in items:
                    if isinstance(item, dict):
                        result = {}
                        if ULR.URL in item:
                            result["url"] = item[ULR.URL][1]
                        if ULR.DETERMINATION in item:
                            result["determination"] = item[ULR.DETERMINATION][1]
                        if ULR.CONFIDENCE in item:
                            result["confidence"] = item[ULR.CONFIDENCE][1]
                        if ULR.TTL in item:
                            result["ttl"] = item[ULR.TTL][1]
                        if ULR.TTL_LONG in item:
                            result["ttl_long"] = item[ULR.TTL_LONG][1]
                        if result:
                            parsed_results.append(result)
                url_info["results"] = parsed_results
            if url_info:
                verdict.url_response_data = url_info

    # Determine clean verdict:
    # Response has Revision + SampleRate but NO threats/samples = CLEAN
    if not verdict.is_malicious and not verdict.sample_requested:
        verdict.clean = True


def _interpret_threat_details(verdict: MAPSVerdict, td_fields: Dict[int, Tuple[str, Any]]):
    """Interpret a ThreatDetails struct."""
    if TDF.THREAT_NAME in td_fields:
        _, name = td_fields[TDF.THREAT_NAME]
        if isinstance(name, str) and name:
            verdict.is_malicious = True
            verdict.threat_name = name
            verdict.detection_name = name

    if TDF.THREAT_ID in td_fields:
        _, tid = td_fields[TDF.THREAT_ID]
        if isinstance(tid, int) and tid > 0:
            verdict.threat_id = tid
            verdict.is_malicious = True

    if TDF.THREAT_SEVERITY in td_fields:
        _, sev = td_fields[TDF.THREAT_SEVERITY]
        if isinstance(sev, int):
            verdict.severity = sev

    if TDF.THREAT_CATEGORY in td_fields:
        _, cat = td_fields[TDF.THREAT_CATEGORY]
        if isinstance(cat, int) and cat > 0:
            verdict.is_malicious = True


def _interpret_signature_patches(verdict: MAPSVerdict, sig_data):
    """Interpret SignaturePatches (FASTPATH dynamic signature delivery).

    When MAPS confirms a threat, it sends back a SignaturePatch containing
    a binary detection signature. The presence of this data means MALICIOUS.

    SignaturePatch structure (from response):
      F9:  LIST<STRUCT> - signature metadata (often empty)
      F12: LIST<INT8>   - raw binary FASTPATH signature data

    The binary signature blob format (385 bytes typical):
      Bytes 0-3:   Header (76 00 FF 00 - format marker)
      Bytes 4-259: Encrypted/compressed detection logic
      Bytes 260+:  Structured tail with metadata including:
                   - Detection name as null-terminated ASCII string
                     (e.g. "Virus:DOS/EICAR_Test_File")
                   - Threat ID, severity, and remediation data

    FASTPATH signature types (from sig_types.rs):
      0xAA = FASTPATH_DATA  - Binary pattern matching data
      0xAB = FASTPATH_SDN   - Static Detection Name
      0xD8 = FASTPATH_TDN   - Threat Detection Name
      0xDA = FASTPATH_SDN_EX - Extended SDN with metadata
    """
    # Handle LIST<STRUCT> wrapper
    if isinstance(sig_data, list):
        for item in sig_data:
            if isinstance(item, dict):
                _interpret_signature_patches(verdict, item)
            elif isinstance(item, (bytes, bytearray)):
                verdict.is_malicious = True
                verdict.signature_data = bytes(item)
        return

    if not isinstance(sig_data, dict):
        return

    # Look for binary signature data in the struct
    for fid, (tname, val) in sig_data.items():
        if isinstance(val, str) and ':' in val and '/' in val:
            # Detection name like "Trojan:Win32/Vigorf.A"
            verdict.is_malicious = True
            verdict.detection_name = val
            verdict.threat_name = val
        elif isinstance(val, (bytes, bytearray)) and len(val) > 0:
            # Raw bytes blob (LIST<UINT8> or LIST<INT8> → bytes)
            verdict.is_malicious = True
            verdict.signature_data = bytes(val)
            _extract_detection_from_sig(verdict, bytes(val))
            # Parse as VDM TLV entries
            try:
                entries = parse_fastpath_blob(bytes(val))
                if entries:
                    verdict.fastpath_entries = entries
                    for e in entries:
                        if e.detection_name and not verdict.detection_name:
                            verdict.detection_name = e.detection_name
                            verdict.threat_name = e.detection_name
                        if e.threat_id is not None and verdict.threat_id is None:
                            verdict.threat_id = e.threat_id
            except Exception:
                pass  # TLV parsing is best-effort
        elif isinstance(val, list) and val:
            if isinstance(val[0], int):
                # INT array fallback
                sig_bytes = bytes(v & 0xFF for v in val)
                verdict.is_malicious = True
                verdict.signature_data = sig_bytes
                _extract_detection_from_sig(verdict, sig_bytes)
                try:
                    entries = parse_fastpath_blob(sig_bytes)
                    if entries:
                        verdict.fastpath_entries = entries
                except Exception:
                    pass
            elif isinstance(val[0], dict):
                # Nested struct list - recurse
                for item in val:
                    if isinstance(item, dict):
                        _interpret_signature_patches(verdict, item)
        elif isinstance(val, dict):
            # Nested struct
            _interpret_signature_patches(verdict, val)


# Detection name prefixes used by Defender
_DETECTION_PREFIXES = (
    b'Virus:', b'Trojan:', b'Backdoor:', b'Worm:', b'Ransom:',
    b'HackTool:', b'Exploit:', b'TrojanDownloader:', b'TrojanDropper:',
    b'TrojanSpy:', b'PWS:', b'DoS:', b'VirTool:', b'Spammer:',
    b'Rogue:', b'Program:', b'Behavior:', b'PUA:', b'App:',
    b'BrowserModifier:', b'SoftwareBundler:', b'Misleading:',
    b'Adware:', b'Joke:', b'MonitoringTool:', b'RemoteAccess:',
    b'SettingsModifier:', b'Tool:', b'Constructor:', b'DDoS:',
)


def _extract_detection_from_sig(verdict: MAPSVerdict, sig_bytes: bytes):
    """Extract detection name from a FASTPATH signature blob.

    The detection name is embedded as a null-terminated ASCII string
    in the tail section of the blob (typically after byte 260).
    """
    for prefix in _DETECTION_PREFIXES:
        idx = sig_bytes.find(prefix)
        if idx >= 0:
            # Find null terminator
            end = sig_bytes.find(b'\x00', idx)
            if end < 0:
                end = len(sig_bytes)
            try:
                name = sig_bytes[idx:end].decode('ascii')
                if name and not verdict.detection_name:
                    verdict.detection_name = name
                    verdict.threat_name = name
                return
            except UnicodeDecodeError:
                continue


def _parse_xml_response(text: str) -> MAPSVerdict:
    """Parse XML fallback response format."""
    verdict = MAPSVerdict(raw_fields={})
    try:
        import xml.etree.ElementTree as ET
        if not text.strip().startswith('<?xml'):
            text = f"<root>{text}</root>"
        root = ET.fromstring(text)

        result_elem = root.find('.//SubmitSpynetReportResult')
        if result_elem is not None and result_elem.text:
            verdict.detection_name = result_elem.text.strip()
            if verdict.detection_name and verdict.detection_name not in ('', 'clean', 'notfound'):
                verdict.is_malicious = True
                verdict.threat_name = verdict.detection_name
            else:
                verdict.clean = True
    except Exception as e:
        verdict.error = f"XML parse failed: {e}"

    return verdict


# ---------------------------------------------------------------------------
# HTTP Transport
# ---------------------------------------------------------------------------

class MAPSTransport:
    """HTTP transport for MAPS cloud communication."""

    def __init__(self, config: MAPSConfig):
        self.config = config
        if not HAS_REQUESTS:
            raise ImportError(
                "The 'requests' library is required for HTTP transport.\n"
                "Install it with: pip install requests"
            )
        self.session = requests.Session()
        self.session.verify = config.verify_ssl

        if config.proxy:
            self.session.proxies = {
                "http": config.proxy,
                "https": config.proxy,
            }

    def send_report(self, payload: bytes, path: str = MAPS_BOND_PATH) -> Tuple[int, bytes, float]:
        """POST a Bond-serialized report to the MAPS endpoint.

        Returns (http_status, response_body, latency_ms).
        """
        url = self.config.endpoint.rstrip('/') + path

        headers = {
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

        # Enterprise mode: add Bearer token (from AAD client cab96880-...)
        if self.config.bearer_token:
            headers["Authorization"] = f"Bearer {self.config.bearer_token}"

        start = time.monotonic()
        try:
            resp = self.session.post(
                url,
                data=payload,
                headers=headers,
                timeout=self.config.timeout,
            )
            latency = (time.monotonic() - start) * 1000
            return resp.status_code, resp.content, latency
        except requests.exceptions.SSLError as e:
            latency = (time.monotonic() - start) * 1000
            raise ConnectionError(
                f"TLS error (cert pinning?): {e}\n"
                "Tip: Use --no-verify or --proxy to bypass cert pinning.\n"
                "On Windows, set SSLOptions=0 in "
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet"
            ) from e
        except requests.exceptions.RequestException as e:
            latency = (time.monotonic() - start) * 1000
            raise ConnectionError(f"HTTP request failed ({latency:.0f}ms): {e}") from e

    def upload_sample(
        self,
        file_data: bytes,
        sas_uri: str,
        compression: str = "",
        content_type: str = "application/octet-stream",
    ) -> Tuple[int, bytes, float]:
        """Upload a file sample to Azure Blob Storage via SAS URI.

        MAPS provides a BLOB_SAS_URI in the SampleRequest response. The file
        is uploaded via HTTP PUT with the SAS token embedded in the URL.

        Args:
            file_data: Raw file bytes to upload.
            sas_uri: Azure Blob SAS URI from SampleRequest.BLOB_SAS_URI.
            compression: Compression method (""=none, "gzip", "deflate").
            content_type: MIME type for the upload.

        Returns:
            (http_status, response_body, latency_ms)
        """
        import gzip as gzip_mod

        upload_data = file_data
        headers = {
            "Content-Type": content_type,
            "x-ms-blob-type": "BlockBlob",
            "User-Agent": self.config.user_agent,
        }

        # Apply compression if requested
        if compression.lower() in ("gzip", "gz"):
            upload_data = gzip_mod.compress(file_data)
            headers["Content-Encoding"] = "gzip"
            headers["x-ms-meta-compression"] = "gzip"
        elif compression.lower() == "deflate":
            import zlib
            upload_data = zlib.compress(file_data)
            headers["Content-Encoding"] = "deflate"
            headers["x-ms-meta-compression"] = "deflate"

        headers["Content-Length"] = str(len(upload_data))

        start = time.monotonic()
        try:
            resp = self.session.put(
                sas_uri,
                data=upload_data,
                headers=headers,
                timeout=self.config.timeout,
            )
            latency = (time.monotonic() - start) * 1000
            return resp.status_code, resp.content, latency
        except requests.exceptions.RequestException as e:
            latency = (time.monotonic() - start) * 1000
            raise ConnectionError(f"Sample upload failed ({latency:.0f}ms): {e}") from e

    def send_report_with_fallback(
        self,
        payload: bytes,
        path: str = "/",
        endpoints: Optional[List[str]] = None,
    ) -> Tuple[int, bytes, float]:
        """Try multiple endpoints with fallback."""
        if endpoints is None:
            endpoints = [self.config.endpoint]

        last_error = None
        for ep in endpoints:
            try:
                url = ep.rstrip('/') + path
                headers = {
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
                    headers["Authorization"] = f"Bearer {self.config.bearer_token}"
                start = time.monotonic()
                resp = self.session.post(
                    url, data=payload, headers=headers,
                    timeout=self.config.timeout,
                )
                latency = (time.monotonic() - start) * 1000
                return resp.status_code, resp.content, latency
            except Exception as e:
                last_error = e
                continue

        raise ConnectionError(f"All endpoints failed. Last error: {last_error}")


# ---------------------------------------------------------------------------
# High-level MAPS client
# ---------------------------------------------------------------------------

class MAPSClient:
    """High-level client for interacting with the MAPS cloud."""

    def __init__(self, config: Optional[MAPSConfig] = None):
        self.config = config or MAPSConfig()
        self.builder = SpynetReportBuilder(self.config)
        self.transport = None
        if HAS_REQUESTS:
            self.transport = MAPSTransport(self.config)

    def scan_file(self, path: str, threat_id: Optional[int] = None) -> MAPSVerdict:
        """Scan a local file through MAPS cloud.

        1. Computes file hashes and metadata
        2. Builds a SpynetReport with FileReportElements → CoreReport
        3. Sends to MAPS cloud
        4. Parses and returns the verdict
        """
        file_info = analyze_file(path)
        payload = self.builder.build_file_scan_report(file_info, threat_id=threat_id)

        if self.transport is None:
            raise RuntimeError("HTTP transport not available (install 'requests')")

        try:
            status, body, latency = self.transport.send_report(payload)
        except ConnectionError as e:
            verdict = MAPSVerdict(raw_fields={}, error=str(e))
            verdict.raw_bytes = payload
            return verdict

        verdict = parse_response(body)
        verdict.http_status = status
        verdict.latency_ms = latency
        return verdict

    def scan_hash(
        self,
        sha256: str,
        sha1: str = "",
        md5: str = "",
        file_name: str = "unknown",
        file_size: int = 0,
    ) -> MAPSVerdict:
        """Query MAPS cloud by file hash (no local file needed)."""
        payload = self.builder.build_hash_query(
            sha256=sha256, sha1=sha1, md5=md5,
            file_name=file_name, file_size=file_size,
        )

        if self.transport is None:
            raise RuntimeError("HTTP transport not available (install 'requests')")

        try:
            status, body, latency = self.transport.send_report(payload)
        except ConnectionError as e:
            return MAPSVerdict(raw_fields={}, error=str(e))

        verdict = parse_response(body)
        verdict.http_status = status
        verdict.latency_ms = latency
        return verdict

    def check_url(self, url: str, referrer: str = "") -> MAPSVerdict:
        """Query URL reputation through MAPS cloud."""
        payload = self.builder.build_url_reputation_query(url, referrer)

        if self.transport is None:
            raise RuntimeError("HTTP transport not available (install 'requests')")

        try:
            status, body, latency = self.transport.send_report(payload)
        except ConnectionError as e:
            return MAPSVerdict(raw_fields={}, error=str(e))

        verdict = parse_response(body)
        verdict.http_status = status
        verdict.latency_ms = latency
        return verdict

    def heartbeat(self, hb_type: int = HeartbeatType.STILL_ALIVE) -> MAPSVerdict:
        """Send a MAPS heartbeat.

        Args:
            hb_type: Heartbeat subtype. See HeartbeatType enum.
        """
        payload = self.builder.build_heartbeat(hb_type=hb_type)

        if self.transport is None:
            raise RuntimeError("HTTP transport not available (install 'requests')")

        try:
            status, body, latency = self.transport.send_report(payload)
        except ConnectionError as e:
            return MAPSVerdict(raw_fields={}, error=str(e))

        verdict = parse_response(body)
        verdict.http_status = status
        verdict.latency_ms = latency
        return verdict

    def upload_sample(
        self,
        path: str,
        sas_uri: str,
        compression: str = "",
    ) -> Dict[str, Any]:
        """Upload a file to Azure Blob Storage for cloud detonation.

        Args:
            path: Local file path to upload.
            sas_uri: Azure Blob SAS URI from SampleRequest.BLOB_SAS_URI.
            compression: Compression method (""=none, "gzip").

        Returns:
            Dict with upload status, HTTP code, and latency.
        """
        if self.transport is None:
            raise RuntimeError("HTTP transport not available (install 'requests')")

        file_data = Path(path).read_bytes()

        try:
            status, body, latency = self.transport.upload_sample(
                file_data=file_data,
                sas_uri=sas_uri,
                compression=compression,
            )
            return {
                "success": 200 <= status < 300,
                "http_status": status,
                "latency_ms": latency,
                "bytes_uploaded": len(file_data),
                "response": body.decode('utf-8', errors='replace') if body else "",
            }
        except ConnectionError as e:
            return {
                "success": False,
                "error": str(e),
                "bytes_uploaded": 0,
            }

    def scan_and_upload(
        self,
        path: str,
        threat_id: Optional[int] = None,
        auto_upload: bool = True,
    ) -> Tuple[MAPSVerdict, Optional[Dict[str, Any]]]:
        """Scan a file and automatically upload if MAPS requests a sample.

        This implements the full cloud detonation flow:
        1. Send SpynetReport with file hashes
        2. If MAPS responds with SampleRequest + BLOB_SAS_URI
        3. Upload the file to Azure Blob Storage

        Returns:
            Tuple of (verdict, upload_result_or_None)
        """
        verdict = self.scan_file(path, threat_id=threat_id)
        upload_result = None

        if verdict.sample_requested and verdict.sample_requests and auto_upload:
            for sr in verdict.sample_requests:
                uri = sr.get("upload_uri")
                if uri:
                    compression = sr.get("compression", "")
                    upload_result = self.upload_sample(
                        path=path,
                        sas_uri=uri,
                        compression=compression,
                    )
                    break  # Upload to first available URI

        return verdict, upload_result

    def request_sample_upload(self, path: str, threat_id: Optional[int] = None) -> MAPSVerdict:
        """Send a SAMPLE_REQUEST report type to request a SAS URI for upload.

        This proactively asks MAPS for a sample upload URL, without waiting
        for MAPS to request it first.
        """
        file_info = analyze_file(path)
        payload = self.builder.build_sample_request_report(file_info, threat_id=threat_id)

        if self.transport is None:
            raise RuntimeError("HTTP transport not available (install 'requests')")

        try:
            status, body, latency = self.transport.send_report(payload)
        except ConnectionError as e:
            return MAPSVerdict(raw_fields={}, error=str(e))

        verdict = parse_response(body)
        verdict.http_status = status
        verdict.latency_ms = latency
        return verdict

    def wdo_scan(self, path: str, threat_id: Optional[int] = None) -> MAPSVerdict:
        """Send a Windows Defender Offline (WDO) report for a file.

        WDO reports are used for boot-time offline scans that detect
        rootkits and persistent threats outside the running OS.
        """
        file_info = analyze_file(path)
        payload = self.builder.build_wdo_report(file_info, threat_id=threat_id)

        if self.transport is None:
            raise RuntimeError("HTTP transport not available (install 'requests')")

        try:
            status, body, latency = self.transport.send_report(payload)
        except ConnectionError as e:
            return MAPSVerdict(raw_fields={}, error=str(e))

        verdict = parse_response(body)
        verdict.http_status = status
        verdict.latency_ms = latency
        return verdict

    def amsi_scan(
        self,
        script_content: str,
        app_id: str = "powershell.exe",
        content_name: str = "",
        session_id: int = 0,
    ) -> MAPSVerdict:
        """Submit script content via AMSI protocol for cloud analysis.

        Sends script content embedded in CoreReport AMSI fields, similar
        to how Windows Defender sends AMSI content from PowerShell,
        cscript, wscript, etc.

        Args:
            script_content: Script text to analyze.
            app_id: AMSI host application identifier.
            content_name: Content name/path (defaults to app_id).
            session_id: AMSI session correlation ID.
        """
        payload = self.builder.build_amsi_report(
            script_content,
            app_id=app_id,
            content_name=content_name,
            session_id=session_id,
        )

        if self.transport is None:
            raise RuntimeError("HTTP transport not available (install 'requests')")

        try:
            status, body, latency = self.transport.send_report(payload)
        except ConnectionError as e:
            return MAPSVerdict(raw_fields={}, error=str(e))

        verdict = parse_response(body)
        verdict.http_status = status
        verdict.latency_ms = latency
        return verdict

    def amsi_uac_report(
        self,
        uac_type: int = 0,
        exe_app_name: str = "",
        exe_command_line: str = "",
        identifier: str = "",
        auto_elevate: bool = False,
        blocked: bool = False,
        trusted_state: int = 0,
        requestor_name: str = "",
    ) -> MAPSVerdict:
        """Submit an AMSI UAC elevation info report to MAPS cloud.

        Reports UAC elevation telemetry using Bond_AmsiUacInfo schema
        (30 fields, RE'd from mpengine.dll at 0x10a055f0 by a9c5bd1 agent).

        Args:
            uac_type: 0=Exe, 1=COM, 2=MSI, 3=ActiveX, 4=PkApp.
            exe_app_name: Executable requesting elevation.
            exe_command_line: Command line of requestor.
            identifier: UAC request identifier.
            auto_elevate: Whether auto-elevation is requested.
            blocked: Whether the elevation was blocked.
            trusted_state: Trust state of the requestor.
            requestor_name: Process requesting elevation.
        """
        payload = self.builder.build_amsi_uac_info_report(
            uac_type=uac_type,
            exe_app_name=exe_app_name,
            exe_command_line=exe_command_line,
            identifier=identifier,
            auto_elevate=auto_elevate,
            blocked=blocked,
            trusted_state=trusted_state,
            requestor_name=requestor_name,
        )

        if self.transport is None:
            raise RuntimeError("HTTP transport not available (install 'requests')")

        try:
            status, body, latency = self.transport.send_report(payload)
        except ConnectionError as e:
            return MAPSVerdict(raw_fields={}, error=str(e))

        verdict = parse_response(body)
        verdict.http_status = status
        verdict.latency_ms = latency
        return verdict

    def network_conn_report(
        self,
        remote_ip: str,
        remote_port: int,
        local_port: int = 0,
        protocol: int = 6,
        source_ip: str = "0.0.0.0",
        uri: str = "",
    ) -> MAPSVerdict:
        """Submit a network connection report to MAPS cloud.

        Reports network connection telemetry using Bond_NetworkConnectionReport
        V1 schema (10 fields, RE'd from mpengine.dll at 0x10A065F0).

        Args:
            remote_ip: Destination IP address.
            remote_port: Destination port number.
            local_port: Source port (0 = ephemeral).
            protocol: IANA protocol number (6=TCP, 17=UDP).
            source_ip: Source IP address.
            uri: Optional URI.
        """
        payload = self.builder.build_network_connection_report(
            remote_ip=remote_ip,
            remote_port=remote_port,
            local_port=local_port,
            protocol=protocol,
            source_ip=source_ip,
            uri=uri,
        )

        if self.transport is None:
            raise RuntimeError("HTTP transport not available (install 'requests')")

        try:
            status, body, latency = self.transport.send_report(payload)
        except ConnectionError as e:
            return MAPSVerdict(raw_fields={}, error=str(e))

        verdict = parse_response(body)
        verdict.http_status = status
        verdict.latency_ms = latency
        return verdict

    def send_raw(self, payload: bytes, path: str = "/") -> Tuple[int, bytes, float]:
        """Send a raw pre-built payload (for replay/testing)."""
        if self.transport is None:
            raise RuntimeError("HTTP transport not available (install 'requests')")
        return self.transport.send_report(payload, path=path)

    # -- Offline analysis ---------------------------------------------------

    def analyze_file_local(self, path: str) -> FileInfo:
        """Analyze a file locally without contacting the cloud."""
        return analyze_file(path)

    def build_report_bytes(self, path: str, threat_id: Optional[int] = None) -> bytes:
        """Build a SpynetReport payload without sending it (for inspection)."""
        file_info = analyze_file(path)
        return self.builder.build_file_scan_report(file_info, threat_id=threat_id)

    @staticmethod
    def decode_payload(data: bytes) -> Dict[int, Tuple[str, Any]]:
        """Decode a Bond CompactBinaryV1 payload (captured traffic).

        Automatically strips the 4-byte marshal header if present.
        """
        if len(data) >= 4:
            magic = struct.unpack_from('<H', data, 0)[0]
            if magic == 0x4243:  # COMPACT_PROTOCOL marshal header
                data = data[4:]
        return bond_deserialize(data)

    @staticmethod
    def format_decoded(fields: Dict[int, Tuple[str, Any]], schema: Optional[Dict[int, str]] = None) -> str:
        """Pretty-print decoded Bond fields."""
        return bond_pretty_print(fields, schema=schema)


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------

CONFIG_DIR = Path.home() / ".maps_scanner"
CONFIG_FILE = CONFIG_DIR / "config.json"


def save_config(config: MAPSConfig):
    """Save config to disk."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    data = {
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
        "customer_type": config.customer_type,
    }
    if config.bearer_token:
        data["bearer_token"] = config.bearer_token
    CONFIG_FILE.write_text(json.dumps(data, indent=2))


def load_config() -> MAPSConfig:
    """Load config from disk, or create defaults."""
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text())
            return MAPSConfig(**{k: v for k, v in data.items()
                                if k in MAPSConfig.__dataclass_fields__})
        except Exception:
            pass
    return MAPSConfig()
