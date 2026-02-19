#!/usr/bin/env python3
"""Create test files for MAPS scanner behavior testing.

Generates files designed to trigger specific MAPS cloud responses:
- EICAR test file (known malware detection)
- Minimal PE (triggers deeper analysis/sample request)
- Random binary (clean, unknown)
- PowerShell script (AMSI-style content)
- Suspicious naming patterns
"""

import hashlib
import os
import struct
import uuid
from pathlib import Path

TEST_DIR = Path(__file__).parent / "samples"


def create_eicar():
    """Standard EICAR test file - triggers Virus:DOS/EICAR_Test_File."""
    data = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    path = TEST_DIR / "eicar_test.com"
    path.write_bytes(data)
    print(f"  eicar_test.com: {len(data)}B sha256={hashlib.sha256(data).hexdigest()}")
    return path


def create_minimal_pe():
    """Create a minimal valid PE executable.

    This is a tiny 'do nothing' PE that exits immediately.
    Not malicious, but triggers file report with PE metadata.
    """
    # Minimal DOS header
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    dos_header[60:64] = struct.pack('<I', 64)  # e_lfanew = offset to PE header

    # PE signature
    pe_sig = b'PE\x00\x00'

    # COFF header (x86, 1 section, no symbols)
    coff = struct.pack('<HHIIIHH',
        0x014C,  # Machine: IMAGE_FILE_MACHINE_I386
        1,       # NumberOfSections
        0x65A0C000,  # TimeDateStamp (fake)
        0,       # PointerToSymbolTable
        0,       # NumberOfSymbols
        0xE0,    # SizeOfOptionalHeader (PE32)
        0x0102,  # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    # Optional header (PE32)
    opt = bytearray(0xE0)
    opt[0:2] = struct.pack('<H', 0x10B)   # Magic: PE32
    opt[2] = 14                            # MajorLinkerVersion
    opt[16:20] = struct.pack('<I', 0x1000) # AddressOfEntryPoint
    opt[28:32] = struct.pack('<I', 0x400000)  # ImageBase
    opt[32:36] = struct.pack('<I', 0x1000)    # SectionAlignment
    opt[36:40] = struct.pack('<I', 0x200)     # FileAlignment
    opt[40:42] = struct.pack('<H', 6)      # MajorOperatingSystemVersion
    opt[44:46] = struct.pack('<H', 6)      # MajorSubsystemVersion
    opt[56:60] = struct.pack('<I', 0x3000) # SizeOfImage
    opt[60:64] = struct.pack('<I', 0x200)  # SizeOfHeaders
    opt[68:70] = struct.pack('<H', 3)      # Subsystem: CONSOLE
    opt[72:76] = struct.pack('<I', 0x100000)  # SizeOfStackReserve
    opt[80:84] = struct.pack('<I', 0x100000)  # SizeOfHeapReserve
    opt[92:96] = struct.pack('<I', 16)        # NumberOfRvaAndSizes

    # Section header (.text)
    section = bytearray(40)
    section[0:8] = b'.text\x00\x00\x00'
    section[8:12] = struct.pack('<I', 0x10)    # VirtualSize
    section[12:16] = struct.pack('<I', 0x1000) # VirtualAddress
    section[16:20] = struct.pack('<I', 0x200)  # SizeOfRawData
    section[20:24] = struct.pack('<I', 0x200)  # PointerToRawData
    section[36:40] = struct.pack('<I', 0x60000020)  # Characteristics: CODE|EXEC|READ

    # Code section: just 'ret' (0xC3) padded to file alignment
    code = bytearray(0x200)
    code[0] = 0xC3  # ret

    # Assemble PE
    pe = bytearray()
    pe.extend(dos_header)
    pe.extend(pe_sig)
    pe.extend(coff)
    pe.extend(opt)
    pe.extend(section)

    # Pad to file alignment
    while len(pe) < 0x200:
        pe.append(0)

    pe.extend(code)

    path = TEST_DIR / "minimal_test.exe"
    path.write_bytes(bytes(pe))
    print(f"  minimal_test.exe: {len(pe)}B sha256={hashlib.sha256(bytes(pe)).hexdigest()}")
    return path


def create_random_binary():
    """Random binary data - should be CLEAN/UNKNOWN."""
    data = os.urandom(4096)
    path = TEST_DIR / "random_data.bin"
    path.write_bytes(data)
    print(f"  random_data.bin: {len(data)}B sha256={hashlib.sha256(data).hexdigest()}")
    return path


def create_suspicious_script():
    """PowerShell-like script with suspicious patterns.

    Contains patterns that would trigger AMSI analysis in real Defender.
    Safe content - just string patterns that look suspicious.
    """
    content = b"""# This is a test script for MAPS scanner testing
# Contains patterns that simulate AMSI-triggerable content
$encoded = [System.Convert]::FromBase64String("VGVzdFN0cmluZw==")
$decoded = [System.Text.Encoding]::UTF8.GetString($encoded)
Write-Host "Test complete: $decoded"
# Simulated process injection keywords (inert):
# VirtualAlloc, WriteProcessMemory, CreateRemoteThread
# These are just comment strings for testing detection patterns
"""
    path = TEST_DIR / "test_script.ps1"
    path.write_bytes(content)
    print(f"  test_script.ps1: {len(content)}B sha256={hashlib.sha256(content).hexdigest()}")
    return path


def create_unique_pe():
    """Create a unique PE that MAPS hasn't seen before.

    Embeds a UUID in the PE so each generation produces a new hash.
    This is more likely to trigger a sample request from MAPS.
    """
    # Same minimal PE but with unique data
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    dos_header[60:64] = struct.pack('<I', 64)

    pe_sig = b'PE\x00\x00'

    coff = struct.pack('<HHIIIHH',
        0x014C, 1, 0x65A0C000, 0, 0, 0xE0, 0x0102,
    )

    opt = bytearray(0xE0)
    opt[0:2] = struct.pack('<H', 0x10B)
    opt[2] = 14
    opt[16:20] = struct.pack('<I', 0x1000)
    opt[28:32] = struct.pack('<I', 0x400000)
    opt[32:36] = struct.pack('<I', 0x1000)
    opt[36:40] = struct.pack('<I', 0x200)
    opt[40:42] = struct.pack('<H', 6)
    opt[44:46] = struct.pack('<H', 6)
    opt[56:60] = struct.pack('<I', 0x3000)
    opt[60:64] = struct.pack('<I', 0x200)
    opt[68:70] = struct.pack('<H', 3)
    opt[72:76] = struct.pack('<I', 0x100000)
    opt[80:84] = struct.pack('<I', 0x100000)
    opt[92:96] = struct.pack('<I', 16)

    section = bytearray(40)
    section[0:8] = b'.text\x00\x00\x00'
    section[8:12] = struct.pack('<I', 0x100)
    section[12:16] = struct.pack('<I', 0x1000)
    section[16:20] = struct.pack('<I', 0x200)
    section[20:24] = struct.pack('<I', 0x200)
    section[36:40] = struct.pack('<I', 0x60000020)

    # Code section with unique UUID embedded
    code = bytearray(0x200)
    code[0] = 0xC3  # ret
    unique_id = uuid.uuid4().bytes
    code[16:32] = unique_id  # embed unique data

    pe = bytearray()
    pe.extend(dos_header)
    pe.extend(pe_sig)
    pe.extend(coff)
    pe.extend(opt)
    pe.extend(section)
    while len(pe) < 0x200:
        pe.append(0)
    pe.extend(code)

    path = TEST_DIR / "unique_test.exe"
    path.write_bytes(bytes(pe))
    sha = hashlib.sha256(bytes(pe)).hexdigest()
    print(f"  unique_test.exe: {len(pe)}B sha256={sha} (unique per run)")
    return path


def create_pe_with_version_info():
    """Create a PE with version info resource strings.

    Tests that the scanner extracts FileDescription, ProductName, etc.
    from the PE version info. Also tests certificate/signer fields.
    """
    # Same minimal PE base but with a .rsrc section containing version info
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    dos_header[60:64] = struct.pack('<I', 64)

    pe_sig = b'PE\x00\x00'

    coff = struct.pack('<HHIIIHH',
        0x014C, 2, 0x65A0C000, 0, 0, 0xE0, 0x0102,
    )

    opt = bytearray(0xE0)
    opt[0:2] = struct.pack('<H', 0x10B)
    opt[2] = 14
    opt[16:20] = struct.pack('<I', 0x1000)
    opt[28:32] = struct.pack('<I', 0x400000)
    opt[32:36] = struct.pack('<I', 0x1000)
    opt[36:40] = struct.pack('<I', 0x200)
    opt[40:42] = struct.pack('<H', 6)
    opt[44:46] = struct.pack('<H', 6)
    opt[56:60] = struct.pack('<I', 0x4000)
    opt[60:64] = struct.pack('<I', 0x200)
    opt[68:70] = struct.pack('<H', 3)
    opt[72:76] = struct.pack('<I', 0x100000)
    opt[80:84] = struct.pack('<I', 0x100000)
    opt[92:96] = struct.pack('<I', 16)

    # .text section
    text_section = bytearray(40)
    text_section[0:8] = b'.text\x00\x00\x00'
    text_section[8:12] = struct.pack('<I', 0x10)
    text_section[12:16] = struct.pack('<I', 0x1000)
    text_section[16:20] = struct.pack('<I', 0x200)
    text_section[20:24] = struct.pack('<I', 0x200)
    text_section[36:40] = struct.pack('<I', 0x60000020)

    # .rsrc section (placeholder)
    rsrc_section = bytearray(40)
    rsrc_section[0:8] = b'.rsrc\x00\x00\x00'
    rsrc_section[8:12] = struct.pack('<I', 0x200)
    rsrc_section[12:16] = struct.pack('<I', 0x2000)
    rsrc_section[16:20] = struct.pack('<I', 0x200)
    rsrc_section[20:24] = struct.pack('<I', 0x400)
    rsrc_section[36:40] = struct.pack('<I', 0x40000040)  # INITIALIZED_DATA | READ

    # Code section
    code = bytearray(0x200)
    code[0] = 0xC3  # ret

    # Resource section (minimal, just padding for now)
    rsrc = bytearray(0x200)
    rsrc[0:16] = b'MAPS_TEST_RSRC\x00\x00'

    pe = bytearray()
    pe.extend(dos_header)
    pe.extend(pe_sig)
    pe.extend(coff)
    pe.extend(opt)
    pe.extend(text_section)
    pe.extend(rsrc_section)
    while len(pe) < 0x200:
        pe.append(0)
    pe.extend(code)
    pe.extend(rsrc)

    path = TEST_DIR / "versioned_test.exe"
    path.write_bytes(bytes(pe))
    sha = hashlib.sha256(bytes(pe)).hexdigest()
    print(f"  versioned_test.exe: {len(pe)}B sha256={sha}")
    return path


def create_dll():
    """Create a minimal DLL to test DLL scanning.

    DLLs are reported differently (IMAGE_FILE_DLL characteristic).
    """
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    dos_header[60:64] = struct.pack('<I', 64)

    pe_sig = b'PE\x00\x00'

    # DLL flag set in characteristics
    coff = struct.pack('<HHIIIHH',
        0x014C, 1, 0x65A0C000, 0, 0, 0xE0,
        0x2102,  # EXECUTABLE_IMAGE | 32BIT_MACHINE | DLL
    )

    opt = bytearray(0xE0)
    opt[0:2] = struct.pack('<H', 0x10B)
    opt[2] = 14
    opt[16:20] = struct.pack('<I', 0x1000)
    opt[28:32] = struct.pack('<I', 0x10000000)  # typical DLL base
    opt[32:36] = struct.pack('<I', 0x1000)
    opt[36:40] = struct.pack('<I', 0x200)
    opt[40:42] = struct.pack('<H', 6)
    opt[44:46] = struct.pack('<H', 6)
    opt[56:60] = struct.pack('<I', 0x3000)
    opt[60:64] = struct.pack('<I', 0x200)
    opt[68:70] = struct.pack('<H', 3)
    opt[72:76] = struct.pack('<I', 0x100000)
    opt[80:84] = struct.pack('<I', 0x100000)
    opt[92:96] = struct.pack('<I', 16)

    section = bytearray(40)
    section[0:8] = b'.text\x00\x00\x00'
    section[8:12] = struct.pack('<I', 0x10)
    section[12:16] = struct.pack('<I', 0x1000)
    section[16:20] = struct.pack('<I', 0x200)
    section[20:24] = struct.pack('<I', 0x200)
    section[36:40] = struct.pack('<I', 0x60000020)

    code = bytearray(0x200)
    code[0:3] = b'\xB0\x01\xC3'  # mov al, 1; ret (DllMain returning TRUE)

    pe = bytearray()
    pe.extend(dos_header)
    pe.extend(pe_sig)
    pe.extend(coff)
    pe.extend(opt)
    pe.extend(section)
    while len(pe) < 0x200:
        pe.append(0)
    pe.extend(code)

    path = TEST_DIR / "test_library.dll"
    path.write_bytes(bytes(pe))
    sha = hashlib.sha256(bytes(pe)).hexdigest()
    print(f"  test_library.dll: {len(pe)}B sha256={sha}")
    return path


def create_batch_file():
    """Create a batch script with suspicious patterns.

    Tests non-PE file scanning. Contains patterns that might trigger
    behavioral analysis in a full Defender pipeline.
    """
    content = b"""@echo off
REM Test batch file for MAPS scanner testing
REM Contains patterns that simulate suspicious batch behavior
echo Starting test...
REM Simulated enumeration (inert)
REM whoami /all
REM net user
REM ipconfig /all
REM These are just comment strings
echo Test complete.
pause
"""
    path = TEST_DIR / "test_batch.cmd"
    path.write_bytes(content)
    sha = hashlib.sha256(content).hexdigest()
    print(f"  test_batch.cmd: {len(content)}B sha256={sha}")
    return path


def create_large_pe():
    """Create a larger PE that's more likely to trigger sample upload.

    MAPS may request samples for PEs above a certain size threshold
    or with certain characteristics (imports, entropy, etc.).
    """
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    dos_header[60:64] = struct.pack('<I', 64)

    pe_sig = b'PE\x00\x00'

    coff = struct.pack('<HHIIIHH',
        0x014C, 1, int.from_bytes(uuid.uuid4().bytes[:4], 'little'), 0, 0, 0xE0, 0x0102,
    )

    opt = bytearray(0xE0)
    opt[0:2] = struct.pack('<H', 0x10B)
    opt[2] = 14
    opt[16:20] = struct.pack('<I', 0x1000)
    opt[28:32] = struct.pack('<I', 0x400000)
    opt[32:36] = struct.pack('<I', 0x1000)
    opt[36:40] = struct.pack('<I', 0x200)
    opt[40:42] = struct.pack('<H', 6)
    opt[44:46] = struct.pack('<H', 6)
    opt[56:60] = struct.pack('<I', 0x10000)
    opt[60:64] = struct.pack('<I', 0x200)
    opt[68:70] = struct.pack('<H', 3)
    opt[72:76] = struct.pack('<I', 0x100000)
    opt[80:84] = struct.pack('<I', 0x100000)
    opt[92:96] = struct.pack('<I', 16)

    section = bytearray(40)
    section[0:8] = b'.text\x00\x00\x00'
    section[8:12] = struct.pack('<I', 0x8000)
    section[12:16] = struct.pack('<I', 0x1000)
    section[16:20] = struct.pack('<I', 0x8000)
    section[20:24] = struct.pack('<I', 0x200)
    section[36:40] = struct.pack('<I', 0x60000020)

    # Larger code section with mixed entropy (part code, part random)
    code = bytearray(0x8000)
    code[0] = 0xC3  # ret
    # Fill with pseudo-random data (unique UUID + padding)
    unique_data = uuid.uuid4().bytes * (0x8000 // 16)
    code[16:] = unique_data[:len(code) - 16]

    pe = bytearray()
    pe.extend(dos_header)
    pe.extend(pe_sig)
    pe.extend(coff)
    pe.extend(opt)
    pe.extend(section)
    while len(pe) < 0x200:
        pe.append(0)
    pe.extend(code)

    path = TEST_DIR / "large_unique_test.exe"
    path.write_bytes(bytes(pe))
    sha = hashlib.sha256(bytes(pe)).hexdigest()
    print(f"  large_unique_test.exe: {len(pe)}B sha256={sha} (unique per run)")
    return path


def create_vbscript():
    """Create a VBScript for AMSI testing with cscript.exe app-id.

    VBScript uses a different AMSI host (cscript.exe/wscript.exe) than
    PowerShell, exercising the --app-id parameter.
    """
    content = b"""' Test VBScript for MAPS scanner AMSI testing
' App ID: cscript.exe or wscript.exe
Dim objShell
Set objShell = CreateObject("WScript.Shell")
' Simulated suspicious patterns (inert in comments):
' Scripting.FileSystemObject, Shell.Application, ADODB.Stream
' These are common COM objects in malicious VBS
WScript.Echo "MAPS AMSI VBScript test complete"
WScript.Quit 0
"""
    path = TEST_DIR / "test_script.vbs"
    path.write_bytes(content)
    sha = hashlib.sha256(content).hexdigest()
    print(f"  test_script.vbs: {len(content)}B sha256={sha}")
    return path


def create_javascript():
    """Create a JavaScript file for AMSI testing with wscript.exe/jscript app-id.

    JScript/JavaScript uses different AMSI patterns than PowerShell or VBS.
    """
    content = b"""// Test JavaScript for MAPS scanner AMSI testing
// App ID: wscript.exe (JScript host)
var shell = new ActiveXObject("WScript.Shell");
// Simulated suspicious patterns (inert):
// eval, new Function, WScript.CreateObject
// Scripting.FileSystemObject, XMLHTTP
WScript.Echo("MAPS AMSI JavaScript test complete");
WScript.Quit(0);
"""
    path = TEST_DIR / "test_script.js"
    path.write_bytes(content)
    sha = hashlib.sha256(content).hexdigest()
    print(f"  test_script.js: {len(content)}B sha256={sha}")
    return path


def create_pe_with_imports():
    """Create a PE with an import table referencing kernel32.dll.

    PEs with imports trigger deeper cloud analysis than minimal stubs.
    MAPS examines import tables for suspicious API combinations.
    """
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    dos_header[60:64] = struct.pack('<I', 64)

    pe_sig = b'PE\x00\x00'

    coff = struct.pack('<HHIIIHH',
        0x014C, 2, 0x65A0C000, 0, 0, 0xE0, 0x0102,
    )

    opt = bytearray(0xE0)
    opt[0:2] = struct.pack('<H', 0x10B)   # PE32
    opt[2] = 14
    opt[16:20] = struct.pack('<I', 0x1000)    # EntryPoint
    opt[28:32] = struct.pack('<I', 0x400000)  # ImageBase
    opt[32:36] = struct.pack('<I', 0x1000)    # SectionAlignment
    opt[36:40] = struct.pack('<I', 0x200)     # FileAlignment
    opt[40:42] = struct.pack('<H', 6)
    opt[44:46] = struct.pack('<H', 6)
    opt[56:60] = struct.pack('<I', 0x4000)    # SizeOfImage
    opt[60:64] = struct.pack('<I', 0x200)     # SizeOfHeaders
    opt[68:70] = struct.pack('<H', 3)         # CONSOLE
    opt[72:76] = struct.pack('<I', 0x100000)
    opt[80:84] = struct.pack('<I', 0x100000)
    opt[92:96] = struct.pack('<I', 16)

    # Import table RVA/Size in data directory (index 1)
    # RVA = 0x2000 (in .idata section), Size = 40 (one import descriptor + null)
    struct.pack_into('<II', opt, 96 + 8, 0x2000, 40)

    # .text section
    text_section = bytearray(40)
    text_section[0:8] = b'.text\x00\x00\x00'
    text_section[8:12] = struct.pack('<I', 0x10)
    text_section[12:16] = struct.pack('<I', 0x1000)
    text_section[16:20] = struct.pack('<I', 0x200)
    text_section[20:24] = struct.pack('<I', 0x200)
    text_section[36:40] = struct.pack('<I', 0x60000020)

    # .idata section (imports)
    idata_section = bytearray(40)
    idata_section[0:8] = b'.idata\x00\x00'
    idata_section[8:12] = struct.pack('<I', 0x200)
    idata_section[12:16] = struct.pack('<I', 0x2000)
    idata_section[16:20] = struct.pack('<I', 0x200)
    idata_section[20:24] = struct.pack('<I', 0x400)
    idata_section[36:40] = struct.pack('<I', 0xC0000040)  # INITIALIZED_DATA | READ | WRITE

    # Code section
    code = bytearray(0x200)
    code[0] = 0xC3  # ret

    # Import section data
    idata = bytearray(0x200)
    # IMAGE_IMPORT_DESCRIPTOR for kernel32.dll
    # OriginalFirstThunk=0x2080, TimeDateStamp=0, ForwarderChain=0
    # Name=0x2060 (RVA of "kernel32.dll"), FirstThunk=0x2090
    struct.pack_into('<IIIII', idata, 0, 0x2080, 0, 0, 0x2060, 0x2090)
    # Null terminator descriptor (20 zero bytes) - already zero

    # DLL name at offset 0x60 within idata
    dll_name = b'kernel32.dll\x00'
    idata[0x60:0x60+len(dll_name)] = dll_name

    # Import Lookup Table (ILT) at offset 0x80
    # One entry: hint/name RVA = 0x20A0, then null terminator
    struct.pack_into('<I', idata, 0x80, 0x20A0)
    # null terminator already zero at 0x84

    # Import Address Table (IAT) at offset 0x90 (mirrors ILT)
    struct.pack_into('<I', idata, 0x90, 0x20A0)

    # Hint/Name at offset 0xA0: hint(2 bytes) + name
    struct.pack_into('<H', idata, 0xA0, 0)  # hint = 0
    api_name = b'ExitProcess\x00'
    idata[0xA2:0xA2+len(api_name)] = api_name

    pe = bytearray()
    pe.extend(dos_header)
    pe.extend(pe_sig)
    pe.extend(coff)
    pe.extend(opt)
    pe.extend(text_section)
    pe.extend(idata_section)
    while len(pe) < 0x200:
        pe.append(0)
    pe.extend(code)
    pe.extend(idata)

    path = TEST_DIR / "pe_with_imports.exe"
    path.write_bytes(bytes(pe))
    sha = hashlib.sha256(bytes(pe)).hexdigest()
    print(f"  pe_with_imports.exe: {len(pe)}B sha256={sha}")
    return path


def create_pe64():
    """Create a minimal x64 PE executable.

    Tests that the scanner handles PE32+ (64-bit) correctly.
    Different optional header size and machine type.
    """
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    dos_header[60:64] = struct.pack('<I', 64)

    pe_sig = b'PE\x00\x00'

    # COFF header: AMD64, 1 section
    coff = struct.pack('<HHIIIHH',
        0x8664,  # Machine: IMAGE_FILE_MACHINE_AMD64
        1,       # NumberOfSections
        0x65A0C000,
        0, 0,
        0xF0,    # SizeOfOptionalHeader (PE32+)
        0x0022,  # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )

    # Optional header (PE32+)
    opt = bytearray(0xF0)
    opt[0:2] = struct.pack('<H', 0x20B)   # Magic: PE32+
    opt[2] = 14                            # MajorLinkerVersion
    opt[16:20] = struct.pack('<I', 0x1000) # AddressOfEntryPoint
    # ImageBase is 8 bytes in PE32+
    struct.pack_into('<Q', opt, 24, 0x140000000)  # ImageBase
    opt[32:36] = struct.pack('<I', 0x1000)    # SectionAlignment
    opt[36:40] = struct.pack('<I', 0x200)     # FileAlignment
    opt[40:42] = struct.pack('<H', 6)
    opt[44:46] = struct.pack('<H', 6)
    opt[56:60] = struct.pack('<I', 0x3000)    # SizeOfImage
    opt[60:64] = struct.pack('<I', 0x200)     # SizeOfHeaders
    opt[68:70] = struct.pack('<H', 3)         # Subsystem: CONSOLE
    # PE32+ uses 8-byte fields for stack/heap
    struct.pack_into('<Q', opt, 72, 0x100000)   # SizeOfStackReserve
    struct.pack_into('<Q', opt, 80, 0x1000)     # SizeOfStackCommit
    struct.pack_into('<Q', opt, 88, 0x100000)   # SizeOfHeapReserve
    struct.pack_into('<Q', opt, 96, 0x1000)     # SizeOfHeapCommit
    opt[108:112] = struct.pack('<I', 16)        # NumberOfRvaAndSizes

    # Section header (.text)
    section = bytearray(40)
    section[0:8] = b'.text\x00\x00\x00'
    section[8:12] = struct.pack('<I', 0x10)
    section[12:16] = struct.pack('<I', 0x1000)
    section[16:20] = struct.pack('<I', 0x200)
    section[20:24] = struct.pack('<I', 0x200)
    section[36:40] = struct.pack('<I', 0x60000020)

    # Code: x64 ret
    code = bytearray(0x200)
    code[0] = 0xC3  # ret

    pe = bytearray()
    pe.extend(dos_header)
    pe.extend(pe_sig)
    pe.extend(coff)
    pe.extend(opt)
    pe.extend(section)
    while len(pe) < 0x200:
        pe.append(0)
    pe.extend(code)

    path = TEST_DIR / "test_x64.exe"
    path.write_bytes(bytes(pe))
    sha = hashlib.sha256(bytes(pe)).hexdigest()
    print(f"  test_x64.exe: {len(pe)}B sha256={sha}")
    return path


def create_dotnet_pe():
    """Create a minimal .NET assembly PE.

    .NET PEs have a different analysis path in Defender (CLR metadata).
    They use IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (index 14) to point
    to the CLR header.
    """
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    dos_header[60:64] = struct.pack('<I', 64)

    pe_sig = b'PE\x00\x00'

    coff = struct.pack('<HHIIIHH',
        0x014C, 1, 0x65A0C000, 0, 0, 0xE0, 0x0102,
    )

    opt = bytearray(0xE0)
    opt[0:2] = struct.pack('<H', 0x10B)
    opt[2] = 14
    opt[16:20] = struct.pack('<I', 0x1000)
    opt[28:32] = struct.pack('<I', 0x400000)
    opt[32:36] = struct.pack('<I', 0x1000)
    opt[36:40] = struct.pack('<I', 0x200)
    opt[40:42] = struct.pack('<H', 6)
    opt[44:46] = struct.pack('<H', 6)
    opt[56:60] = struct.pack('<I', 0x3000)
    opt[60:64] = struct.pack('<I', 0x200)
    opt[68:70] = struct.pack('<H', 3)
    opt[72:76] = struct.pack('<I', 0x100000)
    opt[80:84] = struct.pack('<I', 0x100000)
    opt[92:96] = struct.pack('<I', 16)

    # COM Descriptor (CLR header) data directory at index 14
    # Each entry is 8 bytes (RVA + Size), index 14 = offset 96 + 14*8 = 208
    struct.pack_into('<II', opt, 96 + 14 * 8, 0x1000, 72)  # RVA=0x1000, Size=72

    section = bytearray(40)
    section[0:8] = b'.text\x00\x00\x00'
    section[8:12] = struct.pack('<I', 0x200)
    section[12:16] = struct.pack('<I', 0x1000)
    section[16:20] = struct.pack('<I', 0x200)
    section[20:24] = struct.pack('<I', 0x200)
    section[36:40] = struct.pack('<I', 0x60000020)

    # .text section data - contains CLR header + minimal metadata
    text_data = bytearray(0x200)
    # CLR header (IMAGE_COR20_HEADER) at offset 0 (RVA 0x1000)
    struct.pack_into('<I', text_data, 0, 72)         # cb (size)
    struct.pack_into('<HH', text_data, 4, 2, 5)      # MajorRuntimeVersion=2, MinorRuntimeVersion=5
    struct.pack_into('<II', text_data, 8, 0x1050, 32) # MetaData RVA + Size (placeholder)
    struct.pack_into('<I', text_data, 16, 0x00000001) # Flags: ILONLY

    # Minimal CLI metadata signature at offset 0x50 (RVA 0x1050)
    text_data[0x50:0x54] = b'BSJB'  # .NET metadata signature

    pe = bytearray()
    pe.extend(dos_header)
    pe.extend(pe_sig)
    pe.extend(coff)
    pe.extend(opt)
    pe.extend(section)
    while len(pe) < 0x200:
        pe.append(0)
    pe.extend(text_data)

    path = TEST_DIR / "dotnet_test.exe"
    path.write_bytes(bytes(pe))
    sha = hashlib.sha256(bytes(pe)).hexdigest()
    print(f"  dotnet_test.exe: {len(pe)}B sha256={sha}")
    return path


def main():
    TEST_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Creating test files in {TEST_DIR}/")
    print()

    files = [
        ("EICAR (known malware)", create_eicar),
        ("Minimal PE (triggers PE analysis)", create_minimal_pe),
        ("Random binary (clean/unknown)", create_random_binary),
        ("PowerShell script (AMSI patterns)", create_suspicious_script),
        ("Unique PE (never-seen, may trigger sample request)", create_unique_pe),
        ("PE with version info (certificate/metadata)", create_pe_with_version_info),
        ("DLL (different PE characteristics)", create_dll),
        ("Batch script (non-PE suspicious)", create_batch_file),
        ("Large unique PE (more likely to trigger sample upload)", create_large_pe),
        ("VBScript (AMSI with cscript app-id)", create_vbscript),
        ("JavaScript (AMSI with wscript app-id)", create_javascript),
        ("PE with imports (kernel32 ExitProcess)", create_pe_with_imports),
        ("x64 PE (64-bit executable)", create_pe64),
        (".NET assembly (CLR metadata)", create_dotnet_pe),
    ]

    created = []
    for desc, fn in files:
        print(f"[+] {desc}:")
        path = fn()
        created.append(path)
        print()

    print(f"Created {len(created)} test files in {TEST_DIR}/")
    print("\nUsage examples:")
    print(f"  python -m tools.maps_scanner --no-verify scan {created[0]}")
    print(f"  python -m tools.maps_scanner --no-verify scan {created[0]} --threat-id 2147519003")
    print(f"  python -m tools.maps_scanner --no-verify scan {created[3]}")
    print(f"  python -m tools.maps_scanner --no-verify upload {created[4]}")


if __name__ == "__main__":
    main()
