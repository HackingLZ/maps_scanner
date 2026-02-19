# This is a test script for MAPS scanner testing
# Contains patterns that simulate AMSI-triggerable content
$encoded = [System.Convert]::FromBase64String("VGVzdFN0cmluZw==")
$decoded = [System.Text.Encoding]::UTF8.GetString($encoded)
Write-Host "Test complete: $decoded"
# Simulated process injection keywords (inert):
# VirtualAlloc, WriteProcessMemory, CreateRemoteThread
# These are just comment strings for testing detection patterns
