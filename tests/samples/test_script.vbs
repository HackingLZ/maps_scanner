' Test VBScript for MAPS scanner AMSI testing
' App ID: cscript.exe or wscript.exe
Dim objShell
Set objShell = CreateObject("WScript.Shell")
' Simulated suspicious patterns (inert in comments):
' Scripting.FileSystemObject, Shell.Application, ADODB.Stream
' These are common COM objects in malicious VBS
WScript.Echo "MAPS AMSI VBScript test complete"
WScript.Quit 0
