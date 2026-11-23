' Silent HTTP MCP launcher. WindowStyle 0 = no console.
Option Explicit
Dim sh, cmd, here, pyw
here = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
pyw = "C:\Users\蒋蒋\AppData\Local\Programs\Python\Python310\pythonw.exe"
cmd = """" & pyw & """ """ & here & "\..\mcp\pos-delivery\run_http_9911.py"""
Set sh = CreateObject("Wscript.Shell")
sh.CurrentDirectory = here & "\..\mcp\pos-delivery"
sh.Run cmd, 0, False
