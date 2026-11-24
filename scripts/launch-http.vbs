' Silent HTTP MCP launcher. WindowStyle 0 = no console.
' Looks up pythonw on PATH, then common install dirs. No machine-specific paths.
Option Explicit
Dim sh, fso, cmd, here, repo, pyw, script
Set sh = CreateObject("Wscript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
here = fso.GetParentFolderName(WScript.ScriptFullName)
repo = fso.GetParentFolderName(here)
script = repo & "\mcp\pos-delivery\run_http_9911.py"
pyw = FindPythonw()
If pyw = "" Then
  sh.Popup "找不到 pythonw.exe。请安装 Python 3.10+ 并勾选 Add to PATH。", 8, "ARTEX Terminal", 16
  WScript.Quit 1
End If
If Not fso.FileExists(script) Then
  sh.Popup "找不到 run_http_9911.py", 8, "ARTEX Terminal", 16
  WScript.Quit 1
End If
cmd = """" & pyw & """ """ & script & """"
sh.CurrentDirectory = fso.GetParentFolderName(script)
sh.Run cmd, 0, False

Function FindPythonw()
  Dim paths, p, cand, home, locals, i
  Dim names
  names = Array("pythonw.exe")
  paths = Split(sh.ExpandEnvironmentStrings("%PATH%"), ";")
  For Each p In paths
    p = Trim(p)
    If p <> "" Then
      cand = fso.BuildPath(p, "pythonw.exe")
      If fso.FileExists(cand) Then
        FindPythonw = cand
        Exit Function
      End If
    End If
  Next
  home = sh.ExpandEnvironmentStrings("%LOCALAPPDATA%")
  locals = Array( _
    home & "\Programs\Python\Python314\pythonw.exe", _
    home & "\Programs\Python\Python313\pythonw.exe", _
    home & "\Programs\Python\Python312\pythonw.exe", _
    home & "\Programs\Python\Python311\pythonw.exe", _
    home & "\Programs\Python\Python310\pythonw.exe", _
    "C:\Python314\pythonw.exe", _
    "C:\Python313\pythonw.exe", _
    "C:\Python312\pythonw.exe", _
    "C:\Python311\pythonw.exe", _
    "C:\Python310\pythonw.exe" _
  )
  For i = 0 To UBound(locals)
    If fso.FileExists(locals(i)) Then
      FindPythonw = locals(i)
      Exit Function
    End If
  Next
  FindPythonw = ""
End Function
