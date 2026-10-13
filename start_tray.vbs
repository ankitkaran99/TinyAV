' TinyAV Silent System Tray Launcher
' Runs TinyAV minimized to the system tray with ABSOLUTELY ZERO cmd/console windows.

Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
mainPy = scriptDir & "\main.py"
exeFile = scriptDir & "\dist\TinyAV.exe"

' 1. Check if compiled standalone exe exists
If fso.FileExists(exeFile) Then
    WshShell.CurrentDirectory = scriptDir
    WshShell.Run """" & exeFile & """ --minimized", 0, False
    WScript.Quit 0
End If

' 2. Locate pythonw.exe (windowless python)
pythonwPath = ""
' Check Python install directory via registry or standard paths
On Error Resume Next
Set pyEnv = WshShell.Environment("PROCESS")
userProf = pyEnv("USERPROFILE")
localApp = pyEnv("LOCALAPPDATA")

commonPyw = Array( _
    localApp & "\Programs\Python\Python314\pythonw.exe", _
    localApp & "\Programs\Python\Python313\pythonw.exe", _
    localApp & "\Programs\Python\Python312\pythonw.exe", _
    localApp & "\Programs\Python\Python311\pythonw.exe", _
    localApp & "\Programs\Python\Python310\pythonw.exe", _
    "C:\Python314\pythonw.exe", _
    "C:\Python313\pythonw.exe", _
    "C:\Python312\pythonw.exe", _
    "C:\Python311\pythonw.exe", _
    "C:\Python310\pythonw.exe" _
)

For Each candidate In commonPyw
    If fso.FileExists(candidate) Then
        pythonwPath = candidate
        Exit For
    End If
Next
On Error GoTo 0

If pythonwPath = "" Then
    ' Fallback to pythonw in PATH
    pythonwPath = "pythonw.exe"
End If

targetCmd = """" & pythonwPath & """ """ & mainPy & """ --minimized"
WshShell.CurrentDirectory = scriptDir

' Run targetCmd with window style 0 (SW_HIDE = completely invisible, zero console window)
WshShell.Run targetCmd, 0, False
