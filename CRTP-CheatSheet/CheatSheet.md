# CheatSheet
## Enumeration
### Domain Enumeration Using PowerView.ps1
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

### Enumerate the GPOs using PowerView.ps1
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

### Enumerate ACLs using PowerView.ps1
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

### Enumerate the Domain Trust
Enumerate all the domains in the forest
```
Get-ForestDomain -Verbose
```

Map the trust of the current domain, choose the trust attribute basing on the available ones
```
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "<Trust_attribute>"}
```




