# Resources

## Bypassing AV signatures
It is possible to load script in memory in order to avoid detection using AMSI bypass. 

### AMSITrigger
We can use the AMSITrigger tool to identify the exact part of a script that is detected:

- https://github.com/RythmStick/AMSITrigger

Here below an example of AMSITrigger usage

```
AmsiTrigger_x64.exe -i C:\AD\Tools\Invoke-PowerShellTcp_Detected.ps1
```

In order to avoid signature based detection we can perform the following steps:

1. Scan using AMSITrigger
2. Modify the detected code snippet
3. Rescan
4. Repeat steps 2 and 3 till we get the result "AMSI_RESULT_NOT_DETECTED" or "Blank"

### DefenderCheck
We can use DefenderCheck to identify code and strings from a binary file that Windows Defender may flag

- https://github.com/t3hbb/DefenderCheck

Here below an example of DefenderCheck usage 

```
DefenderCheck.exe PowerUp.ps1
```

### Powershell Obfuscation
For full powershell obfuscation scripts, see Invoke-Obfuscation

- https://github.com/danielbohannon/Invoke-Obfuscation
