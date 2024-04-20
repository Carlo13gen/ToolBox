# Resources

## Bypassing AV signatures
It is possible to load script in memory in order to avoid detection using AMSI bypass. 

### AMSITrigger
We can use the AMSITrigger tool to identify the exact part of a script that is detected:

- https://github.com/RythmStick/AMSITrigger

Here below an example of AMSITrigger usage

AmsiTrigger_x64.exe -i C:\AD\Tools\Invoke-PowerShellTcp_Detected.ps1
DefenderCheck.exe PowerUp.ps1 

### DefenderCheck
We can use DefenderCheck to identify code and strings from a binary file that Windows Defender may flag

- https://github.com/t3hbb/DefenderCheck


