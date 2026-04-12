# RegFilter

RegFilter is a kernel mode registry protection driver for Windows.
It sits between the OS and the registry and blocks anything that 
shouldn't be touching critical keys.

Built because malware loves the registry. Run keys, Winlogon, 
Defender settings, UAC, LSA, services. Every persistent threat 
eventually touches one of these. RegFilter makes sure it doesn't 
go through.

## What it protects

HKLM side:
Run and RunOnce persistence
Winlogon hijacking (Userinit, Shell, AutoAdminLogon)
AppInit_DLLs
Image File Execution Options debugger hijack
exefile shell handler hijack
Keyboard scancode map
Safe boot key tampering
Defender real time protection, exclusions, spynet, tamper protection
Windows Firewall enable flags
HVCI and VBS settings
LSA protection (RunAsPPL, RestrictedAdmin)
Vulnerable driver blocklist
Services hive (kernel and system callers only)

HKCU side:
Run and RunOnce per user
UAC bypass via ms-settings shell command
Proxy hijacking
AppInit_DLLs and Load values
DisableTaskMgr, DisableRegistryTools, DisableCMD
DisableSafeMode

## How it works

Four stage pipeline on every registry operation:

Stage 1 is a DJB2 hash table lookup. O(1). Exact match keys 
get hashed on load and checked instantly. Match means block.

Stage 2 is a linear recursive scan for wildcard entries. 
These can't be hashed since the incoming path is longer than 
the stored prefix. Only runs if stage 1 misses.

Stage 3 is caller context. ChkInt() checks if the caller is 
PPL or Light PPL protected, or if it's services.exe parented 
by wininit.exe. Trusted callers get through. Everyone else 
goes through ControlHiveAccess which blocks userland writes 
to the services hive entirely.

Stage 4 is HKCU filtering. Resolves the caller SID from the 
thread impersonation token first to catch ImpersonateLoggedOnUser 
attempts, falls back to primary token. Builds the full 
REGISTRY\USER\<SID>\... path and checks it against the 
HKCU protection table.

## Memory protection

After DriverEntry completes, ZwProtectVirtualMemory Flags the 
protection tables and callback cookie as read only.
On unload write permissions are restored before cleanup.
Note: Sophisticated or Normal Attackers can still Bypass this quite Easily Actually


## Compatibility

Tested on Windows 11 25H2.
May be able to Support (23H2, 24H2)

## Building Instructions

Requirements:
VS2022 
Latest WDK (preferably)
after Opening VS2022 
Click on View in the Top Panel
Then Click on solution Explorer 
afterwards Right click the Source Files In the Solution Explorer
Then hover to Add then click on New Item Name it whatever what you need 
but make sure it is a .c file 
then paste the code then Build it

## How To Run
After Building the Driver which needs 
VS2022 and the WDK Installed
test on Any OS that ranges from Win10 to Win11 any build May be Compatible 
To actually Run the Driver In Windows Ensure 
That test signing is on:
bcdedit /set testsigning on

## Author

Sal.
