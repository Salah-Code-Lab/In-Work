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

After DriverEntry completes, ZwProtectVirtualMemory marks the 
protection tables and callback cookie as read only. No kernel 
mode attacker can patch the tables in memory to silently remove 
entries. On unload write permissions are restored before cleanup.

## Builds

Two configurations:

Unloadable in Safe Mode only
DriverUnload is NULL in normal boot. The driver cannot be 
stopped via sc stop or ZwUnloadDriver during a live session. 
Safe Mode gives you the unload path for maintenance.

Unloadable Mid Session
Registers DriverUnload unconditionally. You can run sc stop 
RegFilter any time. Driver comes back on next boot since it 
loads at boot start.

## Compatibility

Tested on Windows 10 22H2 and Windows 11 25H2.
Compatible range 19041 through current.
LTSC 2021 RTM (19044.1288) requires the ExFreePoolWithTag 
build due to missing ExFreePool2 export on that baseline.

## Building

Built with WDK. Target x64. Test sign or submit for WHQL 
depending on your use case. Enable testsigning if running 
a test signed build:

bcdedit /set testsigning on

## Author

Sal.
