#pragma once

////////////////////////////
#include <chrono>
#include <stdio.h>
#include <stdlib.h>
#include <thread>
#include <msxml.h>    
#include <atomic>
#include <mutex>
#include <process.h>
#include <iostream>
#include <string>
#include <list>
#include <map>
#include <TlHelp32.h>

#pragma comment(lib, "ntdll.lib")

using namespace std;
////////////////////////////

////////////////////////////
typedef struct _PEB_LDR_DATA_64
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA_64, *PPEB_LDR_DATA_64;

typedef struct _PEB_64
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA_64 Ldr;
} PEB_64, *PPEB_64;

typedef struct _UNICODE_STRING_T
{
	USHORT Length;
	USHORT MaximumLength;
	WCHAR* Buffer;
} UNICODE_STRING_T;

typedef UNICODE_STRING_T* PUNICODE_STRING_T;

typedef struct _STRING32
{
	USHORT Length;
	USHORT MaximumLength;
	ULONG Buffer;
} STRING32;
typedef STRING32* PSTRING32;

typedef STRING32 UNICODE_STRING32;
typedef UNICODE_STRING32* PUNICODE_STRING32;

typedef struct _LDR_DATA_TABLE_ENTRY_64
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING_T FullDllName;
	UNICODE_STRING_T BaseDllName;
} LDR_DATA_TABLE_ENTRY_64, *PLDR_DATA_TABLE_ENTRY_64;

typedef struct _PEB_32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB_32, *PPEB_32;

typedef struct _PEB_LDR_DATA_32
{
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA_32, *PPEB_LDR_DATA_32;

typedef struct _LDR_DATA_TABLE_ENTRY_32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY_32, *PLDR_DATA_TABLE_ENTRY_32;

extern "C" NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);
////////////////////////////

////////////////////////////
DWORD get_process_id_by_name(const wstring& process_name)
{
	PROCESSENTRY32 process_info;
	process_info.dwSize = sizeof(process_info);

	HANDLE processes_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processes_snapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processes_snapshot, &process_info);
	if (!process_name.compare(process_info.szExeFile))
	{
		CloseHandle(processes_snapshot);
		return process_info.th32ProcessID;
	}

	while (Process32Next(processes_snapshot, &process_info))
	{
		if (!process_name.compare(process_info.szExeFile))
		{
			CloseHandle(processes_snapshot);
			return process_info.th32ProcessID;
		}
	}

	CloseHandle(processes_snapshot);
	return 0;
}
////////////////////////////

////////////////////////////
#include "../xor/xor.h"
#include "../xor/xor_data.h"
#include "../xor/xor_value.h"
#include "../driver/dispath/defines.h"
#include "../driver/loader.h"
#include "../driver/driver.h"
#include "../inject/inject.h"
////////////////////////////