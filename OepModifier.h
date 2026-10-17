/*
 * File: OepModifier.h
 * Description: Header file for OEP modification driver
 * Signature: Kernel Mode Driver Header - Windows Kernel Development
 */

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

#define TARGET_PROCESS_NAME L"test.exe"
#define MAX_SHELLCODE_SIZE 0x340 /* 0x33B bytes actual, rounded up */

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
    PVOID LoadedImports;
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    UCHAR Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
    UCHAR Reserved1[2];
    UCHAR BeingDebugged;
    UCHAR Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    UCHAR Reserved4[104];
    PVOID Reserved5[52];
    PVOID PostProcessInitRoutine;
    UCHAR Reserved6[128];
    PVOID Reserved7[1];
    ULONG SessionId;
} PEB, *PPEB;

typedef NTSTATUS (NTAPI *ZWALLOCATEVIRTUALMEMORY)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);

typedef NTSTATUS (NTAPI *ZWPROTECTVIRTUALMEMORY)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
);

extern BOOLEAN g_DriverLoaded;

NTKERNELAPI
PVOID
PsGetProcessSectionBaseAddress(
    _In_ PEPROCESS Process
);

NTKERNELAPI
PVOID
PsGetProcessWow64Process(
    _In_ PEPROCESS Process
);

DRIVER_INITIALIZE DriverEntry;
VOID UnloadDriver(PDRIVER_OBJECT DriverObject);
VOID LoadImageNotifyRoutineEx(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
);

