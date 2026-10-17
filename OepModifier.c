/*
 * File: OepModifier.c
 * Description: Main driver file that redirects test.exe OEP through a
 *              user-mode trampoline that loads c:\test.dll.
 * Signature: Kernel Mode Driver - Windows Kernel Development
 * Architecture: x64
 * Note: This is a proof-of-concept driver for educational purposes
 *
 * Design:
 *   1. In LoadImageNotifyRoutineEx, detect test.exe image load.
 *   2. Allocate executable memory inside test.exe for a user-mode trampoline.
 *   3. Patch OEP with an absolute jump to the trampoline.
 *   4. The trampoline builds "c:\test.dll", calls ntdll!LdrLoadDll,
 *      restores the original OEP bytes, and jumps back.
 *
 * Notes:
 *   [1] The OEP patch is a 12-byte x64 absolute jump:
 *       mov rax, <trampoline>; jmp rax.
 *   [2] The trampoline restores those 12 original bytes before it transfers
 *       control back to the original OEP.
 *   [3] c:\test.dll is loaded by an absolute path, not from the kernel
 *       image-notify path.
 */

#include "OepModifier.h"
#include <ntstrsafe.h>
#include <stdarg.h>

BOOLEAN g_DriverLoaded = FALSE;

#define LOG_FILE_NAME          L"OepModifier.log"
#define LOG_PATH_MAX_CHARS     512u
#define LOG_ENTRY_TEXT_BYTES   768u
#define LOG_QUEUE_LIMIT        1024u
#define LOG_POOL_TAG           'LOep'

typedef struct _LOG_ENTRY {
    LIST_ENTRY ListEntry;
    SIZE_T Length;
    CHAR Text[LOG_ENTRY_TEXT_BYTES];
} LOG_ENTRY, *PLOG_ENTRY;

static KSPIN_LOCK g_LogQueueLock;
static LIST_ENTRY g_LogQueue;
static KEVENT g_LogEvent;
static HANDLE g_LogThreadHandle = NULL;
static HANDLE g_LogFileHandle = NULL;
static volatile LONG g_LogReady = 0;
static volatile LONG64 g_LogSequence = 0;
static BOOLEAN g_LogStop = FALSE;
static ULONG g_LogQueueDepth = 0;
static WCHAR g_LogPathBuffer[LOG_PATH_MAX_CHARS];
static UNICODE_STRING g_LogFilePath;

static NTSTATUS LogInitialize(_In_ PDRIVER_OBJECT DriverObject);
static VOID LogShutdown(VOID);
static VOID LogWorkerThread(_In_opt_ PVOID StartContext);
static VOID LogWriteFile(_In_reads_bytes_(Length) PCCHAR Buffer, _In_ SIZE_T Length);
static VOID LogQueueMessage(
    _In_z_ PCSTR FileName,
    _In_z_ PCSTR FunctionName,
    _In_ ULONG Line,
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
);
static PCSTR LogBaseNameA(_In_opt_z_ PCSTR Path);
static NTSTATUS LogBuildPathFromDriverDirectory(_In_ PDRIVER_OBJECT DriverObject);

#define LOG_PRINT(...) LogQueueMessage(__FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)


/* ======================================================================== */
/*  Async file logger                                                         */
/* ======================================================================== */
static NTSTATUS LogInitialize(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;

    InitializeListHead(&g_LogQueue);
    KeInitializeSpinLock(&g_LogQueueLock);
    KeInitializeEvent(&g_LogEvent, NotificationEvent, FALSE);

    g_LogStop = FALSE;
    g_LogQueueDepth = 0;
    g_LogSequence = 0;
    InterlockedExchange(&g_LogReady, 0);

    status = LogBuildPathFromDriverDirectory(DriverObject);
    if (!NT_SUCCESS(status))
        return status;

    InitializeObjectAttributes(
        &objectAttributes,
        &g_LogFilePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    status = ZwCreateFile(
        &g_LogFileHandle,
        FILE_APPEND_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
        &objectAttributes,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0
    );
    if (!NT_SUCCESS(status)) {
        g_LogFileHandle = NULL;
        return status;
    }

    status = PsCreateSystemThread(
        &g_LogThreadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        LogWorkerThread,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        ZwClose(g_LogFileHandle);
        g_LogFileHandle = NULL;
        g_LogThreadHandle = NULL;
        return status;
    }

    InterlockedExchange(&g_LogReady, 1);
    return STATUS_SUCCESS;
}


static VOID LogShutdown(VOID)
{
    KIRQL oldIrql;

    if (g_LogThreadHandle == NULL)
        return;

    InterlockedExchange(&g_LogReady, 0);

    KeAcquireSpinLock(&g_LogQueueLock, &oldIrql);
    g_LogStop = TRUE;
    KeReleaseSpinLock(&g_LogQueueLock, oldIrql);

    KeSetEvent(&g_LogEvent, IO_NO_INCREMENT, FALSE);

    ZwWaitForSingleObject(g_LogThreadHandle, FALSE, NULL);
    ZwClose(g_LogThreadHandle);
    g_LogThreadHandle = NULL;
}


static VOID LogWorkerThread(_In_opt_ PVOID StartContext)
{
    PLOG_ENTRY entry;
    PLIST_ENTRY listEntry;
    KIRQL oldIrql;
    IO_STATUS_BLOCK ioStatus;

    UNREFERENCED_PARAMETER(StartContext);

    for (;;) {
        KeWaitForSingleObject(
            &g_LogEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );

        for (;;) {
            entry = NULL;

            KeAcquireSpinLock(&g_LogQueueLock, &oldIrql);
            if (IsListEmpty(&g_LogQueue)) {
                if (g_LogStop) {
                    KeReleaseSpinLock(&g_LogQueueLock, oldIrql);
                    goto ExitThread;
                }

                KeClearEvent(&g_LogEvent);
                KeReleaseSpinLock(&g_LogQueueLock, oldIrql);
                break;
            }

            listEntry = RemoveHeadList(&g_LogQueue);
            g_LogQueueDepth--;
            KeReleaseSpinLock(&g_LogQueueLock, oldIrql);

            entry = CONTAINING_RECORD(listEntry, LOG_ENTRY, ListEntry);
            LogWriteFile(entry->Text, entry->Length);
            ExFreePoolWithTag(entry, LOG_POOL_TAG);
        }
    }

ExitThread:
    if (g_LogFileHandle != NULL) {
        ZwFlushBuffersFile(g_LogFileHandle, &ioStatus);
        ZwClose(g_LogFileHandle);
        g_LogFileHandle = NULL;
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}


static VOID LogWriteFile(_In_reads_bytes_(Length) PCCHAR Buffer, _In_ SIZE_T Length)
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatus;
    LARGE_INTEGER byteOffset;

    if (g_LogFileHandle == NULL || Buffer == NULL || Length == 0)
        return;

    if (Length > MAXULONG)
        Length = MAXULONG;

    byteOffset.HighPart = -1;
    byteOffset.LowPart = FILE_WRITE_TO_END_OF_FILE;

    status = ZwWriteFile(
        g_LogFileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        (PVOID)Buffer,
        (ULONG)Length,
        &byteOffset,
        NULL
    );
    if (NT_SUCCESS(status))
        ZwFlushBuffersFile(g_LogFileHandle, &ioStatus);
}


static VOID LogQueueMessage(
    _In_z_ PCSTR FileName,
    _In_z_ PCSTR FunctionName,
    _In_ ULONG Line,
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
)
{
    PLOG_ENTRY entry;
    NTSTATUS status;
    va_list args;
    SIZE_T prefixLength = 0;
    SIZE_T textLength = 0;
    KIRQL oldIrql;
    LONG64 sequence;

    if (Format == NULL)
        return;

    if (InterlockedCompareExchange(&g_LogReady, 0, 0) == 0)
        return;

    entry = (PLOG_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(LOG_ENTRY),
        LOG_POOL_TAG
    );
    if (entry == NULL)
        return;

    RtlZeroMemory(entry, sizeof(LOG_ENTRY));

    sequence = InterlockedIncrement64(&g_LogSequence);
    status = RtlStringCbPrintfA(
        entry->Text,
        sizeof(entry->Text),
        "[%I64d] %s:%lu %s(): ",
        sequence,
        LogBaseNameA(FileName),
        Line,
        (FunctionName != NULL) ? FunctionName : ""
    );
    if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
        ExFreePoolWithTag(entry, LOG_POOL_TAG);
        return;
    }

    status = RtlStringCbLengthA(entry->Text, sizeof(entry->Text), &prefixLength);
    if (!NT_SUCCESS(status))
        prefixLength = 0;

    va_start(args, Format);
    status = RtlStringCbVPrintfA(
        entry->Text + prefixLength,
        sizeof(entry->Text) - prefixLength,
        Format,
        args
    );
    va_end(args);
    UNREFERENCED_PARAMETER(status);

    status = RtlStringCbLengthA(entry->Text, sizeof(entry->Text), &textLength);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(entry, LOG_POOL_TAG);
        return;
    }

    if (textLength + 2 < sizeof(entry->Text)) {
        entry->Text[textLength++] = '\r';
        entry->Text[textLength++] = '\n';
        entry->Text[textLength] = '\0';
    } else if (textLength + 1 < sizeof(entry->Text)) {
        entry->Text[textLength++] = '\n';
        entry->Text[textLength] = '\0';
    }
    entry->Length = textLength;

    KeAcquireSpinLock(&g_LogQueueLock, &oldIrql);
    if (g_LogStop ||
        g_LogQueueDepth >= LOG_QUEUE_LIMIT ||
        InterlockedCompareExchange(&g_LogReady, 0, 0) == 0) {
        KeReleaseSpinLock(&g_LogQueueLock, oldIrql);
        ExFreePoolWithTag(entry, LOG_POOL_TAG);
        return;
    }

    InsertTailList(&g_LogQueue, &entry->ListEntry);
    g_LogQueueDepth++;
    KeReleaseSpinLock(&g_LogQueueLock, oldIrql);

    KeSetEvent(&g_LogEvent, IO_NO_INCREMENT, FALSE);
}


static PCSTR LogBaseNameA(_In_opt_z_ PCSTR Path)
{
    PCSTR baseName;

    if (Path == NULL)
        return "";

    baseName = Path;
    while (*Path != '\0') {
        if (*Path == '\\' || *Path == '/')
            baseName = Path + 1;
        Path++;
    }

    return baseName;
}


static NTSTATUS LogBuildPathFromDriverDirectory(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNICODE_STRING driverPath;
    USHORT driverPathChars;
    USHORT directoryChars = 0;
    SIZE_T logNameChars;
    SIZE_T totalChars;
    USHORT i;

    if (DriverObject == NULL)
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(&driverPath, sizeof(driverPath));
    RtlZeroMemory(g_LogPathBuffer, sizeof(g_LogPathBuffer));
    RtlZeroMemory(&g_LogFilePath, sizeof(g_LogFilePath));

    status = IoQueryFullDriverPath(DriverObject, &driverPath);
    if (!NT_SUCCESS(status))
        return status;

    if (driverPath.Buffer == NULL || driverPath.Length == 0) {
        if (driverPath.Buffer != NULL)
            ExFreePool(driverPath.Buffer);
        return STATUS_OBJECT_PATH_INVALID;
    }

    driverPathChars = driverPath.Length / sizeof(WCHAR);
    for (i = 0; i < driverPathChars; i++) {
        if (driverPath.Buffer[i] == L'\\' || driverPath.Buffer[i] == L'/')
            directoryChars = i + 1;
    }

    status = RtlStringCchLengthW(LOG_FILE_NAME,
                                 RTL_NUMBER_OF(LOG_FILE_NAME),
                                 &logNameChars);
    if (!NT_SUCCESS(status)) {
        ExFreePool(driverPath.Buffer);
        return status;
    }

    totalChars = (SIZE_T)directoryChars + logNameChars;
    if (totalChars + 1 > RTL_NUMBER_OF(g_LogPathBuffer)) {
        ExFreePool(driverPath.Buffer);
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (directoryChars != 0) {
        RtlCopyMemory(g_LogPathBuffer,
                      driverPath.Buffer,
                      directoryChars * sizeof(WCHAR));
    }

    RtlCopyMemory(g_LogPathBuffer + directoryChars,
                  LOG_FILE_NAME,
                  (logNameChars + 1) * sizeof(WCHAR));

    g_LogFilePath.Buffer = g_LogPathBuffer;
    g_LogFilePath.Length = (USHORT)(totalChars * sizeof(WCHAR));
    g_LogFilePath.MaximumLength = sizeof(g_LogPathBuffer);

    ExFreePool(driverPath.Buffer);
    return STATUS_SUCCESS;
}


/*
 * User-mode x64 trampoline shellcode used by the current OEP hook.
 *
 * Runtime behavior:
 *   1. Preserve caller state.
 *   2. Resolve ntdll!LdrLoadDll and ntdll!NtProtectVirtualMemory from the PEB.
 *   3. Build the fixed path "c:\test.dll".
 *   4. Load c:\test.dll.
 *   5. Restore the original OEP bytes, restore the OEP page protection, and
 *      jump to the original OEP.
 *
 * Assembly reference, offsets are byte offsets in this byte array:
 *
 *   0x000 ShellcodeStart:
 *         pushfq
 *         push rax/rcx/rdx/rbx/rbp/rsi/rdi/r8-r15
 *         sub  rsp, 0x488
 *         cld
 *         xor  r12d, r12d                 ; ntdll base
 *         xor  r14d, r14d                 ; LdrLoadDll pointer
 *         xor  r15d, r15d                 ; NtProtectVirtualMemory pointer
 *
 *   0x029 Resolve ntdll exports:
 *         call FindNtdll
 *         test rax, rax
 *         jz   RestoreOriginalOep
 *         mov  r12, rax
 *         mov  rcx, r12
 *         lea  rdx, [rip + LdrLoadDllName]
 *         call ResolveExport
 *         mov  r14, rax
 *         mov  rcx, r12
 *         lea  rdx, [rip + NtProtectVirtualMemoryName]
 *         call ResolveExport
 *         mov  r15, rax
 *
 *   0x05A Load "c:\test.dll":
 *         test r14, r14
 *         jz   RestoreOriginalOep
 *         call BuildDllPath
 *         test eax, eax
 *         jz   RestoreOriginalOep
 *         xor  ecx, ecx                   ; DllPath = NULL
 *         xor  edx, edx                   ; DllCharacteristics = NULL
 *         lea  r8,  [rsp + 0x438]         ; PUNICODE_STRING DllName (BuildDllPath writes at [inner_rsp+0x440]=[outer_rsp+0x438])
 *         lea  r9,  [rsp + 0x450]         ; PVOID *DllHandle
 *         call r14                        ; LdrLoadDll
 *
 *   0x07F RestoreOriginalOep:
 *         lea  rsi, [rip + OriginalPatchBytes]
 *         mov  rdi, [rip + OriginalOepAddress]
 *         mov  ecx, 12
 *         rep  movsb                      ; restore OEP bytes overwritten by hook
 *         test r15, r15
 *         jz   JumpOriginalOep
 *
 *   0x099 Restore OEP page protection:
 *         mov  [rsp + 0x458], OriginalOepAddress
 *         mov  qword ptr [rsp + 0x460], 12
 *         mov  dword ptr [rsp + 0x468], PAGE_EXECUTE_READWRITE
 *         mov  rcx, -1                    ; NtCurrentProcess()
 *         lea  rdx, [rsp + 0x458]         ; BaseAddress
 *         lea  r8,  [rsp + 0x460]         ; RegionSize
 *         mov  r9d, [rip + OriginalProtect]
 *         lea  rax, [rsp + 0x468]
 *         mov  [rsp + 0x20], rax          ; OldProtect, 5th arg
 *         call r15                        ; NtProtectVirtualMemory
 *
 *   0x0F0 JumpOriginalOep:
 *         add  rsp, 0x488
 *         pop  r15-r8/rdi/rsi/rbp/rbx/rdx/rcx/rax
 *         popfq
 *         jmp  qword ptr [rip + OriginalOepAddress]
 *
 *   0x112 FindNtdll:
 *         mov  rax, gs:[0x60]             ; PEB
 *         mov  rax, [rax + 0x18]          ; PEB_LDR_DATA
 *         lea  rcx, [rax + 0x10]          ; InLoadOrderModuleList head
 *         mov  rbx, [rax + 0x10]          ; first LDR_DATA_TABLE_ENTRY
 *         walk InLoadOrder list, compare BaseDllName with L"ntdll.dll",
 *         return DllBase from [entry + 0x30], or NULL on failure.
 *
 *   0x17B ResolveExport:
 *         Input:  rcx = module base, rdx = ANSI export name.
 *         Parse PE64 export directory at OptionalHeader.DataDirectory[0]
 *         (NT headers + 0x88), walk AddressOfNames, compare the string,
 *         resolve ordinal through AddressOfNameOrdinals, then return
 *         module base + AddressOfFunctions[ordinal].
 *
 *   0x20D BuildDllPath:
 *         write L"c:\\test.dll" to [rsp + 0x40],
 *         then build UNICODE_STRING at [rsp + 0x440].
 *
 *   0x2DD Data:
 *         NtdllNameW                   = L"ntdll.dll" without terminator
 *         Unused path padding          = zeroed bytes
 *         LdrLoadDllName               = "LdrLoadDll"
 *         NtProtectVirtualMemoryName   = "NtProtectVirtualMemory"
 *         OriginalOepAddress           = patched by driver at 0x323
 *         OriginalProtect              = patched by driver at 0x32B
 *         OriginalPatchBytes[12]       = patched by driver at 0x32F
 */
static const UCHAR g_TrampolineShellcodeTemplate[] = {
    0x9C, 0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, /* 0x000 */
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0x88, 0x04, 0x00, 0x00, 0xFC, /* 0x010 */
    0x45, 0x33, 0xE4, 0x45, 0x33, 0xF6, 0x45, 0x33, 0xFF, 0xE8, 0xE4, 0x00, 0x00, 0x00, 0x48, 0x85, /* 0x020 */
    0xC0, 0x74, 0x4C, 0x4C, 0x8B, 0xE0, 0x49, 0x8B, 0xCC, 0x48, 0x8D, 0x15, 0xC1, 0x02, 0x00, 0x00, /* 0x030 */
    0xE8, 0x36, 0x01, 0x00, 0x00, 0x4C, 0x8B, 0xF0, 0x49, 0x8B, 0xCC, 0x48, 0x8D, 0x15, 0xBA, 0x02, /* 0x040 */
    0x00, 0x00, 0xE8, 0x24, 0x01, 0x00, 0x00, 0x4C, 0x8B, 0xF8, 0x4D, 0x85, 0xF6, 0x74, 0x20, 0xE8, /* 0x050 */
    0xA9, 0x01, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x17, 0x33, 0xC9, 0x33, 0xD2, 0x4C, 0x8D, 0x84, 0x24, /* 0x060 */
    0x38, 0x04, 0x00, 0x00, 0x4C, 0x8D, 0x8C, 0x24, 0x50, 0x04, 0x00, 0x00, 0x41, 0xFF, 0xD6, 0x48, /* 0x070 */ /* FIX: was 0x40; lea r8,[rsp+0x438] compensates for 8-byte return address pushed by call BuildDllPath */
    0x8D, 0x35, 0xA9, 0x02, 0x00, 0x00, 0x48, 0x8B, 0x3D, 0x96, 0x02, 0x00, 0x00, 0xB9, 0x0C, 0x00, /* 0x080 */
    0x00, 0x00, 0xF3, 0xA4, 0x4D, 0x85, 0xFF, 0x74, 0x54, 0x48, 0x8B, 0x05, 0x83, 0x02, 0x00, 0x00, /* 0x090 */
    0x48, 0x89, 0x84, 0x24, 0x58, 0x04, 0x00, 0x00, 0x48, 0xC7, 0x84, 0x24, 0x60, 0x04, 0x00, 0x00, /* 0x0A0 */
    0x0C, 0x00, 0x00, 0x00, 0xC7, 0x84, 0x24, 0x68, 0x04, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x48, /* 0x0B0 */
    0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x94, 0x24, 0x58, 0x04, 0x00, 0x00, 0x4C, 0x8D, /* 0x0C0 */
    0x84, 0x24, 0x60, 0x04, 0x00, 0x00, 0x44, 0x8B, 0x0D, 0x4E, 0x02, 0x00, 0x00, 0x48, 0x8D, 0x84, /* 0x0D0 */
    0x24, 0x68, 0x04, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x41, 0xFF, 0xD7, 0x48, 0x81, 0xC4, /* 0x0E0 */
    0x88, 0x04, 0x00, 0x00, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, /* 0x0F0 */
    0x41, 0x59, 0x41, 0x58, 0x5F, 0x5E, 0x5D, 0x5B, 0x5A, 0x59, 0x58, 0x9D, 0xFF, 0x25, 0x11, 0x02, /* 0x100 */
    0x00, 0x00, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x58, /* 0x110 */
    0x48, 0x8B, 0x40, 0x18, 0x48, 0x85, 0xC0, 0x74, 0x4F, 0x48, 0x8D, 0x48, 0x10, 0x48, 0x8B, 0x58, /* 0x120 */
    0x10, 0x48, 0x3B, 0xD9, 0x74, 0x42, 0x0F, 0xB7, 0x43, 0x58, 0x83, 0xF8, 0x12, 0x75, 0x34, 0x48, /* 0x130 */
    0x8B, 0x73, 0x60, 0x48, 0x85, 0xF6, 0x74, 0x2B, 0x48, 0x8D, 0x15, 0x8E, 0x01, 0x00, 0x00, 0x41, /* 0x140 */
    0xB8, 0x09, 0x00, 0x00, 0x00, 0x66, 0x8B, 0x06, 0x66, 0x83, 0xC8, 0x20, 0x66, 0x3B, 0x02, 0x75, /* 0x150 */
    0x12, 0x48, 0x83, 0xC6, 0x02, 0x48, 0x83, 0xC2, 0x02, 0x41, 0xFF, 0xC8, 0x75, 0xE7, 0x48, 0x8B, /* 0x160 */
    0x43, 0x30, 0xC3, 0x48, 0x8B, 0x1B, 0xEB, 0xB9, 0x33, 0xC0, 0xC3, 0x53, 0x56, 0x57, 0x41, 0x50, /* 0x170 */
    0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x4C, 0x8B, 0xD9, 0x48, 0x8B, 0xFA, 0x4D, 0x85, 0xDB, 0x74, /* 0x180 */
    0x6E, 0x48, 0x85, 0xFF, 0x74, 0x69, 0x41, 0x8B, 0x43, 0x3C, 0x49, 0x8D, 0x1C, 0x03, 0x8B, 0x83, /* 0x190 */
    0x88, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x57, 0x49, 0x8D, 0x34, 0x03, 0x44, 0x8B, 0x46, 0x18, /* 0x1A0 */
    0x45, 0x85, 0xC0, 0x74, 0x4A, 0x8B, 0x46, 0x20, 0x4D, 0x8D, 0x0C, 0x03, 0x8B, 0x46, 0x24, 0x4D, /* 0x1B0 */
    0x8D, 0x14, 0x03, 0x8B, 0x46, 0x1C, 0x49, 0x8D, 0x1C, 0x03, 0x33, 0xC9, 0x41, 0x3B, 0xC8, 0x73, /* 0x1C0 */
    0x2E, 0x41, 0x8B, 0x04, 0x89, 0x49, 0x8D, 0x14, 0x03, 0x48, 0x8B, 0xF7, 0x8A, 0x02, 0x3A, 0x06, /* 0x1D0 */
    0x75, 0x0C, 0x84, 0xC0, 0x74, 0x0C, 0x48, 0xFF, 0xC2, 0x48, 0xFF, 0xC6, 0xEB, 0xEE, 0xFF, 0xC1, /* 0x1E0 */
    0xEB, 0xDA, 0x41, 0x0F, 0xB7, 0x04, 0x4A, 0x8B, 0x04, 0x83, 0x49, 0x03, 0xC3, 0xEB, 0x02, 0x33, /* 0x1F0 */
    0xC0, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5F, 0x5E, 0x5B, 0xC3, 0x48, 0xB8, 0x63, /* 0x200 */
    0x00, 0x3A, 0x00, 0x5C, 0x00, 0x74, 0x00, 0x48, 0x89, 0x84, 0x24, 0x40, 0x00, 0x00, 0x00, 0x48, /* 0x210 */
    0xB8, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x2E, 0x00, 0x48, 0x89, 0x84, 0x24, 0x48, 0x00, 0x00, /* 0x220 */
    0x00, 0x48, 0xB8, 0x64, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x50, /* 0x230 */
    0x00, 0x00, 0x00, 0x66, 0xC7, 0x84, 0x24, 0x40, 0x04, 0x00, 0x00, 0x16, 0x00, 0x66, 0xC7, 0x84, /* 0x240 */
    0x24, 0x42, 0x04, 0x00, 0x00, 0x18, 0x00, 0x48, 0x8D, 0x84, 0x24, 0x40, 0x00, 0x00, 0x00, 0x48, /* 0x250 */
    0x89, 0x84, 0x24, 0x48, 0x04, 0x00, 0x00, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90, 0x90, /* 0x260 */
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, /* 0x270 */
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, /* 0x280 */
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, /* 0x290 */
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, /* 0x2A0 */
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, /* 0x2B0 */
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, /* 0x2C0 */
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x6E, 0x00, 0x74, /* 0x2D0 */
    0x00, 0x64, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x2E, 0x00, 0x64, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x00, /* 0x2E0 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x2F0 */
    0x00, 0x4C, 0x64, 0x72, 0x4C, 0x6F, 0x61, 0x64, 0x44, 0x6C, 0x6C, 0x00, 0x4E, 0x74, 0x50, 0x72, /* 0x300 */
    0x6F, 0x74, 0x65, 0x63, 0x74, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x4D, 0x65, 0x6D, 0x6F, /* 0x310 */
    0x72, 0x79, 0x00, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x33, /* 0x320 */
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, /* 0x330 */
};

#define OEP_PATCH_SIZE                 12u
#define OFFSET_ORIGINAL_OEP            0x323u
#define OFFSET_ORIGINAL_PROTECT        0x32Bu
#define OFFSET_ORIGINAL_PATCH_BYTES    0x32Fu
#define TRAMPOLINE_SHELLCODE_SIZE      sizeof(g_TrampolineShellcodeTemplate)

C_ASSERT(OFFSET_ORIGINAL_OEP + sizeof(ULONG_PTR) <= TRAMPOLINE_SHELLCODE_SIZE);
C_ASSERT(OFFSET_ORIGINAL_PROTECT + sizeof(ULONG) <= TRAMPOLINE_SHELLCODE_SIZE);
C_ASSERT(OFFSET_ORIGINAL_PATCH_BYTES + OEP_PATCH_SIZE <= TRAMPOLINE_SHELLCODE_SIZE);


/* ======================================================================== */
/*  DriverEntry                                                               */
/* ======================================================================== */
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = UnloadDriver;

    status = LogInitialize(DriverObject);
    if (!NT_SUCCESS(status))
        return status;

    LOG_PRINT("DriverEntry called");

    /*
     * PS_IMAGE_NOTIFY_CONFLICTING_ARCHITECTURE (flag = 1) makes the callback
     * fire for all architectures.  Use 0 for same-arch only if preferred.
     */
    status = PsSetLoadImageNotifyRoutineEx(LoadImageNotifyRoutineEx, (ULONG_PTR)0);
    if (!NT_SUCCESS(status)) {
        LOG_PRINT("PsSetLoadImageNotifyRoutineEx failed: 0x%X", status);
        LogShutdown();
        return status;
    }

    g_DriverLoaded = TRUE;
    LOG_PRINT("Driver loaded, monitoring target process");
    return STATUS_SUCCESS;
}


/* ======================================================================== */
/*  UnloadDriver                                                              */
/* ======================================================================== */
VOID UnloadDriver(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutineEx);
    g_DriverLoaded = FALSE;
    LOG_PRINT("Driver unloaded");
    LogShutdown();
}


/* ======================================================================== */
/*  LoadImageNotifyRoutineEx                                                  */
/* ======================================================================== */
VOID LoadImageNotifyRoutineEx(
    PUNICODE_STRING FullImageName,
    HANDLE          ProcessId,
    PIMAGE_INFO     ImageInfo
)
{
    NTSTATUS   status;
    PEPROCESS  targetProcess   = NULL;
    KAPC_STATE apcState;

    PIMAGE_DOS_HEADER  dosHeader = NULL;
    PIMAGE_NT_HEADERS64 ntHeaders = NULL;
    PVOID  originalOep = NULL;
    PVOID  shellcodeBase = NULL;
    PVOID  protectBase;
    SIZE_T shellcodeSize;
    SIZE_T protectSize;
    ULONG  oldProtect;
    UCHAR  shellcodeBuffer[TRAMPOLINE_SHELLCODE_SIZE];
    UCHAR  oepJump[OEP_PATCH_SIZE];
    BOOLEAN oepProtectionChanged = FALSE;
    BOOLEAN oepPatched = FALSE;

    ZWALLOCATEVIRTUALMEMORY pZwAllocate = NULL;
    ZWPROTECTVIRTUALMEMORY pZwProtect = NULL;
    UNICODE_STRING          ustrZwAllocate;
    UNICODE_STRING         ustrZwProtect;

    /* ---- Basic parameter checks ---- */
    if (FullImageName == NULL || FullImageName->Buffer == NULL || ImageInfo == NULL)
        return;

    /* ---- Filter: only user-mode images ---- */
    if (ImageInfo->SystemModeImage)
        return;

    /* ---- Get EPROCESS for the image owner ---- */
    status = PsLookupProcessByProcessId(ProcessId, &targetProcess);
    if (!NT_SUCCESS(status)) {
        LOG_PRINT("PsLookupProcessByProcessId failed: 0x%X", status);
        return;
    }
    //LOG_PRINT("PsLookupProcessByProcessId succeeded: EPROCESS=%p", targetProcess);

    /* ---- Skip 32-bit (WOW64) processes ---- */
    if (PsGetProcessWow64Process(targetProcess) != NULL) {
        LOG_PRINT("Skipping 32-bit process: PID=%lu", HandleToUlong(ProcessId));
        ObDereferenceObject(targetProcess);
        return;
    }

    /* ---- Only handle the process executable image, not DLLs/other mapped images ---- */
    if (ImageInfo->ImageBase != PsGetProcessSectionBaseAddress(targetProcess)) {
        ObDereferenceObject(targetProcess);
        return;
    }

    LOG_PRINT("Process executable image detected: PID=%lu Base=%p ImageSize=0x%Ix",
              HandleToUlong(ProcessId),
              ImageInfo->ImageBase,
              ImageInfo->ImageSize);

    /* ---- Resolve VM helpers ---- */
    RtlInitUnicodeString(&ustrZwAllocate, L"ZwAllocateVirtualMemory");
    pZwAllocate = (ZWALLOCATEVIRTUALMEMORY)MmGetSystemRoutineAddress(&ustrZwAllocate);
    if (pZwAllocate == NULL) {
        LOG_PRINT("Cannot resolve ZwAllocateVirtualMemory");
        ObDereferenceObject(targetProcess);
        return;
    }
    LOG_PRINT("ZwAllocateVirtualMemory resolved: %p", pZwAllocate);

    RtlInitUnicodeString(&ustrZwProtect, L"ZwProtectVirtualMemory");
    pZwProtect = (ZWPROTECTVIRTUALMEMORY)MmGetSystemRoutineAddress(&ustrZwProtect);
    if (pZwProtect == NULL) {
        LOG_PRINT("Cannot resolve ZwProtectVirtualMemory");
        ObDereferenceObject(targetProcess);
        return;
    }
    LOG_PRINT("ZwProtectVirtualMemory resolved: %p", pZwProtect);
    LOG_PRINT("Full image path: %wZ", FullImageName);

    /* ---- Attach to target process address space ---- */
    KeStackAttachProcess(targetProcess, &apcState);
    LOG_PRINT("Attached to target process address space");

    __try {
        /* ---- Parse PE headers ---- */
        dosHeader = (PIMAGE_DOS_HEADER)ImageInfo->ImageBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            LOG_PRINT("Bad DOS signature: 0x%X", dosHeader->e_magic);
            __leave;
        }
        LOG_PRINT("DOS header validated");

        ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)ImageInfo->ImageBase
                                          + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            LOG_PRINT("Bad NT signature: 0x%X", ntHeaders->Signature);
            __leave;
        }
        if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            LOG_PRINT("Not a 64-bit image: OptionalHeader.Magic=0x%X",
                      ntHeaders->OptionalHeader.Magic);
            __leave;
        }
        LOG_PRINT("NT headers validated: EntryPointRva=0x%X SizeOfImage=0x%X",
                  ntHeaders->OptionalHeader.AddressOfEntryPoint,
                  ntHeaders->OptionalHeader.SizeOfImage);

        /* ---- Locate OEP ---- */
        originalOep = (PVOID)((ULONG_PTR)ImageInfo->ImageBase
                              + ntHeaders->OptionalHeader.AddressOfEntryPoint);
        LOG_PRINT("Original entry point located: %p", originalOep);

        /* ---- Verify the OEP patch fits inside the loaded image ---- */
        if ((ULONG_PTR)originalOep + OEP_PATCH_SIZE >
            (ULONG_PTR)ImageInfo->ImageBase + ImageInfo->ImageSize) {
            LOG_PRINT("OEP patch does not fit: OEP=%p PatchSize=0x%X ImageEnd=%p",
                      originalOep,
                      OEP_PATCH_SIZE,
                      (PVOID)((ULONG_PTR)ImageInfo->ImageBase + ImageInfo->ImageSize));
            __leave;
        }
        LOG_PRINT("OEP patch size check passed: PatchSize=0x%X", OEP_PATCH_SIZE);

        /* ---- Allocate executable shellcode memory in test.exe ---- */
        shellcodeBase = NULL;
        shellcodeSize = TRAMPOLINE_SHELLCODE_SIZE;
        status = pZwAllocate(
            ZwCurrentProcess(),
            &shellcodeBase,
            0,
            &shellcodeSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (!NT_SUCCESS(status)) {
            LOG_PRINT("ZwAllocateVirtualMemory for trampoline failed: 0x%X", status);
            __leave;
        }
        LOG_PRINT("Allocated trampoline memory: Base=%p Size=0x%Ix",
                  shellcodeBase,
                  shellcodeSize);

        RtlCopyMemory(shellcodeBuffer,
                      g_TrampolineShellcodeTemplate,
                      TRAMPOLINE_SHELLCODE_SIZE);
        RtlCopyMemory(shellcodeBuffer + OFFSET_ORIGINAL_PATCH_BYTES,
                      originalOep,
                      OEP_PATCH_SIZE);
        *(PULONG_PTR)(shellcodeBuffer + OFFSET_ORIGINAL_OEP) =
            (ULONG_PTR)originalOep;

        /* ---- Make the OEP patch location writable ---- */
        protectBase = originalOep;
        protectSize = OEP_PATCH_SIZE;
        status = pZwProtect(
            ZwCurrentProcess(),
            &protectBase,
            &protectSize,
            PAGE_EXECUTE_READWRITE,
            &oldProtect
        );
        if (!NT_SUCCESS(status)) {
            LOG_PRINT("ZwProtectVirtualMemory PAGE_EXECUTE_READWRITE failed: 0x%X",
                      status);
            __leave;
        }
        oepProtectionChanged = TRUE;
        LOG_PRINT("OEP page protection changed: ProtectBase=%p ProtectSize=0x%Ix OldProtect=0x%X",
                  protectBase,
                  protectSize,
                  oldProtect);

        *(PULONG)(shellcodeBuffer + OFFSET_ORIGINAL_PROTECT) = oldProtect;
        RtlCopyMemory(shellcodeBase,
                      shellcodeBuffer,
                      TRAMPOLINE_SHELLCODE_SIZE);
        LOG_PRINT("Trampoline shellcode copied: Base=%p Size=0x%Ix",
                  shellcodeBase,
                  (SIZE_T)TRAMPOLINE_SHELLCODE_SIZE);

        RtlZeroMemory(oepJump, sizeof(oepJump));
        oepJump[0] = 0x48;          /* mov rax, imm64 */
        oepJump[1] = 0xB8;
        *(PULONG_PTR)(oepJump + 2) = (ULONG_PTR)shellcodeBase;
        oepJump[10] = 0xFF;         /* jmp rax */
        oepJump[11] = 0xE0;

        RtlCopyMemory(originalOep, oepJump, sizeof(oepJump));
        oepPatched = TRUE;
        LOG_PRINT("OEP patched to trampoline: OEP=%p Trampoline=%p PatchSize=0x%Ix",
                  originalOep,
                  shellcodeBase,
                  sizeof(oepJump));

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_PRINT("Exception while modifying OEP: 0x%X", GetExceptionCode());
    }

    if (oepProtectionChanged && !oepPatched) {
        status = pZwProtect(
            ZwCurrentProcess(),
            &protectBase,
            &protectSize,
            oldProtect,
            &oldProtect
        );
        LOG_PRINT("OEP protection rollback after failed patch: 0x%X", status);
    }

    /* ---- Detach and release reference ---- */
    KeUnstackDetachProcess(&apcState);
    LOG_PRINT("Detached from target process address space");

    if (targetProcess != NULL) {
        ObDereferenceObject(targetProcess);
        LOG_PRINT("Released target process reference");
    }
}
