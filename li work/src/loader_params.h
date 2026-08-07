#pragma once
#include <Windows.h>

// Typedefs matching the actual Windows API signatures
using f_LoadLibraryA    = HMODULE(WINAPI*)(LPCSTR lpLibFileName);
using f_GetProcAddress  = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DllMain         = BOOL(WINAPI*)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
using f_RtlAddFunctionTable = BOOLEAN(WINAPI*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);

// This struct is written into the target process alongside the shellcode.
// The shellcode reads it to resolve imports and call DllMain.
// ALL pointers here must be valid in the TARGET process address space.
struct LoaderParams
{
    LPVOID          imageBase;          // Remote base of the mapped PE
    PIMAGE_NT_HEADERS ntHeaders;        // Remote VA: imageBase + dosHdr->e_lfanew

    f_LoadLibraryA      fnLoadLibraryA;     // kernel32 VA in target
    f_GetProcAddress    fnGetProcAddress;   // kernel32 VA in target
    f_RtlAddFunctionTable fnRtlAddFunctionTable; // ntdll VA in target — for SEH x64

    volatile DWORD  status;             // Written by shellcode on completion
                                        // 0 = not started, 1 = success, 0xDEAD = fail
};
