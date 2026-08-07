#include "loader_params.h"
#include "shellcode.h"
#include "memory/memory.h"
#include "syscalls/syscalls_common.h"

#include <iostream>
#include <vector>
#include <cstdio>
#include <TlHelp32.h>

static LPVOID GetRemoteProcAddress(
    HANDLE  hProcess,
    DWORD   pid,
    const char* moduleName,
    const char* procName)
{
    HMODULE hLocal = GetModuleHandleA(moduleName);
    if (!hLocal) hLocal = LoadLibraryA(moduleName);
    if (!hLocal)
    {
        printf("%s[!] Failed to load %s locally%s\n", Terminal::Red, moduleName, Terminal::Reset);
        return nullptr;
    }

    FARPROC localFn = GetProcAddress(hLocal, procName);
    if (!localFn)
    {
        printf("%s[!] GetProcAddress(%s) failed locally%s\n", Terminal::Red, procName, Terminal::Reset);
        return nullptr;
    }

    DWORD64 localOffset = (DWORD64)localFn - (DWORD64)hLocal;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        printf("%s[!] CreateToolhelp32Snapshot failed: %lu%s\n", Terminal::Red, GetLastError(), Terminal::Reset);
        return nullptr;
    }

    MODULEENTRY32W me = { sizeof(me) };
    LPVOID result = nullptr;

    wchar_t wModuleName[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, moduleName, -1, wModuleName, MAX_PATH);

    if (Module32First(hSnap, &me))
    {
        do {
            if (_wcsicmp(me.szModule, wModuleName) == 0)
            {
                result = (LPVOID)((DWORD64)me.modBaseAddr + localOffset);
                break;
            }
        } while (Module32Next(hSnap, &me));
    }

    CloseHandle(hSnap);

    if (!result)
    {
        printf("%s[~] Module %s not found in target snapshot, using local VA%s\n", Terminal::Yellow, moduleName, Terminal::Reset);
        result = (LPVOID)localFn;
    }

    return result;
}

static void PrintUsage(const char* argv0)
{
    printf("\nUsage: %s <process_name> <dll_path>\n", argv0);
    printf("Example: %s tf_win64.exe C:\\cheats\\Amalgamx64Release.dll\n", argv0);
    printf("\n%s%s%s\n", Terminal::Green, "by war 1", Terminal::Reset);
}

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        PrintUsage(argv[0]);
        return 1;
    }

    const char* processName = argv[1];
    const char* dllPath     = argv[2];

    wchar_t wProcessName[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, processName, -1, wProcessName, MAX_PATH);

    printf("%s[*] Target  : %s%s\n", Terminal::Green, processName, Terminal::Reset);
    printf("%s[*] DLL     : %s%s\n", Terminal::Green, dllPath, Terminal::Reset);

    DWORD pid = Memory.GetProcessID(wProcessName);
    if (!pid)
    {
        printf("%s[!] Process not found: %s%s\n", Terminal::Red, processName, Terminal::Reset);
        return 1;
    }
    printf("%s[+] PID     : %lu%s\n", Terminal::Green, pid, Terminal::Reset);

    HANDLE hProcess = nullptr;
    {
        CLIENT_ID clientID   = {};
        OBJECT_ATTRIBUTES oa = {};
        clientID.UniqueProcess = (HANDLE)(uintptr_t)pid;
        InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

        NTSTATUS st = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &clientID);
        if (st != 0 || !hProcess)
        {
            printf("[!] NtOpenProcess failed: %08lX\n", st);
            return 1;
        }
    }

    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("%s[!] Cannot open DLL: %lu%s\n", Terminal::Red, GetLastError(), Terminal::Reset);
        CloseHandle(hProcess);
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, nullptr);
    std::vector<BYTE> fileBuffer(fileSize);
    DWORD bytesRead = 0;
    ReadFile(hFile, fileBuffer.data(), fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);

    auto* dosHdr = (PIMAGE_DOS_HEADER)fileBuffer.data();
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("[!] Invalid DOS signature\n");
        CloseHandle(hProcess);
        return 1;
    }

    auto* ntHdr = (PIMAGE_NT_HEADERS)(fileBuffer.data() + dosHdr->e_lfanew);
    if (ntHdr->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("[!] Invalid NT signature\n");
        CloseHandle(hProcess);
        return 1;
    }

    if (ntHdr->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        printf("[!] DLL is not x64 (machine: %04X)\n", ntHdr->FileHeader.Machine);
        CloseHandle(hProcess);
        return 1;
    }

    IMAGE_OPTIONAL_HEADER64& optHdr = (IMAGE_OPTIONAL_HEADER64&)ntHdr->OptionalHeader;

    SIZE_T imageSize = optHdr.SizeOfImage;

    std::vector<BYTE> image(imageSize, 0);
    memcpy(image.data(), fileBuffer.data(), optHdr.SizeOfHeaders);

    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHdr);
    for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++)
    {
        if (sections[i].SizeOfRawData == 0) continue;

        SIZE_T copySize = min((SIZE_T)sections[i].SizeOfRawData, (SIZE_T)sections[i].Misc.VirtualSize);

        memcpy(image.data() + sections[i].VirtualAddress, fileBuffer.data() + sections[i].PointerToRawData, copySize);
    }

    LPVOID remoteImage = nullptr;
    SIZE_T allocSize   = imageSize;
    NTSTATUS st = NtAllocateVirtualMemory(hProcess, &remoteImage, 0, &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (st != 0 || !remoteImage)
    {
        printf("[!] NtAllocateVirtualMemory (image) failed: %08lX\n", st);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Remote image base : %p\n", remoteImage);

    DWORD64 delta = (DWORD64)remoteImage - optHdr.ImageBase;

    if (delta != 0)
    {
        IMAGE_DATA_DIRECTORY& relocDir = optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if (relocDir.Size > 0)
        {
            auto* reloc = (PIMAGE_BASE_RELOCATION)(image.data() + relocDir.VirtualAddress);
            DWORD remaining = relocDir.Size;

            while (remaining > 0 && reloc->SizeOfBlock > 0)
            {
                DWORD entryCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD entries = (PWORD)((LPBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));

                for (DWORD i = 0; i < entryCount; i++)
                {
                    WORD type   = entries[i] >> 12;
                    WORD offset = entries[i] & 0xFFF;

                    if (type == IMAGE_REL_BASED_DIR64)
                    {
                        DWORD64* patch = (DWORD64*)(image.data() + reloc->VirtualAddress + offset);
                        *patch += delta;
                    }
                }

                remaining -= reloc->SizeOfBlock;
                reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)reloc + reloc->SizeOfBlock);
            }

            printf("[+] Relocations patched (delta: %016llX)\n", delta);
        }
    }

    auto* remoteNtHdr = (PIMAGE_NT_HEADERS)(image.data() + dosHdr->e_lfanew);
    ((PIMAGE_OPTIONAL_HEADER64)&remoteNtHdr->OptionalHeader)->ImageBase = (ULONGLONG)remoteImage;

    SIZE_T written = 0;
    st = NtWriteVirtualMemory(hProcess, remoteImage, image.data(), imageSize, &written);
    if (st != 0 || written != imageSize)
    {
        printf("[!] NtWriteVirtualMemory (image) failed: %08lX (wrote %zu/%zu)\n", st, written, imageSize);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Image written: %zu bytes\n", written);

    LPVOID remoteLoadLibraryA = GetRemoteProcAddress(hProcess, pid, "kernel32.dll", "LoadLibraryA");
    LPVOID remoteGetProcAddress = GetRemoteProcAddress( hProcess, pid, "kernel32.dll", "GetProcAddress");
    LPVOID remoteRtlAddFunctionTable = GetRemoteProcAddress(hProcess, pid, "ntdll.dll", "RtlAddFunctionTable");

    if (!remoteLoadLibraryA || !remoteGetProcAddress)
    {
        printf("[!] Failed to resolve remote kernel32 exports\n");
        CloseHandle(hProcess);
        return 1;
    }

    printf("[+] Remote LoadLibraryA      : %p\n", remoteLoadLibraryA);
    printf("[+] Remote GetProcAddress    : %p\n", remoteGetProcAddress);
    printf("[+] Remote RtlAddFuncTable   : %p\n", remoteRtlAddFunctionTable);

    LoaderParams params = {};
    params.imageBase = remoteImage;
    params.ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)remoteImage + dosHdr->e_lfanew);
    params.fnLoadLibraryA = (f_LoadLibraryA)remoteLoadLibraryA;
    params.fnGetProcAddress = (f_GetProcAddress)remoteGetProcAddress;
    params.fnRtlAddFunctionTable = (f_RtlAddFunctionTable)remoteRtlAddFunctionTable;
    params.status = 0;

    SIZE_T shellcodeSize = (LPBYTE)ShellcodeEnd - (LPBYTE)ShellcodeLoader;
    SIZE_T stubRegionSize = shellcodeSize + sizeof(LoaderParams);

    LPVOID remoteStub = nullptr;
    st = NtAllocateVirtualMemory(hProcess, &remoteStub, 0, &stubRegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (st != 0 || !remoteStub)
    {
        printf("[!] NtAllocateVirtualMemory (stub) failed: %08lX\n", st);
        CloseHandle(hProcess);
        return 1;
    }

    LPVOID remoteParams = (LPVOID)((LPBYTE)remoteStub + shellcodeSize);

    SIZE_T scWritten = 0;
    NtWriteVirtualMemory(hProcess, remoteStub, (LPVOID)ShellcodeLoader, shellcodeSize, &scWritten);

    SIZE_T paramsWritten = 0;
    NtWriteVirtualMemory(hProcess, remoteParams, &params, sizeof(LoaderParams), &paramsWritten);

    printf("[+] Stub at %p (%zu code + %zu params)\n", remoteStub, shellcodeSize, sizeof(LoaderParams));

    HANDLE hThread = nullptr;
    st = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        nullptr,
        hProcess,
        (LPTHREAD_START_ROUTINE)remoteStub,
        remoteParams,                         
        0, 0, 0, 0,
        nullptr);

    if (st != 0 || !hThread)
    {
        printf("[!] NtCreateThreadEx failed: %08lX\n", st);
        CloseHandle(hProcess);
        return 1;
    }

    printf("[+] Thread : %p\n", hThread);

    const DWORD timeout = 15000;
    DWORD waited = 0;
    DWORD remoteStatus = 0;

    while (waited < timeout)
    {
        SIZE_T rd = 0;
        NtReadVirtualMemory(
            hProcess, 
            (LPVOID)((LPBYTE)remoteParams + offsetof(LoaderParams, status)),
            &remoteStatus, sizeof(DWORD), &rd);

        if (remoteStatus != 0) break;

        Sleep(50);
        waited += 50;
    }

    WaitForSingleObject(hThread, 1000);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);

    if (remoteStatus == 1)
        printf("%s[+] Injection OK (status=1, thread exit=%08lX)%s\n", Terminal::Green, exitCode, Terminal::Reset);
    else if (remoteStatus == 0xDEAD)
        printf("%s[!] Shellcode reported failure (import resolution failed)%s\n", Terminal::Red, Terminal::Reset);
    else
        printf("%s[!] Timed out or unexpected status: %08lX (thread exit=%08lX)%s\n", Terminal::Red, remoteStatus, exitCode, Terminal::Reset);

    CloseHandle(hProcess);
    return (remoteStatus == 1) ? 0 : 1;
}
