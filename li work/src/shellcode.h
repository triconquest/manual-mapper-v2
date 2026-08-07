#pragma once
#include "loader_params.h"

// critical: this function and everything it calls must be compiled with either /O1 or /Od, NOT /O2!!
// it should contain NO CRT CALLS, NO GLOBALS, and should be in a section compiled without runtime checks! (/GS- /RTC-)
// fyi this function is copied as raw bytes into the target process

#pragma runtime_checks("", off)
#pragma optimize("", off)

// Inline strcmp — no CRT
static __forceinline int _cmp(const char* a, const char* b)
{
    while (*a && *b && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

// Inline strncmp — no CRT
static __forceinline int _ncmp(const char* a, const char* b, int n)
{
    for (int i = 0; i < n; i++) {
        if (!a[i] || a[i] != b[i]) return (unsigned char)a[i] - (unsigned char)b[i];
    }
    return 0;
}

void __stdcall ShellcodeLoader(LoaderParams* params)
{
    if (!params) return;

    LPVOID imageBase = params->imageBase;
    PIMAGE_NT_HEADERS ntHdr = params->ntHeaders;

    // apply base relocations
    DWORD64 delta = (DWORD64)imageBase - ntHdr->OptionalHeader.ImageBase;

    if (delta != 0)
    {
        IMAGE_DATA_DIRECTORY& relocDir = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if (relocDir.Size > 0)
        {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)imageBase + relocDir.VirtualAddress);

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
                        DWORD64* patch = (DWORD64*)((LPBYTE)imageBase + reloc->VirtualAddress + offset);
                        *patch += delta;
                    }
                }

                remaining -= reloc->SizeOfBlock;
                reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)reloc + reloc->SizeOfBlock);
            }
        }
    }

    // resolve IAT
    IMAGE_DATA_DIRECTORY& importDir =
        ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (importDir.Size > 0)
    {
        PIMAGE_IMPORT_DESCRIPTOR impDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)imageBase + importDir.VirtualAddress);

        while (impDesc->Name)
        {
            char* modName = (char*)((LPBYTE)imageBase + impDesc->Name);

            HMODULE hMod = nullptr;

            hMod = params->fnLoadLibraryA(modName);

            if (!hMod)
            {
                params->status = 0xDEAD;
                return;
            }

            PIMAGE_THUNK_DATA orig = (PIMAGE_THUNK_DATA)((LPBYTE)imageBase + impDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA iat  = (PIMAGE_THUNK_DATA)((LPBYTE)imageBase + impDesc->FirstThunk);

            while (orig->u1.AddressOfData)
            {
                FARPROC fn = nullptr;

                if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                {
                    fn = params->fnGetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(orig->u1.Ordinal));
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)imageBase + orig->u1.AddressOfData);
                    fn = params->fnGetProcAddress(hMod, ibn->Name);
                }

                if (!fn)
                {
                    params->status = 0xDEAD;
                    return;
                }

                iat->u1.Function = (ULONGLONG)fn;
                orig++;
                iat++;
            }

            impDesc++;
        }
    }

    // register SEH exception table (x64 requirement)
    // without this, any C++ exception in the injected DLL causes an access violation
    IMAGE_DATA_DIRECTORY& exceptionDir =
        ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    if (exceptionDir.Size > 0 && params->fnRtlAddFunctionTable)
    {
        PRUNTIME_FUNCTION rfTable = (PRUNTIME_FUNCTION)((LPBYTE)imageBase + exceptionDir.VirtualAddress);

        DWORD entryCount = exceptionDir.Size / sizeof(RUNTIME_FUNCTION);

        params->fnRtlAddFunctionTable(rfTable, entryCount, (DWORD64)imageBase);
    }

    // execute TLS callbacks (if any)
    IMAGE_DATA_DIRECTORY& tlsDir =
        ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    if (tlsDir.Size > 0)
    {
        PIMAGE_TLS_DIRECTORY64 tlsDirectory =
            (PIMAGE_TLS_DIRECTORY64)((LPBYTE)imageBase + tlsDir.VirtualAddress);

        if (tlsDirectory->AddressOfCallBacks)
        {
            PIMAGE_TLS_CALLBACK* cbs = (PIMAGE_TLS_CALLBACK*)tlsDirectory->AddressOfCallBacks;

            while (*cbs)
            {
                (*cbs)((PVOID)imageBase, DLL_PROCESS_ATTACH, nullptr);
                cbs++;
            }
        }
    }

    // call DllMain
    if (ntHdr->OptionalHeader.AddressOfEntryPoint)
    {
        f_DllMain dllMain = (f_DllMain)((LPBYTE)imageBase + ntHdr->OptionalHeader.AddressOfEntryPoint);

        dllMain((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, nullptr);
    }

    params->status = 1;  // success
}

static void ShellcodeEnd() {}

#pragma optimize("", on)
#pragma runtime_checks("", restore)
