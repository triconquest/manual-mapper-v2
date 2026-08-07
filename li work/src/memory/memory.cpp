#include "memory.h"

#include <TlHelp32.h>

DWORD CMemory::GetProcessID(const wchar_t* procName)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(snapshot, &entry))
	{
		do {
			if (!wcscmp(procName, entry.szExeFile))
			{
				CloseHandle(snapshot);
				return entry.th32ProcessID;
			}
		} while (Process32Next(snapshot, &entry));
	}

	CloseHandle(snapshot);
	return 0;
}
