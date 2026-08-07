#pragma once
#include <Windows.h>

namespace Terminal {
    constexpr auto Reset = "\033[0m";
    constexpr auto Bold = "\033[1m";

    constexpr auto Red = "\033[31m";
    constexpr auto Green = "\033[32m";
    constexpr auto Yellow = "\033[33m";
    constexpr auto Cyan = "\033[36m";
}

class CMemory {
public:

	inline void GetHandle(HANDLE hProcess) { m_hProcess = hProcess; }
	DWORD GetProcessID(const wchar_t* procName);

private:
	HANDLE m_hProcess;
};

inline CMemory Memory;