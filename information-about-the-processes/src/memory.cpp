#include "../include/memory.h"
#include "../include/utils.h"
#include <psapi.h>
#include <iomanip>

std::wstring GetProtectionString(DWORD protect) {
    switch (protect) {
    case PAGE_NOACCESS:          return L"PAGE_NOACCESS";
    case PAGE_READONLY:          return L"PAGE_READONLY";
    case PAGE_READWRITE:         return L"PAGE_READWRITE";
    case PAGE_WRITECOPY:         return L"PAGE_WRITECOPY";
    case PAGE_EXECUTE:           return L"PAGE_EXECUTE";
    case PAGE_EXECUTE_READ:      return L"PAGE_EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE: return L"PAGE_EXECUTE_READWRITE";
    case PAGE_EXECUTE_WRITECOPY: return L"PAGE_EXECUTE_WRITECOPY";
    default:                     return L"UNKNOWN";
    }
}

std::wstring GetStateString(DWORD state) {
    switch (state) {
    case MEM_COMMIT:   return L"COMMIT";
    case MEM_RESERVE:  return L"RESERVE";
    case MEM_FREE:     return L"FREE";
    default:           return L"UNKNOWN";
    }
}

bool EnumerateMemoryRegions(DWORD pid) {
    SmartHandle hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (!hProcess) {
        std::wcerr << L"OpenProcess failed, error code: " << GetLastError() << std::endl;
        return false;
    }
    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID address = 0;
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        tcout << std::hex << std::setw(12) << std::setfill(L'0')
            << (uintptr_t)mbi.BaseAddress
            << L"  " << std::setw(10) << std::setfill(L' ') << std::dec
            << mbi.RegionSize
            << L"  " << std::setw(14) << std::left
            << GetProtectionString(mbi.Protect)
            << L"  " << GetStateString(mbi.State)
            << std::endl;
        address = (LPCVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }
    return true;
}