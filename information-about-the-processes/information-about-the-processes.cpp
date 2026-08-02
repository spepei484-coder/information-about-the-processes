#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <iomanip>
#include <psapi.h>
#include <string>

#pragma comment(lib, "psapi.lib")

#ifdef UNICODE
#define tcout std::wcout
#else 
#define tcout std::cout 
#endif


class SmartHandle {
public:
    SmartHandle(HANDLE handle) : _handle(handle) {}
    ~SmartHandle() { if (_handle) CloseHandle(_handle); }
    operator bool() { return _handle != NULL; }
    operator HANDLE() { return _handle; }
    HANDLE handle() { return _handle; }
    SmartHandle(const SmartHandle&) = delete;
    SmartHandle& operator = (const SmartHandle&) = delete;
    SmartHandle(SmartHandle&& other) noexcept : _handle(other._handle) {
        other._handle = NULL;
    }
    SmartHandle& operator = (SmartHandle&& other) noexcept {
        if (this != &other) {
            CloseHandle(_handle);
            _handle = other._handle;
            other._handle = NULL;
        }
        return *this;
    }
private:
    HANDLE _handle = NULL;
};
//ПОИСК ВСЕХ ПРОЦЕССОВ 
bool ScaningProcess() {
    SmartHandle pSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!pSnap) {
        std::wcerr << L"CreateToolhelp32Snapshot failed, error code: " << GetLastError() << std::endl;
        return false;
    }

    PROCESSENTRY32 pe{ sizeof(PROCESSENTRY32) };
    if (!Process32First(pSnap, &pe)) {
        std::wcerr << L"Process32First failed, error code: " << GetLastError() << std::endl;
        return false;
    }
    do {
        tcout << std::setw(8) << std::right << pe.th32ProcessID << " - " << pe.szExeFile << std::endl;
    } while (Process32Next(pSnap, &pe));
    return true;
}
//ПОИСК ВСЕХ МОДУЛЕЙ ПРОЦЕССА
bool ScaningModule(DWORD pid) {
    SmartHandle mSnap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid));
    if (!mSnap) {
        std::wcerr << L"CreateToolhelp32Snapshot failed, error code: " << GetLastError() << std::endl;
        return false;
    }

    MODULEENTRY32 me{ sizeof(MODULEENTRY32) };
    if (!Module32First(mSnap, &me)) {
        std::wcerr << L"Process32First failed, error code: " << GetLastError() << std::endl;
        return false;
    }
    do {
        tcout << L" MODULE: " << me.szModule << std::endl
            << L"   BASE ADDRESS: " << std::hex << me.modBaseAddr << std::endl
            << L"   SIZE: " << std::dec << me.modBaseSize << std::endl;
    } while (Module32Next(mSnap, &me));
    return true;
}
//ИНФОРМАЦИЯ О РЕГЕНАХ
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
//ПОИСК ПУТИ ПРОЦЕССА 
std::string GetExePathByPid(DWORD pid) {
    std::string result;

    SmartHandle hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "OpenProcess failed, error code: " << GetLastError() << std::endl;
        return result;
    }
    char buffer[MAX_PATH] = { 0 };
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameA(hProcess, 0, buffer, &size)) {
        result = std::string(buffer, size);
    }
    else {
        std::cerr << "QueryFullProcessImageNameA failed, error code: " << GetLastError << std::endl;
    }
    return result;
}

int main() {
    while (true) {
        std::wcout << L"Choose a number: \n"
            << L"1 - All processes\n"
            << L"2 - All modules according to pdi\n"
            << L"3 - Information about the regions\n"
            << L"4 - Path to the executable file\n"
            << L"0 - Exit\n";

        int num;
        std::cin >> num;
        std::wcout << std::endl;

        DWORD pid = 0;

        switch (num) {
        case 0: return 0;
        case 1: {
            if (!ScaningProcess()) {
                std::cerr << "ScaningProcess failed, error code: " << GetLastError() << std::endl;
                return 2;
            }
            break;
        }
        case 2: {
            std::wcout << L"Write the process ID: ";
            std::wcin >> pid;
            std::wcout << std::endl;

            if (!ScaningModule(pid)) {
                std::cerr << "ScaningModule failed, error code: " << GetLastError() << std::endl;
                return 3;
            }
            break;
        }
        case 3: {
            std::wcout << L"Write the process ID: ";
            std::wcin >> pid;
            std::wcout << std::endl;
            if (pid == 0) {
                std::wcerr << L"Process ID not set. Please select option 2 first or enter PID manually.\n";
                break;
            }
            if (!EnumerateMemoryRegions(pid)) {
                std::cerr << "EnumerateMemoryRegions failed, error code: " << GetLastError() << std::endl;
                return 4;
            }
            break;
        }
        case 4: {
            std::wcout << L"Write the process ID: ";
            std::wcin >> pid;
            std::wcout << std::endl;
            if (pid == 0) {
                std::wcerr << L"Process ID not set. Please select option 2 first or enter PID manually.\n";
                break;
            }
            std::string path = GetExePathByPid(pid);
            if (!path.empty()) {
                std::cout << "Path EXE: " << path << std::endl;
            }
            else {
                std::wcerr << L"Could not retieve executadle path.\n";
            }
            break;
        }
        default: {
            std::wcerr << "Invalid choice." << std::endl;
            break;
        }
        }
    }
    return 0;
     
}