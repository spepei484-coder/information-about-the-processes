#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <iomanip>

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
        if (this != other) {
            CloseHandle(_handle);
            _handle = other._handle;
            other._handle = NULL;
        }
        return *this;
    }
private:
    HANDLE _handle = NULL;
};

int main() {
    SmartHandle pSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!pSnap) {
        std::wcerr << L"CreateToolhelp32Snapshot failed, error code: " << GetLastError() << std::endl;
        return 1;
    }

    PROCESSENTRY32 pe{ sizeof(PROCESSENTRY32) };
    if (!Process32First(pSnap, &pe)) {
        std::wcerr << L"Process32First failed, error code: " << GetLastError() << std::endl;
        return 2;
    }
    do {
        std::wcout << std::setw(8) << std::right << pe.th32ProcessID << " - " << pe.szExeFile << std::endl;
    } while (Process32Next(pSnap, &pe));

    DWORD pid;
    std::wcout << L" Write the process ID: ";
    std::wcin >> pid;
    std::wcout << std::endl;

    SmartHandle mSnap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid));
    if (!mSnap) {
        std::wcerr << L"CreateToolhelp32Snapshot failed, error code: " << GetLastError() << std::endl;
        return 3;
    }

    MODULEENTRY32 me{ sizeof(MODULEENTRY32) };
    if (!Module32First(mSnap, &me)) {
        std::wcerr << L"Process32First failed, error code: " << GetLastError() << std::endl;
        return 4;
    }
    do {
        std::wcout << L" MODULE: " << me.szModule << std::endl
            << L" BASE ADDRESS: " << std::hex << me.modBaseAddr << std::endl
            << L" SIZE: " << std::dec << me.modBaseSize << std::endl;
    } while (Module32Next(mSnap, &me));

    return 0;
}