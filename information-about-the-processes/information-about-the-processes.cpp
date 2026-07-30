#include <windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <iostream>

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
    if (!pSnap) return 1;

    PROCESSENTRY32 pe{ sizeof(PROCESSENTRY32) };
    if (!Process32First(pSnap, &pe)) return 2;
    do {
        std::wcout << L"PID: " << pe.th32ProcessID << L" NAME: " << pe.szExeFile << std::endl;
        SmartHandle mSnap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe.th32ProcessID));
        if (!mSnap) continue;

        MODULEENTRY32 me{ sizeof(MODULEENTRY32) };
        if (!Module32First(mSnap, &me)) continue;
        do {
            std::wcout << L" MODULE" << me.szModule << L" BASE ADDRESS" << std::hex << me.modBaseAddr << L" SIZE: " << std::dec << me.modBaseSize << std::endl;
        } while (Module32Next(mSnap, &me));

    } while (Process32Next(pSnap, &pe));



    return 0;
}