#include "../include/module.h"
#include "../include/utils.h"
#include <tlhelp32.h>

bool ScaningModule(DWORD pid) {
    SmartHandle mSnap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
    if (!mSnap) {
        std::wcerr << L"CreateToolhelp32Snapshot failed, error code: " << GetLastError() << std::endl;
        return false;
    }
    MODULEENTRY32 me{ sizeof(MODULEENTRY32) };
    if (!Module32First(mSnap, &me)) {
        std::wcerr << L"Module32First failed, error code: " << GetLastError() << std::endl;
        return false;
    }
    do {
        tcout << L" MODULE: " << me.szModule << std::endl;
    } while (Module32Next(mSnap, &me));
    return true;
}