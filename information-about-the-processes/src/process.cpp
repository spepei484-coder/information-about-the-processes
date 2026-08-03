#include "../include/process.h"
#include "../include/utils.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <tchar.h>
#include <iomanip>

#pragma comment(lib, "psapi.lib")

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

bool namebySearch(const std::wstring& targetName) {
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
    bool found = false;
    do {
        if (_tcscmp(pe.szExeFile, targetName.c_str()) == 0) {
            std::wcout << L"PID " << pe.szExeFile << L": " << pe.th32ProcessID << std::endl;
            found = true;
        }
    } while (Process32Next(pSnap, &pe));
    if (!found) std::wcout << L"Process \"" << targetName << L"\" not found." << std::endl;
    return found;
}

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
        std::cerr << "QueryFullProcessImageNameA failed, error code: " << GetLastError() << std::endl;
    }
    return result;
}