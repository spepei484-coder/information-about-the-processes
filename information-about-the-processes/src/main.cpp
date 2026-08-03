#include "../include/process.h"
#include "../include/module.h"
#include "../include/memory.h"
#include "../include/pe_scanner.h"
#include <iostream>
#include <limits>

int main() {
    std::setlocale(LC_ALL, "");

    while (true) {
        std::wcout << L"Choose a number: \n"
            << L"1 - All processes\n"
            << L"2 - All modules according to PID\n"
            << L"3 - Information about the regions\n"
            << L"4 - Path to the executable file\n"
            << L"5 - Name search\n"
            << L"6 - Scan PE Header of process\n"
            << L"0 - Exit\n";

        int num;
        std::cin >> num;
        std::wcin.ignore((std::numeric_limits<std::streamsize>::max)(), L'\n');
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
                std::wcerr << L"Process ID not set.\n";
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
                std::wcerr << L"Process ID not set.\n";
                break;
            }
            std::string path = GetExePathByPid(pid);
            if (!path.empty()) {
                std::cout << "Path EXE: " << path << std::endl;
            }
            else {
                std::wcerr << L"Could not retrieve executable path.\n";
            }
            break;
        }
        case 5: {
            std::wcout << L"Write name process: ";
            std::wstring processName;
            std::getline(std::wcin, processName);
            std::wcout << std::endl;
            namebySearch(processName);
            break;
        }
        case 6: {
            std::wcout << L"Write the process ID: ";
            std::wcin >> pid;
            std::wcout << std::endl;
            if (pid == 0) {
                std::wcerr << L"Process ID not set.\n";
                break;
            }
            std::string path = GetExePathByPid(pid);
            if (path.empty()) {
                std::wcerr << L"Could not retrieve executable path.\n";
                break;
            }
            ScaningPEHeader(path);
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