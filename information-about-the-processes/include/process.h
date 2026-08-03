#pragma once
#include <windows.h>
#include <string>

bool ScaningProcess();
bool namebySearch(const std::wstring& targetName);
std::string GetExePathByPid(DWORD pid);
