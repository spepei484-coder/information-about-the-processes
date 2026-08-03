#pragma once
#include <windows.h>
#include <iostream>
#include <string>

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