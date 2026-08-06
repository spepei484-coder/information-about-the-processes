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
    SmartHandle(HANDLE handle = NULL) : _handle(handle) {}
    ~SmartHandle() { if (_handle != NULL && _handle != INVALID_HANDLE_VALUE) CloseHandle(_handle); }

    explicit operator bool() const { return _handle != NULL && _handle != INVALID_HANDLE_VALUE; }
    operator HANDLE() const { return _handle; }
    HANDLE get() const { return _handle; }

    SmartHandle(const SmartHandle&) = delete;
    SmartHandle& operator=(const SmartHandle&) = delete;

    SmartHandle(SmartHandle&& other) noexcept : _handle(other._handle) {
        other._handle = NULL;
    }
    SmartHandle& operator=(SmartHandle&& other) noexcept {
        if (this != &other) {
            if (_handle && _handle != INVALID_HANDLE_VALUE) CloseHandle(_handle);
            _handle = other._handle;
            other._handle = NULL;
        }
        return *this;
    }

    void reset(HANDLE handle = NULL) {
        if (_handle && _handle != INVALID_HANDLE_VALUE) CloseHandle(_handle);
        _handle = handle;
    }

private:
    HANDLE _handle;
};