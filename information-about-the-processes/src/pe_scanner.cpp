#include "../include/pe_scanner.h"
#include "../include/utils.h"
#include <vector>
#include <iomanip>

bool ScaningPEHeader(const std::string& path) {
    SmartHandle hFile(CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL));
    if (!hFile) {
        std::cerr << "CreateFileA failed, error: " << GetLastError() << std::endl;
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        std::cerr << "GetFileSize failed, error: " << GetLastError() << std::endl;
        return false;
    }

    std::vector<BYTE> buffer(fileSize);
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        std::cerr << "ReadFile failed or incomplete read, error: " << GetLastError() << std::endl;
        return false;
    }

    // DOS header
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) {
        std::cerr << "File too small for DOS header" << std::endl;
        return false;
    }
    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid DOS signature: 0x" << std::hex << dosHeader->e_magic << std::dec << std::endl;
        return false;
    }

    // NT headers
    LONG e_lfanew = dosHeader->e_lfanew;
    if (e_lfanew < 0 || static_cast<DWORD>(e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > fileSize) {
        std::cerr << "Invalid e_lfanew value" << std::endl;
        return false;
    }
    IMAGE_NT_HEADERS32* ntHeader32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(buffer.data() + e_lfanew);
    if (ntHeader32->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Invalid PE signature" << std::endl;
        return false;
    }

    IMAGE_FILE_HEADER* fileHeader = &ntHeader32->FileHeader;

    std::cout << "=== IMAGE_FILE_HEADER ===" << std::endl;
    std::cout << "Machine: " << fileHeader->Machine;
    if (fileHeader->Machine == IMAGE_FILE_MACHINE_AMD64)
        std::cout << " (x64)";
    else if (fileHeader->Machine == IMAGE_FILE_MACHINE_I386)
        std::cout << " (x86)";
    else
        std::cout << " (unknown)";
    std::cout << std::endl;
    std::cout << "NumberOfSections: " << fileHeader->NumberOfSections << std::endl;
    std::cout << "SizeOfOptionalHeader: " << fileHeader->SizeOfOptionalHeader << std::endl;

    // Optional header 
    BYTE* optHeaderStart = buffer.data() + e_lfanew + offsetof(IMAGE_NT_HEADERS32, OptionalHeader);
    DWORD optSize = fileHeader->SizeOfOptionalHeader;
    if (optSize < sizeof(WORD)) {
        std::cerr << "Optional header too small" << std::endl;
        return false;
    }
    WORD magic = *reinterpret_cast<WORD*>(optHeaderStart);
    std::cout << "=== IMAGE_OPTIONAL_HEADER ===" << std::endl;
    std::cout << "Magic: 0x" << std::hex << magic << std::dec << std::endl;

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (optSize < sizeof(IMAGE_OPTIONAL_HEADER32)) {
            std::cerr << "Optional header size too small for 32-bit" << std::endl;
            return false;
        }
        IMAGE_OPTIONAL_HEADER32* opt32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(optHeaderStart);
        std::cout << "AddressOfEntryPoint: 0x" << std::hex << opt32->AddressOfEntryPoint << std::dec << std::endl
            << "ImageBase: 0x" << std::hex << opt32->ImageBase << std::dec << std::endl
            << "SectionAlignment: 0x" << std::hex << opt32->SectionAlignment << std::dec << std::endl
            << "FileAlignment: 0x" << std::hex << opt32->FileAlignment << std::dec << std::endl
            << "SizeOfImage: 0x" << std::hex << opt32->SizeOfImage << std::dec << std::endl
            << "Subsystem: " << opt32->Subsystem << std::endl
            << "NumberOfRvaAndSizes: " << opt32->NumberOfRvaAndSizes << std::endl;
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (optSize < sizeof(IMAGE_OPTIONAL_HEADER64)) {
            std::cerr << "Optional header size too small for 64-bit" << std::endl;
            return false;
        }
        IMAGE_OPTIONAL_HEADER64* opt64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(optHeaderStart);
        std::cout << "AddressOfEntryPoint: 0x" << std::hex << opt64->AddressOfEntryPoint << std::dec << std::endl
            << "ImageBase: 0x" << std::hex << opt64->ImageBase << std::dec << std::endl
            << "SectionAlignment: 0x" << std::hex << opt64->SectionAlignment << std::dec << std::endl
            << "FileAlignment: 0x" << std::hex << opt64->FileAlignment << std::dec << std::endl
            << "SizeOfImage: 0x" << std::hex << opt64->SizeOfImage << std::dec << std::endl
            << "Subsystem: " << opt64->Subsystem << std::endl
            << "NumberOfRvaAndSizes: " << opt64->NumberOfRvaAndSizes << std::endl;
    }
    else {
        std::cerr << "Unknown Magic in OptionalHeader" << std::endl;
        return false;
    }

    // Section headers
    std::cout << "=== SECTION HEADERS ===" << std::endl;
    IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader32);
    for (UINT i = 0; i < fileHeader->NumberOfSections; ++i, ++sectionHeader) {
        char name[9] = { 0 };
        memcpy(name, sectionHeader->Name, 8);
        std::cout << std::left << std::setw(3) << "Section " << i << ": " << name << std::endl;
        std::cout << "  VirtualSize:   0x" << std::hex << std::setw(8) << std::setfill('0')
            << sectionHeader->Misc.VirtualSize << std::dec << std::endl;
        std::cout << "  VirtualAddress:0x" << std::hex << std::setw(8) << std::setfill('0')
            << sectionHeader->VirtualAddress << std::dec << std::endl;
        std::cout << "  SizeOfRawData: 0x" << std::hex << std::setw(8) << std::setfill('0')
            << sectionHeader->SizeOfRawData << std::dec << std::endl;
        std::cout << "  PointerToRawData:0x" << std::hex << std::setw(8) << std::setfill('0')
            << sectionHeader->PointerToRawData << std::dec << std::endl;
        std::cout << "  Characteristics:0x" << std::hex << std::setw(8) << std::setfill('0')
            << sectionHeader->Characteristics << std::dec << std::endl;
        std::cout << std::endl;
    }

    std::cout << "PE header parsing completed successfully." << std::endl;
    return true;
}