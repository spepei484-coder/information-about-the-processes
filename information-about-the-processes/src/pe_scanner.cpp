#include "../include/pe_scanner.h"
#include "../include/utils.h"
#include <vector>

bool ScaningPEHeader(const std::string& path) {
    SmartHandle hFile(CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL));
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateFileA failed, error: " << GetLastError() << std::endl;
        return false;
    }

    IMAGE_DOS_HEADER dosHeader = {};
    DWORD byteRead;
    if (!ReadFile(hFile, &dosHeader, sizeof(dosHeader), &byteRead, NULL) || byteRead != sizeof(dosHeader)) {
        std::cerr << "Failed to read DOS-HEADER" << std::endl;
        return false;
    }
    if (dosHeader.e_magic != 0x5A4D) {
        std::cerr << "invalid DOS-signature: 0x" << std::hex << dosHeader.e_magic << std::dec << std::endl;
        return false;
    }

    if (SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        std::cerr << "SetFilePointer to e_lfanew failed" << std::endl;
        return false;
    }

    DWORD peSignature;
    if (!ReadFile(hFile, &peSignature, sizeof(peSignature), &byteRead, NULL) || byteRead != sizeof(peSignature)) {
        std::cerr << "Fail to read PE signature" << std::endl;
        return false;
    }
    if (peSignature != 0x00004550) {
        std::cerr << "Invalid PE signature" << std::endl;
        return false;
    }

    IMAGE_FILE_HEADER fileHeader = {};
    if (!ReadFile(hFile, &fileHeader, sizeof(fileHeader), &byteRead, NULL) || byteRead != sizeof(fileHeader)) {
        std::cerr << "Failed to read FILE-HEADER" << std::endl;
        return false;
    }
    std::cout << "=== IMAGE_FILE_HEADER ===" << std::endl;
    if (fileHeader.Machine == 34404) std::cout << "Machine: " << fileHeader.Machine << " - x64" << std::endl;
    else std::cout << "Machine: " << fileHeader.Machine << " - x32" << std::endl;
    std::cout << "NumberOfSections: " << fileHeader.NumberOfSections << std::endl;
    std::cout << "SizeOfOptionalHeader: " << fileHeader.SizeOfOptionalHeader << std::endl;

    DWORD optionalSize = fileHeader.SizeOfOptionalHeader;
    if (optionalSize == 0) {
        std::cerr << "SizeOfOptionalHeader is 0" << std::endl;
        return false;
    }
    std::vector<BYTE> optionalBuffer(optionalSize);
    if (!ReadFile(hFile, optionalBuffer.data(), optionalSize, &byteRead, NULL) || byteRead != optionalSize) {
        std::cerr << "Failed to read OptionalHeader" << std::endl;
        return false;
    }

    WORD magic = *reinterpret_cast<WORD*>(optionalBuffer.data());
    std::cout << "=== IMAGE_OPTIONAL_HEADER ===" << std::endl;
    std::cout << "Magic: 0x" << std::hex << magic << std::dec << std::endl;

    if (magic == 0x10b) {
        IMAGE_OPTIONAL_HEADER32* opt32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(optionalBuffer.data());
        std::cout << "AddressOfEntryPoint: 0x" << std::hex << opt32->AddressOfEntryPoint << std::dec << std::endl
            << "ImageBase: 0x" << std::hex << opt32->ImageBase << std::dec << std::endl
            << "SectionAlignment: 0x" << std::hex << opt32->SectionAlignment << std::dec << std::endl
            << "FileAlignment: 0x" << std::hex << opt32->FileAlignment << std::dec << std::endl
            << "SizeOfImage: 0x" << std::hex << opt32->SizeOfImage << std::dec << std::endl
            << "Subsystem: " << opt32->Subsystem << std::endl
            << "NumberOfRvaAndSizes: " << opt32->NumberOfRvaAndSizes << std::endl;
    }
    else if (magic == 0x20b) {
        IMAGE_OPTIONAL_HEADER64* opt64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(optionalBuffer.data());
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
    }

    std::cout << "=== SECTION HEADERS ===" << std::endl;
    for (WORD i = 0; i < fileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sectionHeader = {};
        if (!ReadFile(hFile, &sectionHeader, sizeof(sectionHeader), &byteRead, NULL) || byteRead != sizeof(sectionHeader)) {
            std::cerr << "Failed to read SECTION-HEADER" << std::endl;
            return false;
        }
        char name[9] = { 0 };
        memcpy(name, sectionHeader.Name, 8);
        std::cout << "Section " << i << ": " << name
            << ", VirtualSize: 0x" << std::hex << sectionHeader.Misc.VirtualSize
            << ", VirtualAddress: 0x" << sectionHeader.VirtualAddress
            << ", SizeOfRawData: 0x" << sectionHeader.SizeOfRawData
            << ", PointerToRawData: 0x" << sectionHeader.PointerToRawData
            << ", Characteristics: " << std::hex << sectionHeader.Characteristics
            << std::dec << std::endl;
    }
    std::cout << "PE header parsing completed successfully." << std::endl;
    return true;
}