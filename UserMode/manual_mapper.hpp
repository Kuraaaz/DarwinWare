#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <memory>
#include <map>
#include "driver_com.h"

namespace ManualMapper {

    // Structures PE (existant)
#pragma pack(push, 1)
    struct IMAGE_DOS_HEADER {
        WORD e_magic;
        WORD e_cblp;
        WORD e_cp;
        WORD e_crlc;
        WORD e_cparhdr;
        WORD e_minalloc;
        WORD e_maxalloc;
        WORD e_ss;
        WORD e_sp;
        WORD e_csum;
        WORD e_ip;
        WORD e_cs;
        WORD e_lfarlc;
        WORD e_ovno;
        WORD e_res[4];
        WORD e_oemid;
        WORD e_oeminfo;
        WORD e_res2[10];
        LONG e_lfanew;
    };

    struct IMAGE_FILE_HEADER {
        WORD Machine;
        WORD NumberOfSections;
        DWORD TimeDateStamp;
        DWORD PointerToSymbolTable;
        DWORD NumberOfSymbols;
        WORD SizeOfOptionalHeader;
        WORD Characteristics;
    };

    struct IMAGE_DATA_DIRECTORY {
        DWORD VirtualAddress;
        DWORD Size;
    };

    struct IMAGE_OPTIONAL_HEADER64 {
        WORD Magic;
        BYTE MajorLinkerVersion;
        BYTE MinorLinkerVersion;
        DWORD SizeOfCode;
        DWORD SizeOfInitializedData;
        DWORD SizeOfUninitializedData;
        DWORD AddressOfEntryPoint;
        DWORD BaseOfCode;
        ULONGLONG ImageBase;
        DWORD SectionAlignment;
        DWORD FileAlignment;
        WORD MajorOperatingSystemVersion;
        WORD MinorOperatingSystemVersion;
        WORD MajorImageVersion;
        WORD MinorImageVersion;
        WORD MajorSubsystemVersion;
        WORD MinorSubsystemVersion;
        DWORD Win32VersionValue;
        DWORD SizeOfImage;
        DWORD SizeOfHeaders;
        DWORD CheckSum;
        WORD Subsystem;
        WORD DllCharacteristics;
        ULONGLONG SizeOfStackReserve;
        ULONGLONG SizeOfStackCommit;
        ULONGLONG SizeOfHeapReserve;
        ULONGLONG SizeOfHeapCommit;
        DWORD LoaderFlags;
        DWORD NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[16];
    };

    struct IMAGE_NT_HEADERS64 {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    };

    struct IMAGE_SECTION_HEADER {
        BYTE Name[8];
        union {
            DWORD PhysicalAddress;
            DWORD VirtualSize;
        } Misc;
        DWORD VirtualAddress;
        DWORD SizeOfRawData;
        DWORD PointerToRawData;
        DWORD PointerToRelocations;
        DWORD PointerToLinenumbers;
        WORD NumberOfRelocations;
        WORD NumberOfLinenumbers;
        DWORD Characteristics;
    };

    struct IMAGE_IMPORT_DESCRIPTOR {
        union {
            DWORD Characteristics;
            DWORD OriginalFirstThunk;
        };
        DWORD TimeDateStamp;
        DWORD ForwarderChain;
        DWORD Name;
        DWORD FirstThunk;
    };

    struct IMAGE_THUNK_DATA64 {
        ULONGLONG AddressOfData;
    };

    struct IMAGE_IMPORT_BY_NAME {
        WORD Hint;
        CHAR Name[1];
    };

    struct IMAGE_BASE_RELOCATION {
        DWORD VirtualAddress;
        DWORD SizeOfBlock;
    };

    // AJOUT: Structure pour les exports
    struct IMAGE_EXPORT_DIRECTORY {
        DWORD Characteristics;
        DWORD TimeDateStamp;
        WORD MajorVersion;
        WORD MinorVersion;
        DWORD Name;
        DWORD Base;
        DWORD NumberOfFunctions;
        DWORD NumberOfNames;
        DWORD AddressOfFunctions;
        DWORD AddressOfNames;
        DWORD AddressOfNameOrdinals;
    };
#pragma pack(pop)

#define IMAGE_FIRST_SECTION(ntheader) ((IMAGE_SECTION_HEADER*)((ULONG_PTR)(ntheader) + \
    offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + \
    ((IMAGE_NT_HEADERS64*)(ntheader))->FileHeader.SizeOfOptionalHeader))

    // Structures de données
    struct SectionInfo {
        std::string name;
        uintptr_t virtualAddress;
        uintptr_t rawDataPtr;
        DWORD rawDataSize;
        DWORD virtualSize;
        DWORD characteristics;
    };

    struct ImportInfo {
        std::string dllName;
        std::vector<std::string> functionNames;
        uintptr_t importTableAddress;
    };

    struct PEInfo {
        bool is64Bit;
        uintptr_t imageBase;
        uintptr_t entryPoint;
        uintptr_t sizeOfImage;
        std::vector<SectionInfo> sections;
        std::vector<ImportInfo> imports;
        uintptr_t relocationTableAddress;
        DWORD relocationTableSize;
    };

    // AJOUT: Structures pour la résolution des imports
    struct ResolvedImport {
        std::string functionName;
        uintptr_t functionAddress;
        uintptr_t iatEntryAddress;
    };

    struct ResolvedModule {
        std::string moduleName;
        HMODULE moduleBase;
        std::vector<ResolvedImport> imports;
    };

    // Classe principale du mapper
    class Mapper {
    private:
        std::vector<uint8_t> dllData;
        PEInfo peInfo;
        uintptr_t mappedBaseAddress;

        // Fonctions utilitaires internes
        uintptr_t RvaToOffset(uintptr_t rva);
        uintptr_t RvaToVa(uintptr_t rva);
        std::string ReadStringFromDll(uintptr_t offset);
        bool WriteMemoryToTarget(uintptr_t address, const void* data, size_t size);
        bool ReadMemoryFromTarget(uintptr_t address, void* buffer, size_t size);

        // AJOUT: Fonctions pour la résolution des imports
        HMODULE LoadModuleInTargetProcess(const std::string& moduleName);
        uintptr_t GetFunctionAddressFromModule(HMODULE moduleBase, const std::string& functionName);

    public:
        bool LoadDLLFromFile(const std::wstring& filePath);
        bool ParsePEStructure();
        bool AllocateTargetMemory();
        bool MapSections();
        bool ResolveImports();
        bool ApplyRelocations();
        bool FixSectionPermissions();
        bool CallDllMain();
        bool MapDLLToProcess(const std::wstring& dllPath);

        uintptr_t GetMappedBaseAddress() const { return mappedBaseAddress; }
        const PEInfo& GetPEInfo() const { return peInfo; }
    };

} // namespace ManualMapper