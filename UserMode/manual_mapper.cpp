#include "manual_mapper.hpp"
#include <iostream>
#include <fstream>
#include <algorithm>

using namespace ManualMapper;


HMODULE Mapper::LoadModuleInTargetProcess(const std::string& moduleName) {
    // Charger la DLL dans le processus cible en utilisant notre driver
    std::wstring wideModuleName(moduleName.begin(), moduleName.end());

    // Essayer de trouver le module déjà chargé
    ULONGLONG moduleBase = comDriver::GetModuleBase(wideModuleName.c_str());
    if (moduleBase != 0) {
        std::cout << "   Module déjà chargé: " << moduleName << " @ 0x" << std::hex << moduleBase << std::dec << "\n";
        return reinterpret_cast<HMODULE>(moduleBase);
    }

    // Si le module n'est pas chargé, on va devoir le charger
    // Pour l'instant, on suppose que les DLLs système sont déjà chargées
    std::cout << "    Module non trouvé (doit être chargé manuellement): " << moduleName << "\n";
    return nullptr;
}

uintptr_t Mapper::GetFunctionAddressFromModule(HMODULE moduleBase, const std::string& functionName) {
    if (moduleBase == nullptr) return 0;

    // Lire les headers PE du module pour trouver l'export table
    BYTE moduleHeader[0x1000];
    if (!ReadMemoryFromTarget(reinterpret_cast<uintptr_t>(moduleBase), moduleHeader, sizeof(moduleHeader))) {
        return 0;
    }

    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleHeader);
    if (dosHeader->e_magic != 0x5A4D) return 0;

    auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(moduleHeader + dosHeader->e_lfanew);
    if (ntHeaders->Signature != 0x4550) return 0;

    // Trouver la table d'exports
    auto exportDir = ntHeaders->OptionalHeader.DataDirectory[0];
    if (exportDir.VirtualAddress == 0) return 0;

    // Lire le répertoire d'export
    DWORD exportDirSize = exportDir.Size;
    std::vector<BYTE> exportData(exportDirSize);
    if (!ReadMemoryFromTarget(reinterpret_cast<uintptr_t>(moduleBase) + exportDir.VirtualAddress,
        exportData.data(), exportDirSize)) {
        return 0;
    }

    auto exportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(exportData.data());

    // Lire les tables d'export
    std::vector<DWORD> nameTable(exportDirectory->NumberOfNames);
    std::vector<WORD> ordinalTable(exportDirectory->NumberOfNames);
    std::vector<DWORD> addressTable(exportDirectory->NumberOfFunctions);

    if (!ReadMemoryFromTarget(reinterpret_cast<uintptr_t>(moduleBase) + exportDirectory->AddressOfNames,
        nameTable.data(), exportDirectory->NumberOfNames * sizeof(DWORD)) ||
        !ReadMemoryFromTarget(reinterpret_cast<uintptr_t>(moduleBase) + exportDirectory->AddressOfNameOrdinals,
            ordinalTable.data(), exportDirectory->NumberOfNames * sizeof(WORD)) ||
        !ReadMemoryFromTarget(reinterpret_cast<uintptr_t>(moduleBase) + exportDirectory->AddressOfFunctions,
            addressTable.data(), exportDirectory->NumberOfFunctions * sizeof(DWORD))) {
        return 0;
    }

    // Chercher la fonction par nom
    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        // Lire le nom de la fonction
        char functionNameBuffer[256];
        if (!ReadMemoryFromTarget(reinterpret_cast<uintptr_t>(moduleBase) + nameTable[i],
            functionNameBuffer, sizeof(functionNameBuffer))) {
            continue;
        }

        if (strcmp(functionNameBuffer, functionName.c_str()) == 0) {
            WORD ordinal = ordinalTable[i];
            if (ordinal < exportDirectory->NumberOfFunctions) {
                DWORD functionRVA = addressTable[ordinal];
                return reinterpret_cast<uintptr_t>(moduleBase) + functionRVA;
            }
        }
    }

    return 0;
}

bool Mapper::ResolveImports() {
    std::cout << "Résolution des imports...\n";

    // Liste des modules système communs qu'on peut résoudre
    std::vector<std::string> systemModules = {
        "KERNEL32.dll", "USER32.dll", "SHELL32.dll", "MSVCP140.dll",
        "dxgi.dll", "d3d12.dll", "IMM32.dll", "D3DCOMPILER_47.dll",
        "VCRUNTIME140_1.dll", "VCRUNTIME140.dll"
    };

    int resolvedCount = 0;
    int totalFunctions = 0;

    for (const auto& import : peInfo.imports) {
        std::cout << "  DLL: " << import.dllName << " (" << import.functionNames.size() << " fonctions)\n";

        // Vérifier si c'est un module système qu'on peut résoudre
        bool isSystemModule = false;
        for (const auto& systemModule : systemModules) {
            if (_stricmp(import.dllName.c_str(), systemModule.c_str()) == 0) {
                isSystemModule = true;
                break;
            }
        }

        if (!isSystemModule) {
            std::cout << "      Module non-système - résolution manuelle requise\n";
            continue;
        }

        // Charger le module dans le processus cible
        HMODULE moduleBase = LoadModuleInTargetProcess(import.dllName);
        if (moduleBase == nullptr) {
            std::cout << "     Impossible de charger le module: " << import.dllName << "\n";
            continue;
        }

        // Résoudre chaque fonction
        for (const auto& funcName : import.functionNames) {
            uintptr_t functionAddress = GetFunctionAddressFromModule(moduleBase, funcName);

            if (functionAddress != 0) {
                // Écrire l'adresse dans l'IAT (Import Address Table)
                uintptr_t iatEntry = mappedBaseAddress + import.importTableAddress +
                    (&funcName - &import.functionNames[0]) * sizeof(uintptr_t);

                if (WriteMemoryToTarget(iatEntry, &functionAddress, sizeof(functionAddress))) {
                    resolvedCount++;
                    std::cout << "     " << funcName << " -> 0x" << std::hex << functionAddress << std::dec << "\n";
                }
                else {
                    std::cout << "     Échec écriture IAT pour: " << funcName << "\n";
                }
            }
            else {
                std::cout << "     Fonction non trouvée: " << funcName << "\n";
            }

            totalFunctions++;
        }
    }

    std::cout << " Résumé: " << resolvedCount << "/" << totalFunctions << " fonctions résolues\n";

    if (resolvedCount > 0) {
        std::cout << " Import resolution partiellement réussie\n";
        return true;
    }
    else {
        std::cout << " Aucune fonction résolue - la DLL risque de crasher\n";
        return false;
    }
}



bool Mapper::CallDllMain() {
    if (peInfo.entryPoint == 0) {
        std::cout << "Pas d'entry point - skipping DllMain\n";
        return true;
    }

    std::cout << "Appel de DllMain... ";
    uintptr_t entryPoint = mappedBaseAddress + peInfo.entryPoint;
    std::cout << "EntryPoint: 0x" << std::hex << entryPoint << std::dec << "\n";

    // Pour appeler DllMain, on aurait besoin d'exécuter du code dans le processus cible
    // Ceci nécessiterait une technique d'injection de shellcode ou de thread distant
    // Pour l'instant, on va simplement préparer l'appel

    std::cout << "DllMain prêt à être appelé à 0x" << std::hex << entryPoint << std::dec << "\n";
    std::cout << "Pour l'appeler, il faudrait injecter un shellcode qui appelle:\n";
    std::cout << " DllMain(hModule, DLL_PROCESS_ATTACH, nullptr)\n";

    return true;
}


uintptr_t Mapper::RvaToOffset(uintptr_t rva) {
    for (const auto& section : peInfo.sections) {
        if (rva >= section.virtualAddress && rva < section.virtualAddress + section.virtualSize) {
            return rva - section.virtualAddress + section.rawDataPtr;
        }
    }
    return rva;
}

uintptr_t Mapper::RvaToVa(uintptr_t rva) {
    return mappedBaseAddress + rva;
}

std::string Mapper::ReadStringFromDll(uintptr_t offset) {
    if (offset >= dllData.size()) return "";

    const char* str = reinterpret_cast<const char*>(dllData.data() + offset);
    return std::string(str);
}

bool Mapper::WriteMemoryToTarget(uintptr_t address, const void* data, size_t size) {
    return comDriver::WriteMemory(reinterpret_cast<uintptr_t>(data), address, size);
}

bool Mapper::ReadMemoryFromTarget(uintptr_t address, void* buffer, size_t size) {
    return comDriver::ReadMemory(address, reinterpret_cast<uintptr_t>(buffer), size);
}

// ==================== FONCTIONS PRINCIPALES ====================

bool Mapper::LoadDLLFromFile(const std::wstring& filePath) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::wcout << L" Impossible to open the file: " << filePath << L"\n";
        return false;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    dllData.resize(size);
    if (!file.read(reinterpret_cast<char*>(dllData.data()), size)) {
        std::wcout << L" Error file opening: " << filePath << L"\n";
        return false;
    }

    std::wcout << L" DLL loaded: " << size << L" bytes\n";
    return true;
}

bool Mapper::ParsePEStructure() {
    if (dllData.size() < sizeof(IMAGE_DOS_HEADER)) {
        std::cout << "Fichier trop petit pour être une DLL valide\n";
        return false;
    }

    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(dllData.data());
    if (dosHeader->e_magic != 0x5A4D) {
        std::cout << "Signature MZ non trouvée\n";
        return false;
    }

    auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(dllData.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != 0x4550) {
        std::cout << "Signature PE non trouvée\n";
        return false;
    }

    peInfo.is64Bit = ntHeaders->OptionalHeader.Magic == 0x20B;
    peInfo.imageBase = ntHeaders->OptionalHeader.ImageBase;
    peInfo.entryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    peInfo.sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;

    std::cout << "? Header PE parsé - ";
    std::cout << (peInfo.is64Bit ? "64-bit" : "32-bit") << " - ";
    std::cout << "EntryPoint: 0x" << std::hex << peInfo.entryPoint << std::dec << "\n";

    auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++) {
        SectionInfo section;
        section.name = std::string(reinterpret_cast<char*>(sectionHeader->Name), 8);
        section.virtualAddress = sectionHeader->VirtualAddress;
        section.rawDataPtr = sectionHeader->PointerToRawData;
        section.rawDataSize = sectionHeader->SizeOfRawData;
        section.virtualSize = sectionHeader->Misc.VirtualSize;
        section.characteristics = sectionHeader->Characteristics;

        peInfo.sections.push_back(section);

        std::cout << "  Section: " << section.name << " VA: 0x" << std::hex << section.virtualAddress;
        std::cout << " Size: 0x" << section.rawDataSize << std::dec << "\n";
    }

    auto importDir = ntHeaders->OptionalHeader.DataDirectory[1];
    if (importDir.VirtualAddress != 0 && importDir.Size > 0) {
        auto importDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            dllData.data() + RvaToOffset(importDir.VirtualAddress));

        while (importDescriptor->Name != 0) {
            ImportInfo import;
import.dllName = ReadStringFromDll(RvaToOffset(importDescriptor->Name));
import.importTableAddress = importDescriptor->FirstThunk;

            auto thunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(
                dllData.data() + RvaToOffset(importDescriptor->OriginalFirstThunk));

            while (thunk->AddressOfData != 0) {
                if (!(thunk->AddressOfData & 0x8000000000000000)) {
                    auto importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                        dllData.data() + RvaToOffset(thunk->AddressOfData));
import.functionNames.push_back(importByName->Name);
                }
                thunk++;
            }

            peInfo.imports.push_back(import);
            importDescriptor++;
        }
    }

    auto relocDir = ntHeaders->OptionalHeader.DataDirectory[5];
    peInfo.relocationTableAddress = relocDir.VirtualAddress;
    peInfo.relocationTableSize = relocDir.Size;

    std::cout << "PE Structure completely parsed\n";
    return true;
}

bool Mapper::AllocateTargetMemory() {
    std::cout << "Allocation of 0x" << std::hex << peInfo.sizeOfImage << " bytes... ";

    uintptr_t desiredAddress = peInfo.imageBase;
    size_t size = peInfo.sizeOfImage;

    if (comDriver::AllocateVirtualMemory(&desiredAddress, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
        mappedBaseAddress = desiredAddress;
        std::cout << "SUCCES at 0x" << std::hex << mappedBaseAddress << std::dec << "\n";
        return true;
    }
    else {
        std::cout << "ERROR\n";
        return false;
    }
}

bool Mapper::MapSections() {
    std::cout << "Mapping the sections...\n";

    auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(dllData.data() +
        reinterpret_cast<IMAGE_DOS_HEADER*>(dllData.data())->e_lfanew);

    DWORD sizeOfHeaders = ntHeaders->OptionalHeader.SizeOfHeaders;
    if (!WriteMemoryToTarget(mappedBaseAddress, dllData.data(), sizeOfHeaders)) {
        std::cout << "error pe headers past\n";
        return false;
    }

    for (const auto& section : peInfo.sections) {
        if (section.rawDataSize > 0) {
            uintptr_t targetAddress = mappedBaseAddress + section.virtualAddress;
            const void* sourceData = dllData.data() + section.rawDataPtr;

            if (!WriteMemoryToTarget(targetAddress, sourceData, section.rawDataSize)) {
                std::cout << " Error of section past " << section.name << "\n";
                return false;
            }

            std::cout << "  Section " << section.name << " mapped at 0x"
                << std::hex << targetAddress << std::dec << "\n";
        }
    }

    std::cout << "all sections mapped succesfully\n";
    return true;
}



bool Mapper::ApplyRelocations() {
    if (peInfo.relocationTableAddress == 0 || peInfo.relocationTableSize == 0) {
        std::cout << "no relocs to apply\n";
        return true;
    }

    std::cout << "Application of relocations...\n";

    auto relocBase = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
        dllData.data() + RvaToOffset(peInfo.relocationTableAddress));

    ULONGLONG delta = mappedBaseAddress - peInfo.imageBase;

    if (delta == 0) {
        std::cout << "DLL mapped to his favourite location - no relocation needed\n";
        return true;
    }

    while (relocBase->VirtualAddress > 0 && relocBase->SizeOfBlock > 0) {
        DWORD entriesCount = (relocBase->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* relocEntries = reinterpret_cast<WORD*>(relocBase + 1);

        for (DWORD i = 0; i < entriesCount; i++) {
            if (relocEntries[i] != 0) {
                WORD type = relocEntries[i] >> 12;
                WORD offset = relocEntries[i] & 0xFFF;

                if (type == 10) {
                    uintptr_t relocAddress = mappedBaseAddress + relocBase->VirtualAddress + offset;

                    ULONGLONG value;
                    if (ReadMemoryFromTarget(relocAddress, &value, sizeof(value))) {
                        value += delta;
                        WriteMemoryToTarget(relocAddress, &value, sizeof(value));
                    }
                }
            }
        }

        relocBase = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<BYTE*>(relocBase) + relocBase->SizeOfBlock);
    }

    std::cout << "? Relocations appliquées (delta: 0x" << std::hex << delta << ")\n";
    return true;
}

bool Mapper::FixSectionPermissions() {
    std::cout << "Fixation des permissions...\n";

    for (const auto& section : peInfo.sections) {
        uintptr_t sectionAddress = mappedBaseAddress + section.virtualAddress;
        DWORD protect = 0;

        if (section.characteristics & 0x20000000) {
            if (section.characteristics & 0x80000000) {
                protect = PAGE_EXECUTE_READWRITE;
            }
            else if (section.characteristics & 0x40000000) {
                protect = PAGE_EXECUTE_READ;
            }
            else {
                protect = PAGE_EXECUTE;
            }
        }
        else {
            if (section.characteristics & 0x80000000) {
                protect = PAGE_READWRITE;
            }
            else if (section.characteristics & 0x40000000) {
                protect = PAGE_READONLY;
            }
            else {
                protect = PAGE_NOACCESS;
            }
        }

        ULONG oldProtect;
        if (comDriver::ProtectVirtualMemory(sectionAddress, section.virtualSize, protect, &oldProtect)) {
            std::string permStr;
            switch (protect) {
            case PAGE_EXECUTE_READWRITE: permStr = "RWX"; break;
            case PAGE_EXECUTE_READ: permStr = "RX"; break;
            case PAGE_READWRITE: permStr = "RW"; break;
            case PAGE_READONLY: permStr = "R"; break;
            default: permStr = "?";
            }
            std::cout << " Section " << section.name << " -> " << permStr << "\n";
        }
        else {
            std::cout << "Echec protection section " << section.name << "\n";
        }
    }

    std::cout << "Permissions fixées\n";
    return true;
}



bool Mapper::MapDLLToProcess(const std::wstring& dllPath) {
    std::cout << "\n=== MANUAL MAPPING DE DLL ===\n";

    if (!LoadDLLFromFile(dllPath)) return false;
    if (!ParsePEStructure()) return false;
    if (!AllocateTargetMemory()) return false;
    if (!MapSections()) return false;
    if (!ApplyRelocations()) return false;
    if (!ResolveImports()) return false;
    if (!FixSectionPermissions()) return false;
    if (!CallDllMain()) return false;

    std::cout << " MANUAL MAPPING TERMINÉ AVEC SUCCÈS!\n";
    std::cout << "DLL mappée à: 0x" << std::hex << mappedBaseAddress << std::dec << "\n";

    return true;
}