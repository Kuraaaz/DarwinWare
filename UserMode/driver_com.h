#pragma once
#include "ioctl.h"

#include <string>
#include <iostream>
#include <cassert>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

// Définition de quelques statuts NTSTATUS communs si non définis
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

namespace comDriver {

    inline ULONG pid;
    inline HANDLE hDriver;
    inline const wchar_t* driverName = L"\\\\.\\{XorExt}";

    inline bool InitDriver() {
        hDriver = CreateFileW(driverName, 0xC0000000, 3, nullptr, 3, 0, nullptr);
        if (comDriver::hDriver == INVALID_HANDLE_VALUE) {
            std::wcout << L"CreateFileW failed, err = " << GetLastError() << std::endl;
        }
        return hDriver != INVALID_HANDLE_VALUE;
    };

    inline bool CloseDriver() {
        if (hDriver && hDriver != INVALID_HANDLE_VALUE) {
            CloseHandle(hDriver);
            hDriver = nullptr;
            return true;
        }
        return false;
    };

    inline bool ReadMemory(uintptr_t source, uintptr_t destination, uintptr_t size) {
        if (hDriver == nullptr || hDriver == INVALID_HANDLE_VALUE) {
            std::cerr << "ReadMemory: driver handle invalide\n";
            return false;
        }

        if (size == 0) {
            std::cerr << "ReadMemory: taille nulle\n";
            return false;
        }

        KRwRequest req{};
        req.pid = pid;
        req.src = static_cast<ULONGLONG>(source);
        req.dst = static_cast<ULONGLONG>(destination);
        req.size = static_cast<ULONGLONG>(size);

        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDriver,
            ioctl_read_memory,
            &req,
            static_cast<DWORD>(sizeof(req)),
            nullptr,
            0,
            &bytesReturned,
            nullptr
        );

        if (!ok) {
            DWORD err = GetLastError();
            std::cerr << "DeviceIoControl(IOCTL_ReadMemory) failed. GetLastError() = " << err << "\n";
            return false;
        }

        return true;
    }

    inline bool WriteMemory(uintptr_t source, uintptr_t destination, uintptr_t size) {
        if (hDriver == nullptr || hDriver == INVALID_HANDLE_VALUE) {
            std::cerr << "WriteMemory: driver handle invalide\n";
            return false;
        }

        if (size == 0) {
            std::cerr << "WriteMemory: taille nulle\n";
            return false;
        }

        KRwRequest req{};
        req.pid = pid;
        req.src = static_cast<ULONGLONG>(source);
        req.dst = static_cast<ULONGLONG>(destination);
        req.size = static_cast<ULONGLONG>(size);

        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDriver,
            ioctl_write_memory,
            &req,
            static_cast<DWORD>(sizeof(req)),
            nullptr,
            0,
            &bytesReturned,
            nullptr
        );

        if (!ok) {
            DWORD err = GetLastError();
            std::cerr << "DeviceIoControl(IOCTL_WriteMemory) failed. GetLastError() = " << err << "\n";
            return false;
        }

        return true;
    }

    inline ULONGLONG GetModuleBase(const std::wstring& moduleName) {
        if (hDriver == nullptr || hDriver == INVALID_HANDLE_VALUE) {
            std::cerr << "GetModuleBase: driver handle invalide\n";
            return 0;
        }

        KGetBaseModuleRequest req{};
        req.pid = pid;
        req.handle = 0;

        if (!moduleName.empty()) {
            wcsncpy_s(req.name, moduleName.c_str(), _TRUNCATE);
        }
        else {
            req.name[0] = L'\0';
        }

        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(hDriver, ioctl_get_module_base, &req, static_cast<DWORD>(sizeof(req)), &req, static_cast<DWORD>(sizeof(req)), &bytesReturned, nullptr);

        if (!ok) {
            DWORD err = GetLastError();
            std::cerr << "DeviceIoControl(IOCTL_GetModuleBase) failed. GetLastError() = " << err << "\n";
            return 0;
        }

        return req.handle;
    }

    // Nouvelle fonction pour allouer de la mémoire virtuelle
    inline bool AllocateVirtualMemory(uintptr_t* address, size_t* size, ULONG allocationType, ULONG protect) {
        if (hDriver == nullptr || hDriver == INVALID_HANDLE_VALUE) {
            std::cerr << "AllocateVirtualMemory: driver handle invalide\n";
            return false;
        }

        KAllocMemRequest req{};
        req.pid = pid;
        // Convertir l'adresse initiale en PVOID (si address est non nul, sinon nullptr)
        req.addr = (address != nullptr) ? static_cast<ULONGLONG>(*address) : 0ULL;
        req.size = static_cast<ULONGLONG>(*size);
        req.allocation_type = allocationType;
        req.protect = protect;

        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDriver,
            ioctl_allocate_virtual_memory,
            &req,
            static_cast<DWORD>(sizeof(req)),
            &req,
            static_cast<DWORD>(sizeof(req)),
            &bytesReturned,
            nullptr
        );
       

        if (!ok) {
            DWORD err = GetLastError();
            std::cerr << "DeviceIoControl(IOCTL_AllocateVirtualMemory) failed. GetLastError() = " << err << "\n";
            return false;
        }

        // Mettre à jour l'adresse et la taille
        if (address) *address = static_cast<uintptr_t>(req.addr);
        *size = req.size;
        return true;
    }

    // Nouvelle fonction pour protéger la mémoire virtuelle
    inline bool ProtectVirtualMemory(uintptr_t address, size_t size, ULONG newProtect, ULONG* oldProtect) {
        if (hDriver == nullptr || hDriver == INVALID_HANDLE_VALUE) {
            std::cerr << "ProtectVirtualMemory: driver handle invalide\n";
            return false;
        }

        KProtectMemRequest req{};
        req.pid = pid;
        req.addr = static_cast<ULONGLONG>(address);
        req.size = static_cast<ULONGLONG>(size);
        req.protect = newProtect;

        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDriver,
            ioctl_protect_virutal_memory,
            &req,
            static_cast<DWORD>(sizeof(req)),
            &req,
            static_cast<DWORD>(sizeof(req)),
            &bytesReturned,
            nullptr
        );

        if (!ok) {
            DWORD err = GetLastError();
            std::cerr << "DeviceIoControl(IOCTL_ProtectVirtualMemory) failed. GetLastError() = " << err << "\n";
            return false;
        }

        if (oldProtect) *oldProtect = req.protect;
        return true;
    }

    // Nouvelle fonction pour écrire du shellcode avec retour de statut détaillé
    inline bool WriteShellcode(uintptr_t source, uintptr_t destination, uintptr_t size) {
        if (hDriver == nullptr || hDriver == INVALID_HANDLE_VALUE) {
            std::cerr << "WriteShellcode: driver handle invalide\n";
            return false;
        }

        KRwRequest req{};
        req.pid = pid;
        req.src = static_cast<ULONGLONG>(source);
        req.dst = static_cast<ULONGLONG>(destination);
        req.size = static_cast<ULONGLONG>(size);

        NTSTATUS status = STATUS_UNSUCCESSFUL;
        DWORD bytesReturned = 0;

        BOOL ok = DeviceIoControl(
            hDriver,
            ioctl_write_shellcode,
            &req,
            static_cast<DWORD>(sizeof(req)),
            &status,
            sizeof(status),
            &bytesReturned,
            nullptr
        );

        if (!ok) {
            DWORD err = GetLastError();
            std::cerr << "DeviceIoControl(IOCTL_WriteShellcode) failed. GetLastError() = " << err << "\n";
            return false;
        }

        // Vérifier le statut renvoyé par le driver
        if (status != STATUS_SUCCESS) {
            std::cerr << "WriteShellcode: operation failed with status 0x" << std::hex << status << std::dec << "\n";
            return false;
        }

        return true;
    }

    inline bool CreateThread(uintptr_t startAddress, uintptr_t parameter = 0) {
        if (hDriver == nullptr || hDriver == INVALID_HANDLE_VALUE) {
            std::cerr << "CreateRemoteThread: driver handle invalide\n";
            return false;
        }

        KCreateThreadRequest req{};
        req.pid = pid;
        req.start_address = static_cast<ULONGLONG>(startAddress);
        req.parameter = static_cast<ULONGLONG>(parameter);

        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDriver,
            ioctl_create_thread,
            &req,
            static_cast<DWORD>(sizeof(req)),
            nullptr,
            0,
            &bytesReturned,
            nullptr
        );

        if (!ok) {
            DWORD err = GetLastError();
            std::cerr << "DeviceIoControl(IOCTL_CreateThread) failed. GetLastError() = " << err << "\n";
            return false;
        }

        return true;
    }
    inline bool FindThread(HANDLE* threadId) {
        if (hDriver == nullptr || hDriver == INVALID_HANDLE_VALUE) {
            std::cerr << "? FindThread: driver handle invalide\n";
            return false;
        }

        std::cout << "[DEBUG] FindThread - PID: " << pid << "\n";
        std::cout << "[DEBUG] Preparation de la requete...\n";

        KFindThreadRequest req{};
        req.pid = pid;
        req.thread_id = NULL;

        DWORD bytesReturned = 0;

        std::cout << "[DEBUG] Appel DeviceIoControl...\n";
        BOOL ok = DeviceIoControl(
            hDriver,
            ioctl_find_thread,
            &req,
            static_cast<DWORD>(sizeof(req)),
            &req,
            static_cast<DWORD>(sizeof(req)),
            &bytesReturned,
            nullptr
        );

        std::cout << "[DEBUG] DeviceIoControl retour: " << (ok ? "SUCCES" : "ECHEC") << "\n";
        std::cout << "[DEBUG] Bytes retournes: " << bytesReturned << "\n";
        std::cout << "[DEBUG] Thread ID recu: 0x" << std::hex << req.thread_id << std::dec << "\n";

        if (!ok) {
            DWORD err = GetLastError();
            std::cerr << "? DeviceIoControl(IOCTL_FIND_THREAD) failed. GetLastError() = " << err << "\n";

            // Messages d'erreur détaillés
            switch (err) {
            case ERROR_INVALID_HANDLE:
                std::cerr << "   ? Le handle du driver est invalide\n";
                break;
            case ERROR_INVALID_PARAMETER:
                std::cerr << "   ? Paramètres invalides dans la requête\n";
                break;
            case ERROR_NOT_FOUND:
                std::cerr << "   ? Aucun thread trouvé (driver retour)\n";
                break;
            case ERROR_ACCESS_DENIED:
                std::cerr << "   ? Accès refusé par le driver\n";
                break;
            default:
                std::cerr << "   ? Erreur système: " << err << "\n";
                break;
            }
            return false;
        }

        if (threadId) {
            *threadId = req.thread_id;
        }

        bool success = (req.thread_id != NULL);
        std::cout << "[DEBUG] FindThread result: " << (success ? "THREAD_TROUVE" : "AUCUN_THREAD") << "\n";

        return success;
    }

    

    
    

    
    

   
};