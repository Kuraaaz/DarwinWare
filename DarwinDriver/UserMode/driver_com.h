#pragma once
#include "ioctl.h"

#include <string>
#include <iostream>
#include <cassert>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

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
    inline bool AllocateVirtualMemory(PVOID* address, SIZE_T size, ULONG allocationType = MEM_COMMIT | MEM_RESERVE, ULONG protect = PAGE_EXECUTE_READWRITE) {
        if (hDriver == nullptr || hDriver == INVALID_HANDLE_VALUE) {
            std::cerr << "AllocateVirtualMemory: driver handle invalide\n";
            return false;
        }
        if (size == 0) {
            std::cerr << "AllocateVirtualMemory: taille nulle\n";
            return false;
        }

        KAllocMemRequest req{};
        req.pid = pid;
        req.addr = reinterpret_cast<ULONGLONG>(*address);
        req.size = size;
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

        *address = reinterpret_cast<PVOID>(req.addr);
        return true;
    }

    inline bool ProtectVirtualMemory(PVOID address, SIZE_T size, ULONG newProtect, ULONG* oldProtect = nullptr) {
        if (hDriver == nullptr || hDriver == INVALID_HANDLE_VALUE) {
            std::cerr << "ProtectVirtualMemory: driver handle invalide\n";
            return false;
        }
        if (size == 0) {
            std::cerr << "ProtectVirtualMemory: taille nulle\n";
            return false;
        }

        KProtectMemRequest req{};
        req.pid = pid;
        req.addr = reinterpret_cast<ULONGLONG>(address);
        req.size = size;
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

        if (oldProtect != nullptr) {
            *oldProtect = req.protect;
        }
        return true;
    }

    inline bool WriteShellcode(uintptr_t source, uintptr_t destination, uintptr_t size) {
        if (hDriver == nullptr || hDriver == INVALID_HANDLE_VALUE) {
            std::cerr << "WriteShellcode: driver handle invalide\n";
            return false;
        }
        if (size == 0) {
            std::cerr << "WriteShellcode: taille nulle\n";
            return false;
        }

        KRwRequest req{};
        req.pid = pid;
        req.src = static_cast<ULONGLONG>(source);
        req.dst = static_cast<ULONGLONG>(destination);
        req.size = static_cast<ULONGLONG>(size);

        NTSTATUS status = 0;
        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDriver,
            ioctl_write_shellcode,
            &req,
            static_cast<DWORD>(sizeof(req)),
            &status,
            static_cast<DWORD>(sizeof(status)),
            &bytesReturned,
            nullptr
        );

        if (!ok) {
            DWORD err = GetLastError();
            std::cerr << "DeviceIoControl(IOCTL_WriteShellcode) failed. GetLastError() = " << err << "\n";
            return false;
        }

        if (!NT_SUCCESS(status)) {
            std::cerr << "WriteShellcode: kernel operation failed. NTSTATUS = 0x" << std::hex << status << std::dec << "\n";
            return false;
        }

        return true;
    }

    inline bool CreateThread(ULONGLONG startAddress) {
        if (hDriver == nullptr || hDriver == INVALID_HANDLE_VALUE) {
            std::cerr << "CreateThread: driver handle invalide\n";
            return false;
        }
        if (startAddress == 0) {
            std::cerr << "CreateThread: adresse de départ nulle\n";
            return false;
        }

        KCreateThreadRequest req{};
        req.pid = pid;
        req.start_address = startAddress;

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
};