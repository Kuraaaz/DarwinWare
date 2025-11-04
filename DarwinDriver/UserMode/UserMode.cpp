#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include "driver_com.h"

void ListProcesses() {
    std::wcout << L"\n=== Liste des processus ===" << std::endl;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &processEntry)) {
        int count = 0;
        do {
            std::wcout << L"PID: " << processEntry.th32ProcessID << L" | " << processEntry.szExeFile << std::endl;
            count++;
        } while (Process32NextW(snapshot, &processEntry) && count < 30);
    }

    CloseHandle(snapshot);
}

DWORD FindProcessId(const std::wstring& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    DWORD foundPid = 0;
    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (_wcsicmp(processEntry.szExeFile, processName.c_str()) == 0) {
                foundPid = processEntry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return foundPid;
}

// Injection via shellcode LoadLibrary (plus stable)
bool InjectDLLSafe(DWORD pid, const std::wstring& dllPath) {
    comDriver::pid = pid;

    // 1. Allouer de la mémoire pour le chemin DLL
    size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    PVOID remotePath = nullptr;

    std::cout << "Allocation memoire pour le chemin DLL..." << std::endl;
    if (!comDriver::AllocateVirtualMemory(&remotePath, pathSize, PAGE_READWRITE)) {
        std::cerr << "Erreur: Echec allocation memoire" << std::endl;
        return false;
    }

    // 2. Écrire le chemin DLL
    std::wcout << L"Ecriture du chemin DLL..." << std::endl;
    if (!comDriver::WriteMemory(reinterpret_cast<uintptr_t>(dllPath.c_str()),
        reinterpret_cast<uintptr_t>(remotePath),
        pathSize)) {
        std::cerr << "Erreur: Echec ecriture chemin DLL" << std::endl;
        return false;
    }

    // 3. Obtenir kernel32 base
    std::wcout << L"Recherche de kernel32.dll..." << std::endl;
    ULONGLONG kernel32Base = comDriver::GetModuleBase(L"kernel32.dll");
    if (!kernel32Base) {
        std::cerr << "Erreur: Impossible de trouver kernel32.dll" << std::endl;
        return false;
    }

    std::cout << "Kernel32 base: 0x" << std::hex << kernel32Base << std::dec << std::endl;

    // 4. Pour l'instant, on va simplement tester les fonctions safe
    std::cout << "Test des fonctions de base reussi!" << std::endl;
    std::cout << "Le chemin DLL a ete ecrit a: 0x" << std::hex << remotePath << std::dec << std::endl;
    std::wcout << L"Chemin: " << dllPath << std::endl;

    std::cout << "\nATTENTION: La creation de thread est desactivee temporairement pour eviter les BSOD" << std::endl;
    std::cout << "Le driver doit etre corrige pour utiliser RtlCreateUserThread au lieu de PsCreateSystemThread" << std::endl;

    return true;
}

// Test des fonctions de base seulement
bool TestDriverFunctions(DWORD pid) {
    comDriver::pid = pid;

    std::cout << "\n=== Test des fonctions driver ===" << std::endl;

    // Test GetModuleBase
    std::wcout << L"Test GetModuleBase..." << std::endl;
    ULONGLONG kernelBase = comDriver::GetModuleBase(L"kernel32.dll");
    if (kernelBase) {
        std::cout << "SUCCES: kernel32.dll base = 0x" << std::hex << kernelBase << std::dec << std::endl;
    }
    else {
        std::cerr << "ECHEC: GetModuleBase" << std::endl;
        return false;
    }

    // Test AllocateVirtualMemory
    std::cout << "Test AllocateVirtualMemory..." << std::endl;
    PVOID testMem = nullptr;
    if (comDriver::AllocateVirtualMemory(&testMem, 4096, PAGE_READWRITE)) {
        std::cout << "SUCCES: Memoire allouee a 0x" << std::hex << testMem << std::dec << std::endl;
    }
    else {
        std::cerr << "ECHEC: AllocateVirtualMemory" << std::endl;
        return false;
    }

    // Test WriteMemory
    std::cout << "Test WriteMemory..." << std::endl;
    const char testData[] = "TEST";
    if (comDriver::WriteMemory(reinterpret_cast<uintptr_t>(testData),
        reinterpret_cast<uintptr_t>(testMem),
        sizeof(testData))) {
        std::cout << "SUCCES: WriteMemory" << std::endl;
    }
    else {
        std::cerr << "ECHEC: WriteMemory" << std::endl;
        return false;
    }

    // Test ReadMemory
    std::cout << "Test ReadMemory..." << std::endl;
    char readBuffer[sizeof(testData)] = { 0 };
    if (comDriver::ReadMemory(reinterpret_cast<uintptr_t>(testMem),
        reinterpret_cast<uintptr_t>(readBuffer),
        sizeof(readBuffer))) {
        std::cout << "SUCCES: ReadMemory - Donnees lues: " << readBuffer << std::endl;
    }
    else {
        std::cerr << "ECHEC: ReadMemory" << std::endl;
        return false;
    }

    // Test ProtectVirtualMemory
    std::cout << "Test ProtectVirtualMemory..." << std::endl;
    ULONG oldProtect;
    if (comDriver::ProtectVirtualMemory(testMem, 4096, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cout << "SUCCES: Protection modifiee" << std::endl;
    }
    else {
        std::cerr << "ECHEC: ProtectVirtualMemory" << std::endl;
        return false;
    }

    std::cout << "\n=== TOUS LES TESTS REUSSIS ===" << std::endl;
    return true;
}

int main() {
    std::wcout << L"=== Injecteur DLL (Version Safe) ===" << std::endl;

    if (!comDriver::InitDriver()) {
        std::cerr << "ERREUR: Impossible d'initialiser le driver" << std::endl;
        return 1;
    }

    std::cout << "Driver initialise avec succes" << std::endl;

    int choice;
    do {
        std::cout << "\n=== Menu Principal ===" << std::endl;
        std::cout << "1. Lister les processus" << std::endl;
        std::cout << "2. Preparer l'injection DLL (Safe)" << std::endl;
        std::cout << "3. Tester les fonctions du driver" << std::endl;
        std::cout << "0. Quitter" << std::endl;
        std::cout << "Choix: ";
        std::cin >> choice;

        switch (choice) {
        case 1: {
            ListProcesses();
            break;
        }

        case 2: {
            DWORD pid;
            std::wstring dllPath;

            std::cout << "PID du processus cible: ";
            std::cin >> pid;
            std::wcout << L"Chemin complet de la DLL: ";
            std::wcin >> dllPath;

            InjectDLLSafe(pid, dllPath);
            break;
        }

        case 3: {
            DWORD pid;
            std::cout << "PID pour les tests: ";
            std::cin >> pid;
            TestDriverFunctions(pid);
            break;
        }

        case 0:
            std::cout << "Au revoir!" << std::endl;
            break;

        default:
            std::cout << "Choix invalide!" << std::endl;
            break;
        }

        if (choice != 0) {
            std::cout << "\nAppuyez sur une touche pour continuer...";
            std::cin.ignore();
            std::cin.get();
        }
    } while (choice != 0);

    comDriver::CloseDriver();
    return 0;
}