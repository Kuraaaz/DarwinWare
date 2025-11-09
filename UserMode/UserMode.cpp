#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <thread>
#include <chrono>
#include "manual_mapper.hpp"
#include "driver_com.h"

// Fonction pour trouver le PID du processus
DWORD FindProcessPID(const std::wstring& processName = L"Darwin-Win64-Shipping.exe") {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                if (wcscmp(processEntry.szExeFile, processName.c_str()) == 0) {
                    pid = processEntry.th32ProcessID;
                    std::wcout << L" Process found: " << processEntry.szExeFile << L" (PID=" << pid << L")\n";
                    break;
                }
            } while (Process32NextW(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }

    if (pid == 0) {
        std::wcout << L" Process " << processName << L" not found\n";
    }

    return pid;
}

// Fonction pour lancer le jeu
bool LaunchGame() {
    std::wcout << L" trying to load the game\n";

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (CreateProcessW(
        LR"(C:\Program Files (x86)\Steam\steamapps\common\Darwin Project\Darwin.exe)",
        nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {

        std::wcout << L" game started with PID: " << pi.dwProcessId << L"\n";

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        // Attendre que le jeu se charge
        std::wcout << L" waiting for game loading (10 secondes)...\n";
        std::this_thread::sleep_for(std::chrono::seconds(10));

        return true;
    }
    else {
        DWORD err = GetLastError();
        std::wcout << L" loading error: " << err << L"\n";
        return false;
    }
}

// Attendre que le module principal soit chargé
void WaitForGameModule(DWORD pid, const std::wstring& moduleName = L"Darwin-Win64-Shipping.exe") {
    std::wcout << L" waiting for module " << moduleName << L"...\n";

    ULONGLONG base = 0;
    int waitTime = 0;
    int maxWaitTime = 40000; // 30 secondes max

    while (base == 0 && waitTime < maxWaitTime) {
        base = comDriver::GetModuleBase(moduleName.c_str());
        if (base == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            waitTime += 1000;
            std::wcout << L" waiting (" << (waitTime / 1000) << "s)...\n";
        }
    }

    if (base != 0) {
        std::wcout << L"Module loaded: 0x" << std::hex << base << std::dec << L"\n";
    }
    else {
        std::wcout << L" Timeout: module not loaded yet after " << (maxWaitTime / 1000) << L" secondes\n";
    }
}

// Fonction pour injecter une DLL avec le manual mapper
void InjectDLLWithMapper() {
    std::wstring dllPath;
    std::wcout << L"\n Enter complete path of the dll: ";
    std::wcin.ignore(); // Nettoyer le buffer
    std::getline(std::wcin, dllPath);

    // Vérifier si le fichier existe
    DWORD fileAttributes = GetFileAttributesW(dllPath.c_str());
    if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
        std::wcout << L" File not found please check the path: " << dllPath << L"\n";
        return;
    }

    ManualMapper::Mapper mapper;

    std::wcout << L" manual mapping start...\n";
    auto startTime = std::chrono::high_resolution_clock::now();

    if (mapper.MapDLLToProcess(dllPath)) {
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

        std::cout << " Manual mapping successful in " << duration.count() << "ms!\n";
        std::cout << " Base adress: 0x" << std::hex << mapper.GetMappedBaseAddress() << std::dec << "\n";

        // Afficher les infos PE détaillées
        auto peInfo = mapper.GetPEInfo();
        std::cout << "\n INFORMATIONS DE LA DLL MAPPÉE:\n";
        std::cout << "   - Architecture: " << (peInfo.is64Bit ? "64-bit" : "32-bit") << "\n";
        std::cout << "   - Entry Point: 0x" << std::hex << peInfo.entryPoint << std::dec << "\n";
        std::cout << "   - Entry Point Final: 0x" << std::hex << (mapper.GetMappedBaseAddress() + peInfo.entryPoint) << std::dec << "\n";
        std::cout << "   - Taille Image: 0x" << std::hex << peInfo.sizeOfImage << std::dec << " bytes\n";
        std::cout << "   - Sections: " << peInfo.sections.size() << "\n";
        std::cout << "   - DLLs Importées: " << peInfo.imports.size() << "\n";

        // Afficher les sections
        std::cout << "\n SECTIONS MAPPÉES:\n";
        for (const auto& section : peInfo.sections) {
            std::cout << "   - " << section.name << " @ 0x" << std::hex
                << (mapper.GetMappedBaseAddress() + section.virtualAddress)
                << " (0x" << section.rawDataSize << " bytes)" << std::dec << "\n";
        }

        std::cout << "\n The DLL is officially mapped in the process' memory .\n";
        std::cout << "   in order to execute it you will need to execute the entrypoint adress.\n";

    }
    else {
        std::cout << " Manual mapping échoué!\n";
        std::cout << "   Vérifiez que:\n";
        std::cout << "   - Le driver est bien chargé\n";
        std::cout << "   - Vous avez les privilèges admin\n";
        std::cout << "   - La DLL est valide (PE 64-bit)\n";
    }
}
void TestFindThread() {
    std::cout << "\n TEST DE RECHERCHE DE THREAD\n";

    HANDLE threadId = NULL;
    std::cout << "Recherche d'un thread dans le processus PID: " << comDriver::pid << "... ";

    if (comDriver::FindThread(&threadId)) {
        std::cout << "SUCCÈS!\n";
        std::cout << "Thread ID trouvé: 0x" << std::hex << threadId << std::dec << "\n";
        std::cout << "Ce thread peut être utilisé pour hijack.\n";
    }
    else {
        std::cout << "ÉCHEC\n";
        std::cout << "Aucun thread trouvé dans le processus.\n";
        std::cout << "Vérifiez que le processus est bien en cours d'exécution.\n";
    }
}


// Fonction pour tester les fonctions de base du driver
void TestDriverFunctions() {
    std::cout << "\n TEST DES FONCTIONS DU DRIVER\n";

    // Test lecture mémoire
    ULONGLONG base = comDriver::GetModuleBase(L"Darwin-Win64-Shipping.exe");
    if (base != 0) {
        std::cout << " GetModuleBase OK - Base: 0x" << std::hex << base << std::dec << "\n";
    }
    else {
        std::cout << " GetModuleBase échoué\n";
    }

    // Test allocation mémoire
    uintptr_t testAddr = 0;
    size_t testSize = 0x1000;
    std::cout << "Test allocation 0x1000 bytes... ";
    if (comDriver::AllocateVirtualMemory(&testAddr, &testSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
        std::cout << " SUCCES à 0x" << std::hex << testAddr << std::dec << "\n";

        // Test écriture
        char testData[] = "TEST";
        if (comDriver::WriteMemory(reinterpret_cast<uintptr_t>(testData), testAddr, sizeof(testData))) {
            std::cout << " WriteMemory OK\n";
        }
        else {
            std::cout << " WriteMemory échoué\n";
        }

        // Test lecture
        char readBuffer[5] = { 0 };
        if (comDriver::ReadMemory(testAddr, reinterpret_cast<uintptr_t>(readBuffer), sizeof(readBuffer))) {
            std::cout << " ReadMemory OK - Données: " << readBuffer << "\n";
        }
        else {
            std::cout << " ReadMemory échoué\n";
        }
    }
    else {
        DWORD err = GetLastError();
        std::cout << " ECHEC (Error: " << err << ")\n";
    }
}

// NOUVELLE FONCTION : Tester la création de thread
void TestThreadCreation() {
    std::cout << "\n TEST DE CRÉATION DE THREAD\n";

    // Allouer une petite mémoire pour un shellcode simple (ret instruction)
    uintptr_t shellcodeAddr = 0;
    size_t shellcodeSize = 0x1000;

    std::cout << "Allocation mémoire pour shellcode test... ";
    if (comDriver::AllocateVirtualMemory(&shellcodeAddr, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) {
        std::cout << "SUCCÈS à 0x" << std::hex << shellcodeAddr << std::dec << "\n";

        // Écrire un shellcode simple qui fait juste "ret" (0xC3 en x64)
        unsigned char retShellcode[] = { 0x48, 0x83, 0xEC, 0x28,                   // sub rsp, 0x28
    0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0x7F, // mov rcx, 0x7FFFFFFF (INFINITE)
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, &Sleep
    0xFF, 0xD0,                               // call rax
    0xEB, 0xEE }; // instruction RET
        if (comDriver::WriteMemory(reinterpret_cast<uintptr_t>(retShellcode), shellcodeAddr, sizeof(retShellcode))) {
            std::cout << "Shellcode RET écrit en mémoire\n";

            std::cout << "Création du thread sur l'adresse 0x" << std::hex << shellcodeAddr << std::dec << "... ";
            if (comDriver::CreateThread(shellcodeAddr)) {
                std::cout << "SUCCÈS!\n";
                std::cout << "Thread créé avec succès - le shellcode RET a été exécuté\n";
            }
            else {
                std::cout << "ÉCHEC\n";
                std::cout << "La création du thread a échoué\n";
            }
        }
        else {
            std::cout << "Échec de l'écriture du shellcode\n";
        }
    }
    else {
        std::cout << "ÉCHEC\n";
        std::cout << "Impossible d'allouer la mémoire pour le test\n";
    }
}

// NOUVELLE FONCTION : Tester la recherche de thread


// Menu principal
void PrintMenu() {
    std::cout << "\n";
    std::cout << "=========================================\n";
    std::cout << "  MANUAL MAPPER TOOL - DUMPER7\n";
    std::cout << "=========================================\n";
    std::cout << "1.  Automatically find process\n";
    std::cout << "2.  Automatically start game\n";
    std::cout << "3.  Inject DLL (Manual Map)\n";
    std::cout << "4.  Test driver's functions (debug) \n";
    std::cout << "5.  Test thread creation\n";
    std::cout << "6.  Test find thread\n";  // NOUVELLE OPTION
    std::cout << "7.  Leave\n";  // Changé de 6 à 7
    std::cout << "=========================================\n";
    std::cout << "Choice: ";
}

// Option 1: Trouver et préparer
void FindAndPrepare() {
    std::cout << "\n Recherche du processus...\n";

    DWORD pid = FindProcessPID();
    if (pid == 0) {
        std::cout << " Processus non trouvé. Voulez-vous le lancer? (o/n): ";
        char choice;
        std::cin >> choice;

        if (choice == 'o' || choice == 'O') {
            if (LaunchGame()) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                pid = FindProcessPID();
            }
        }

        if (pid == 0) {
            std::cout << " Aucun processus cible disponible.\n";
            return;
        }
    }

    comDriver::pid = pid;
    std::cout << " PID cible défini: " << pid << "\n";

    // Attendre que le module soit chargé
    WaitForGameModule(pid);

    std::cout << "\n Prêt pour l'injection!\n";
}

// Option 2: Lancer et préparer
void LaunchAndPrepare() {
    std::cout << "\n Lancement du jeu...\n";

    if (LaunchGame()) {
        // Attendre un peu puis trouver le PID
        std::this_thread::sleep_for(std::chrono::seconds(2));

        DWORD pid = FindProcessPID();
        if (pid != 0) {
            comDriver::pid = pid;
            std::cout << " PID cible défini: " << pid << "\n";

            WaitForGameModule(pid);

            std::cout << "\n Prêt pour l'injection!\n";
        }
        else {
            std::cout << " Impossible de trouver le PID après le lancement.\n";
        }
    }
}

int main() {
    std::cout << "  Initialisation du Manual Mapper Tool...\n";

    // Vérifier les privilèges admin
    BOOL isAdmin = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }

    if (!isAdmin) {
        std::cout << "  ATTENTION: L'application n'est pas exécutée en administrateur!\n";
        std::cout << "   Certaines fonctionnalités peuvent ne pas fonctionner.\n";
        std::cout << "   Relancez en tant qu'administrateur pour de meilleurs résultats.\n";
    }
    else {
        std::cout << " Privilèges administrateur confirmés.\n";
    }

    // Initialiser le driver
    std::cout << "\n Initialisation du driver... ";
    if (!comDriver::InitDriver()) {
        std::cout << " ÉCHEC\n";
        std::cout << "   Assurez-vous que:\n";
        std::cout << "   - Le driver est chargé (sc create + sc start)\n";
        std::cout << "   - Le service est en cours d'exécution\n";
        std::cout << "   - Le nom du device est correct\n";
    }
    else {
        std::cout << " SUCCÈS\n";
    }

    // Menu principal
    int choice = 0;
    while (choice != 7) {  // Changé de 6 à 7
        PrintMenu();
        std::cin >> choice;

        switch (choice) {
        case 1:
            FindAndPrepare();
            break;
        case 2:
            LaunchAndPrepare();
            break;
        case 3:
            if (comDriver::hDriver && comDriver::hDriver != INVALID_HANDLE_VALUE && comDriver::pid != 0) {
                InjectDLLWithMapper();
            }
            else {
                std::cout << " Driver non initialisé ou PID non défini!\n";
                std::cout << "   Utilisez d'abord l'option 1 ou 2.\n";
            }
            break;
        case 4:
            if (comDriver::hDriver && comDriver::hDriver != INVALID_HANDLE_VALUE) {
                TestDriverFunctions();
            }
            else {
                std::cout << " Driver non initialisé!\n";
            }
            break;
        case 5:  // Test thread creation
            if (comDriver::hDriver && comDriver::hDriver != INVALID_HANDLE_VALUE && comDriver::pid != 0) {
                TestThreadCreation();
            }
            else {
                std::cout << " Driver non initialisé ou PID non défini!\n";
                std::cout << "   Utilisez d'abord l'option 1 ou 2.\n";
            }
        case 6:  // NOUVELLE OPTION : Test find thread
            if (comDriver::hDriver && comDriver::hDriver != INVALID_HANDLE_VALUE && comDriver::pid != 0) {
                TestFindThread();
            }
            else {
                std::cout << " Driver non initialisé ou PID non défini!\n";
                std::cout << "   Utilisez d'abord l'option 1 ou 2.\n";
            }
            break;
        
            
        case 7:  // Changé de 6 à 7
            std::cout << " Au revoir!\n";
            break;
        default:
            std::cout << " Choix invalide!\n";
            break;
        }

        if (choice != 6) {  // Changé de 6 à 7
            std::cout << "\nAppuyez sur Entrée pour continuer...";
            std::cin.ignore();
            std::cin.get();
        }
    }

    // Nettoyage
    if (comDriver::hDriver && comDriver::hDriver != INVALID_HANDLE_VALUE) {
        comDriver::CloseDriver();
        std::cout << " Driver fermé.\n";
    }

    std::cout << " Fermeture de l'application.\n";
    return 0;
}