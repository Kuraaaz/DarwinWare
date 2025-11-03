#include "stdafx.h"
#include "utils.h"
#include "features.h"
#include <thread>

namespace globals {
    HMODULE mainModule;     
    HWND mainWindow;       
    int uninjectKey;
    int openMenuKey;
}



static DWORD WINAPI onAttach(LPVOID lpParameter)
{
    DebugLog("[DllMain] onAttach starting.\n");

    utils::Console::initConsole();

    {
        MH_STATUS mhStatus = MH_Initialize();
        if (mhStatus != MH_OK) {
            DebugLog("[DllMain] MinHook initialization failed: %s\n",
                MH_StatusToString(mhStatus));
            return 1;
        }
        DebugLog("[DllMain] MinHook initialized.\n");
    }


    if (!cheat::Cheat::InitCheat()) {
        utils::Setup::CleanupAndShutdown();
        return 0;
    }

    hooks::Init();

    DebugLog("[DllMain] hooks::Init completed.\n");

    return 0;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DebugLog("[DllMain] DLL_PROCESS_ATTACH: hModule=%p\n", hModule);
        globals::mainModule = hModule;
        {
            HANDLE thread = CreateThread(
                nullptr, 0,
                onAttach,
                nullptr,
                0,
                nullptr
            );
            if (thread) CloseHandle(thread);
            else DebugLog("[DllMain] Failed to create hook thread: %d\n", GetLastError());
        }
        break;

    case DLL_PROCESS_DETACH:
        DebugLog("[DllMain] DLL_PROCESS_DETACH. Uninitializing hooks.\n");
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        break;
    }
    return TRUE;
}
