#pragma once
#include "stdafx.h"


using Microsoft::WRL::ComPtr;

namespace d3d11hook {
    typedef long(__stdcall* PresentD3D11)(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags);
    PresentD3D11 oPresentD3D11 = nullptr;

    static ID3D11Device* gDevice = nullptr;
    static ID3D11DeviceContext* gContext = nullptr;
    static ID3D11RenderTargetView* gRenderTargetView = nullptr;
    static bool gInitialized = false;
    static bool gShutdown = false;
    DXGI_SWAP_CHAIN_DESC gDesc = {};

    // Utility to log HRESULTs
    inline void LogHRESULT(const char* label, HRESULT hr) {
        DebugLog("[d3d11hook] %s: hr=0x%08X\n", label, hr);
    }

    long __stdcall hookPresentD3D11(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags) {
        if (!gInitialized) {
            DebugLog("[d3d11hook] Initializing ImGui on first Present.\n");

            if (FAILED(pSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&gDevice))) {
                LogHRESULT("GetDevice", E_FAIL);
                return oPresentD3D11(pSwapChain, SyncInterval, Flags);
            }

            gDevice->GetImmediateContext(&gContext);

            pSwapChain->GetDesc(&gDesc);

            // Create Render Target
            ID3D11Texture2D* backBuffer = nullptr;
            if (FAILED(pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)&backBuffer))) {
                LogHRESULT("GetBuffer", E_FAIL);
                return oPresentD3D11(pSwapChain, SyncInterval, Flags);
            }

            if (FAILED(gDevice->CreateRenderTargetView(backBuffer, nullptr, &gRenderTargetView))) {
                LogHRESULT("CreateRenderTargetView", E_FAIL);
                backBuffer->Release();
                return oPresentD3D11(pSwapChain, SyncInterval, Flags);
            }
            backBuffer->Release();

            // ImGui setup
            ImGui::CreateContext();
            while (ShowCursor(FALSE) >= 0);
            while (ShowCursor(TRUE) < 0);

            
            

       
            ImGui::StyleColorsDark();
            ImGui_ImplWin32_Init(gDesc.OutputWindow);
            ImGui_ImplDX11_Init(gDevice, gContext);

            gInitialized = true;
            DebugLog("[d3d11hook] ImGui initialized.\n");
        }

        if (!gShutdown && gDevice && gContext && gRenderTargetView && gInitialized) {
            // Start new ImGui frame
            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();
            

            
            ImGui::Render();

            gContext->OMSetRenderTargets(1, &gRenderTargetView, nullptr);
            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        }

        return oPresentD3D11(pSwapChain, SyncInterval, Flags);
    }

    void release() {
        DebugLog("[d3d11hook] Releasing resources.\n");
        gShutdown = true;
        if (gRenderTargetView) gRenderTargetView->Release();
        if (gContext) gContext->Release();
        if (gDevice) gDevice->Release();

        // Unhook
        MH_DisableHook(MH_ALL_HOOKS);
        DebugLog("[d3d11hook] Hooks disabled.\n");
    }
}



namespace hooks {
    // Dummy objects pour extraire les v-tables
    static ComPtr<IDXGISwapChain>    pSwapChain = nullptr;
    static ComPtr<ID3D11Device>      pDevice = nullptr;
    static ComPtr<ID3D11DeviceContext> pContext = nullptr;
    static HWND                       hDummyWindow = nullptr;
    static const wchar_t* dummyClassName = L"DummyWndClass";

    // Create hidden Window + device + DX11 swapchain
    static HRESULT CreateDeviceAndSwapChain() {
        // 1) Register dummy window
        WNDCLASSEXW wc = { sizeof(WNDCLASSEXW), CS_CLASSDC, DefWindowProcW, 0, 0,
                           GetModuleHandleW(nullptr), nullptr, nullptr, nullptr, nullptr,
                           dummyClassName, nullptr };
        if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
            DebugLog("[hooks] RegisterClassExW failed: %u\n", GetLastError());
            return E_FAIL;
        }

        // 2) Create hidden window
        hDummyWindow = CreateWindowExW(0, dummyClassName, L"Dummy",
            WS_OVERLAPPEDWINDOW, 0, 0, 1, 1,
            nullptr, nullptr, wc.hInstance, nullptr);
        if (!hDummyWindow) {
            DebugLog("[hooks] CreateWindowExW failed: %u\n", GetLastError());
            return E_FAIL;
        }

        // 3) SwapChain description
        DXGI_SWAP_CHAIN_DESC scDesc = {};
        scDesc.BufferCount = 2;
        scDesc.BufferDesc.Width = 1;
        scDesc.BufferDesc.Height = 1;
        scDesc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        scDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        scDesc.OutputWindow = hDummyWindow;
        scDesc.SampleDesc.Count = 1;
        scDesc.SampleDesc.Quality = 0;
        scDesc.Windowed = TRUE;
        scDesc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

        // 4) Create device & swapchain
        D3D_FEATURE_LEVEL featureLevel;
        HRESULT hr = D3D11CreateDeviceAndSwapChain(
            nullptr,                        // Adapter
            D3D_DRIVER_TYPE_HARDWARE,
            nullptr,                        // Software
            0,                              // Flags
            nullptr, 0,                     // Feature levels
            D3D11_SDK_VERSION,
            &scDesc,
            &pSwapChain,
            &pDevice,
            &featureLevel,
            &pContext
        );
        if (FAILED(hr)) {
            DebugLog("[hooks] D3D11CreateDeviceAndSwapChain failed: 0x%08X\n", hr);
            return hr;
        }

        return S_OK;
    }

    void Init() {
        DebugLog("[hooks] Init starting\n");

        if (FAILED(CreateDeviceAndSwapChain())) {
            DebugLog("[hooks] Failed to create dummy device/swapchain.\n");
            return;
        }

        MH_STATUS mh;

        // --- Hook Present sur SwapChain (vTable index 8 pour DX11 aussi) ---
        auto scVTable = *reinterpret_cast<uintptr_t**>(pSwapChain.Get());
        mh = MH_CreateHook(
            reinterpret_cast<LPVOID>(scVTable[8]),
            reinterpret_cast<LPVOID>(d3d11hook::hookPresentD3D11),
            reinterpret_cast<LPVOID*>(&d3d11hook::oPresentD3D11)
        );
        if (mh != MH_OK)
            DebugLog("[hooks] MH_CreateHook Present failed: %s\n", MH_StatusToString(mh));

        // --- Enable hooks ---
        mh = MH_EnableHook(MH_ALL_HOOKS);
        if (mh != MH_OK)
            DebugLog("[hooks] MH_EnableHook failed: %s\n", MH_StatusToString(mh));
        else
            DebugLog("[hooks] Hooks enabled. Present@%p\n", reinterpret_cast<LPVOID>(scVTable[8]));
    }
}



