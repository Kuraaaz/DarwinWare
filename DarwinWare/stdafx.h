#pragma once
#pragma comment(lib, "libMinHook.x64.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3d11.lib")

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstdarg>

#include <dxgi1_4.h>
#include <d3d11.h>

#include <wrl/client.h>

#if defined _M_X64
typedef uint64_t uintx_t;
#elif defined _M_IX86
typedef uint32_t uintx_t;
#endif

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include "MinHook.h"


// Helper macro for debug logging via DebugView
inline void DebugLog(const char* fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    OutputDebugStringA(buf);
}
#pragma once
