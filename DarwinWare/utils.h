#pragma once
#pragma once
#include <iostream>
#include <string>
#include <windows.h>
#include <iomanip> 
     
#include <d3d11.h>          
#include <dxgi.h>     

namespace utils
{
	class Console {
	public:
		static inline std::string consoleTitle = "Niggaware";


		static inline void initConsole()
		{
			FreeConsole();

			AllocConsole();

			FILE* f;
			freopen_s(&f, "CONIN$", "r", stdin);
			freopen_s(&f, "CONOUT$", "w", stdout);
			freopen_s(&f, "CONOUT$", "w", stderr);

			SetConsoleTitleA(consoleTitle.c_str());

			HWND hConsole = GetConsoleWindow();
			if (hConsole)
			{
				ShowWindow(hConsole, SW_SHOW);
				ShowWindow(hConsole, SW_MINIMIZE);
			}
		}

		static inline void closeConsole()
		{
			fclose(stdin);
			fclose(stdout);
			fclose(stderr);
			FreeConsole();
		}

		static inline void Clear()
		{
			HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
			if (hConsole == INVALID_HANDLE_VALUE) return;

			CONSOLE_SCREEN_BUFFER_INFO csbi;
			DWORD written;
			COORD topLeft = { 0, 0 };

			if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) return;

			DWORD consoleSize = csbi.dwSize.X * csbi.dwSize.Y;

			FillConsoleOutputCharacter(hConsole, ' ', consoleSize, topLeft, &written);
			FillConsoleOutputAttribute(hConsole, csbi.wAttributes, consoleSize, topLeft, &written);
			SetConsoleCursorPosition(hConsole, topLeft);
		}

		static inline void log(std::string message)
		{
			std::cout << "[+] " << message << std::endl;
		}

		static inline void logError(std::string message)
		{
			std::cout << "[-] " << message << std::endl;
		}

		static inline void logAddress(std::string addressName, uintptr_t address)
		{
			std::cout << "[+] " << addressName << " address: 0x" << std::hex << std::showbase << address << std::endl;
		}

	private:
		static FILE* outStream;
	};

	class Setup {
	public:
		static inline HMODULE gModule = nullptr;

		static inline void CleanupAndShutdown()
		{
			Console::closeConsole();
			if (gModule)
				FreeLibraryAndExitThread(gModule, 0);
		}
	};
}


namespace globals {
    extern HMODULE mainModule;
	extern HWND mainWindow;
	extern int uninjectKey;
	extern int openMenuKey;
}

namespace hooks {
	extern void Init();
}

namespace inputhook {
	extern void Init(HWND hWindow);
	extern void Remove(HWND hWindow);
	static LRESULT APIENTRY WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
}

namespace d3d11hook {
	// Typedef pour Present DX11
	typedef long(__stdcall* PresentD3D11)(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags);
	extern PresentD3D11 oPresentD3D11;

	// Hook Present
	extern long __stdcall hookPresentD3D11(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags);

	// Release / cleanup resources
	extern void release();
}

