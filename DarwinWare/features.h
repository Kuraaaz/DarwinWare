#pragma once

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"
#include <fstream>
#include <sstream>
#include <unordered_set>
#define PI 3.14159265358979323846




namespace cheat {
    class Cheat {
    public:
        static bool InitCheat();
        static void RefreshCheat();
    };
    
}

    
    


