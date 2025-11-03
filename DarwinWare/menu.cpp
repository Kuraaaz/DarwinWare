#include "menu.h"

namespace menu {
    bool isOpen = false;
    bool noTitleBar = false;

    bool intro = true;
    float intro_timer = 0.f;
    const float intro_duration = 4.f;
    ImFont* intro_font = nullptr;


    void DrawMenu() {

        if (!isOpen) return;

        static float current_applied_scale = 1.0f;
        float textWidth = ImGui::CalcTextSize("DarwinWare").x;
        static int current_tab = 0;
        static bool styled = false;



       

        if (!styled) {
            ImGuiStyle& style = ImGui::GetStyle();
            style.Alpha = 0.978f;
            style.WindowPadding = ImVec2(12, 12);
            style.FramePadding = ImVec2(8, 6);
            style.ItemSpacing = ImVec2(10, 8);
            style.WindowRounding = 20.0f;
            style.FrameRounding = 10.0f;
            style.PopupRounding = 8.0f;
            style.IndentSpacing = 15.0f;
            style.ScrollbarSize = 14.0f;
            style.GrabRounding = 7.0f;

            ImVec4* colors = style.Colors;

            colors[ImGuiCol_Text] = ImVec4(0.95f, 0.96f, 0.98f, 1.00f);
            colors[ImGuiCol_WindowBg] = ImVec4(0.07f, 0.08f, 0.09f, 1.00f);
            colors[ImGuiCol_FrameBg] = ImVec4(frameStatic);
            colors[ImGuiCol_FrameBgHovered] = ImVec4(frameHovered);
            colors[ImGuiCol_FrameBgActive] = ImVec4(frameActive);
            colors[ImGuiCol_TitleBg] = ImVec4(0.05f, 0.05f, 0.05f, 1.00f);
            colors[ImGuiCol_TitleBgActive] = ImVec4(0.05f, 0.05f, 0.05f, 1.00f);
            colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.05f, 0.05f, 0.05f, 1.00f);
            colors[ImGuiCol_Button] = featurescolors::generalcolor;
            
          
            colors[ImGuiCol_CheckMark] = featurescolors::generalcolor;
            colors[ImGuiCol_PopupBg] = ImVec4(0.10f, 0.10f, 0.12f, 1.00f);
            colors[ImGuiCol_Header] = featurescolors::generalcolor;
            
          

            styled = true;
        }


        ImGuiWindowFlags flags = ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar;

        ImVec2 base_size(1080, 600);
        //ImVec2 scaled_size = ImVec2(base_size.x * features::menu_scale_factor, base_size.y * features::menu_scale_factor);
        //ImGui::SetNextWindowSize(scaled_size, ImGuiCond_Always);

        const char* tabs[] = {
            "Players", "View", "Weapon",
            "Server", "Misc", "Settings" };

        ImGui::Begin("Banana Mega Hack", &isOpen, flags);

        float windowWidth = ImGui::GetWindowSize().x;
        ImGui::SetCursorPosX((windowWidth - textWidth) * 0.5f);
        ImGui::Text("Banana Mega Hack");

        /*if (memcmp(&lastColor, &featurescolors::generalcolor, sizeof(ImVec4)) != 0)
        {
            ImVec4* colors = ImGui::GetStyle().Colors;
            colors[ImGuiCol_Button] = featurescolors::generalcolor;
            colors[ImGuiCol_ButtonHovered] = DarkenColor(featurescolors::generalcolor, 0.3f);
            colors[ImGuiCol_ButtonActive] = DarkenColor(featurescolors::generalcolor, 0.5f);

            colors[ImGuiCol_CheckMark] = featurescolors::generalcolor;

            colors[ImGuiCol_PopupBg] = ImVec4(0.10f, 0.10f, 0.12f, 1.00f);

            colors[ImGuiCol_Header] = featurescolors::generalcolor;
            colors[ImGuiCol_HeaderHovered] = DarkenColor(featurescolors::generalcolor, 0.3f);
            colors[ImGuiCol_HeaderActive] = DarkenColor(featurescolors::generalcolor, 0.5f);
            lastColor = featurescolors::generalcolor;
        }*/
        /*featurescolors::generalcolorU32 = ImGui::ColorConvertFloat4ToU32(featurescolors::generalcolor);
        ImGui::BeginChild("##Sidebar", ImVec2(150 * features::menu_scale_factor, 0), true);*/

        for (int i = 0; i < IM_ARRAYSIZE(tabs); ++i) {
            bool selected = (current_tab == i);
            ImVec4 bgColor = selected ? featurescolors::generalcolor : ImVec4(0.13f, 0.14f, 0.16f, 1.0f);
            ImVec4 textColor = selected ? ImVec4(1.0f, 1.0f, 1.0f, 1.0f) : ImVec4(0.85f, 0.88f, 0.91f, 1.0f);
            ImGui::PushStyleColor(ImGuiCol_Button, bgColor);
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, bgColor);
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, bgColor);
            ImGui::PushStyleColor(ImGuiCol_Text, textColor);
            /*ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f * features::menu_scale_factor);
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12 * features::menu_scale_factor, 8 * features::menu_scale_factor));
            if (ImGui::Button(tabs[i], ImVec2(-1.0f, 32.0f * features::menu_scale_factor))) current_tab = i;*/
            ImGui::PopStyleVar(2);
            ImGui::PopStyleColor(4);
        }

        ImGui::EndChild();
        ImGui::SameLine();

        ImGui::BeginChild("##MainContent", ImVec2(0, 0), true);
        ImGui::Text("  "); ImGui::SameLine();
        ImGui::TextColored(ImVec4(1, 1, 1, 1), "Tab: ");
        ImGui::SameLine(); ImGui::TextDisabled(tabs[current_tab]);
        ImGui::Separator();
        ImGui::SetNextItemWidth(200);
        static char search[64] = "";
        ImGui::InputTextWithHint("##Search", "Search...", search, IM_ARRAYSIZE(search));
        ImGui::Spacing();

        if (strcmp(tabs[current_tab], "Players") == 0) {
            /*ImGui::Checkbox("Bone ESP", &features::bone_esp);
            ImGui::SameLine();
            DrawCoolSelectorU32(":##bone", featurescolors::Bones_color);
            ImGui::Checkbox("2D Box ESP  ", &features::box2d_esp);
            ImGui::SameLine();
            DrawCoolSelectorU32(":##2D", featurescolors::box_color2D);
            ImGui::Checkbox("3D Box ESP", &features::box3d_esp);
            ImGui::SameLine();
            DrawCoolSelectorU32(":##3D", featurescolors::box_color3D);
            ImGui::Checkbox("Health Bar", &features::health_bar);*/

        }
        else if (strcmp(tabs[current_tab], "View") == 0) {
            /*ImGui::Checkbox("Enable FOV", &features::fov_enabled);
            ImGui::SameLine();
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 11);
            CustomRoundedSlider("##FOVSlider", &features::fov, 60.0f, 179.0f, ImVec2(300 * features::menu_scale_factor, 6 * features::menu_scale_factor), featurescolors::generalcolorU32);
            ImGui::Separator();
            ImGui::Checkbox("Enable Crosshair", &features::crosshair_enabled);
            ImGui::SameLine();
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 298);
            ImGui::SetNextItemWidth(200.0f * features::menu_scale_factor);
            DrawCoolSelector("Crosshair color", featurescolors::crosshair_color);
            ImGui::Combo("Crosshair Type", &features::crosshair_type, "Dot\0Cross\0");

            ImGui::Text("Crosshair Size");
            ImGui::SameLine();
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 6);
            CustomRoundedSlider("##crossize", &features::crosshair_size, 2.0f, 20.0f, ImVec2(300 * features::menu_scale_factor, 6 * features::menu_scale_factor), featurescolors::generalcolorU32);
            ImGui::Text("Crosshair Thickness");
            ImGui::SameLine();
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 6);
            CustomRoundedSlider("##crossthick", &features::crosshair_thickness, 0.5f, 5.0f, ImVec2(300 * features::menu_scale_factor, 6 * features::menu_scale_factor), featurescolors::generalcolorU32);*/

        }
        else if (strcmp(tabs[current_tab], "Weapon") == 0) {
            //ImGui::Checkbox("Enable Aimbot", &features::aimbot_enabled);

            //ImGui::Checkbox("Enable Magic Bullet", &features::enable_magicbullet);
            //ImGui::Checkbox("Show Selected Player", &features::show_selected_player);
            //ImGui::SameLine();
            //ImGui::SetNextItemWidth(200.0f * features::menu_scale_factor);
            //DrawCoolSelectorU32(":##SPL", featurescolors::Aimbot_dot_color);
            //ImGui::Text("Selected Player Size");
            //ImGui::SameLine();
            //ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 6);
            //CustomRoundedSlider("##SPSlider", &features::selected_player_size, 0.0f, 20.0f, ImVec2(300 * features::menu_scale_factor, 6 * features::menu_scale_factor), featurescolors::generalcolorU32);
            //ImGui::Checkbox("Use Aimbot FOV Limit", &features::aimbot_fov_enabled);
            //ImGui::SameLine();
            //ImGui::SetNextItemWidth(200.0f * features::menu_scale_factor);
            //DrawCoolSelectorU32(":##FOV", featurescolors::Aimbot_FOV_color);
            //ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 6);
            //ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 2);
            //CustomRoundedSlider("##FOVaimbot", &features::aimbot_fov, 0.0f, 1000.0f, ImVec2(300 * features::menu_scale_factor, 6 * features::menu_scale_factor), featurescolors::generalcolorU32);
            //const char* aimModes[] = { "Closest to Crosshair", "Closest by Distance" };
            //ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 6);
            //if (CustomComboBox("Aimbot Type", &features::aimbot_type, aimModes, IM_ARRAYSIZE(aimModes))) {}
            //ImGui::Separator();
            //ImGui::Checkbox("Infinite Ammo", &features::infinite_ammo);
            //ImGui::Checkbox("QS", &features::qs);
            //ImGui::Checkbox("No Reload", &features::no_reload);
            ////ImGui::Checkbox("Enable Demon Shoot [+] temporary unavailable", &features::demon_shoot);









        }
        else if (strcmp(tabs[current_tab], "Misc") == 0) {
            /*ImGui::Checkbox("Bunny Hop", &features::bhop);
            ImGui::Checkbox("Gode Mode", &features::godmode);
            ImGui::Checkbox("Infinite Supplies", &features::infinite_supplies);
            ImGui::Separator();
            ImGui::Checkbox("Fly", &features::enable_fly);
            CustomRoundedSlider("##Fly_force", &features::fly_force, 10.0f, 500.0f, ImVec2(300 * features::menu_scale_factor, 6 * features::menu_scale_factor), featurescolors::generalcolorU32);
            ImGui::Separator();
            ImGui::Checkbox("Long Cannon Interact", &features::long_cannon_interact_enabled);
            CustomRoundedSlider("##FOVaimbot", &features::long_cannon_interact_max_dist, 0.0f, 200000.0f, ImVec2(300, 6), featurescolors::generalcolorU32);
            ImGui::Checkbox("Speed (host only)", &features::coolspeed);

            if (features::coolspeed)
            {
                ImGui::Text("Walk speed");
                ImGui::SameLine();
                CustomRoundedSlider("Walk Speed", &features::walkspeed, 0.0f, 10000.0f, ImVec2(300, 6), featurescolors::generalcolorU32);
                ImGui::Text("Sprint speed");
                ImGui::SameLine();
                CustomRoundedSlider("Sprint Speed", &features::sprintspeed, 0.0f, 10000.0f, ImVec2(300, 6), featurescolors::generalcolorU32);

            }*/




        }
        else if (strcmp(tabs[current_tab], "Server") == 0) {
            bool prestaEnabled = false;
            /*ImGui::Checkbox("Enable Presta d'Haikiu", &prestaEnabled);
            ImGui::Separator();
            ImGui::InputText("Spoofed Name", features::spoofed_name, sizeof(features::spoofed_name));
            ImGui::Checkbox("Enable Name Spoofing", &features::spoof_name_enabled);*/
        }
        else if (strcmp(tabs[current_tab], "Settings") == 0) {
            /*ImGui::SetNextItemWidth(200.0f * features::menu_scale_factor);
            DrawCoolSelector("General color", featurescolors::generalcolor);
            ImGui::Separator();
            static const char* scale_labels[] = { "50%", "75%", "100%", "150%", "200%" };
            static float scale_values[] = { 0.5f, 0.75f, 1.0f, 1.5f, 2.0f };
            static int current_scale_index = 3;
            if (ImGui::Combo("Menu Size", &current_scale_index, scale_labels, IM_ARRAYSIZE(scale_labels))) {
                features::menu_scale_factor = scale_values[current_scale_index];

                if (features::menu_scale_factor != current_applied_scale) {
                    ApplyMenuScale(features::menu_scale_factor, current_applied_scale, styled);
                }
            }*/

            ImGui::Separator();
            static char newConfigName[64] = "default";

            ImGui::InputText("Config name", newConfigName, IM_ARRAYSIZE(newConfigName));
            ImGui::Separator();

            /*if (ImGui::Button("Save Config")) config::Save(newConfigName);
            ImGui::SameLine();
            if (ImGui::Button("Load Config")) config::Load(newConfigName);
            ImGui::SameLine();
            if (ImGui::Button("Delete Config")) config::Delete(newConfigName);
            ImGui::Separator();*/

            /*ImGui::Text("Available Configs:");
            auto configs = config::ListConfigs();
            if (configs.empty()) {
                ImGui::TextColored(ImVec4(1, 0.4f, 0.4f, 1), "No configs found.");
            }
            else {
                for (auto& cfg : configs) {
                    if (ImGui::Selectable(cfg.c_str())) {
                        strcpy_s(newConfigName, cfg.c_str());
                    }
                }
            }*/
        }

        ImGui::EndChild();
        ImGui::End();
    }

    void RenderIntro() {
        const float fade_in_duration = 0.5f;
        const float fade_out_duration = 1.0f;

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
        ImGui::Begin("##IntroOverlay", nullptr,
            ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoInputs |
            ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoBringToFrontOnFocus);

        ImVec2 display_size = ImGui::GetIO().DisplaySize;
        ImDrawList* draw_list = ImGui::GetWindowDrawList();

        float screen_width = display_size.x;
        float screen_height = display_size.y;

        float global_alpha = 1.0f;
        if (intro_timer < fade_in_duration)
            global_alpha = intro_timer / fade_in_duration;
        else if (intro_timer > menu::intro_duration - fade_out_duration)
            global_alpha = (menu::intro_duration - intro_timer) / fade_out_duration;

        ImVec2 padding(50.0f, 50.0f);

        ImU32 overlay_color = ImGui::GetColorU32(ImVec4(0, 0, 0, global_alpha * 0.8f));
        draw_list->AddRectFilled(
            ImVec2(-padding.x, -padding.y),
            ImVec2(display_size.x + padding.x, display_size.y + padding.y),
            overlay_color
        );

        std::string text = "BMH";
        int total_chars = text.length();

        ImGui::PushFont(menu::intro_font);

        float char_height = ImGui::CalcTextSize("A").y;
        float total_width = 0.0f;
        //std::vector<float> advances;

        /*for (int i = 0; i < total_chars; ++i)
        {
            float adv = menu::intro_font->GetCharAdvance(text[i]);
            advances.push_back(adv);
            total_width += adv;
        }*/
        float start_x = (screen_width - total_width) * 0.5f;
        float base_y = (screen_height - char_height) * 0.5f;

        float anim_time = intro_timer;
        float text_start_time = 0.5f;
        float per_letter_delay = 0.06f;
        float char_width = ImGui::CalcTextSize("A").x;
        float current_x = start_x;
        for (int i = 0; i < total_chars; ++i) {
            float delay = i * per_letter_delay;
            float letter_time = anim_time - text_start_time - delay;
           // float progress = std::clamp(letter_time, 0.0f, 1.0f);

            /*float y_offset = ImLerp(30.0f, 0.0f, progress);
            float alpha = std::clamp(progress, 0.0f, 1.0f) * global_alpha;*/

            //ImGui::PushStyleVar(ImGuiStyleVar_Alpha, alpha);

            float x = current_x;
            //ImGui::SetCursorPos(ImVec2(x, base_y + y_offset));
            //current_x += advances[i];
            ImGui::TextColored(ImColor(255, 140, 0), std::string(1, text[i]).c_str());

            ImGui::PopStyleVar();
        }

        ImGui::PopFont();
        ImGui::End();
    }
}
