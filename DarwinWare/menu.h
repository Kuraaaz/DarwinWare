
#pragma once

#ifndef MENU_H
#define MENU_H
#include "utils.h"
#include <stdio.h>

#include "imgui.h"




namespace menu {
   

    void DrawMenu();
    void RenderIntro();
}

namespace features {
   

}

namespace featurescolors {
    inline ImVec4 generalcolor = ImVec4(1.0f, 0.55f, 0.2f, 1.0f);
   
}



inline void DrawCoolSelector(const char* label, ImVec4& color)
{
    const char* displayLabel = label;
    const char* hashPos = strstr(label, "##");
    if (hashPos && hashPos != label) {
        static char temp[128];
        strncpy_s(temp, label, hashPos - label);
        temp[hashPos - label] = '\0';
        displayLabel = temp;
    }

    ImGui::TextUnformatted(displayLabel);
    ImGui::SameLine();

    ImGui::PushID(label);
    {
        float lineHeight = ImGui::GetTextLineHeight();
        float buttonSize = 20.0f;
        float verticalOffset = (lineHeight - buttonSize) * 0.5f;

        ImVec2 cursor = ImGui::GetCursorPos();
        cursor.y += verticalOffset;
        ImGui::SetCursorPos(cursor);

        if (ImGui::ColorButton("##ColorBtn", color, ImGuiColorEditFlags_NoTooltip, ImVec2(buttonSize, buttonSize)))
            ImGui::OpenPopup("ColorPopup");

        if (ImGui::BeginPopup("ColorPopup")) {
            ImGui::ColorPicker4("##picker", (float*)&color,
                ImGuiColorEditFlags_NoInputs |
                ImGuiColorEditFlags_AlphaBar |
                ImGuiColorEditFlags_NoSidePreview |
                ImGuiColorEditFlags_DisplayRGB);
            ImGui::EndPopup();
        }
    }
    ImGui::PopID();
}

inline void DrawCoolSelectorU32(const char* label, ImU32& color)
{
    ImVec4 tempColor = ImGui::ColorConvertU32ToFloat4(color);

    const char* displayLabel = label;
    const char* hashPos = strstr(label, "##");
    if (hashPos && hashPos != label) {
        static char temp[128];
        strncpy_s(temp, label, hashPos - label);
        temp[hashPos - label] = '\0';
        displayLabel = temp;
    }

    ImGui::TextUnformatted(displayLabel);
    ImGui::SameLine();

    ImGui::PushID(label);
    {
        float lineHeight = ImGui::GetTextLineHeight();
        float buttonSize = 20.0f;
        float offset = (lineHeight - buttonSize) * 0.5f;
        ImVec2 pos = ImGui::GetCursorPos();
        pos.y += offset;
        ImGui::SetCursorPos(pos);

        if (ImGui::ColorButton("##ColorBtn", tempColor, ImGuiColorEditFlags_NoTooltip, ImVec2(buttonSize, buttonSize)))
            ImGui::OpenPopup("ColorPopup");

        if (ImGui::BeginPopup("ColorPopup")) {
            if (ImGui::ColorPicker4("##picker", (float*)&tempColor,
                ImGuiColorEditFlags_NoInputs |
                ImGuiColorEditFlags_AlphaBar |
                ImGuiColorEditFlags_NoSidePreview |
                ImGuiColorEditFlags_DisplayRGB)) {
                color = ImGui::ColorConvertFloat4ToU32(tempColor);
            }
            ImGui::EndPopup();
        }
    }
    ImGui::PopID();
}

inline float Clamp01(float value) {
    return value < 0.0f ? 0.0f : (value > 1.0f ? 1.0f : value);
}
inline bool CustomComboBox(const char* label, int* current_item, const char* items[], int items_count, const ImVec2& size = ImVec2(300, 0))
{
    ImGui::PushID(label);

    bool changed = false;

    ImVec2 pos = ImGui::GetCursorScreenPos();
    ImVec2 box_size = size;
    if (box_size.y == 0)
        box_size.y = ImGui::GetFrameHeight();

    ImDrawList* draw = ImGui::GetWindowDrawList();

    // Draw background rounded rect
    float rounding = box_size.y * 0.25f;
    draw->AddRectFilled(pos, ImVec2(pos.x + box_size.x, pos.y + box_size.y), IM_COL32(40, 40, 40, 180), rounding);

    // Draw current selected text
    const char* current_text = (*current_item >= 0 && *current_item < items_count) ? items[*current_item] : "";
    ImGui::SetCursorScreenPos(ImVec2(pos.x + 10, pos.y + (box_size.y - ImGui::GetTextLineHeight()) * 0.5f));
    ImGui::TextUnformatted(current_text);

    // Invisible button to catch clicks
    ImGui::SetCursorScreenPos(pos);
    if (ImGui::InvisibleButton("##customcombo", box_size))
        ImGui::OpenPopup("##customcombo_popup");

    // Draw border
    draw->AddRect(pos, ImVec2(pos.x + box_size.x, pos.y + box_size.y), IM_COL32(255, 255, 255, 150), rounding);

    if (ImGui::BeginPopup("##customcombo_popup"))
    {
        for (int i = 0; i < items_count; ++i)
        {
            bool is_selected = (i == *current_item);
            ImGui::PushID(i);
            if (ImGui::Selectable(items[i], is_selected))
            {
                *current_item = i;
                changed = true;
                ImGui::CloseCurrentPopup();
            }
            ImGui::PopID();
        }
        ImGui::EndPopup();
    }

    ImGui::PopID();

    return changed;
}
inline bool CustomRoundedSlider(const char* label, float* value, float min, float max, const ImVec2& size = ImVec2(300, 6), ImU32 fill_color = IM_COL32(255, 0, 0, 255))
{
    ImVec2 pos = ImGui::GetCursorScreenPos();
    ImDrawList* draw = ImGui::GetWindowDrawList();

    float radius = size.y * 0.5f;
    float t = (*value - min) / (max - min);
    t = Clamp01(t);

    // Fond du slider
    draw->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y), IM_COL32(40, 40, 40, 180), radius);

    // Barre remplie
    draw->AddRectFilled(pos, ImVec2(pos.x + size.x * t, pos.y + size.y), fill_color, radius);

    // Cercle rempli plus grand
    float circleRadius = radius * 3.0f; // plus grand que la barre
    ImVec2 circleCenter = ImVec2(pos.x + size.x * t, pos.y + radius);

    // Cercle rempli
    draw->AddCircleFilled(circleCenter, circleRadius, fill_color);

    // Contour noir pour bien délimiter
    draw->AddCircle(circleCenter, circleRadius, IM_COL32(0, 0, 0, 255), 32, 2.0f);

    ImGui::InvisibleButton(label, size);
    bool changed = false;
    if (ImGui::IsItemActive()) {
        ImVec2 mouse = ImGui::GetIO().MousePos;
        float new_t = Clamp01((mouse.x - pos.x) / size.x);
        *value = min + (max - min) * new_t;
        changed = true;
    }

    ImVec2 text_pos = ImVec2(pos.x + size.x + 8, pos.y - 2);
    char buf[16];
    snprintf(buf, sizeof(buf), "%.0f", *value);
    draw->AddText(text_pos, ImGui::GetColorU32(ImGuiCol_Text), buf);

    return changed;
}

const ImVec4 frameStatic = ImVec4(0.13f, 0.14f, 0.16f, 1.00f);
const ImVec4 frameHovered = ImVec4(0.18f, 0.20f, 0.22f, 1.00f);
const ImVec4 frameActive = ImVec4(0.22f, 0.24f, 0.26f, 1.00f);
const ImVec4 popupcombo = ImVec4(0.13f, 0.14f, 0.16f, 1.00f);

#endif