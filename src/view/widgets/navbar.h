/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "base_widget.h"
#include "base_viewmodel.h"
#include "icon_button.h"

#include <array>
#include <memory>

namespace app {
class AssetManager;
}

namespace view::widgets {

class NavBar : public BaseWidgets {
public:
    NavBar(lv_obj_t* parent, viewmodel::BaseViewModel& view_model, app::AssetManager& assets);
    ~NavBar() override;

    void build() override;

private:
    void create_icon_buttons();
    void update_icon_buttons();

    static void show_networks_cb(lv_event_t* event);
    static void show_channels_cb(lv_event_t* event);
    static void return_to_networks_cb(lv_event_t* event);
    static void cycle_sort_cb(lv_event_t* event);
    static void toggle_band_cb(lv_event_t* event);
    static void toggle_theme_cb(lv_event_t* event);
    static void toggle_scan_paused_cb(lv_event_t* event);
    static void update_icons_cb(lv_observer_t* observer, lv_subject_t* subject);

    viewmodel::BaseViewModel& view_model_;
    app::AssetManager& assets_;
    std::array<std::unique_ptr<IconButton>, 5> icon_buttons_;
    lv_font_t* icon_font_{nullptr};
    lv_observer_t* theme_observer_{nullptr};
    lv_observer_t* paused_observer_{nullptr};
    lv_observer_t* page_observer_{nullptr};
    lv_observer_t* band_toggle_observer_{nullptr};
};

} // namespace view::widgets
