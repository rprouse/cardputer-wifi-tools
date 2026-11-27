/*
 * SPDX-FileCopyrightText: 2026 Rob Prouse
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "base_screen.h"

#include <array>

namespace screen {

// Everything known about the network selected in the list. UP/DOWN steps through the list.
class NetworkDetailScreen : public BaseScreen {
public:
    NetworkDetailScreen(viewmodel::BaseViewModel& view_model, app::AssetManager& assets);

private:
    static constexpr size_t kCells = 12;

    struct Cell {
        lv_obj_t* key{nullptr};
        lv_obj_t* value{nullptr};
    };

    void build_content(lv_obj_t* content) override;
    void render();
    static void refresh_cb(lv_observer_t* observer, lv_subject_t* subject);

    lv_obj_t* ssid_label_{nullptr};
    lv_obj_t* position_label_{nullptr};
    lv_obj_t* bssid_label_{nullptr};
    lv_obj_t* message_label_{nullptr};
    std::array<Cell, kCells> cells_{};
};

} // namespace screen
