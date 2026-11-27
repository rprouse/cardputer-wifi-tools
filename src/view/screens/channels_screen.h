/*
 * SPDX-FileCopyrightText: 2026 Rob Prouse
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "base_screen.h"

#include <array>

namespace screen {

// Bar chart of WiFi networks per channel for the selected band.
class ChannelsScreen : public BaseScreen {
public:
    ChannelsScreen(viewmodel::BaseViewModel& view_model, app::AssetManager& assets);

private:
    static constexpr size_t kMaxColumns = 32;

    struct Column {
        lv_obj_t* highlight{nullptr};
        lv_obj_t* bar{nullptr};
        lv_obj_t* count{nullptr};
        lv_obj_t* label{nullptr};
    };

    void build_content(lv_obj_t* content) override;
    void render();
    static void refresh_cb(lv_observer_t* observer, lv_subject_t* subject);

    lv_obj_t* band_label_{nullptr};
    lv_obj_t* status_label_{nullptr};
    lv_obj_t* message_label_{nullptr};
    lv_obj_t* detail_label_{nullptr};
    lv_obj_t* baseline_{nullptr};
    std::array<Column, kMaxColumns> columns_{};
};

} // namespace screen
