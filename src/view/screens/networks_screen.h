/*
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "base_screen.h"

#include <array>

namespace screen {

// Scrollable list of networks in the current band, optionally limited to one channel.
class NetworksScreen : public BaseScreen {
public:
    NetworksScreen(viewmodel::BaseViewModel& view_model, app::AssetManager& assets);

private:
    static constexpr size_t kVisibleRows = 5;

    struct Row {
        lv_obj_t* background{nullptr};
        lv_obj_t* signal{nullptr};
        lv_obj_t* ssid{nullptr};
        lv_obj_t* channel{nullptr};
        lv_obj_t* security{nullptr};
    };

    void build_content(lv_obj_t* content) override;
    void render();
    static void refresh_cb(lv_observer_t* observer, lv_subject_t* subject);

    lv_obj_t* title_label_{nullptr};
    lv_obj_t* info_label_{nullptr};
    lv_obj_t* message_label_{nullptr};
    lv_obj_t* detail_label_{nullptr};
    const lv_font_t* row_font_{nullptr};
    const lv_font_t* row_bold_font_{nullptr};
    std::array<Row, kVisibleRows> rows_{};
};

} // namespace screen
