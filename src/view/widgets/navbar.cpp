/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */

#include "navbar.h"

#include "asset_manager.h"
#include "bindings.h"
#include "linux_input.h"
#include "theme.h"
#include "ui_const.h"

namespace view::widgets {
namespace {

struct IconSpec {
    const char* text;
    lv_event_cb_t click_cb;
};

constexpr std::array<int32_t, 5> kNavButtonXOffsets = {30, 17, 2, -15, -30};

viewmodel::BaseViewModel* view_model_from(lv_event_t* event) {
    return static_cast<viewmodel::BaseViewModel*>(lv_event_get_user_data(event));
}

} // namespace

NavBar::NavBar(lv_obj_t* parent, viewmodel::BaseViewModel& view_model, app::AssetManager& assets)
    : BaseWidgets(parent), view_model_(view_model), assets_(assets) {}

NavBar::~NavBar() {
    for (size_t i = 0; i < icon_buttons_.size(); ++i) {
        if (icon_buttons_[i]) {
            platform::unregister_nav_button(i, icon_buttons_[i]->root());
        }
    }

    if (theme_observer_) {
        lv_observer_remove(theme_observer_);
        theme_observer_ = nullptr;
    }
    if (paused_observer_) {
        lv_observer_remove(paused_observer_);
        paused_observer_ = nullptr;
    }
    if (page_observer_) {
        lv_observer_remove(page_observer_);
        page_observer_ = nullptr;
    }
    if (band_toggle_observer_) {
        lv_observer_remove(band_toggle_observer_);
        band_toggle_observer_ = nullptr;
    }
}

void NavBar::build() {
    if (core_obj_) {
        return;
    }

    core_obj_ = lv_obj_create(parent_);
    lv_obj_remove_style_all(core_obj_);
    lv_obj_set_size(core_obj_, LV_PCT(100), kNavBarHeight);
    lv_obj_align(core_obj_, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_clear_flag(core_obj_, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(core_obj_, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(core_obj_, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_left(core_obj_, 8, 0);
    lv_obj_set_style_pad_right(core_obj_, 8, 0);
    reactive::bind_theme(core_obj_, view_model_.dark_mode_subject(), reactive::ThemeRole::Bar);

    create_icon_buttons();
    theme_observer_ = reactive::observe_obj(core_obj_, view_model_.dark_mode_subject(), update_icons_cb, this);
    paused_observer_ = reactive::observe_obj(core_obj_, view_model_.scan_paused_subject(), update_icons_cb, this);
    page_observer_ = reactive::observe_obj(core_obj_, view_model_.current_page_subject(), update_icons_cb, this);
    band_toggle_observer_ =
        reactive::observe_obj(core_obj_, view_model_.band_toggle_subject(), update_icons_cb, this);
    update_icon_buttons();
}

void NavBar::create_icon_buttons() {
    const auto light_color = view::palette(false).text;
    const auto dark_color = view::palette(true).text;
    icon_font_ = assets_.load_font("Phosphor-Fill.ttf", 22);

    for (size_t i = 0; i < icon_buttons_.size(); ++i) {
        icon_buttons_[i] = std::make_unique<IconButton>(core_obj_,
                                                        view_model_,
                                                        32,
                                                        24,
                                                        "",
                                                        icon_font_ ? icon_font_ : &lv_font_montserrat_14,
                                                        light_color,
                                                        dark_color,
                                                        nullptr,
                                                        &view_model_,
                                                        true);
        icon_buttons_[i]->build();
        // Nav buttons are driven by keys 4-8, not focus. Keep them out of the default focus group so
        // ENTER (used to open the network list) never "clicks" whichever button happens to be focused.
        lv_group_remove_obj(icon_buttons_[i]->root());
        lv_obj_set_style_translate_x(icon_buttons_[i]->root(), kNavButtonXOffsets[i], 0);
        platform::register_nav_button(i, icon_buttons_[i]->root());
    }
}

void NavBar::update_icon_buttons() {
    const char* theme_icon = view_model_.is_dark_mode() ? ICON_SUN : ICON_MOON;
    const char* scan_icon = view_model_.scan_paused() ? ICON_PLAY : ICON_PAUSE;
    const auto page = view_model_.current_page();
    const bool on_networks = page == model::AppPage::Networks;
    const bool on_detail = page == model::AppPage::NetworkDetail;
    // Keys 4-8 map to these buttons from left to right. ESC exits (chart) or goes back.
    const IconSpec first = on_detail     ? IconSpec{ICON_SQUARE_ARROW_LEFT, return_to_networks_cb}
                           : on_networks ? IconSpec{ICON_SQUARE_ARROW_LEFT, show_channels_cb}
                                         : IconSpec{ICON_SQUARE_ARROW_RIGHT, show_networks_cb};
    // Single-band radios (e.g. 2.4 GHz only) leave the band button disabled, as does the details
    // page (the network shown belongs to one band).
    const bool band_enabled = view_model_.can_toggle_band() && !on_detail;
    const std::array<IconSpec, 5> icons = {{
        first,
        {ICON_WIFI_HIGH, band_enabled ? toggle_band_cb : nullptr},
        {theme_icon, toggle_theme_cb},
        {scan_icon, toggle_scan_paused_cb},
        on_networks ? IconSpec{ICON_SORT, cycle_sort_cb} : IconSpec{"", nullptr},
    }};

    platform::set_nav_shortcut_mode(false);
    for (size_t i = 0; i < icon_buttons_.size(); ++i) {
        auto& button = icon_buttons_[i];
        if (!button || !button->root()) {
            continue;
        }

        button->set_text(icons[i].text);
        lv_obj_remove_event_cb(button->root(), show_networks_cb);
        lv_obj_remove_event_cb(button->root(), show_channels_cb);
        lv_obj_remove_event_cb(button->root(), return_to_networks_cb);
        lv_obj_remove_event_cb(button->root(), cycle_sort_cb);
        lv_obj_remove_event_cb(button->root(), toggle_band_cb);
        lv_obj_remove_event_cb(button->root(), toggle_theme_cb);
        lv_obj_remove_event_cb(button->root(), toggle_scan_paused_cb);
        if (icons[i].click_cb) {
            lv_obj_add_event_cb(button->root(), icons[i].click_cb, LV_EVENT_CLICKED, &view_model_);
            button->set_enabled(true);
        }
        else {
            button->set_enabled(false);
        }
    }
}

void NavBar::show_networks_cb(lv_event_t* event) {
    if (auto* view_model = view_model_from(event)) {
        view_model->show_networks_page(0);
    }
}

void NavBar::show_channels_cb(lv_event_t* event) {
    if (auto* view_model = view_model_from(event)) {
        view_model->show_channels_page();
    }
}

void NavBar::return_to_networks_cb(lv_event_t* event) {
    if (auto* view_model = view_model_from(event)) {
        view_model->return_to_networks_page();
    }
}

void NavBar::cycle_sort_cb(lv_event_t* event) {
    if (auto* view_model = view_model_from(event)) {
        view_model->cycle_network_sort();
    }
}

void NavBar::toggle_band_cb(lv_event_t* event) {
    if (auto* view_model = view_model_from(event)) {
        view_model->toggle_band();
    }
}

void NavBar::toggle_theme_cb(lv_event_t* event) {
    if (auto* view_model = view_model_from(event)) {
        view_model->toggle_dark_mode();
    }
}

void NavBar::toggle_scan_paused_cb(lv_event_t* event) {
    if (auto* view_model = view_model_from(event)) {
        view_model->toggle_scan_paused();
    }
}

void NavBar::update_icons_cb(lv_observer_t* observer, lv_subject_t* subject) {
    LV_UNUSED(subject);

    auto* nav_bar = static_cast<NavBar*>(lv_observer_get_user_data(observer));
    if (nav_bar) {
        nav_bar->update_icon_buttons();
    }
}

} // namespace view::widgets
