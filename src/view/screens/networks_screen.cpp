/*
 * SPDX-License-Identifier: MIT
 */

#include "networks_screen.h"

#include "asset_manager.h"
#include "bindings.h"
#include "theme.h"

#include <algorithm>
#include <string>

namespace screen {
namespace {

constexpr int32_t kPadX      = 8;
constexpr int32_t kRowWidth  = view::kScreenWidth - 2 * kPadX;
constexpr int32_t kHeaderY   = 2;
constexpr int32_t kRowsTop   = 19;
constexpr int32_t kRowHeight = 15;
constexpr int32_t kDetailY   = 96;

// Column layout inside a row (x offsets relative to the row).
constexpr int32_t kSignalX      = 4;
constexpr int32_t kSignalWidth  = 30;
constexpr int32_t kSsidX        = 40;
constexpr int32_t kSsidWidth    = 170;
constexpr int32_t kChannelX     = 212;
constexpr int32_t kChannelWidth = 26;
constexpr int32_t kSecurityX    = 246;
constexpr int32_t kSecurityWidth = kRowWidth - kSecurityX - 4;

const lv_font_t* font_or(const lv_font_t* font, const lv_font_t* fallback) {
    return font ? font : fallback;
}

lv_obj_t* make_label(lv_obj_t* parent, const lv_font_t* font, int32_t x, int32_t width, lv_text_align_t align) {
    auto* label = lv_label_create(parent);
    lv_obj_set_style_text_font(label, font, 0);
    lv_obj_set_style_text_align(label, align, 0);
    lv_label_set_long_mode(label, LV_LABEL_LONG_DOT);
    lv_obj_set_width(label, width);
    lv_obj_align(label, LV_ALIGN_LEFT_MID, x, 0);
    return label;
}

std::string ssid_text(const model::AccessPointInfo& ap) {
    return ap.ssid.empty() ? "(hidden)" : ap.ssid;
}

lv_color_t security_color(const view::ThemePalette& colors, model::SecurityLevel level) {
    switch (level) {
        case model::SecurityLevel::Open:
            return colors.error;
        case model::SecurityLevel::Weak:
            return colors.warning;
        case model::SecurityLevel::Good:
        default:
            return colors.text_disabled;
    }
}

} // namespace

NetworksScreen::NetworksScreen(viewmodel::BaseViewModel& view_model, app::AssetManager& assets)
    : BaseScreen(view_model, assets) {
    init();
}

void NetworksScreen::build_content(lv_obj_t* content) {
    const auto* header_font = font_or(assets().load_standard_font(13), &lv_font_montserrat_14);
    const auto* small_font =
        font_or(assets().load_standard_font(11, app::StandardFontWeight::Regular), &lv_font_montserrat_12);
    row_font_ = font_or(assets().load_standard_font(12, app::StandardFontWeight::Regular), &lv_font_montserrat_12);
    row_bold_font_ = font_or(assets().load_standard_font(12), &lv_font_montserrat_12);

    title_label_ = lv_label_create(content);
    lv_obj_set_style_text_font(title_label_, header_font, 0);
    lv_obj_set_pos(title_label_, kPadX, kHeaderY);

    info_label_ = lv_label_create(content);
    lv_obj_set_style_text_font(info_label_, small_font, 0);
    lv_obj_align(info_label_, LV_ALIGN_TOP_RIGHT, -kPadX, kHeaderY + 1);

    for (size_t i = 0; i < rows_.size(); ++i) {
        auto& row = rows_[i];
        row.background = lv_obj_create(content);
        lv_obj_remove_style_all(row.background);
        lv_obj_clear_flag(row.background, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_clear_flag(row.background, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_set_size(row.background, kRowWidth, kRowHeight);
        lv_obj_set_pos(row.background, kPadX, kRowsTop + static_cast<int32_t>(i) * kRowHeight);
        lv_obj_set_style_radius(row.background, 3, 0);

        row.signal = make_label(row.background, row_font_, kSignalX, kSignalWidth, LV_TEXT_ALIGN_RIGHT);
        row.ssid = make_label(row.background, row_font_, kSsidX, kSsidWidth, LV_TEXT_ALIGN_LEFT);
        row.channel = make_label(row.background, row_font_, kChannelX, kChannelWidth, LV_TEXT_ALIGN_RIGHT);
        row.security = make_label(row.background, small_font, kSecurityX, kSecurityWidth, LV_TEXT_ALIGN_LEFT);
    }

    message_label_ = lv_label_create(content);
    lv_obj_set_style_text_font(message_label_, small_font, 0);
    lv_obj_set_style_text_align(message_label_, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(message_label_, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(message_label_, kRowWidth - 16);
    lv_obj_align(message_label_, LV_ALIGN_TOP_MID, 0, kRowsTop + 22);

    detail_label_ = lv_label_create(content);
    lv_obj_set_style_text_font(detail_label_, small_font, 0);
    lv_label_set_long_mode(detail_label_, LV_LABEL_LONG_DOT);
    lv_obj_set_width(detail_label_, kRowWidth);
    lv_obj_set_pos(detail_label_, kPadX, kDetailY);

    reactive::observe_obj(content, view_model().wifi_revision_subject(), refresh_cb, this);
    reactive::observe_obj(content, view_model().dark_mode_subject(), refresh_cb, this);
    render();
}

void NetworksScreen::render() {
    const auto& wifi = view_model().wifi();
    const auto colors = view::palette(view_model().is_dark_mode());
    const auto& networks = wifi.networks();

    std::string title = model::band_label(wifi.band());
    title += wifi.network_filter() == 0 ? "   all channels" : "   ch " + std::to_string(wifi.network_filter());
    lv_label_set_text(title_label_, title.c_str());
    lv_obj_set_style_text_color(title_label_, colors.primary, 0);

    const std::string info = std::to_string(networks.size()) + " shown, by " + model::sort_label(wifi.network_sort());
    lv_label_set_text(info_label_, info.c_str());
    lv_obj_set_style_text_color(info_label_, colors.text_disabled, 0);
    lv_obj_align(info_label_, LV_ALIGN_TOP_RIGHT, -kPadX, kHeaderY + 1);

    // Keep the selection roughly centred while scrolling.
    const size_t selected = wifi.selected_network_index();
    size_t top = selected > kVisibleRows / 2 ? selected - kVisibleRows / 2 : 0;
    if (networks.size() > kVisibleRows) {
        top = std::min(top, networks.size() - kVisibleRows);
    }
    else {
        top = 0;
    }

    for (size_t i = 0; i < rows_.size(); ++i) {
        auto& row = rows_[i];
        const size_t index = top + i;
        if (index >= networks.size()) {
            lv_obj_add_flag(row.background, LV_OBJ_FLAG_HIDDEN);
            continue;
        }
        lv_obj_remove_flag(row.background, LV_OBJ_FLAG_HIDDEN);

        const auto& ap = *networks[index];
        const bool is_selected = index == selected;
        lv_obj_set_style_bg_color(row.background, colors.primary, 0);
        lv_obj_set_style_bg_opa(row.background, is_selected ? LV_OPA_20 : LV_OPA_TRANSP, 0);

        lv_label_set_text_fmt(row.signal, "%d%%", static_cast<int>(std::max<int32_t>(ap.strength_percent, 0)));
        lv_obj_set_style_text_color(row.signal, colors.text, 0);

        lv_label_set_text(row.ssid, ssid_text(ap).c_str());
        lv_obj_set_style_text_font(row.ssid, ap.connected ? row_bold_font_ : row_font_, 0);
        lv_obj_set_style_text_color(row.ssid,
                                    ap.connected ? colors.info : (ap.ssid.empty() ? colors.text_disabled : colors.text),
                                    0);

        lv_label_set_text_fmt(row.channel, "%d", static_cast<int>(ap.channel));
        lv_obj_set_style_text_color(row.channel, colors.text_disabled, 0);

        const auto security = model::describe_security(ap.security);
        lv_label_set_text(row.security, security.label.c_str());
        lv_obj_set_style_text_color(row.security, security_color(colors, security.level), 0);
    }

    if (networks.empty()) {
        const bool error = wifi.status() == model::ScanStatus::Error && wifi.total_networks() == 0;
        lv_label_set_text(message_label_,
                          error ? wifi.error().c_str()
                                : wifi.status() == model::ScanStatus::Starting ? "Scanning for networks..."
                                                                               : "No networks here.");
        lv_obj_set_style_text_color(message_label_, error ? colors.error : colors.text, 0);
        lv_obj_remove_flag(message_label_, LV_OBJ_FLAG_HIDDEN);
        lv_obj_add_flag(detail_label_, LV_OBJ_FLAG_HIDDEN);
        return;
    }
    lv_obj_add_flag(message_label_, LV_OBJ_FLAG_HIDDEN);
    lv_obj_remove_flag(detail_label_, LV_OBJ_FLAG_HIDDEN);

    const auto* ap = wifi.selected_network();
    std::string detail;
    if (ap) {
        detail = ap->bssid + "  " + std::to_string(ap->frequency_mhz) + " MHz";
        if (ap->connected) {
            detail += "  connected";
        }
        else if (ap->channel_utilization_percent >= 0) {
            detail += "  load " + std::to_string(ap->channel_utilization_percent) + "%";
        }
    }
    lv_label_set_text(detail_label_, detail.c_str());
    lv_obj_set_style_text_color(detail_label_, ap && ap->connected ? colors.info : colors.text, 0);
}

void NetworksScreen::refresh_cb(lv_observer_t* observer, lv_subject_t* subject) {
    LV_UNUSED(subject);
    auto* screen = static_cast<NetworksScreen*>(lv_observer_get_user_data(observer));
    if (screen && screen->detail_label_) {
        screen->render();
    }
}

} // namespace screen
