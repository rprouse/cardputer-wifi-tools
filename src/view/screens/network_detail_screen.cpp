/*
 * SPDX-FileCopyrightText: 2026 Rob Prouse
 *
 * SPDX-License-Identifier: MIT
 */

#include "network_detail_screen.h"

#include "asset_manager.h"
#include "bindings.h"
#include "theme.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <string>
#include <vector>

namespace screen {
namespace {

constexpr int32_t kPadX       = 8;
constexpr int32_t kWidth      = view::kScreenWidth - 2 * kPadX;
constexpr int32_t kHeaderY    = 1;
constexpr int32_t kBssidY     = 16;
constexpr int32_t kGridTop    = 30;
constexpr int32_t kCellHeight = 13;
constexpr size_t kRows        = 6;

// Left column: radio details. Right column: security and neighbours (wider, longer values).
struct ColumnLayout {
    int32_t x;
    int32_t key_width;
    int32_t value_width;
};
constexpr std::array<ColumnLayout, 2> kColumns = {{
    {kPadX, 60, 82},
    {kPadX + 146, 64, kWidth - 146 - 64},
}};

const lv_font_t* font_or(const lv_font_t* font, const lv_font_t* fallback) {
    return font ? font : fallback;
}

enum class Tone {
    Normal,
    Warning,
    Error,
};

struct Item {
    const char* key;
    std::string value;
    Tone tone{Tone::Normal};
};

struct Items {
    std::vector<Item> radio;
    std::vector<Item> other;
};

// The first octet's "locally administered" bit marks a BSSID the router made up, typically for
// a guest network or an extra SSID on the same radio.
bool locally_administered(const std::string& bssid) {
    if (bssid.size() < 2) {
        return false;
    }
    const long first = std::strtol(bssid.substr(0, 2).c_str(), nullptr, 16);
    return (first & 0x02) != 0;
}

Items build_items(const model::WifiModel& wifi, const model::AccessPointInfo& ap) {
    Items result;
    auto& items = result.radio;

    items.push_back({"Signal", std::to_string(std::max<int32_t>(ap.strength_percent, 0)) + "%"});
    if (ap.signal_dbm != 0) {
        // nmcli only reports a percentage, so Linux shows an estimate.
        items.push_back({"RSSI", (ap.signal_dbm_estimated ? "~" : "") + std::to_string(ap.signal_dbm) + " dBm"});
    }

    items.push_back({"Channel", std::to_string(ap.channel) + "  " + std::to_string(ap.frequency_mhz) + " MHz"});

    if (ap.channel_width_mhz > 0) {
        items.push_back({"Width", std::to_string(ap.channel_width_mhz) + " MHz"});
    }
    if (!ap.standard.empty()) {
        items.push_back({"Standard", ap.standard});
    }
    if (ap.max_rate_mbps > 0) {
        items.push_back({"Rate", std::to_string(ap.max_rate_mbps) + " Mb/s"});
    }
    if (!ap.mode.empty() && ap.mode != "Infra") {
        items.push_back({"Mode", ap.mode});
    }

    auto& other = result.other;
    const auto security = model::describe_security(ap.security);
    other.push_back({"Security",
                     security.label,
                     security.level == model::SecurityLevel::Open   ? Tone::Error
                     : security.level == model::SecurityLevel::Weak ? Tone::Warning
                                                                    : Tone::Normal});
    if (!ap.key_mgmt.empty()) {
        other.push_back({"Auth", ap.key_mgmt});
    }
    if (!ap.ciphers.empty()) {
        const bool weak = ap.ciphers.find("TKIP") != std::string::npos || ap.ciphers.find("WEP") != std::string::npos;
        other.push_back({"Cipher", ap.ciphers, weak ? Tone::Warning : Tone::Normal});
    }
    if (ap.channel_utilization_percent >= 0) {
        other.push_back({"Load", std::to_string(ap.channel_utilization_percent) + "%"});
    }

    // Other access points with the same name: mesh nodes, extenders, or the other band.
    if (!ap.ssid.empty()) {
        const auto matches = wifi.same_ssid(ap);
        if (matches.size() > 1) {
            std::string text = std::to_string(matches.size()) + " APs:";
            std::vector<int32_t> channels;
            for (const auto* match : matches) {
                if (std::find(channels.begin(), channels.end(), match->channel) == channels.end()) {
                    channels.push_back(match->channel);
                    text += (channels.size() == 1 ? " " : ",") + std::to_string(match->channel);
                }
            }
            other.push_back({"Same SSID", text});
        }
    }

    if (const auto* stats = wifi.channel_stats(ap.channel)) {
        std::string text = std::to_string(std::max<int32_t>(stats->network_count - 1, 0)) + " others";
        if (stats->overlapping_count > 0) {
            text += ", " + std::to_string(stats->overlapping_count) + " overlap";
        }
        other.push_back({"Sharing", text});
    }

    if (!ap.devices.empty()) {
        other.push_back({"Seen by", ap.devices});
    }
    return result;
}

} // namespace

NetworkDetailScreen::NetworkDetailScreen(viewmodel::BaseViewModel& view_model, app::AssetManager& assets)
    : BaseScreen(view_model, assets) {
    init();
}

void NetworkDetailScreen::build_content(lv_obj_t* content) {
    const auto* header_font = font_or(assets().load_standard_font(13), &lv_font_montserrat_14);
    const auto* small_font =
        font_or(assets().load_standard_font(11, app::StandardFontWeight::Regular), &lv_font_montserrat_12);

    ssid_label_ = lv_label_create(content);
    lv_obj_set_style_text_font(ssid_label_, header_font, 0);
    lv_label_set_long_mode(ssid_label_, LV_LABEL_LONG_DOT);
    lv_obj_set_width(ssid_label_, kWidth - 60);
    lv_obj_set_pos(ssid_label_, kPadX, kHeaderY);

    position_label_ = lv_label_create(content);
    lv_obj_set_style_text_font(position_label_, small_font, 0);
    lv_obj_align(position_label_, LV_ALIGN_TOP_RIGHT, -kPadX, kHeaderY + 2);

    bssid_label_ = lv_label_create(content);
    lv_obj_set_style_text_font(bssid_label_, small_font, 0);
    lv_label_set_long_mode(bssid_label_, LV_LABEL_LONG_DOT);
    lv_obj_set_width(bssid_label_, kWidth);
    lv_obj_set_pos(bssid_label_, kPadX, kBssidY);

    for (size_t i = 0; i < cells_.size(); ++i) {
        const auto& column = kColumns[i / kRows];
        const int32_t y = kGridTop + static_cast<int32_t>(i % kRows) * kCellHeight;

        // Fixed sizes keep long values on one line (LONG_DOT / LONG_CLIP need a fixed height).
        auto& cell = cells_[i];
        cell.key = lv_label_create(content);
        lv_obj_set_style_text_font(cell.key, small_font, 0);
        lv_label_set_long_mode(cell.key, LV_LABEL_LONG_CLIP);
        lv_obj_set_size(cell.key, column.key_width, kCellHeight + 1);
        lv_obj_set_pos(cell.key, column.x, y);

        cell.value = lv_label_create(content);
        lv_obj_set_style_text_font(cell.value, small_font, 0);
        lv_label_set_long_mode(cell.value, LV_LABEL_LONG_DOT);
        lv_obj_set_size(cell.value, column.value_width, kCellHeight + 1);
        lv_obj_set_pos(cell.value, column.x + column.key_width, y);
    }

    message_label_ = lv_label_create(content);
    lv_obj_set_style_text_font(message_label_, small_font, 0);
    lv_obj_set_style_text_align(message_label_, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(message_label_, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(message_label_, kWidth - 16);
    lv_obj_align(message_label_, LV_ALIGN_TOP_MID, 0, kGridTop + 14);

    reactive::observe_obj(content, view_model().wifi_revision_subject(), refresh_cb, this);
    reactive::observe_obj(content, view_model().dark_mode_subject(), refresh_cb, this);
    render();
}

void NetworkDetailScreen::render() {
    const auto& wifi = view_model().wifi();
    const auto colors = view::palette(view_model().is_dark_mode());
    const auto& networks = wifi.networks();
    const auto* ap = wifi.selected_network_present() ? wifi.selected_network() : nullptr;

    lv_obj_set_style_text_color(position_label_, colors.text_disabled, 0);
    if (!networks.empty()) {
        lv_label_set_text_fmt(position_label_,
                              "%u / %u",
                              static_cast<unsigned>(wifi.selected_network_index() + 1),
                              static_cast<unsigned>(networks.size()));
    }
    else {
        lv_label_set_text(position_label_, "");
    }
    lv_obj_align(position_label_, LV_ALIGN_TOP_RIGHT, -kPadX, kHeaderY + 2);

    if (!ap) {
        lv_label_set_text(ssid_label_, "Network lost");
        lv_obj_set_style_text_color(ssid_label_, colors.primary, 0);
        lv_label_set_text(bssid_label_, "");
        for (auto& cell : cells_) {
            lv_obj_add_flag(cell.key, LV_OBJ_FLAG_HIDDEN);
            lv_obj_add_flag(cell.value, LV_OBJ_FLAG_HIDDEN);
        }
        lv_label_set_text(message_label_,
                          "This network dropped out of the last scan.\nUP / DOWN to pick another, ESC to go back.");
        lv_obj_set_style_text_color(message_label_, colors.text, 0);
        lv_obj_remove_flag(message_label_, LV_OBJ_FLAG_HIDDEN);
        return;
    }
    lv_obj_add_flag(message_label_, LV_OBJ_FLAG_HIDDEN);

    lv_label_set_text(ssid_label_, ap->ssid.empty() ? "(hidden network)" : ap->ssid.c_str());
    lv_obj_set_style_text_color(ssid_label_, ap->connected ? colors.info : colors.primary, 0);

    std::string bssid = ap->bssid;
    if (ap->connected) {
        bssid += "   connected";
    }
    if (locally_administered(ap->bssid)) {
        bssid += "   virtual BSSID";
    }
    lv_label_set_text(bssid_label_, bssid.c_str());
    lv_obj_set_style_text_color(bssid_label_, ap->connected ? colors.info : colors.text_disabled, 0);

    // Radio details fill the left column, everything else the right; overflow from either side
    // uses any free rows in the other column.
    auto built = build_items(wifi, *ap);
    std::vector<Item> items(cells_.size(), Item{nullptr, {}});
    std::vector<Item> overflow;
    for (size_t i = 0; i < built.radio.size(); ++i) {
        (i < kRows ? items[i] : overflow.emplace_back()) = built.radio[i];
    }
    for (size_t i = 0; i < built.other.size(); ++i) {
        (i < kRows ? items[kRows + i] : overflow.emplace_back()) = built.other[i];
    }
    for (auto& extra : overflow) {
        auto free_slot = std::find_if(items.begin(), items.end(), [](const Item& item) { return !item.key; });
        if (free_slot == items.end()) {
            break;
        }
        *free_slot = std::move(extra);
    }

    for (size_t i = 0; i < cells_.size(); ++i) {
        auto& cell = cells_[i];
        if (!items[i].key) {
            lv_obj_add_flag(cell.key, LV_OBJ_FLAG_HIDDEN);
            lv_obj_add_flag(cell.value, LV_OBJ_FLAG_HIDDEN);
            continue;
        }
        const auto& item = items[i];
        lv_label_set_text(cell.key, item.key);
        lv_label_set_text(cell.value, item.value.c_str());
        lv_obj_set_style_text_color(cell.key, colors.text_disabled, 0);
        lv_obj_set_style_text_color(cell.value,
                                    item.tone == Tone::Error     ? colors.error
                                    : item.tone == Tone::Warning ? colors.warning
                                                                 : colors.text,
                                    0);
        lv_obj_remove_flag(cell.key, LV_OBJ_FLAG_HIDDEN);
        lv_obj_remove_flag(cell.value, LV_OBJ_FLAG_HIDDEN);
    }
}

void NetworkDetailScreen::refresh_cb(lv_observer_t* observer, lv_subject_t* subject) {
    LV_UNUSED(subject);
    auto* screen = static_cast<NetworkDetailScreen*>(lv_observer_get_user_data(observer));
    if (screen && screen->message_label_) {
        screen->render();
    }
}

} // namespace screen
