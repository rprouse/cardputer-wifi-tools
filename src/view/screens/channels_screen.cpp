/*
 * SPDX-FileCopyrightText: 2026 Rob Prouse
 *
 * SPDX-License-Identifier: MIT
 */

#include "channels_screen.h"

#include "asset_manager.h"
#include "bindings.h"
#include "theme.h"

#include <algorithm>
#include <cstdio>
#include <string>

namespace screen {
namespace {

constexpr int32_t kPadX          = 8;
constexpr int32_t kChartWidth    = view::kScreenWidth - 2 * kPadX;
constexpr int32_t kHeaderY       = 2;
constexpr int32_t kChartTop      = 20;
constexpr int32_t kBaselineY     = 82;
constexpr int32_t kCountHeight   = 12;
constexpr int32_t kBarMaxHeight  = kBaselineY - kChartTop - kCountHeight;
constexpr int32_t kLabelY        = kBaselineY + 2;
constexpr int32_t kDetailY       = 96;
constexpr int32_t kMinScaleCount = 4;

const lv_font_t* font_or(const lv_font_t* font, const lv_font_t* fallback) {
    return font ? font : fallback;
}

lv_obj_t* make_plain(lv_obj_t* parent) {
    auto* obj = lv_obj_create(parent);
    lv_obj_remove_style_all(obj);
    lv_obj_clear_flag(obj, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_clear_flag(obj, LV_OBJ_FLAG_CLICKABLE);
    return obj;
}

lv_color_t bar_color(const view::ThemePalette& colors, int32_t network_count) {
    if (network_count >= 5) {
        return colors.error;
    }
    if (network_count >= 3) {
        return colors.warning;
    }
    return colors.success;
}

std::string detail_text(const model::WifiModel& wifi) {
    const auto* channel = wifi.selected_channel();
    if (!channel) {
        return {};
    }

    std::string text = "Ch " + std::to_string(channel->channel);
    if (channel->has_connected) {
        text += " (yours)";
    }
    if (channel->network_count == 0) {
        text += "  no networks";
    }
    else {
        text += "  " + std::to_string(channel->network_count) +
                (channel->network_count == 1 ? " network" : " networks");
        if (channel->strongest_percent >= 0) {
            text += "  best " + std::to_string(channel->strongest_percent) + "%";
        }
    }
    if (wifi.band() == model::WifiBand::Ghz24) {
        text += "  overlap " + std::to_string(channel->overlapping_count);
    }
    if (channel->utilization_percent >= 0) {
        text += "  load " + std::to_string(channel->utilization_percent) + "%";
    }
    return text;
}

std::string header_text(const model::WifiModel& wifi) {
    std::string text = model::band_label(wifi.band());
    if (!wifi.can_toggle_band()) {
        text += " only";
    }
    const auto& best = wifi.recommendation();
    if (best.first > 0) {
        text += "   best " + std::to_string(best.first);
        if (best.last != best.first) {
            text += "-" + std::to_string(best.last);
        }
        if (best.dfs) {
            text += " DFS";
        }
    }
    return text;
}

} // namespace

ChannelsScreen::ChannelsScreen(viewmodel::BaseViewModel& view_model, app::AssetManager& assets)
    : BaseScreen(view_model, assets) {
    init();
}

void ChannelsScreen::build_content(lv_obj_t* content) {
    const auto* header_font = font_or(assets().load_standard_font(13), &lv_font_montserrat_14);
    const auto* small_font =
        font_or(assets().load_standard_font(11, app::StandardFontWeight::Regular), &lv_font_montserrat_12);
    const auto* tiny_font =
        font_or(assets().load_standard_font(10, app::StandardFontWeight::Regular), &lv_font_montserrat_10);

    band_label_ = lv_label_create(content);
    lv_obj_set_style_text_font(band_label_, header_font, 0);
    lv_obj_set_pos(band_label_, kPadX, kHeaderY);

    status_label_ = lv_label_create(content);
    lv_obj_set_style_text_font(status_label_, small_font, 0);
    lv_label_bind_text(status_label_, view_model().scan_status_subject(), nullptr);
    lv_obj_align(status_label_, LV_ALIGN_TOP_RIGHT, -kPadX, kHeaderY + 1);

    for (auto& column : columns_) {
        column.highlight = make_plain(content);
        lv_obj_set_style_radius(column.highlight, 3, 0);
        lv_obj_set_style_bg_opa(column.highlight, LV_OPA_20, 0);

        column.bar = make_plain(content);
        lv_obj_set_style_radius(column.bar, 2, 0);
        lv_obj_set_style_bg_opa(column.bar, LV_OPA_COVER, 0);

        column.count = lv_label_create(content);
        lv_obj_set_style_text_font(column.count, tiny_font, 0);
        lv_obj_set_style_text_align(column.count, LV_TEXT_ALIGN_CENTER, 0);

        column.label = lv_label_create(content);
        lv_obj_set_style_text_font(column.label, tiny_font, 0);
        lv_obj_set_style_text_align(column.label, LV_TEXT_ALIGN_CENTER, 0);
    }

    baseline_ = make_plain(content);
    lv_obj_set_style_bg_opa(baseline_, LV_OPA_COVER, 0);
    lv_obj_set_size(baseline_, kChartWidth, 1);
    lv_obj_set_pos(baseline_, kPadX, kBaselineY);

    message_label_ = lv_label_create(content);
    lv_obj_set_style_text_font(message_label_, small_font, 0);
    lv_obj_set_style_text_align(message_label_, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(message_label_, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(message_label_, kChartWidth - 16);
    lv_obj_align(message_label_, LV_ALIGN_TOP_MID, 0, kChartTop + 14);

    detail_label_ = lv_label_create(content);
    lv_obj_set_style_text_font(detail_label_, small_font, 0);
    lv_label_set_long_mode(detail_label_, LV_LABEL_LONG_DOT);
    lv_obj_set_width(detail_label_, kChartWidth);
    lv_obj_set_pos(detail_label_, kPadX, kDetailY);

    reactive::observe_obj(content, view_model().wifi_revision_subject(), refresh_cb, this);
    reactive::observe_obj(content, view_model().dark_mode_subject(), refresh_cb, this);
    render();
}

void ChannelsScreen::render() {
    const auto& wifi = view_model().wifi();
    const auto colors = view::palette(view_model().is_dark_mode());
    const auto& channels = wifi.channels();
    const size_t count = std::min(channels.size(), kMaxColumns);
    const bool no_data = wifi.status() == model::ScanStatus::Starting ||
                         (wifi.status() == model::ScanStatus::Error && wifi.total_networks() == 0);

    lv_label_set_text(band_label_, header_text(wifi).c_str());
    lv_obj_set_style_text_color(band_label_, colors.primary, 0);
    lv_obj_set_style_text_color(status_label_,
                                wifi.status() == model::ScanStatus::Error ? colors.error : colors.text_disabled,
                                0);
    lv_obj_set_style_bg_color(baseline_, colors.border, 0);

    int32_t max_count = kMinScaleCount;
    for (size_t i = 0; i < count; ++i) {
        max_count = std::max(max_count, channels[i].network_count);
    }

    const int32_t column_width = count > 0 ? kChartWidth / static_cast<int32_t>(count) : kChartWidth;
    const int32_t bar_width = std::max<int32_t>(4, column_width - (column_width >= 16 ? 6 : 3));
    const bool sparse_labels = column_width < 18;
    const size_t selected = wifi.selected_index();

    for (size_t i = 0; i < columns_.size(); ++i) {
        auto& column = columns_[i];
        if (i >= count || no_data) {
            lv_obj_add_flag(column.highlight, LV_OBJ_FLAG_HIDDEN);
            lv_obj_add_flag(column.bar, LV_OBJ_FLAG_HIDDEN);
            lv_obj_add_flag(column.count, LV_OBJ_FLAG_HIDDEN);
            lv_obj_add_flag(column.label, LV_OBJ_FLAG_HIDDEN);
            continue;
        }

        const auto& stats = channels[i];
        const bool is_selected = i == selected;
        const int32_t x = kPadX + static_cast<int32_t>(i) * column_width;
        const int32_t center = x + column_width / 2;

        // Selection highlight behind the whole column.
        lv_obj_set_pos(column.highlight, x, kChartTop - 2);
        lv_obj_set_size(column.highlight, column_width, kLabelY + 12 - (kChartTop - 2));
        lv_obj_set_style_bg_color(column.highlight, colors.primary, 0);
        if (is_selected) {
            lv_obj_remove_flag(column.highlight, LV_OBJ_FLAG_HIDDEN);
        }
        else {
            lv_obj_add_flag(column.highlight, LV_OBJ_FLAG_HIDDEN);
        }

        // Bar: height proportional to the number of networks on the channel.
        const int32_t bar_height =
            stats.network_count > 0 ? std::max<int32_t>(3, stats.network_count * kBarMaxHeight / max_count) : 2;
        lv_obj_set_size(column.bar, bar_width, bar_height);
        lv_obj_set_pos(column.bar, center - bar_width / 2, kBaselineY - bar_height);
        lv_obj_set_style_bg_color(column.bar,
                                  stats.network_count > 0 ? bar_color(colors, stats.network_count) : colors.border,
                                  0);
        // Outline the channel of the network this device is connected to.
        lv_obj_set_style_border_width(column.bar, stats.has_connected ? 2 : 0, 0);
        lv_obj_set_style_border_color(column.bar, colors.info, 0);
        lv_obj_remove_flag(column.bar, LV_OBJ_FLAG_HIDDEN);

        if (stats.network_count > 0) {
            lv_label_set_text_fmt(column.count, "%d", static_cast<int>(stats.network_count));
            lv_obj_set_width(column.count, 24);
            lv_obj_set_pos(column.count, center - 12, kBaselineY - bar_height - kCountHeight);
            lv_obj_set_style_text_color(column.count, stats.has_connected ? colors.info : colors.text, 0);
            lv_obj_remove_flag(column.count, LV_OBJ_FLAG_HIDDEN);
        }
        else {
            lv_obj_add_flag(column.count, LV_OBJ_FLAG_HIDDEN);
        }

        // Channel numbers: every channel when there is room, otherwise alternate ones plus the
        // selection (skipping neighbours of the selection so labels never collide).
        const bool next_to_selected = (i + 1 == selected) || (i == selected + 1);
        const bool show_label =
            !sparse_labels || is_selected || (i % 2 == selected % 2 && !next_to_selected);
        if (show_label) {
            lv_label_set_text_fmt(column.label, "%d", static_cast<int>(stats.channel));
            lv_obj_set_width(column.label, 24);
            lv_obj_set_pos(column.label, center - 12, kLabelY);
            lv_obj_set_style_text_color(column.label, is_selected ? colors.primary : colors.text_disabled, 0);
            lv_obj_remove_flag(column.label, LV_OBJ_FLAG_HIDDEN);
        }
        else {
            lv_obj_add_flag(column.label, LV_OBJ_FLAG_HIDDEN);
        }
    }

    if (no_data) {
        lv_label_set_text(message_label_,
                          wifi.status() == model::ScanStatus::Error ? wifi.error().c_str()
                                                                    : "Scanning for networks...");
        lv_obj_set_style_text_color(message_label_,
                                    wifi.status() == model::ScanStatus::Error ? colors.error : colors.text,
                                    0);
        lv_obj_remove_flag(message_label_, LV_OBJ_FLAG_HIDDEN);
        lv_obj_add_flag(detail_label_, LV_OBJ_FLAG_HIDDEN);
        return;
    }

    lv_obj_add_flag(message_label_, LV_OBJ_FLAG_HIDDEN);
    lv_obj_remove_flag(detail_label_, LV_OBJ_FLAG_HIDDEN);
    if (wifi.status() == model::ScanStatus::Error) {
        lv_label_set_text(detail_label_, wifi.error().c_str());
        lv_obj_set_style_text_color(detail_label_, colors.error, 0);
    }
    else {
        lv_label_set_text(detail_label_, detail_text(wifi).c_str());
        lv_obj_set_style_text_color(detail_label_, colors.text, 0);
    }
}

void ChannelsScreen::refresh_cb(lv_observer_t* observer, lv_subject_t* subject) {
    LV_UNUSED(subject);
    auto* screen = static_cast<ChannelsScreen*>(lv_observer_get_user_data(observer));
    if (screen && screen->detail_label_) {
        screen->render();
    }
}

} // namespace screen
