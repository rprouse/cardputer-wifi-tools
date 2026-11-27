/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */

#include "base_viewmodel.h"

#include <cstdio>
#include <cstring>
#include <utility>
#include <vector>

namespace viewmodel {
namespace {

constexpr uint32_t kScanIntervalMs = 5000;
constexpr uint32_t kPollIntervalMs = 250;

int page_to_int(model::AppPage page) {
    return static_cast<int>(page);
}

} // namespace

BaseViewModel::BaseViewModel()
    : title_subject_(model_.app_title()),
      dark_mode_subject_(model_.dark_mode()),
      current_page_subject_(page_to_int(model_.current_page())),
      quit_requested_subject_(false),
      wifi_revision_subject_(0),
      scan_paused_subject_(false),
      scan_status_subject_("Scanning..."),
      band_toggle_subject_(true) {}

BaseViewModel::~BaseViewModel() {
    if (poll_timer_) {
        lv_timer_delete(poll_timer_);
        poll_timer_ = nullptr;
    }
    scanner_.stop();
}

lv_subject_t* BaseViewModel::title_subject() {
    return title_subject_.native();
}

lv_subject_t* BaseViewModel::dark_mode_subject() {
    return dark_mode_subject_.native();
}

lv_subject_t* BaseViewModel::current_page_subject() {
    return current_page_subject_.native();
}

lv_subject_t* BaseViewModel::quit_requested_subject() {
    return quit_requested_subject_.native();
}

lv_subject_t* BaseViewModel::wifi_revision_subject() {
    return wifi_revision_subject_.native();
}

lv_subject_t* BaseViewModel::scan_paused_subject() {
    return scan_paused_subject_.native();
}

lv_subject_t* BaseViewModel::scan_status_subject() {
    return scan_status_subject_.native();
}

lv_subject_t* BaseViewModel::band_toggle_subject() {
    return band_toggle_subject_.native();
}

bool BaseViewModel::is_dark_mode() const {
    return model_.dark_mode();
}

void BaseViewModel::set_dark_mode(bool enabled) {
    model_.set_dark_mode(enabled);
    publish_all();
}

void BaseViewModel::toggle_dark_mode() {
    model_.toggle_dark_mode();
    publish_all();
}

model::AppPage BaseViewModel::current_page() const {
    return model_.current_page();
}

void BaseViewModel::show_networks_page(int32_t filter_channel) {
    wifi_model_.set_network_filter(filter_channel);
    model_.set_current_page(model::AppPage::Networks);
    publish_wifi();
    publish_all();
}

void BaseViewModel::show_channels_page() {
    model_.set_current_page(model::AppPage::Channels);
    publish_all();
}

void BaseViewModel::request_quit() {
    quit_requested_subject_.set(true);
}

void BaseViewModel::start_scanning() {
    if (poll_timer_) {
        return;
    }
    scanner_.start(kScanIntervalMs);
    poll_timer_ = lv_timer_create(poll_timer_cb, kPollIntervalMs, this);
}

const model::WifiModel& BaseViewModel::wifi() const {
    return wifi_model_;
}

bool BaseViewModel::scan_paused() const {
    return scanner_.paused();
}

bool BaseViewModel::can_toggle_band() const {
    return wifi_model_.can_toggle_band();
}

void BaseViewModel::toggle_scan_paused() {
    const bool paused = !scanner_.paused();
    scanner_.set_paused(paused);
    scan_paused_subject_.set(paused);
    update_status_text();
}

void BaseViewModel::toggle_band() {
    wifi_model_.toggle_band();
    publish_wifi();
}

void BaseViewModel::select_previous_channel() {
    wifi_model_.select_previous();
    publish_wifi();
}

void BaseViewModel::select_next_channel() {
    wifi_model_.select_next();
    publish_wifi();
}

void BaseViewModel::select_previous_network() {
    wifi_model_.select_previous_network();
    publish_wifi();
}

void BaseViewModel::select_next_network() {
    wifi_model_.select_next_network();
    publish_wifi();
}

void BaseViewModel::previous_network_filter() {
    wifi_model_.previous_network_filter();
    publish_wifi();
}

void BaseViewModel::next_network_filter() {
    wifi_model_.next_network_filter();
    publish_wifi();
}

void BaseViewModel::cycle_network_sort() {
    wifi_model_.cycle_network_sort();
    publish_wifi();
}

void BaseViewModel::publish_all() {
    title_subject_.set(model_.app_title());
    dark_mode_subject_.set(model_.dark_mode());
    current_page_subject_.set(page_to_int(model_.current_page()));
}

void BaseViewModel::publish_wifi() {
    wifi_revision_subject_.set(wifi_revision_subject_.value() + 1);
    update_status_text();
}

void BaseViewModel::update_status_text() {
    char text[48];
    if (scanner_.paused()) {
        std::snprintf(text, sizeof(text), "Paused");
    }
    else if (!has_result_) {
        std::snprintf(text, sizeof(text), "Scanning...");
    }
    else if (wifi_model_.status() == model::ScanStatus::Error) {
        std::snprintf(text, sizeof(text), "Scan failed");
    }
    else {
        const uint32_t age_s = lv_tick_elaps(last_result_tick_) / 1000;
        std::snprintf(text,
                      sizeof(text),
                      "%u nets  %us ago",
                      static_cast<unsigned>(wifi_model_.band_networks()),
                      static_cast<unsigned>(age_s));
    }

    if (std::strcmp(text, scan_status_subject_.value()) != 0) {
        scan_status_subject_.set(text);
    }
}

void BaseViewModel::poll_scanner() {
    platform::WifiScanResult result;
    if (scanner_.take_result(result)) {
        has_result_ = true;
        last_result_tick_ = lv_tick_get();
        if (result.ok) {
            wifi_model_.set_band_support(result.supports_24ghz, result.supports_5ghz);
            if (band_toggle_subject_.value() != wifi_model_.can_toggle_band()) {
                band_toggle_subject_.set(wifi_model_.can_toggle_band());
            }
            std::vector<model::AccessPointInfo> aps;
            aps.reserve(result.access_points.size());
            for (auto& ap : result.access_points) {
                aps.push_back(model::AccessPointInfo{std::move(ap.ssid),
                                                     std::move(ap.bssid),
                                                     ap.frequency_mhz,
                                                     ap.channel,
                                                     ap.strength_percent,
                                                     ap.channel_utilization_percent,
                                                     std::move(ap.security),
                                                     ap.connected});
            }
            wifi_model_.apply_scan(std::move(aps));
        }
        else {
            wifi_model_.apply_error(std::move(result.error));
        }
        publish_wifi();
        return;
    }
    update_status_text();
}

void BaseViewModel::poll_timer_cb(lv_timer_t* timer) {
    auto* self = static_cast<BaseViewModel*>(lv_timer_get_user_data(timer));
    if (self) {
        self->poll_scanner();
    }
}

} // namespace viewmodel
