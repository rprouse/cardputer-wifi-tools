/*
 * SPDX-FileCopyrightText: 2026 Rob Prouse
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "subjects.h"
#include "base_model.h"
#include "wifi_model.h"
#include "wifi_scan.h"

#include "lvgl.h"

#include <cstdint>

namespace viewmodel {

class BaseViewModel {
public:
    BaseViewModel();
    ~BaseViewModel();

    BaseViewModel(const BaseViewModel&) = delete;
    BaseViewModel& operator=(const BaseViewModel&) = delete;

    lv_subject_t* title_subject();
    lv_subject_t* dark_mode_subject();
    lv_subject_t* current_page_subject();
    lv_subject_t* quit_requested_subject();
    // Bumped whenever channel data, band, or selection changes.
    lv_subject_t* wifi_revision_subject();
    lv_subject_t* scan_paused_subject();
    lv_subject_t* scan_status_subject();
    // False when the radio only supports one band, so the band button is disabled.
    lv_subject_t* band_toggle_subject();

    bool is_dark_mode() const;
    void set_dark_mode(bool enabled);
    void toggle_dark_mode();

    model::AppPage current_page() const;
    // Opens the network list; filter_channel limits it to one channel (0 = all).
    void show_networks_page(int32_t filter_channel);
    void show_channels_page();
    // Opens the details page for the selected network.
    void show_network_detail_page();
    // Back to the network list, keeping its filter and selection.
    void return_to_networks_page();
    void request_quit();

    // WiFi scanning
    void start_scanning();
    const model::WifiModel& wifi() const;
    bool scan_paused() const;
    bool can_toggle_band() const;
    void toggle_scan_paused();
    void toggle_band();
    void select_previous_channel();
    void select_next_channel();
    void select_previous_network();
    void select_next_network();
    void previous_network_filter();
    void next_network_filter();
    void cycle_network_sort();

private:
    void publish_all();
    void publish_wifi();
    void update_status_text();
    void poll_scanner();
    static void poll_timer_cb(lv_timer_t* timer);

    model::BaseModel model_;
    model::WifiModel wifi_model_;
    platform::WifiScanner scanner_;
    lv_timer_t* poll_timer_{nullptr};
    uint32_t last_result_tick_{0};
    bool has_result_{false};

    reactive::StringSubject<32> title_subject_;
    reactive::BoolSubject dark_mode_subject_;
    reactive::IntSubject current_page_subject_;
    reactive::BoolSubject quit_requested_subject_;
    reactive::IntSubject wifi_revision_subject_;
    reactive::BoolSubject scan_paused_subject_;
    reactive::StringSubject<48> scan_status_subject_;
    reactive::BoolSubject band_toggle_subject_;
};

} // namespace viewmodel
