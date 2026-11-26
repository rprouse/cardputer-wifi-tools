/*
 * SPDX-License-Identifier: MIT
 */

#include "wifi_model.h"

#include <algorithm>
#include <cstdlib>
#include <utility>

namespace model {
namespace {

// Standard 20 MHz 5 GHz channels (UNII-1 through UNII-3).
constexpr std::array<int32_t, 25> k5GhzChannels = {{
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
}};

constexpr int32_t kOverlapDistance = 4;

std::vector<int32_t> channel_list(WifiBand band, const std::vector<AccessPointInfo>& aps) {
    std::vector<int32_t> channels;
    if (band == WifiBand::Ghz24) {
        for (int32_t ch = 1; ch <= 13; ++ch) {
            channels.push_back(ch);
        }
    }
    else {
        channels.assign(k5GhzChannels.begin(), k5GhzChannels.end());
    }

    // Include any non-standard channel that is actually in use (e.g. 14, 169, 173).
    for (const auto& ap : aps) {
        if (frequency_in_band(ap.frequency_mhz, band) &&
            std::find(channels.begin(), channels.end(), ap.channel) == channels.end()) {
            channels.push_back(ap.channel);
        }
    }
    std::sort(channels.begin(), channels.end());
    return channels;
}

} // namespace

const char* band_label(WifiBand band) {
    return band == WifiBand::Ghz24 ? "2.4 GHz" : "5 GHz";
}

bool frequency_in_band(int32_t frequency_mhz, WifiBand band) {
    if (band == WifiBand::Ghz24) {
        return frequency_mhz >= 2400 && frequency_mhz < 2500;
    }
    return frequency_mhz >= 5150 && frequency_mhz < 5925;
}

std::vector<ChannelStats> compute_channel_stats(WifiBand band, const std::vector<AccessPointInfo>& aps) {
    std::vector<ChannelStats> stats;
    for (const auto channel : channel_list(band, aps)) {
        ChannelStats entry;
        entry.channel = channel;
        for (const auto& ap : aps) {
            if (!frequency_in_band(ap.frequency_mhz, band)) {
                continue;
            }
            if (ap.channel == channel) {
                ++entry.network_count;
                entry.strongest_percent = std::max(entry.strongest_percent, ap.strength_percent);
                entry.utilization_percent =
                    std::max(entry.utilization_percent, ap.channel_utilization_percent);
            }
            else if (band == WifiBand::Ghz24 && std::abs(ap.channel - channel) <= kOverlapDistance) {
                ++entry.overlapping_count;
            }
        }
        stats.push_back(entry);
    }
    return stats;
}

WifiModel::WifiModel() {
    rebuild();
}

WifiBand WifiModel::band() const {
    return band_;
}

void WifiModel::toggle_band() {
    band_ = band_ == WifiBand::Ghz24 ? WifiBand::Ghz5 : WifiBand::Ghz24;
    rebuild();
}

const std::vector<ChannelStats>& WifiModel::channels() const {
    return channels_;
}

size_t WifiModel::selected_index() const {
    return selected_index_;
}

const ChannelStats* WifiModel::selected_channel() const {
    return selected_index_ < channels_.size() ? &channels_[selected_index_] : nullptr;
}

void WifiModel::select_previous() {
    if (channels_.empty()) {
        return;
    }
    selected_index_ = selected_index_ == 0 ? channels_.size() - 1 : selected_index_ - 1;
    selected_channel_[static_cast<size_t>(band_)] = channels_[selected_index_].channel;
}

void WifiModel::select_next() {
    if (channels_.empty()) {
        return;
    }
    selected_index_ = (selected_index_ + 1) % channels_.size();
    selected_channel_[static_cast<size_t>(band_)] = channels_[selected_index_].channel;
}

void WifiModel::apply_scan(std::vector<AccessPointInfo> aps) {
    access_points_ = std::move(aps);
    status_ = ScanStatus::Ok;
    error_.clear();
    rebuild();
}

void WifiModel::apply_error(std::string error) {
    // Keep the last good data on screen; only surface the error.
    status_ = ScanStatus::Error;
    error_ = std::move(error);
}

ScanStatus WifiModel::status() const {
    return status_;
}

const std::string& WifiModel::error() const {
    return error_;
}

size_t WifiModel::total_networks() const {
    return access_points_.size();
}

size_t WifiModel::band_networks() const {
    return static_cast<size_t>(std::count_if(access_points_.begin(), access_points_.end(), [this](const auto& ap) {
        return frequency_in_band(ap.frequency_mhz, band_);
    }));
}

void WifiModel::rebuild() {
    channels_ = compute_channel_stats(band_, access_points_);

    const int32_t wanted = selected_channel_[static_cast<size_t>(band_)];
    selected_index_ = 0;
    int32_t best_distance = -1;
    for (size_t i = 0; i < channels_.size(); ++i) {
        const int32_t distance = std::abs(channels_[i].channel - wanted);
        if (best_distance < 0 || distance < best_distance) {
            best_distance = distance;
            selected_index_ = i;
        }
    }
}

} // namespace model
