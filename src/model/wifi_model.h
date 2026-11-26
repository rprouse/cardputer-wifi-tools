/*
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace model {

enum class WifiBand {
    Ghz24 = 0,
    Ghz5  = 1,
};

struct AccessPointInfo {
    std::string ssid;
    std::string bssid;
    int32_t frequency_mhz{0};
    int32_t channel{0};
    int32_t strength_percent{-1};
    int32_t channel_utilization_percent{-1};
};

struct ChannelStats {
    int32_t channel{0};
    // Networks whose primary channel is this channel.
    int32_t network_count{0};
    // Strongest signal on this channel, 0-100, or -1 when the channel is empty.
    int32_t strongest_percent{-1};
    // 2.4 GHz only: networks on other channels close enough to overlap (within 4 channels).
    int32_t overlapping_count{0};
    // Highest BSS Load utilisation reported by an AP on this channel, or -1 when none reported.
    int32_t utilization_percent{-1};
};

enum class ScanStatus {
    Starting,
    Ok,
    Error,
};

const char* band_label(WifiBand band);
bool frequency_in_band(int32_t frequency_mhz, WifiBand band);
std::vector<ChannelStats> compute_channel_stats(WifiBand band, const std::vector<AccessPointInfo>& aps);

class WifiModel {
public:
    WifiModel();

    WifiBand band() const;
    void toggle_band();

    const std::vector<ChannelStats>& channels() const;
    size_t selected_index() const;
    const ChannelStats* selected_channel() const;
    void select_previous();
    void select_next();

    void apply_scan(std::vector<AccessPointInfo> aps);
    void apply_error(std::string error);

    ScanStatus status() const;
    const std::string& error() const;
    size_t total_networks() const;
    size_t band_networks() const;

private:
    void rebuild();

    WifiBand band_{WifiBand::Ghz24};
    std::vector<AccessPointInfo> access_points_;
    std::vector<ChannelStats> channels_;
    // Remember the selected channel number per band so switching bands keeps the cursor.
    std::array<int32_t, 2> selected_channel_{{6, 36}};
    size_t selected_index_{0};
    ScanStatus status_{ScanStatus::Starting};
    std::string error_;
};

} // namespace model
