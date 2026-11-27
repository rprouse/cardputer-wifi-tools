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
    // Raw security tokens from the scanner ("WPA2 WPA3", "WEP", ...); empty means open.
    std::string security;
    bool connected{false};
};

enum class SecurityLevel {
    Open,  // no encryption
    Weak,  // WEP or WPA1 only
    Good,  // WPA2 / WPA3 / OWE
};

struct SecurityInfo {
    std::string label;  // short label for display, e.g. "WPA2/3", "WPA2-Ent", "Open"
    SecurityLevel level{SecurityLevel::Good};
};

SecurityInfo describe_security(const std::string& tokens);

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
    // True when the network this device is connected to uses this channel.
    bool has_connected{false};
};

// Least congested channel (2.4 GHz) or 80 MHz channel group (5 GHz). first == 0 when unknown.
struct ChannelRecommendation {
    int32_t first{0};
    int32_t last{0};
    // 5 GHz channels 52-144 need radar detection (DFS); not every AP or client supports them.
    bool dfs{false};
};

enum class ScanStatus {
    Starting,
    Ok,
    Error,
};

enum class NetworkSort {
    Signal  = 0,
    Channel = 1,
    Name    = 2,
};

const char* band_label(WifiBand band);
const char* sort_label(NetworkSort sort);
bool frequency_in_band(int32_t frequency_mhz, WifiBand band);
std::vector<ChannelStats> compute_channel_stats(WifiBand band, const std::vector<AccessPointInfo>& aps);
// Scores candidates by the signal strength of networks that would share airtime, ignoring the
// network this device is connected to (it is the one you would be moving).
ChannelRecommendation recommend_channel(WifiBand band, const std::vector<AccessPointInfo>& aps);

class WifiModel {
public:
    WifiModel();

    WifiBand band() const;
    // Does nothing when the radio only supports one band.
    void toggle_band();
    bool band_supported(WifiBand band) const;
    bool can_toggle_band() const;
    // Records which bands the radio can scan; moves to a supported band if the current one is not.
    void set_band_support(bool ghz24, bool ghz5);

    // Channel chart
    const std::vector<ChannelStats>& channels() const;
    size_t selected_index() const;
    const ChannelStats* selected_channel() const;
    void select_previous();
    void select_next();
    const ChannelRecommendation& recommendation() const;

    // Network list: networks in the current band, optionally limited to one channel.
    const std::vector<const AccessPointInfo*>& networks() const;
    size_t selected_network_index() const;
    const AccessPointInfo* selected_network() const;
    void select_previous_network();
    void select_next_network();
    // 0 = all channels.
    int32_t network_filter() const;
    void set_network_filter(int32_t channel);
    void previous_network_filter();
    void next_network_filter();
    NetworkSort network_sort() const;
    void cycle_network_sort();

    const AccessPointInfo* connected_network() const;

    void apply_scan(std::vector<AccessPointInfo> aps);
    void apply_error(std::string error);

    ScanStatus status() const;
    const std::string& error() const;
    size_t total_networks() const;
    size_t band_networks() const;

private:
    void rebuild();
    void rebuild_networks();
    std::vector<int32_t> filter_choices() const;

    WifiBand band_{WifiBand::Ghz24};
    std::array<bool, 2> band_supported_{{true, true}};
    std::vector<AccessPointInfo> access_points_;
    std::vector<ChannelStats> channels_;
    ChannelRecommendation recommendation_;
    // Remember the selected channel number per band so switching bands keeps the cursor.
    std::array<int32_t, 2> selected_channel_{{6, 36}};
    size_t selected_index_{0};

    std::vector<const AccessPointInfo*> networks_;
    size_t selected_network_index_{0};
    std::string selected_bssid_;
    int32_t network_filter_{0};
    NetworkSort network_sort_{NetworkSort::Signal};

    ScanStatus status_{ScanStatus::Starting};
    std::string error_;
};

} // namespace model
