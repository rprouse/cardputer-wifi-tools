/*
 * SPDX-FileCopyrightText: 2026 Rob Prouse
 *
 * SPDX-License-Identifier: MIT
 */

#include "wifi_model.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <sstream>
#include <tuple>
#include <utility>

namespace model {
namespace {

// Standard 20 MHz 5 GHz channels (UNII-1 through UNII-3).
constexpr std::array<int32_t, 25> k5GhzChannels = {{
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
}};

// Non-overlapping 2.4 GHz channels.
constexpr std::array<int32_t, 3> k24GhzCandidates = {{1, 6, 11}};

struct ChannelGroup {
    int32_t first;
    int32_t last;
    bool dfs;  // needs radar detection; many APs avoid these
};

// 80 MHz groups, the common width for modern 5 GHz access points.
constexpr std::array<ChannelGroup, 6> k5GhzGroups = {{
    {36, 48, false},
    {52, 64, true},
    {100, 112, true},
    {116, 128, true},
    {132, 144, true},
    {149, 161, false},
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

bool has_token(const std::string& tokens, const char* token) {
    std::istringstream stream(tokens);
    std::string word;
    while (stream >> word) {
        if (word == token) {
            return true;
        }
    }
    return false;
}

std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return text;
}

int32_t signal_weight(const AccessPointInfo& ap) {
    return std::max<int32_t>(ap.strength_percent, 0);
}

} // namespace

SecurityInfo describe_security(const std::string& tokens) {
    const bool wpa1 = has_token(tokens, "WPA1") || has_token(tokens, "WPA");
    const bool wpa2 = has_token(tokens, "WPA2");
    const bool wpa3 = has_token(tokens, "WPA3") || has_token(tokens, "SAE");
    const bool enterprise = has_token(tokens, "802.1X");
    const bool wep = has_token(tokens, "WEP");
    const bool owe = has_token(tokens, "OWE");

    SecurityInfo info;
    if (wpa2 && wpa3) {
        info.label = "WPA2/3";
    }
    else if (wpa3) {
        info.label = "WPA3";
    }
    else if (wpa1 && wpa2) {
        // Mixed mode keeps TKIP enabled for old clients.
        info.label = "WPA1/2";
        info.level = SecurityLevel::Weak;
    }
    else if (wpa2) {
        info.label = "WPA2";
    }
    else if (wpa1) {
        info.label = "WPA1";
        info.level = SecurityLevel::Weak;
    }
    else if (wep) {
        info.label = "WEP";
        info.level = SecurityLevel::Weak;
    }
    else if (owe) {
        info.label = "OWE";
    }
    else {
        info.label = "Open";
        info.level = SecurityLevel::Open;
    }

    if (enterprise && (wpa1 || wpa2 || wpa3)) {
        info.label += "-Ent";
    }
    return info;
}

const char* band_label(WifiBand band) {
    return band == WifiBand::Ghz24 ? "2.4 GHz" : "5 GHz";
}

const char* sort_label(NetworkSort sort) {
    switch (sort) {
        case NetworkSort::Channel:
            return "channel";
        case NetworkSort::Name:
            return "name";
        case NetworkSort::Signal:
        default:
            return "signal";
    }
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
                entry.has_connected |= ap.connected;
            }
            else if (band == WifiBand::Ghz24 && std::abs(ap.channel - channel) <= kOverlapDistance) {
                ++entry.overlapping_count;
            }
        }
        stats.push_back(entry);
    }
    return stats;
}

ChannelRecommendation recommend_channel(WifiBand band, const std::vector<AccessPointInfo>& aps) {
    std::string own_ssid;
    for (const auto& ap : aps) {
        if (ap.connected) {
            own_ssid = ap.ssid;
        }
    }
    const auto is_own = [&](const AccessPointInfo& ap) {
        return ap.connected || (!own_ssid.empty() && ap.ssid == own_ssid);
    };

    ChannelRecommendation best;
    if (band == WifiBand::Ghz24) {
        int64_t best_score = -1;
        for (const auto candidate : k24GhzCandidates) {
            int64_t score = 0;
            for (const auto& ap : aps) {
                if (!frequency_in_band(ap.frequency_mhz, band) || is_own(ap)) {
                    continue;
                }
                const int32_t distance = std::abs(ap.channel - candidate);
                if (distance <= kOverlapDistance) {
                    // Same channel counts fully; partial overlap counts less the further away it is.
                    score += static_cast<int64_t>(signal_weight(ap)) * (kOverlapDistance + 1 - distance);
                }
            }
            if (best_score < 0 || score < best_score) {
                best_score = score;
                best = {candidate, candidate};
            }
        }
        return best;
    }

    std::tuple<int64_t, bool> best_key{-1, true};
    for (const auto& group : k5GhzGroups) {
        int64_t score = 0;
        for (const auto& ap : aps) {
            if (frequency_in_band(ap.frequency_mhz, band) && !is_own(ap) && ap.channel >= group.first &&
                ap.channel <= group.last) {
                score += signal_weight(ap);
            }
        }
        // Lower score wins; on a tie prefer channels that do not need radar detection.
        const std::tuple<int64_t, bool> key{score, group.dfs};
        if (std::get<0>(best_key) < 0 || key < best_key) {
            best_key = key;
            best = {group.first, group.last, group.dfs};
        }
    }
    return best;
}

WifiModel::WifiModel() {
    rebuild();
}

WifiBand WifiModel::band() const {
    return band_;
}

void WifiModel::toggle_band() {
    if (!can_toggle_band()) {
        return;
    }
    band_ = band_ == WifiBand::Ghz24 ? WifiBand::Ghz5 : WifiBand::Ghz24;
    network_filter_ = 0;
    selected_bssid_.clear();
    rebuild();
}

bool WifiModel::band_supported(WifiBand band) const {
    return band_supported_[static_cast<size_t>(band)];
}

bool WifiModel::can_toggle_band() const {
    return band_supported_[0] && band_supported_[1];
}

void WifiModel::set_band_support(bool ghz24, bool ghz5) {
    if (!ghz24 && !ghz5) {
        return;
    }
    band_supported_ = {{ghz24, ghz5}};
    if (!band_supported(band_)) {
        band_ = ghz24 ? WifiBand::Ghz24 : WifiBand::Ghz5;
        network_filter_ = 0;
        selected_bssid_.clear();
        rebuild();
    }
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

const ChannelRecommendation& WifiModel::recommendation() const {
    return recommendation_;
}

const std::vector<const AccessPointInfo*>& WifiModel::networks() const {
    return networks_;
}

size_t WifiModel::selected_network_index() const {
    return selected_network_index_;
}

const AccessPointInfo* WifiModel::selected_network() const {
    return selected_network_index_ < networks_.size() ? networks_[selected_network_index_] : nullptr;
}

void WifiModel::select_previous_network() {
    if (networks_.empty()) {
        return;
    }
    selected_network_index_ =
        selected_network_index_ == 0 ? networks_.size() - 1 : selected_network_index_ - 1;
    selected_bssid_ = networks_[selected_network_index_]->bssid;
}

void WifiModel::select_next_network() {
    if (networks_.empty()) {
        return;
    }
    selected_network_index_ = (selected_network_index_ + 1) % networks_.size();
    selected_bssid_ = networks_[selected_network_index_]->bssid;
}

int32_t WifiModel::network_filter() const {
    return network_filter_;
}

void WifiModel::set_network_filter(int32_t channel) {
    network_filter_ = channel;
    selected_bssid_.clear();
    rebuild_networks();
}

std::vector<int32_t> WifiModel::filter_choices() const {
    std::vector<int32_t> choices{0};
    for (const auto& stats : channels_) {
        if (stats.network_count > 0 || stats.channel == network_filter_) {
            choices.push_back(stats.channel);
        }
    }
    return choices;
}

void WifiModel::previous_network_filter() {
    const auto choices = filter_choices();
    auto it = std::find(choices.begin(), choices.end(), network_filter_);
    const size_t index = it == choices.end() ? 0 : static_cast<size_t>(it - choices.begin());
    set_network_filter(choices[index == 0 ? choices.size() - 1 : index - 1]);
}

void WifiModel::next_network_filter() {
    const auto choices = filter_choices();
    auto it = std::find(choices.begin(), choices.end(), network_filter_);
    const size_t index = it == choices.end() ? 0 : static_cast<size_t>(it - choices.begin());
    set_network_filter(choices[(index + 1) % choices.size()]);
}

NetworkSort WifiModel::network_sort() const {
    return network_sort_;
}

void WifiModel::cycle_network_sort() {
    network_sort_ = static_cast<NetworkSort>((static_cast<int>(network_sort_) + 1) % 3);
    rebuild_networks();
}

const AccessPointInfo* WifiModel::connected_network() const {
    for (const auto& ap : access_points_) {
        if (ap.connected) {
            return &ap;
        }
    }
    return nullptr;
}

void WifiModel::pin_selected_network() {
    if (const auto* ap = selected_network()) {
        selected_bssid_ = ap->bssid;
    }
}

bool WifiModel::selected_network_present() const {
    const auto* ap = selected_network();
    return ap && (selected_bssid_.empty() || ap->bssid == selected_bssid_);
}

std::vector<const AccessPointInfo*> WifiModel::same_ssid(const AccessPointInfo& ap) const {
    std::vector<const AccessPointInfo*> matches;
    for (const auto& other : access_points_) {
        if (&other == &ap || (!ap.ssid.empty() && other.ssid == ap.ssid)) {
            matches.push_back(&other);
        }
    }
    std::sort(matches.begin(), matches.end(), [](const AccessPointInfo* a, const AccessPointInfo* b) {
        return a->frequency_mhz < b->frequency_mhz;
    });
    return matches;
}

const ChannelStats* WifiModel::channel_stats(int32_t channel) const {
    for (const auto& stats : channels_) {
        if (stats.channel == channel) {
            return &stats;
        }
    }
    return nullptr;
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
    recommendation_ = status_ == ScanStatus::Starting ? ChannelRecommendation{}
                                                      : recommend_channel(band_, access_points_);

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

    rebuild_networks();
}

void WifiModel::rebuild_networks() {
    networks_.clear();
    for (const auto& ap : access_points_) {
        if (frequency_in_band(ap.frequency_mhz, band_) &&
            (network_filter_ == 0 || ap.channel == network_filter_)) {
            networks_.push_back(&ap);
        }
    }

    const auto by_signal = [](const AccessPointInfo* a, const AccessPointInfo* b) {
        return a->strength_percent > b->strength_percent;
    };
    const auto by_name = [](const AccessPointInfo* a, const AccessPointInfo* b) {
        // Hidden networks (empty SSID) sort last.
        if (a->ssid.empty() != b->ssid.empty()) {
            return b->ssid.empty();
        }
        return lower(a->ssid) < lower(b->ssid);
    };
    std::stable_sort(networks_.begin(), networks_.end(), [&](const AccessPointInfo* a, const AccessPointInfo* b) {
        switch (network_sort_) {
            case NetworkSort::Channel:
                if (a->channel != b->channel) {
                    return a->channel < b->channel;
                }
                return by_signal(a, b);
            case NetworkSort::Name:
                if (by_name(a, b) || by_name(b, a)) {
                    return by_name(a, b);
                }
                return by_signal(a, b);
            case NetworkSort::Signal:
            default:
                if (a->strength_percent != b->strength_percent) {
                    return by_signal(a, b);
                }
                return by_name(a, b);
        }
    });

    // Keep the cursor on the same access point across rescans and re-sorts.
    selected_network_index_ = 0;
    if (!selected_bssid_.empty()) {
        for (size_t i = 0; i < networks_.size(); ++i) {
            if (networks_[i]->bssid == selected_bssid_) {
                selected_network_index_ = i;
                break;
            }
        }
    }
}

} // namespace model
