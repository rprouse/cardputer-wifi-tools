/*
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace platform {

struct WifiAccessPoint {
    std::string ssid;
    std::string bssid;
    int32_t frequency_mhz{0};
    int32_t channel{0};
    int32_t strength_percent{-1};
    // Channel utilisation advertised by the AP in its BSS Load element, or -1 when unknown.
    int32_t channel_utilization_percent{-1};
    // Space-separated security tokens, e.g. "WPA2 WPA3", "WPA2 802.1X", "WEP", "OWE".
    // Empty means an open network.
    std::string security;
    // True for the access point this device is currently associated with.
    bool connected{false};

    // Extra detail; empty / 0 when the backend cannot report it.
    int32_t signal_dbm{0};
    // True when signal_dbm was estimated from the percentage (nmcli only reports a percentage).
    bool signal_dbm_estimated{false};
    int32_t channel_width_mhz{0};
    int32_t max_rate_mbps{0};
    // "Wi-Fi 6", "Wi-Fi 5", "Wi-Fi 4" or empty.
    std::string standard;
    // "Infra", "Ad-Hoc", "Mesh" or empty.
    std::string mode;
    // Key management, e.g. "PSK SAE", "802.1X".
    std::string key_mgmt;
    // Pairwise ciphers, e.g. "CCMP", "TKIP CCMP".
    std::string ciphers;
    // Interfaces that saw this access point, e.g. "wlan0 wlan1".
    std::string devices;
};

struct WifiScanResult {
    bool ok{false};
    std::string error;
    std::vector<WifiAccessPoint> access_points;
    // Bands the WiFi radio(s) can scan. Both stay true when the backend cannot tell.
    bool supports_24ghz{true};
    bool supports_5ghz{true};
};

// Maps a centre frequency to its IEEE 802.11 channel number, or 0 when unknown.
int32_t wifi_frequency_to_channel(int32_t frequency_mhz);

// Runs WiFi scans on a worker thread so the LVGL loop never blocks.
//
// Backends:
//   Windows  - Native WLAN API (wlanapi). Needs Location access enabled in Windows Settings.
//   Linux    - NetworkManager via `nmcli` (desktop Linux and the CardputerZero device).
//   Others   - Reports an explicit "not supported" error.
class WifiScanner {
public:
    WifiScanner();
    ~WifiScanner();

    WifiScanner(const WifiScanner&) = delete;
    WifiScanner& operator=(const WifiScanner&) = delete;

    void start(uint32_t interval_ms);
    void stop();
    void set_paused(bool paused);
    bool paused() const;

    // True while a scan request is in flight.
    bool busy() const;

    // Moves the newest unread result into `result`. Returns false when nothing new arrived.
    bool take_result(WifiScanResult& result);

private:
    void run();

    std::thread worker_;
    mutable std::mutex mutex_;
    std::condition_variable wake_;
    WifiScanResult pending_;
    bool has_pending_{false};
    bool stop_requested_{false};
    std::atomic<bool> paused_{false};
    std::atomic<bool> busy_{false};
    uint32_t interval_ms_{5000};
};

} // namespace platform
