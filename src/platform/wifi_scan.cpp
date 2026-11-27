/*
 * SPDX-License-Identifier: MIT
 */

#include "wifi_scan.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <string>
#include <utility>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wlanapi.h>
#elif defined(__linux__)
#include <sys/wait.h>
#endif

namespace platform {
namespace {

// Appends a space-separated token once.
[[maybe_unused]] void add_token(std::string& tokens, const char* token) {
    const std::string needle(token);
    size_t start = 0;
    while (start <= tokens.size()) {
        auto end = tokens.find(' ', start);
        if (end == std::string::npos) {
            end = tokens.size();
        }
        if (tokens.compare(start, end - start, needle) == 0) {
            return;
        }
        start = end + 1;
    }
    if (!tokens.empty()) {
        tokens.push_back(' ');
    }
    tokens += token;
}

#if defined(_WIN32)

std::string format_bssid(const unsigned char* bytes) {
    char buffer[18];
    std::snprintf(buffer,
                  sizeof(buffer),
                  "%02X:%02X:%02X:%02X:%02X:%02X",
                  bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
    return buffer;
}

// Reads the BSS Load element (ID 11) from a beacon/probe response IE blob.
int32_t read_bss_load_utilization(const unsigned char* ies, unsigned long size) {
    unsigned long offset = 0;
    while (offset + 2 <= size) {
        const unsigned char id = ies[offset];
        const unsigned char length = ies[offset + 1];
        if (offset + 2 + length > size) {
            break;
        }
        if (id == 11 && length >= 5) {
            const unsigned char utilization = ies[offset + 2 + 2];
            return static_cast<int32_t>(utilization) * 100 / 255;
        }
        offset += 2U + length;
    }
    return -1;
}

const char* cipher_name(unsigned char suite) {
    switch (suite) {
        case 1:
        case 5:
            return "WEP";
        case 2:
            return "TKIP";
        case 4:
            return "CCMP";
        case 8:
            return "GCMP";
        case 9:
            return "GCMP-256";
        case 10:
            return "CCMP-256";
        default:
            return nullptr;
    }
}

// Decodes an RSN element (ID 48): AKM suites into WPA2/WPA3/802.1X/OWE tokens, plus the key
// management and pairwise cipher names shown on the details page.
void read_rsn(const unsigned char* data,
              unsigned char length,
              std::string& tokens,
              std::string& key_mgmt,
              std::string& ciphers) {
    // version(2) + group cipher(4) + pairwise count(2)
    if (length < 8) {
        add_token(tokens, "WPA2");
        return;
    }
    size_t offset = 6;
    const size_t pairwise_count = data[offset] | (data[offset + 1] << 8);
    for (size_t i = 0; i < pairwise_count && offset + 2 + 4 * i + 4 <= length; ++i) {
        const unsigned char* suite = data + offset + 2 + 4 * i;
        if (suite[0] == 0x00 && suite[1] == 0x0F && suite[2] == 0xAC) {
            if (const char* name = cipher_name(suite[3])) {
                add_token(ciphers, name);
            }
        }
    }
    offset += 2 + 4 * pairwise_count;
    if (offset + 2 > length) {
        add_token(tokens, "WPA2");
        return;
    }
    const size_t akm_count = data[offset] | (data[offset + 1] << 8);
    offset += 2;
    bool any = false;
    for (size_t i = 0; i < akm_count && offset + 4 <= length; ++i, offset += 4) {
        if (data[offset] != 0x00 || data[offset + 1] != 0x0F || data[offset + 2] != 0xAC) {
            continue;
        }
        any = true;
        switch (data[offset + 3]) {
            case 1:
            case 3:
            case 5:
                add_token(tokens, "WPA2");
                add_token(tokens, "802.1X");
                add_token(key_mgmt, "802.1X");
                break;
            case 12:
                add_token(tokens, "WPA3");
                add_token(tokens, "802.1X");
                add_token(key_mgmt, "802.1X");
                break;
            case 2:
            case 4:
            case 6:
                add_token(tokens, "WPA2");
                add_token(key_mgmt, "PSK");
                break;
            case 8:
            case 9:
            case 24:
            case 25:
                add_token(tokens, "WPA3");
                add_token(key_mgmt, "SAE");
                break;
            case 18:
                add_token(tokens, "OWE");
                add_token(key_mgmt, "OWE");
                break;
            default:
                add_token(tokens, "WPA2");
                break;
        }
    }
    if (!any) {
        add_token(tokens, "WPA2");
    }
}

// Fills security tokens, key management, ciphers, Wi-Fi generation and channel width from the
// beacon / probe response information elements.
void read_ies(const unsigned char* ies, unsigned long size, bool privacy, WifiAccessPoint& ap) {
    std::string tokens;
    bool ht = false;
    bool vht = false;
    bool he = false;
    bool eht = false;
    int32_t width = 20;
    unsigned long offset = 0;
    while (offset + 2 <= size) {
        const unsigned char id = ies[offset];
        const unsigned char length = ies[offset + 1];
        if (offset + 2 + length > size) {
            break;
        }
        const unsigned char* data = ies + offset + 2;
        if (id == 48) {
            read_rsn(data, length, tokens, ap.key_mgmt, ap.ciphers);
        }
        else if (id == 221 && length >= 4 && data[0] == 0x00 && data[1] == 0x50 && data[2] == 0xF2 &&
                 data[3] == 0x01) {
            add_token(tokens, "WPA1");
            if (ap.ciphers.empty()) {
                add_token(ap.ciphers, "TKIP");
            }
        }
        else if (id == 45) {
            ht = true;
        }
        else if (id == 61 && length >= 2) {
            // HT Operation: STA channel width bit set means 40 MHz is in use.
            if ((data[1] & 0x04) != 0) {
                width = std::max<int32_t>(width, 40);
            }
        }
        else if (id == 191) {
            vht = true;
        }
        else if (id == 192 && length >= 3) {
            // VHT Operation: width 1 = 80 MHz, or 160 MHz when the second segment is set.
            if (data[0] == 1) {
                width = std::max<int32_t>(width, data[2] != 0 ? 160 : 80);
            }
            else if (data[0] == 2 || data[0] == 3) {
                width = std::max<int32_t>(width, 160);
            }
        }
        else if (id == 255 && length >= 1) {
            if (data[0] == 35) {
                he = true;
            }
            else if (data[0] == 108) {
                eht = true;
            }
        }
        offset += 2U + length;
    }
    if (tokens.empty() && privacy) {
        tokens = "WEP";
        ap.ciphers = "WEP";
    }
    ap.security = tokens;
    ap.standard = eht ? "Wi-Fi 7" : he ? "Wi-Fi 6" : vht ? "Wi-Fi 5" : ht ? "Wi-Fi 4" : "";
    ap.channel_width_mhz = width;
}

std::string describe_wlan_error(const char* call, DWORD code) {
    if (code == ERROR_ACCESS_DENIED) {
        return "Access denied. Turn on Location in Windows Settings > Privacy & security > Location "
               "and allow desktop apps to use it.";
    }
    if (code == ERROR_SERVICE_NOT_ACTIVE) {
        return "The WLAN AutoConfig service is not running.";
    }
    return std::string(call) + " failed (error " + std::to_string(code) + ").";
}

class ScanBackend {
public:
    ~ScanBackend() {
        if (handle_) {
            WlanCloseHandle(handle_, nullptr);
        }
    }

    WifiScanResult scan() {
        WifiScanResult result;
        if (!handle_) {
            DWORD negotiated_version = 0;
            const DWORD status = WlanOpenHandle(2, nullptr, &negotiated_version, &handle_);
            if (status != ERROR_SUCCESS) {
                handle_ = nullptr;
                result.error = describe_wlan_error("WlanOpenHandle", status);
                return result;
            }
        }

        PWLAN_INTERFACE_INFO_LIST interfaces = nullptr;
        DWORD status = WlanEnumInterfaces(handle_, nullptr, &interfaces);
        if (status != ERROR_SUCCESS) {
            result.error = describe_wlan_error("WlanEnumInterfaces", status);
            return result;
        }
        if (!interfaces || interfaces->dwNumberOfItems == 0) {
            if (interfaces) {
                WlanFreeMemory(interfaces);
            }
            result.error = "No WiFi adapter found.";
            return result;
        }

        const GUID interface_guid = interfaces->InterfaceInfo[0].InterfaceGuid;
        WlanFreeMemory(interfaces);

        std::string connected_bssid;
        DWORD attributes_size = 0;
        PWLAN_CONNECTION_ATTRIBUTES attributes = nullptr;
        if (WlanQueryInterface(handle_,
                               &interface_guid,
                               wlan_intf_opcode_current_connection,
                               nullptr,
                               &attributes_size,
                               reinterpret_cast<PVOID*>(&attributes),
                               nullptr) == ERROR_SUCCESS &&
            attributes) {
            if (attributes->isState == wlan_interface_state_connected) {
                connected_bssid = format_bssid(attributes->wlanAssociationAttributes.dot11Bssid);
            }
            WlanFreeMemory(attributes);
        }

        PWLAN_BSS_LIST bss_list = nullptr;
        status = WlanGetNetworkBssList(handle_,
                                       &interface_guid,
                                       nullptr,
                                       dot11_BSS_type_any,
                                       FALSE,
                                       nullptr,
                                       &bss_list);
        if (status != ERROR_SUCCESS) {
            result.error = describe_wlan_error("WlanGetNetworkBssList", status);
            return result;
        }

        for (DWORD i = 0; i < bss_list->dwNumberOfItems; ++i) {
            const WLAN_BSS_ENTRY& entry = bss_list->wlanBssEntries[i];
            WifiAccessPoint ap;
            ap.ssid.assign(reinterpret_cast<const char*>(entry.dot11Ssid.ucSSID),
                           entry.dot11Ssid.uSSIDLength);
            ap.bssid = format_bssid(entry.dot11Bssid);
            ap.frequency_mhz = static_cast<int32_t>(entry.ulChCenterFrequency / 1000);
            ap.channel = wifi_frequency_to_channel(ap.frequency_mhz);
            ap.strength_percent = static_cast<int32_t>(entry.uLinkQuality);
            ap.signal_dbm = static_cast<int32_t>(entry.lRssi);
            ap.mode = entry.dot11BssType == dot11_BSS_type_independent ? "Ad-Hoc" : "Infra";
            const auto* ies = reinterpret_cast<const unsigned char*>(&entry) + entry.ulIeOffset;
            ap.channel_utilization_percent = read_bss_load_utilization(ies, entry.ulIeSize);
            read_ies(ies, entry.ulIeSize, (entry.usCapabilityInformation & 0x0010) != 0, ap);
            ap.connected = !connected_bssid.empty() && ap.bssid == connected_bssid;
            result.access_points.push_back(std::move(ap));
        }
        WlanFreeMemory(bss_list);

        // Ask the driver for a fresh scan; its results are picked up on the next round.
        WlanScan(handle_, &interface_guid, nullptr, nullptr, nullptr);

        result.ok = true;
        return result;
    }

private:
    HANDLE handle_{nullptr};
};

#elif defined(__linux__)

// Splits one line of `nmcli -t -e yes` output, honouring "\:" and "\\" escapes.
std::vector<std::string> split_terse(const std::string& line) {
    std::vector<std::string> fields(1);
    for (size_t i = 0; i < line.size(); ++i) {
        const char ch = line[i];
        if (ch == '\\' && i + 1 < line.size()) {
            fields.back().push_back(line[++i]);
        }
        else if (ch == ':') {
            fields.emplace_back();
        }
        else {
            fields.back().push_back(ch);
        }
    }
    return fields;
}

int32_t parse_int(const std::string& text, int32_t fallback) {
    try {
        size_t used = 0;
        const int value = std::stoi(text, &used);
        return used > 0 ? value : fallback;
    }
    catch (...) {
        return fallback;
    }
}

bool run_command(const std::string& command, std::string& output, int& exit_code) {
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        return false;
    }
    char buffer[512];
    output.clear();
    while (std::fgets(buffer, sizeof(buffer), pipe)) {
        output += buffer;
    }
    const int status = pclose(pipe);
    exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return true;
}

// Columns 0-11 exist in every NetworkManager release; BANDWIDTH (12) needs NetworkManager 1.46+.
constexpr const char* kNmcliFields = "IN-USE,BSSID,SSID,CHAN,FREQ,SIGNAL,SECURITY,MODE,RATE,RSN-FLAGS,WPA-FLAGS,DEVICE";

bool run_nmcli(const char* rescan, bool with_bandwidth, std::string& output, int& exit_code) {
    std::string command = "LC_ALL=C nmcli -t -e yes -f ";
    command += kNmcliFields;
    if (with_bandwidth) {
        command += ",BANDWIDTH";
    }
    command += " device wifi list --rescan ";
    command += rescan;
    command += " 2>&1";
    return run_command(command, output, exit_code);
}

// Turns nmcli RSN/WPA flags ("pair_ccmp group_ccmp psk sae") into key management and pairwise
// cipher names.
void read_nm_flags(const std::string& flags, std::string& key_mgmt, std::string& ciphers) {
    size_t start = 0;
    while (start < flags.size()) {
        auto end = flags.find(' ', start);
        if (end == std::string::npos) {
            end = flags.size();
        }
        const std::string flag = flags.substr(start, end - start);
        start = end + 1;
        if (flag.rfind("pair_", 0) == 0) {
            std::string name = flag.substr(5);
            for (auto& ch : name) {
                ch = ch == '_' ? '-' : static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
            }
            if (name.rfind("WEP", 0) == 0) {
                name = "WEP";
            }
            add_token(ciphers, name.c_str());
        }
        else if (flag == "psk") {
            add_token(key_mgmt, "PSK");
        }
        else if (flag == "sae") {
            add_token(key_mgmt, "SAE");
        }
        else if (flag == "802.1X") {
            add_token(key_mgmt, "802.1X");
        }
        else if (flag == "owe" || flag == "owe_tm") {
            add_token(key_mgmt, "OWE");
        }
    }
}

// Works out which bands the WiFi devices NetworkManager scans with can use, from lines like
// "GENERAL.STATE:100 (connected)" and "WIFI-PROPERTIES.5GHZ:no". Unmanaged devices (e.g. an
// adapter in monitor mode) and unavailable ones (radio off) are skipped because nmcli does not
// scan with them. Leaves both bands enabled when nothing conclusive comes back.
void read_band_support(WifiScanResult& result) {
    std::string output;
    int exit_code = -1;
    if (!run_command("LC_ALL=C nmcli -t -f GENERAL.STATE,WIFI-PROPERTIES device show 2>/dev/null",
                     output,
                     exit_code) ||
        exit_code != 0) {
        return;
    }

    bool usable = true;
    bool seen = false;
    bool any_24 = false;
    bool any_5 = false;
    size_t start = 0;
    while (start < output.size()) {
        auto end = output.find('\n', start);
        if (end == std::string::npos) {
            end = output.size();
        }
        std::string line = output.substr(start, end - start);
        start = end + 1;
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        const auto colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        const std::string key = line.substr(0, colon);
        const std::string value = line.substr(colon + 1);
        if (key == "GENERAL.STATE") {
            usable = value.find("unmanaged") == std::string::npos &&
                     value.find("unavailable") == std::string::npos;
            continue;
        }
        if (!usable) {
            continue;
        }
        // "unknown" means the driver did not say; give it the benefit of the doubt.
        const bool supported = value != "no";
        if (key == "WIFI-PROPERTIES.2GHZ") {
            seen = true;
            any_24 |= supported;
        }
        else if (key == "WIFI-PROPERTIES.5GHZ") {
            seen = true;
            any_5 |= supported;
        }
    }

    if (seen && (any_24 || any_5)) {
        result.supports_24ghz = any_24;
        result.supports_5ghz = any_5;
    }
}

// With more than one adapter nmcli lists each access point once per adapter. Keep one entry per
// BSSID with the strongest signal so networks are not double counted.
void merge_duplicate_bssids(std::vector<WifiAccessPoint>& aps) {
    std::vector<WifiAccessPoint> merged;
    merged.reserve(aps.size());
    for (auto& ap : aps) {
        auto existing = std::find_if(merged.begin(), merged.end(), [&](const WifiAccessPoint& other) {
            return !ap.bssid.empty() && other.bssid == ap.bssid;
        });
        if (existing == merged.end()) {
            merged.push_back(std::move(ap));
            continue;
        }
        const bool connected = existing->connected || ap.connected;
        std::string devices = existing->devices;
        add_token(devices, ap.devices.c_str());
        if (ap.strength_percent > existing->strength_percent) {
            *existing = std::move(ap);
        }
        existing->connected = connected;
        existing->devices = std::move(devices);
    }
    aps = std::move(merged);
}

std::string first_line(const std::string& text) {
    const auto end = text.find('\n');
    return end == std::string::npos ? text : text.substr(0, end);
}

int32_t parse_leading_int(const std::string& text) {
    // "540 Mbit/s", "80 MHz"
    return parse_int(text, 0);
}

class ScanBackend {
public:
    WifiScanResult scan() {
        WifiScanResult result;
        std::string output;
        int exit_code = -1;
        if (!list(output, exit_code)) {
            result.error = "Could not start nmcli.";
            return result;
        }
        if (exit_code == 127) {
            result.error = "nmcli not found. NetworkManager is required for scanning.";
            return result;
        }
        if (exit_code != 0) {
            result.error = "nmcli: " + first_line(output);
            return result;
        }

        size_t start = 0;
        while (start < output.size()) {
            auto end = output.find('\n', start);
            if (end == std::string::npos) {
                end = output.size();
            }
            const auto fields = split_terse(output.substr(start, end - start));
            start = end + 1;
            if (fields.size() < 7) {
                continue;
            }

            WifiAccessPoint ap;
            ap.connected = fields[0] == "*";
            ap.bssid = fields[1];
            ap.ssid = fields[2];
            ap.frequency_mhz = parse_int(fields[4], 0);
            ap.channel = wifi_frequency_to_channel(ap.frequency_mhz);
            if (ap.channel == 0) {
                ap.channel = parse_int(fields[3], 0);
            }
            ap.strength_percent = parse_int(fields[5], -1);
            ap.security = fields[6] == "--" ? std::string() : fields[6];
            if (ap.strength_percent >= 0) {
                // Inverse of NetworkManager's dBm-to-percent mapping (-100 dBm = 0%, -40 dBm = 100%).
                ap.signal_dbm = -40 - (100 - std::min<int32_t>(ap.strength_percent, 100)) * 60 / 100;
                ap.signal_dbm_estimated = true;
            }
            if (fields.size() >= 12) {
                ap.mode = fields[7];
                ap.max_rate_mbps = parse_leading_int(fields[8]);
                read_nm_flags(fields[9], ap.key_mgmt, ap.ciphers);
                read_nm_flags(fields[10], ap.key_mgmt, ap.ciphers);
                ap.devices = fields[11];
            }
            if (fields.size() >= 13) {
                ap.channel_width_mhz = parse_leading_int(fields[12]);
            }
            if (ap.channel > 0) {
                result.access_points.push_back(std::move(ap));
            }
        }

        merge_duplicate_bssids(result.access_points);
        read_band_support(result);
        result.ok = true;
        return result;
    }

private:
    // Lists networks, asking for a rescan first. Rescans can be refused (permissions, rate
    // limits), in which case cached results are used. Older NetworkManager releases reject the
    // BANDWIDTH column; drop it once and remember.
    bool list(std::string& output, int& exit_code) {
        for (int attempt = 0; attempt < 2; ++attempt) {
            if (!run_nmcli("yes", with_bandwidth_, output, exit_code)) {
                return false;
            }
            if (exit_code != 0 && exit_code != 127 &&
                !(with_bandwidth_ && output.find("BANDWIDTH") != std::string::npos)) {
                if (!run_nmcli("no", with_bandwidth_, output, exit_code)) {
                    return false;
                }
            }
            if (exit_code != 0 && with_bandwidth_ && output.find("BANDWIDTH") != std::string::npos) {
                with_bandwidth_ = false;
                continue;
            }
            return true;
        }
        return true;
    }

    bool with_bandwidth_{true};
};

#else

class ScanBackend {
public:
    WifiScanResult scan() {
        WifiScanResult result;
        result.error = "WiFi scanning is not supported on this platform.";
        return result;
    }
};

#endif

} // namespace

int32_t wifi_frequency_to_channel(int32_t frequency_mhz) {
    if (frequency_mhz == 2484) {
        return 14;
    }
    if (frequency_mhz >= 2412 && frequency_mhz <= 2472) {
        return (frequency_mhz - 2407) / 5;
    }
    if (frequency_mhz >= 5150 && frequency_mhz <= 5895) {
        return (frequency_mhz - 5000) / 5;
    }
    if (frequency_mhz >= 5955 && frequency_mhz <= 7115) {
        return (frequency_mhz - 5950) / 5;
    }
    return 0;
}

WifiScanner::WifiScanner() = default;

WifiScanner::~WifiScanner() {
    stop();
}

void WifiScanner::start(uint32_t interval_ms) {
    if (worker_.joinable()) {
        return;
    }
    interval_ms_ = interval_ms;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stop_requested_ = false;
    }
    worker_ = std::thread(&WifiScanner::run, this);
}

void WifiScanner::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stop_requested_ = true;
    }
    wake_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
}

void WifiScanner::set_paused(bool paused) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        paused_ = paused;
    }
    wake_.notify_all();
}

bool WifiScanner::paused() const {
    return paused_;
}

bool WifiScanner::busy() const {
    return busy_;
}

bool WifiScanner::take_result(WifiScanResult& result) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!has_pending_) {
        return false;
    }
    result = std::move(pending_);
    pending_ = WifiScanResult{};
    has_pending_ = false;
    return true;
}

void WifiScanner::run() {
    ScanBackend backend;
    std::unique_lock<std::mutex> lock(mutex_);
    while (!stop_requested_) {
        if (paused_) {
            wake_.wait(lock, [this] { return stop_requested_ || !paused_; });
            continue;
        }

        busy_ = true;
        lock.unlock();
        WifiScanResult result = backend.scan();
        lock.lock();
        busy_ = false;

        pending_ = std::move(result);
        has_pending_ = true;

        wake_.wait_for(lock, std::chrono::milliseconds(interval_ms_), [this] {
            return stop_requested_ || paused_;
        });
    }
}

} // namespace platform
