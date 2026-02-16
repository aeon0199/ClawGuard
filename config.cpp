#include "clawguard.h"

namespace clawguard {

namespace {

std::string trim_copy(const std::string& s) {
    const size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    const size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::string to_lower_trim(std::string s) {
    s = trim_copy(s);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    return s;
}

bool parse_int_safe(const std::string& s, int& out) {
    try {
        size_t idx = 0;
        long long v = std::stoll(s, &idx);
        if (idx != s.size()) return false;
        if (v < std::numeric_limits<int>::min() || v > std::numeric_limits<int>::max()) return false;
        out = static_cast<int>(v);
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_float_safe(const std::string& s, float& out) {
    try {
        size_t idx = 0;
        float v = std::stof(s, &idx);
        if (idx != s.size()) return false;
        out = v;
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_bool_safe(const std::string& s, bool& out) {
    const std::string v = to_lower_trim(s);
    if (v == "1" || v == "true" || v == "yes" || v == "on") { out = true; return true; }
    if (v == "0" || v == "false" || v == "no" || v == "off") { out = false; return true; }
    return false;
}

bool parse_mode_safe(const std::string& s, std::string& out) {
    const std::string v = to_lower_trim(s);
    if (v == "readonly" || v == "read-only" || v == "monitor" || v == "monitor-only") {
        out = "readonly";
        return true;
    }
    if (v == "standard" || v == "normal") {
        out = "standard";
        return true;
    }
    return false;
}

void warn_bad_config_value(const std::string& key, const std::string& val) {
    std::cerr << "[ClawGuard] Invalid config value for '" << key << "': '" << val
              << "' (keeping previous/default)\n";
}

} // namespace

// ─── Config ───────────────────────────────────────────────────
Config Config::load(const std::string& path) {
    Config cfg;
    std::ifstream f(path);
    if (!f.is_open()) return cfg;
    
    std::string line;
    while (std::getline(f, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        
        std::string key = trim_copy(line.substr(0, eq));
        std::string val = trim_copy(line.substr(eq + 1));
        
        if (key == "poll_interval_sec") {
            int v = 0;
            if (parse_int_safe(val, v) && v > 0) cfg.poll_interval_sec = v; else warn_bad_config_value(key, val);
        }
        else if (key == "mode") {
            std::string v;
            if (parse_mode_safe(val, v)) cfg.mode = v; else warn_bad_config_value(key, val);
        }
        else if (key == "history_max_minutes") {
            int v = 0;
            if (parse_int_safe(val, v) && v > 0) cfg.history_max_minutes = v; else warn_bad_config_value(key, val);
        }
        else if (key == "http_port") {
            int v = 0;
            if (parse_int_safe(val, v) && v > 0 && v <= 65535) cfg.http_port = v; else warn_bad_config_value(key, val);
        }
        else if (key == "http_bind") cfg.http_bind = val;
        else if (key == "allow_remote_http") {
            bool v = false; if (parse_bool_safe(val, v)) cfg.allow_remote_http = v; else warn_bad_config_value(key, val);
        }
        else if (key == "api_auth_token") cfg.api_auth_token = val;
        else if (key == "api_rate_limit_enabled") {
            bool v = false; if (parse_bool_safe(val, v)) cfg.api_rate_limit_enabled = v; else warn_bad_config_value(key, val);
        }
        else if (key == "api_rate_limit_per_min") {
            int v = 0;
            if (parse_int_safe(val, v) && v > 0) cfg.api_rate_limit_per_min = v; else warn_bad_config_value(key, val);
        }
        else if (key == "data_dir") cfg.data_dir = val;
        else if (key == "port_scan_interval_sec") {
            int v = 0;
            if (parse_int_safe(val, v) && v >= 0) cfg.port_scan_interval_sec = v; else warn_bad_config_value(key, val);
        }
        else if (key == "openclaw_event_log_file") cfg.openclaw_event_log_file = val;
        else if (key == "openclaw_event_tail_max") {
            int v = 0;
            if (parse_int_safe(val, v) && v > 0) cfg.openclaw_event_tail_max = v; else warn_bad_config_value(key, val);
        }
        else if (key == "policy_file") cfg.policy_file = val;
        else if (key == "security_scan_interval_sec") {
            int v = 0;
            if (parse_int_safe(val, v) && v >= 0) cfg.security_scan_interval_sec = v; else warn_bad_config_value(key, val);
        }
        else if (key == "openclaw_config_file") cfg.openclaw_config_file = val;
        else if (key == "integrity_baseline_file") cfg.integrity_baseline_file = val;
        else if (key == "containment_enabled") {
            bool v = false; if (parse_bool_safe(val, v)) cfg.containment_enabled = v; else warn_bad_config_value(key, val);
        }
        else if (key == "containment_shadow_mode") {
            bool v = false; if (parse_bool_safe(val, v)) cfg.containment_shadow_mode = v; else warn_bad_config_value(key, val);
        }
        else if (key == "containment_auto_soft_actions") {
            bool v = false; if (parse_bool_safe(val, v)) cfg.containment_auto_soft_actions = v; else warn_bad_config_value(key, val);
        }
        else if (key == "containment_auto_hard_actions") {
            bool v = false; if (parse_bool_safe(val, v)) cfg.containment_auto_hard_actions = v; else warn_bad_config_value(key, val);
        }
        else if (key == "containment_require_user_approval_for_hard") {
            bool v = false; if (parse_bool_safe(val, v)) cfg.containment_require_user_approval_for_hard = v; else warn_bad_config_value(key, val);
        }
        else if (key == "containment_block_ttl_sec") {
            int v = 0;
            if (parse_int_safe(val, v) && v >= 0) cfg.containment_block_ttl_sec = v; else warn_bad_config_value(key, val);
        }
        else if (key == "containment_max_actions_per_hour") {
            int v = 0;
            if (parse_int_safe(val, v) && v > 0) cfg.containment_max_actions_per_hour = v; else warn_bad_config_value(key, val);
        }
        else if (key == "containment_block_port_command") cfg.containment_block_port_command = val;
        else if (key == "containment_actions_log_file") cfg.containment_actions_log_file = val;
        else if (key == "cpu_warn_pct") {
            float v = 0.0f; if (parse_float_safe(val, v)) cfg.cpu_warn_pct = v; else warn_bad_config_value(key, val);
        }
        else if (key == "cpu_crit_pct") {
            float v = 0.0f; if (parse_float_safe(val, v)) cfg.cpu_crit_pct = v; else warn_bad_config_value(key, val);
        }
        else if (key == "mem_warn_pct") {
            float v = 0.0f; if (parse_float_safe(val, v)) cfg.mem_warn_pct = v; else warn_bad_config_value(key, val);
        }
        else if (key == "mem_crit_pct") {
            float v = 0.0f; if (parse_float_safe(val, v)) cfg.mem_crit_pct = v; else warn_bad_config_value(key, val);
        }
        else if (key == "disk_warn_pct") {
            float v = 0.0f; if (parse_float_safe(val, v)) cfg.disk_warn_pct = v; else warn_bad_config_value(key, val);
        }
        else if (key == "disk_crit_pct") {
            float v = 0.0f; if (parse_float_safe(val, v)) cfg.disk_crit_pct = v; else warn_bad_config_value(key, val);
        }
        else if (key == "openclaw_alerts") {
            bool v = false; if (parse_bool_safe(val, v)) cfg.openclaw_alerts = v; else warn_bad_config_value(key, val);
        }
        else if (key == "alert_file") cfg.alert_file = val;
    }
    return cfg;
}

void Config::save(const std::string& path) const {
    std::ofstream f(path);
    f << "# ClawGuard Configuration\n";
    f << "# https://github.com/YOUR_USERNAME/clawguard\n\n";
    f << "# Monitoring\n";
    f << "poll_interval_sec = " << poll_interval_sec << "\n";
    f << "history_max_minutes = " << history_max_minutes << "\n";
    f << "mode = " << mode << "\n";
    f << "http_port = " << http_port << "\n";
    f << "http_bind = " << http_bind << "\n";
    f << "allow_remote_http = " << (allow_remote_http ? "true" : "false") << "\n";
    f << "api_auth_token = " << api_auth_token << "\n";
    f << "api_rate_limit_enabled = " << (api_rate_limit_enabled ? "true" : "false") << "\n";
    f << "api_rate_limit_per_min = " << api_rate_limit_per_min << "\n";
    f << "data_dir = " << data_dir << "\n\n";
    f << "# Pro Signals\n";
    f << "port_scan_interval_sec = " << port_scan_interval_sec << "\n\n";
    f << "# OpenClaw Correlation (optional)\n";
    f << "openclaw_event_log_file = " << openclaw_event_log_file << "\n";
    f << "openclaw_event_tail_max = " << openclaw_event_tail_max << "\n\n";
    f << "# Trusted Ops Policy (optional)\n";
    f << "policy_file = " << policy_file << "\n\n";
    f << "# Security Posture\n";
    f << "security_scan_interval_sec = " << security_scan_interval_sec << "\n";
    f << "openclaw_config_file = " << openclaw_config_file << "\n";
    f << "integrity_baseline_file = " << integrity_baseline_file << "\n\n";
    f << "# Experimental Containment (off by default)\n";
    f << "containment_enabled = " << (containment_enabled ? "true" : "false") << "\n";
    f << "containment_shadow_mode = " << (containment_shadow_mode ? "true" : "false") << "\n";
    f << "containment_auto_soft_actions = " << (containment_auto_soft_actions ? "true" : "false") << "\n";
    f << "containment_auto_hard_actions = " << (containment_auto_hard_actions ? "true" : "false") << "\n";
    f << "containment_require_user_approval_for_hard = " << (containment_require_user_approval_for_hard ? "true" : "false") << "\n";
    f << "containment_block_ttl_sec = " << containment_block_ttl_sec << "\n";
    f << "containment_max_actions_per_hour = " << containment_max_actions_per_hour << "\n";
    f << "containment_block_port_command = " << containment_block_port_command << "\n";
    f << "containment_actions_log_file = " << containment_actions_log_file << "\n\n";
    f << "# Alert Thresholds\n";
    f << "cpu_warn_pct = " << cpu_warn_pct << "\n";
    f << "cpu_crit_pct = " << cpu_crit_pct << "\n";
    f << "mem_warn_pct = " << mem_warn_pct << "\n";
    f << "mem_crit_pct = " << mem_crit_pct << "\n";
    f << "disk_warn_pct = " << disk_warn_pct << "\n";
    f << "disk_crit_pct = " << disk_crit_pct << "\n\n";
    f << "# OpenClaw Integration\n";
    f << "openclaw_alerts = " << (openclaw_alerts ? "true" : "false") << "\n";
    f << "alert_file = " << alert_file << "\n";
}

// ─── MetricHistory ────────────────────────────────────────────
MetricHistory::MetricHistory(size_t max_entries) : max_entries_(max_entries) {}

void MetricHistory::push(const SystemSnapshot& snap) {
    std::lock_guard<std::mutex> lock(mutex_);
    buffer_.push_back(snap);
    while (buffer_.size() > max_entries_) {
        buffer_.pop_front();
    }
}

std::vector<SystemSnapshot> MetricHistory::get_range(int64_t from_ms, int64_t to_ms) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<SystemSnapshot> result;
    for (const auto& s : buffer_) {
        if (s.timestamp_ms >= from_ms && s.timestamp_ms <= to_ms) {
            result.push_back(s);
        }
    }
    return result;
}

std::vector<SystemSnapshot> MetricHistory::get_last_n(size_t n) const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = std::min(n, buffer_.size());
    return std::vector<SystemSnapshot>(buffer_.end() - count, buffer_.end());
}

SystemSnapshot MetricHistory::get_latest() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (buffer_.empty()) return {};
    return buffer_.back();
}

size_t MetricHistory::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return buffer_.size();
}

double MetricHistory::cpu_trend_slope(int minutes) const {
    std::lock_guard<std::mutex> lock(mutex_);
    int64_t cutoff = util::now_ms() - (minutes * 60000LL);
    
    std::vector<std::pair<double, double>> points;
    for (const auto& s : buffer_) {
        if (s.timestamp_ms >= cutoff) {
            points.emplace_back(
                static_cast<double>(s.timestamp_ms - cutoff) / 60000.0,
                s.cpu.usage_pct
            );
        }
    }
    
    if (points.size() < 2) return 0.0;
    
    // Simple linear regression
    double sum_x = 0, sum_y = 0, sum_xy = 0, sum_x2 = 0;
    double n = static_cast<double>(points.size());
    for (const auto& [x, y] : points) {
        sum_x += x; sum_y += y; sum_xy += x * y; sum_x2 += x * x;
    }
    double denom = n * sum_x2 - sum_x * sum_x;
    if (std::abs(denom) < 1e-10) return 0.0;
    return (n * sum_xy - sum_x * sum_y) / denom;
}

double MetricHistory::mem_trend_slope(int minutes) const {
    std::lock_guard<std::mutex> lock(mutex_);
    int64_t cutoff = util::now_ms() - (minutes * 60000LL);
    
    std::vector<std::pair<double, double>> points;
    for (const auto& s : buffer_) {
        if (s.timestamp_ms >= cutoff) {
            points.emplace_back(
                static_cast<double>(s.timestamp_ms - cutoff) / 60000.0,
                s.mem.usage_pct
            );
        }
    }
    
    if (points.size() < 2) return 0.0;
    
    double sum_x = 0, sum_y = 0, sum_xy = 0, sum_x2 = 0;
    double n = static_cast<double>(points.size());
    for (const auto& [x, y] : points) {
        sum_x += x; sum_y += y; sum_xy += x * y; sum_x2 += x * x;
    }
    double denom = n * sum_x2 - sum_x * sum_x;
    if (std::abs(denom) < 1e-10) return 0.0;
    return (n * sum_xy - sum_x * sum_y) / denom;
}

} // namespace clawguard
