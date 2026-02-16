#include "clawguard.h"

namespace clawguard::util {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

std::string format_bytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0;
    double size = static_cast<double>(bytes);
    while (size >= 1024.0 && i < 4) {
        size /= 1024.0;
        i++;
    }
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1) << size << " " << units[i];
    return ss.str();
}

std::string format_duration(int64_t seconds) {
    int64_t days = seconds / 86400;
    int64_t hours = (seconds % 86400) / 3600;
    int64_t mins = (seconds % 3600) / 60;
    
    std::ostringstream ss;
    if (days > 0) ss << days << "d ";
    if (hours > 0) ss << hours << "h ";
    ss << mins << "m";
    return ss.str();
}

std::string format_timestamp(int64_t ms) {
    auto tp = std::chrono::system_clock::time_point(std::chrono::milliseconds(ms));
    auto time_t_val = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_val;
    localtime_r(&time_t_val, &tm_val);
    
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_val);
    return std::string(buf);
}

std::string escape_json(const std::string& s) {
    std::string result;
    result.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n";  break;
            case '\r': result += "\\r";  break;
            case '\t': result += "\\t";  break;
            default:   result += c;
        }
    }
    return result;
}

std::string to_json_number(double v) {
    if (std::isnan(v) || std::isinf(v)) return "0";
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2) << v;
    return ss.str();
}

} // namespace clawguard::util
