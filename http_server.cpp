#include "clawguard.h"
#include <unistd.h>

namespace clawguard {

namespace {

std::string trim_copy_http(const std::string& s) {
    const size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    const size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::string to_lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

bool is_loopback_bind_ip(const std::string& ip) {
    if (ip == "127.0.0.1" || ip == "localhost" || ip == "loopback") return true;
    return ip.rfind("127.", 0) == 0;
}

bool path_is_api(const std::string& path) {
    return path == "/api" || path.rfind("/api/", 0) == 0;
}

std::string extract_header_value_ci(const std::string& req_str, const std::string& header_name) {
    std::istringstream in(req_str);
    std::string line;
    std::string needle = to_lower_copy(header_name);

    // Skip request line
    if (!std::getline(in, line)) return "";

    while (std::getline(in, line)) {
        if (line == "\r" || line.empty()) break;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = to_lower_copy(trim_copy_http(line.substr(0, colon)));
        if (name != needle) continue;
        return trim_copy_http(line.substr(colon + 1));
    }
    return "";
}

bool constant_time_equals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

} // namespace

HttpServer::HttpServer(int port, MetricHistory& history, SystemCollector& collector,
                       AlertEngine& alerts, const Config& config)
    : port_(port), history_(history), collector_(collector), 
      alerts_(alerts), config_(config) {}

HttpServer::~HttpServer() { stop(); }

void HttpServer::start() {
    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) { std::cerr << "[ClawGuard] Socket failed\n"; return; }
    
    int opt = 1;
    setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    std::string bind_ip = config_.http_bind;
    if (bind_ip.empty() || bind_ip == "localhost" || bind_ip == "loopback") {
        bind_ip = "127.0.0.1";
    }
    if (inet_pton(AF_INET, bind_ip.c_str(), &addr.sin_addr) != 1) {
        std::cerr << "[ClawGuard] Invalid bind address '" << bind_ip
                  << "', falling back to 127.0.0.1\n";
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        bind_ip = "127.0.0.1";
    }
    bind_ip_ = bind_ip;
    remote_bind_enabled_ = !is_loopback_bind_ip(bind_ip_);
    if (remote_bind_enabled_ && !config_.allow_remote_http) {
        std::cerr << "[ClawGuard] Refusing non-loopback bind '" << bind_ip_
                  << "'. Set allow_remote_http=true to explicitly allow remote exposure.\n";
        close(server_fd_);
        server_fd_ = -1;
        return;
    }
    if (remote_bind_enabled_ && trim_copy_http(config_.api_auth_token).empty()) {
        std::cerr << "[ClawGuard] Refusing remote bind without API auth token. "
                  << "Set api_auth_token in config when allow_remote_http=true.\n";
        close(server_fd_);
        server_fd_ = -1;
        return;
    }
    addr.sin_port = htons(port_);
    
    if (bind(server_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[ClawGuard] Bind failed on " << bind_ip << ":" << port_ << "\n";
        close(server_fd_); server_fd_ = -1; return;
    }
    listen(server_fd_, 16);
    running_ = true;
    server_thread_ = std::thread(&HttpServer::serve_loop, this);
}

void HttpServer::stop() {
    running_ = false;
    if (server_fd_ >= 0) { shutdown(server_fd_, SHUT_RDWR); close(server_fd_); server_fd_ = -1; }
    if (server_thread_.joinable()) server_thread_.join();
}

void HttpServer::serve_loop() {
    while (running_) {
        struct sockaddr_in ca{}; socklen_t cl = sizeof(ca);
        struct timeval tv{1, 0};
        setsockopt(server_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        int cfd = accept(server_fd_, (struct sockaddr*)&ca, &cl);
        if (cfd < 0) continue;
        
        char buf[4096]; int n = recv(cfd, buf, sizeof(buf)-1, 0);
        if (n <= 0) { close(cfd); continue; }
        buf[n] = '\0';
        
        std::string req_str(buf);
        std::istringstream ss{req_str};
        std::string method, path; ss >> method >> path;
        char ipbuf[INET_ADDRSTRLEN] = {0};
        std::string client_ip = "unknown";
        if (inet_ntop(AF_INET, &(ca.sin_addr), ipbuf, sizeof(ipbuf)) != nullptr) {
            client_ip = ipbuf;
        }

        std::string status = "200 OK";
        std::string ct = (path == "/" || path == "/dashboard")
            ? "text/html; charset=utf-8" : "application/json";
        std::string body;
        std::string extra_headers;
        if (path_is_api(path) && api_rate_limited(client_ip, path)) {
            status = "429 Too Many Requests";
            body = R"({"error":"rate_limited"})";
            extra_headers += "\r\nRetry-After: 60";
        } else if (api_auth_required() && path_is_api(path) && !request_authorized(req_str)) {
            status = "401 Unauthorized";
            body = R"({"error":"unauthorized"})";
        } else {
            body = handle_request(method, path);
        }

        std::string security_headers =
            "\r\nX-Content-Type-Options: nosniff"
            "\r\nX-Frame-Options: DENY"
            "\r\nReferrer-Policy: no-referrer"
            "\r\nCache-Control: no-store";
        if (ct.find("text/html") == 0) {
            security_headers +=
                "\r\nContent-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
        }

        std::string resp = "HTTP/1.1 " + status + "\r\nContent-Type: " + ct +
            security_headers + extra_headers +
            "\r\nContent-Length: " +
            std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        
        send(cfd, resp.c_str(), resp.size(), 0);
        close(cfd);
    }
}

bool HttpServer::api_auth_required() const {
    return remote_bind_enabled_;
}

bool HttpServer::request_authorized(const std::string& req_str) const {
    const std::string expected = trim_copy_http(config_.api_auth_token);
    if (expected.empty()) return false;

    const std::string x_api_key = extract_header_value_ci(req_str, "X-API-Key");
    if (!x_api_key.empty() && constant_time_equals(x_api_key, expected)) return true;

    const std::string auth = extract_header_value_ci(req_str, "Authorization");
    if (auth.empty()) return false;

    std::string token = auth;
    const std::string lower_auth = to_lower_copy(auth);
    if (lower_auth.rfind("bearer ", 0) == 0 && auth.size() >= 7) {
        token = auth.substr(7);
    }
    token = trim_copy_http(token);
    return !token.empty() && constant_time_equals(token, expected);
}

bool HttpServer::api_rate_limited(const std::string& client_ip, const std::string& path) {
    if (!path_is_api(path)) return false;
    if (!config_.api_rate_limit_enabled) return false;
    const int limit = std::max(1, config_.api_rate_limit_per_min);
    const int64_t now = util::now_ms();

    const std::string key = client_ip.empty() ? "unknown" : client_ip;
    auto& st = api_rate_state_[key];
    if (st.window_start_ms == 0 || (now - st.window_start_ms) >= 60000) {
        st.window_start_ms = now;
        st.count = 0;
    }
    st.count++;

    // Best-effort prune stale entries to cap memory in long-running processes.
    if (api_rate_state_.size() > 512) {
        for (auto it = api_rate_state_.begin(); it != api_rate_state_.end();) {
            if ((now - it->second.window_start_ms) > 10 * 60000) {
                it = api_rate_state_.erase(it);
            } else {
                ++it;
            }
        }
    }

    return st.count > limit;
}

std::string HttpServer::handle_request(const std::string& method, const std::string& path) {
    (void)method;
    if (path == "/" || path == "/dashboard") return serve_dashboard();
    if (path == "/api/current") return json_current();
    if (path == "/api/system") return json_system_info();
    if (path == "/api/alerts") return json_alerts();
    if (path == "/api/activity") return json_activity();
    if (path == "/api/security") return json_security();
    if (path == "/api/containment") return json_containment();
    if (path == "/api/recommendations") return json_recommendations();
    if (path == "/api/brief") return json_brief();
    if (path == "/api/trends") return json_trends();
    if (path == "/api/ports") {
        auto ports = alerts_.get_listening_ports();
        std::ostringstream j;
        j << "{\"ports\":[";
        for (size_t i = 0; i < ports.size(); i++) {
            if (i > 0) j << ",";
            const auto& p = ports[i];
            j << "{\"port\":" << p.port
              << ",\"proto\":\"" << util::escape_json(p.proto) << "\""
              << ",\"pid\":" << p.pid
              << ",\"process\":\"" << util::escape_json(p.process) << "\""
              << ",\"bind\":\"" << util::escape_json(p.bind) << "\"}";
        }
        j << "]}";
        return j.str();
    }
    if (path.find("/api/history") == 0) {
        int min = 60; auto q = path.find("minutes=");
        if (q != std::string::npos) {
            try {
                min = std::stoi(path.substr(q+8));
            } catch (...) {
                min = 60;
            }
        }
        if (min < 1) min = 1;
        if (min > 10080) min = 10080; // cap to 7 days
        return json_history(min);
    }
    return R"({"error":"not found"})";
}

bool HttpServer::json_extract_string(const std::string& line, const std::string& key, std::string& out) {
    const std::string pat = "\"" + key + "\"";
    auto k = line.find(pat);
    if (k == std::string::npos) return false;
    auto colon = line.find(':', k + pat.size());
    if (colon == std::string::npos) return false;
    size_t i = colon + 1;
    while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i]))) i++;
    if (i >= line.size() || line[i] != '"') return false;
    i++;
    std::string v;
    v.reserve(64);
    bool esc = false;
    while (i < line.size()) {
        char c = line[i++];
        if (esc) {
            // minimal escapes for logs written by our helper script
            if (c == '"' || c == '\\' || c == '/') v.push_back(c);
            else if (c == 'n') v.push_back('\n');
            else if (c == 'r') v.push_back('\r');
            else if (c == 't') v.push_back('\t');
            else v.push_back(c);
            esc = false;
            continue;
        }
        if (c == '\\') { esc = true; continue; }
        if (c == '"') break;
        v.push_back(c);
    }
    out = v;
    return true;
}

bool HttpServer::json_extract_int64(const std::string& line, const std::string& key, int64_t& out) {
    const std::string pat = "\"" + key + "\"";
    auto k = line.find(pat);
    if (k == std::string::npos) return false;
    auto colon = line.find(':', k + pat.size());
    if (colon == std::string::npos) return false;
    size_t i = colon + 1;
    while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i]))) i++;
    size_t j = i;
    while (j < line.size() && (std::isdigit(static_cast<unsigned char>(line[j])) || line[j] == '-')) j++;
    if (j == i) return false;
    try {
        out = std::stoll(line.substr(i, j - i));
        return true;
    } catch (...) {
        return false;
    }
}

OpenClawEvent HttpServer::parse_openclaw_event_best_effort(const std::string& line) {
    OpenClawEvent e;
    (void)json_extract_int64(line, "ts_ms", e.ts_ms);
    (void)json_extract_string(line, "skill", e.skill);
    (void)json_extract_string(line, "tool", e.tool);
    (void)json_extract_string(line, "command", e.command);
    (void)json_extract_string(line, "status", e.status);
    (void)json_extract_string(line, "correlation_id", e.correlation_id);
    return e;
}

void HttpServer::refresh_openclaw_events() {
    const int64_t now = util::now_ms();
    if (now - openclaw_events_loaded_ms_ < 1000) return; // 1s cache
    openclaw_events_loaded_ms_ = now;

    openclaw_events_.clear();
    if (config_.openclaw_event_log_file.empty()) return;

    std::ifstream f(config_.openclaw_event_log_file);
    if (!f.is_open()) return;

    const int max_events = std::max(1, config_.openclaw_event_tail_max);
    std::deque<std::string> tail;
    tail.clear();

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        tail.push_back(line);
        while ((int)tail.size() > max_events) tail.pop_front();
    }

    for (const auto& l : tail) {
        auto e = parse_openclaw_event_best_effort(l);
        if (e.ts_ms <= 0) continue;
        openclaw_events_.push_back(e);
    }
}

std::string HttpServer::json_current() {
    auto s = history_.get_latest();
    std::ostringstream j;
    j << "{\"timestamp\":" << s.timestamp_ms;
    j << ",\"cpu\":{\"usage\":" << util::to_json_number(s.cpu.usage_pct)
      << ",\"load_1m\":" << util::to_json_number(s.cpu.load_1m)
      << ",\"load_5m\":" << util::to_json_number(s.cpu.load_5m)
      << ",\"load_15m\":" << util::to_json_number(s.cpu.load_15m)
      << ",\"cores\":[";
    for (size_t i=0; i<s.cpu.per_core_pct.size(); i++) {
        if (i>0) j<<","; j<<util::to_json_number(s.cpu.per_core_pct[i]);
    }
    j << "]}";
    j << ",\"memory\":{\"total\":" << s.mem.total_bytes
      << ",\"used\":" << s.mem.used_bytes
      << ",\"available\":" << s.mem.available_bytes
      << ",\"usage\":" << util::to_json_number(s.mem.usage_pct)
      << ",\"swap_total\":" << s.mem.swap_total
      << ",\"swap_used\":" << s.mem.swap_used << "}";
    j << ",\"disks\":[";
    for (size_t i=0; i<s.disk.disks.size(); i++) {
        if (i>0) j<<","; auto& d = s.disk.disks[i];
        j << "{\"mount\":\"" << util::escape_json(d.mount_point) << "\""
          << ",\"fs\":\"" << util::escape_json(d.filesystem) << "\""
          << ",\"total\":" << d.total_bytes << ",\"used\":" << d.used_bytes
          << ",\"available\":" << d.available_bytes
          << ",\"usage\":" << util::to_json_number(d.usage_pct) << "}";
    }
    j << "]";
    j << ",\"network\":{\"sent\":" << s.net.bytes_sent
      << ",\"recv\":" << s.net.bytes_recv
      << ",\"sent_rate\":" << s.net.bytes_sent_rate
      << ",\"recv_rate\":" << s.net.bytes_recv_rate << "}";
    j << ",\"processes\":{\"total\":" << s.procs.total_processes;
    j << ",\"top_cpu\":[";
    for (size_t i=0; i<s.procs.top_cpu.size(); i++) {
        if (i>0) j<<","; auto& p = s.procs.top_cpu[i];
        j << "{\"pid\":" << p.pid << ",\"name\":\"" << util::escape_json(p.name) << "\""
          << ",\"cpu_pct\":" << util::to_json_number(p.cpu_pct)
          << ",\"mem_bytes\":" << p.mem_bytes
          << ",\"mem_pct\":" << util::to_json_number(p.mem_pct) << "}";
    }
    j << "]";
    j << ",\"top_mem\":[";
    for (size_t i=0; i<s.procs.top_mem.size(); i++) {
        if (i>0) j<<","; auto& p = s.procs.top_mem[i];
        j << "{\"pid\":" << p.pid << ",\"name\":\"" << util::escape_json(p.name) << "\""
          << ",\"cpu_pct\":" << util::to_json_number(p.cpu_pct)
          << ",\"mem_bytes\":" << p.mem_bytes
          << ",\"mem_pct\":" << util::to_json_number(p.mem_pct) << "}";
    }
    j << "]}";
    j << "}";
    return j.str();
}

std::string HttpServer::json_history(int minutes) {
    int64_t now = util::now_ms();
    auto snaps = history_.get_range(now - (int64_t(minutes)*60000LL), now);
    size_t step = std::max(size_t(1), snaps.size() / 200);
    std::ostringstream j;
    j << "{\"count\":" << snaps.size() << ",\"points\":[";
    bool first = true;
    for (size_t i=0; i<snaps.size(); i+=step) {
        if (!first) j<<","; first=false;
        j << "{\"t\":" << snaps[i].timestamp_ms
          << ",\"cpu\":" << util::to_json_number(snaps[i].cpu.usage_pct)
          << ",\"mem\":" << util::to_json_number(snaps[i].mem.usage_pct)
          << ",\"net_in\":" << snaps[i].net.bytes_recv_rate
          << ",\"net_out\":" << snaps[i].net.bytes_sent_rate;
        if (!snaps[i].disk.disks.empty())
            j << ",\"disk\":" << util::to_json_number(snaps[i].disk.disks[0].usage_pct);
        j << "}";
    }
    j << "]}";
    return j.str();
}

std::string HttpServer::json_alerts() {
    refresh_openclaw_events();
    auto al = alerts_.get_active_alerts();
    std::ostringstream j;
    j << "{\"alerts\":[";
    for (size_t i=0; i<al.size(); i++) {
        if (i>0) j<<","; auto& a = al[i];
        std::string type_str = "process";
        if (a.type == AlertType::CPU) type_str = "cpu";
        else if (a.type == AlertType::MEMORY) type_str = "memory";
        else if (a.type == AlertType::DISK) type_str = "disk";
        else if (a.type == AlertType::NETWORK) type_str = "network";
        else if (a.type == AlertType::SECURITY) type_str = "security";
        j << "{\"level\":\"" << (a.level==AlertLevel::CRITICAL?"critical":a.level==AlertLevel::WARNING?"warning":"info") << "\""
          << ",\"type\":\"" << type_str << "\""
          << ",\"message\":\"" << util::escape_json(a.message) << "\""
          << ",\"value\":" << util::to_json_number(a.value)
          << ",\"timestamp\":" << a.timestamp_ms
          << ",\"acked\":" << (a.acknowledged?"true":"false");

        // Correlate: events within 2 minutes before the alert.
        j << ",\"related_events\":[";
        int added = 0;
        for (int ei = (int)openclaw_events_.size() - 1; ei >= 0 && added < 3; ei--) {
            const auto& e = openclaw_events_[ei];
            if (e.ts_ms <= 0) continue;
            if (e.ts_ms > a.timestamp_ms) continue;
            if ((a.timestamp_ms - e.ts_ms) > 120000) break;
            if (added > 0) j << ",";
            j << "{\"ts_ms\":" << e.ts_ms
              << ",\"skill\":\"" << util::escape_json(e.skill) << "\""
              << ",\"tool\":\"" << util::escape_json(e.tool) << "\""
              << ",\"status\":\"" << util::escape_json(e.status) << "\""
              << ",\"correlation_id\":\"" << util::escape_json(e.correlation_id) << "\""
              << ",\"command\":\"" << util::escape_json(e.command) << "\"}";
            added++;
        }
        j << "]";

        j << "}";
    }
    j << "]}";
    return j.str();
}

std::string HttpServer::json_activity() {
    refresh_openclaw_events();
    std::ostringstream j;
    j << "{\"path\":\"" << util::escape_json(config_.openclaw_event_log_file) << "\",\"events\":[";
    for (size_t i = 0; i < openclaw_events_.size(); i++) {
        if (i > 0) j << ",";
        const auto& e = openclaw_events_[i];
        j << "{\"ts_ms\":" << e.ts_ms
          << ",\"skill\":\"" << util::escape_json(e.skill) << "\""
          << ",\"tool\":\"" << util::escape_json(e.tool) << "\""
          << ",\"status\":\"" << util::escape_json(e.status) << "\""
          << ",\"correlation_id\":\"" << util::escape_json(e.correlation_id) << "\""
          << ",\"command\":\"" << util::escape_json(e.command) << "\"}";
    }
    j << "]}";
    return j.str();
}

std::string HttpServer::json_security() {
    const auto sr = alerts_.get_security_report();
    std::ostringstream j;
    j << "{\"timestamp_ms\":" << sr.timestamp_ms
      << ",\"status\":\"" << util::escape_json(sr.status) << "\""
      << ",\"openclaw\":{"
      << "\"installed\":" << (sr.openclaw.installed ? "true" : "false")
      << ",\"version\":\"" << util::escape_json(sr.openclaw.version) << "\""
      << ",\"source\":\"" << util::escape_json(sr.openclaw.source) << "\""
      << ",\"minimum_required\":\"" << util::escape_json(sr.openclaw.minimum_required) << "\""
      << ",\"minimum_recommended\":\"" << util::escape_json(sr.openclaw.minimum_recommended) << "\""
      << ",\"status\":\"" << util::escape_json(sr.openclaw.status) << "\""
      << ",\"message\":\"" << util::escape_json(sr.openclaw.message) << "\""
      << "}";

    j << ",\"config_findings\":[";
    for (size_t i = 0; i < sr.config_findings.size(); i++) {
        if (i > 0) j << ",";
        const auto& f = sr.config_findings[i];
        j << "{\"id\":\"" << util::escape_json(f.id) << "\""
          << ",\"severity\":\"" << util::escape_json(f.severity) << "\""
          << ",\"message\":\"" << util::escape_json(f.message) << "\""
          << ",\"path\":\"" << util::escape_json(f.path) << "\"}";
    }
    j << "]";

    j << ",\"integrity\":{"
      << "\"status\":\"" << util::escape_json(sr.integrity.status) << "\""
      << ",\"baseline_path\":\"" << util::escape_json(sr.integrity.baseline_path) << "\""
      << ",\"tracked_count\":" << sr.integrity.tracked_count
      << ",\"message\":\"" << util::escape_json(sr.integrity.message) << "\"";

    auto write_str_list = [&](const char* key, const std::vector<std::string>& v) {
        j << ",\"" << key << "\":[";
        for (size_t i = 0; i < v.size(); i++) {
            if (i > 0) j << ",";
            j << "\"" << util::escape_json(v[i]) << "\"";
        }
        j << "]";
    };

    write_str_list("changed", sr.integrity.changed);
    write_str_list("new", sr.integrity.new_files);
    write_str_list("missing", sr.integrity.missing);
    write_str_list("errors", sr.integrity.errors);
    j << "}";

    j << ",\"recommendations\":[";
    for (size_t i = 0; i < sr.recommendations.size(); i++) {
        if (i > 0) j << ",";
        j << "\"" << util::escape_json(sr.recommendations[i]) << "\"";
    }
    j << "]}";
    return j.str();
}

std::string HttpServer::json_containment() {
    auto actions = alerts_.get_recent_containment_actions();
    std::ostringstream j;
    j << "{"
      << "\"enabled\":" << (config_.containment_enabled ? "true" : "false")
      << ",\"shadow_mode\":" << (config_.containment_shadow_mode ? "true" : "false")
      << ",\"auto_soft_actions\":" << (config_.containment_auto_soft_actions ? "true" : "false")
      << ",\"auto_hard_actions\":" << (config_.containment_auto_hard_actions ? "true" : "false")
      << ",\"require_user_approval_for_hard\":" << (config_.containment_require_user_approval_for_hard ? "true" : "false")
      << ",\"block_ttl_sec\":" << config_.containment_block_ttl_sec
      << ",\"max_actions_per_hour\":" << config_.containment_max_actions_per_hour
      << ",\"block_port_command_configured\":" << (!config_.containment_block_port_command.empty() ? "true" : "false")
      << ",\"actions_log_file\":\"" << util::escape_json(config_.containment_actions_log_file) << "\""
      << ",\"experimental\":true"
      << ",\"actions\":[";

    for (size_t i = 0; i < actions.size(); i++) {
        if (i > 0) j << ",";
        const auto& a = actions[i];
        j << "{\"id\":\"" << util::escape_json(a.id) << "\""
          << ",\"ts_ms\":" << a.timestamp_ms
          << ",\"level\":\"" << util::escape_json(a.level) << "\""
          << ",\"action\":\"" << util::escape_json(a.action) << "\""
          << ",\"target\":\"" << util::escape_json(a.target) << "\""
          << ",\"reason\":\"" << util::escape_json(a.reason) << "\""
          << ",\"status\":\"" << util::escape_json(a.status) << "\""
          << ",\"detail\":\"" << util::escape_json(a.detail) << "\""
          << ",\"command\":\"" << util::escape_json(a.command) << "\""
          << ",\"rollback\":\"" << util::escape_json(a.rollback) << "\""
          << ",\"expires_at_ms\":" << a.expires_at_ms
          << "}";
    }

    j << "]}";
    return j.str();
}

static int parse_first_port_from_msg(const std::string& msg) {
    // Expect: "New listening TCP port detected: 9001 ..."
    auto colon = msg.find(':');
    if (colon == std::string::npos) return -1;
    size_t i = colon + 1;
    while (i < msg.size() && !std::isdigit(static_cast<unsigned char>(msg[i]))) i++;
    size_t j = i;
    while (j < msg.size() && std::isdigit(static_cast<unsigned char>(msg[j]))) j++;
    if (j == i) return -1;
    try { return std::stoi(msg.substr(i, j - i)); } catch (...) { return -1; }
}

std::string HttpServer::json_recommendations() {
    refresh_openclaw_events();
    auto s = history_.get_latest();
    auto al = alerts_.get_active_alerts();
    auto ports = alerts_.get_listening_ports();
    auto pol = alerts_.get_policy();
    auto sec = alerts_.get_security_report();
    auto containment_actions = alerts_.get_recent_containment_actions();

    std::ostringstream j;
    j << "{\"recommendations\":[";
    bool first = true;

    // Port alerts -> concrete triage steps
    for (const auto& a : al) {
        if (a.type != AlertType::NETWORK) continue;
        if (a.message.find("New listening TCP port detected") == std::string::npos) continue;
        int port = parse_first_port_from_msg(a.message);
        if (port <= 0) continue;

        int pid = -1;
        std::string proc;
        for (const auto& lp : ports) {
            if (lp.port == port) { pid = lp.pid; proc = lp.process; break; }
        }

        if (!first) j << ","; first = false;
        j << "{\"id\":\"triage_new_port_" << port << "\""
          << ",\"title\":\"Triage new listening port " << port << "\""
          << ",\"severity\":\"warning\""
          << ",\"why\":\"A new TCP listener can indicate a new service or an unexpected backdoor. Confirm what opened it.\""
          << ",\"commands\":[";
        j << "\"lsof -nP -iTCP:" << port << " -sTCP:LISTEN\"";
#ifdef __linux__
        j << ",\"ss -ltnp | grep :" << port << "\"";
#endif
        if (pid > 0) {
            j << ",\"ps -p " << pid << " -o pid,ppid,pcpu,pmem,comm\"";
            j << ",\"kill " << pid << "  # only if unexpected\"";
        }
        j << "],\"context\":{"
          << "\"pid\":" << pid
          << ",\"process\":\"" << util::escape_json(proc) << "\""
          << "}}";
    }

    // High CPU -> point at top CPU process list
    if (s.cpu.usage_pct >= config_.cpu_warn_pct) {
        if (!first) j << ","; first = false;
        j << "{\"id\":\"high_cpu\""
          << ",\"title\":\"Investigate high CPU\""
          << ",\"severity\":\"" << (s.cpu.usage_pct >= config_.cpu_crit_pct ? "critical" : "warning") << "\""
          << ",\"why\":\"CPU is elevated; check the top CPU consumers and recent OpenClaw actions.\""
          << ",\"top_cpu\":[";
        for (size_t i = 0; i < std::min<size_t>(5, s.procs.top_cpu.size()); i++) {
            if (i > 0) j << ",";
            const auto& p = s.procs.top_cpu[i];
            j << "{\"pid\":" << p.pid << ",\"name\":\"" << util::escape_json(p.name) << "\""
              << ",\"cpu_pct\":" << util::to_json_number(p.cpu_pct) << "}";
        }
        j << "]}";
    }

    // Policy reminder if not present
    if (!pol.loaded_from.empty() && pol.allow_ports.empty() && pol.allow_process.empty()) {
        if (!first) j << ","; first = false;
        j << "{\"id\":\"policy_hint\""
          << ",\"title\":\"Optional: add trusted ports/processes\""
          << ",\"severity\":\"info\""
          << ",\"why\":\"If you run known services (Postgres, etc.), add them to the trusted policy to suppress noisy port alerts.\""
          << ",\"policy_file\":\"" << util::escape_json(pol.loaded_from) << "\"}";
    }

    // Security posture recommendations from the built-in audit.
    for (size_t i = 0; i < sec.recommendations.size(); i++) {
        if (!first) j << ","; first = false;
        std::string sev = "info";
        if (sec.status == "critical") sev = "critical";
        else if (sec.status == "warn") sev = "warning";
        j << "{\"id\":\"security_rec_" << i << "\""
          << ",\"title\":\"Security posture action\""
          << ",\"severity\":\"" << sev << "\""
          << ",\"why\":\"" << util::escape_json(sec.recommendations[i]) << "\"}";
    }

    bool has_network_warning = false;
    for (const auto& a : al) {
        if (a.type == AlertType::NETWORK && !a.acknowledged) { has_network_warning = true; break; }
    }

    if (!config_.containment_enabled && has_network_warning) {
        if (!first) j << ","; first = false;
        j << "{\"id\":\"containment_experimental_opt_in\""
          << ",\"title\":\"Optional: enable experimental containment\""
          << ",\"severity\":\"info\""
          << ",\"why\":\"You have network alerts. Containment can auto-isolate incidents but is disabled by default for safety.\""
          << ",\"next_steps\":["
          << "\"Set containment_enabled = true in ~/.clawguard/config.ini\""
          << ",\"Keep containment_shadow_mode = true first to tune safely\""
          << "]}";
    } else if (config_.containment_enabled && config_.containment_shadow_mode) {
        if (!first) j << ","; first = false;
        j << "{\"id\":\"containment_shadow_mode\""
          << ",\"title\":\"Containment is in shadow mode\""
          << ",\"severity\":\"info\""
          << ",\"why\":\"Actions are simulated only. Review /api/containment before enabling enforcement.\""
          << ",\"recent_actions\":" << containment_actions.size()
          << "}";
    }

    j << "]}";
    return j.str();
}

std::string HttpServer::json_brief() {
    refresh_openclaw_events();
    auto s = history_.get_latest();
    auto al = alerts_.get_active_alerts();

    // Compute overall status
    std::string status = "healthy";
    for (const auto& a : al) {
        if (a.acknowledged) continue;
        if (a.level == AlertLevel::CRITICAL) { status = "critical"; break; }
        if (a.level == AlertLevel::WARNING) status = "warning";
    }

    std::ostringstream j;
    j << "{\"status\":\"" << status << "\""
      << ",\"timestamp\":" << s.timestamp_ms
      << ",\"cpu_usage\":" << util::to_json_number(s.cpu.usage_pct)
      << ",\"mem_usage\":" << util::to_json_number(s.mem.usage_pct)
      << ",\"alerts\":" << json_alerts()
      << ",\"security\":" << json_security()
      << ",\"containment\":" << json_containment()
      << ",\"recommendations\":" << json_recommendations()
      << ",\"activity\":" << json_activity()
      << "}";
    return j.str();
}

std::string HttpServer::json_system_info() {
    auto i = collector_.get_system_info();
    std::ostringstream j;
    j << "{\"hostname\":\"" << util::escape_json(i.hostname) << "\""
      << ",\"os\":\"" << util::escape_json(i.os) << "\""
      << ",\"kernel\":\"" << util::escape_json(i.kernel) << "\""
      << ",\"arch\":\"" << util::escape_json(i.arch) << "\""
      << ",\"cpu_cores\":" << i.cpu_cores
      << ",\"total_ram\":" << i.total_ram
      << ",\"total_ram_fmt\":\"" << util::format_bytes(i.total_ram) << "\""
      << ",\"uptime\":" << i.uptime_seconds
      << ",\"uptime_fmt\":\"" << util::format_duration(i.uptime_seconds) << "\""
      << ",\"clawguard_version\":\"" << VERSION << "\"}";
    return j.str();
}

std::string HttpServer::json_trends() {
    double cs = history_.cpu_trend_slope(30), ms = history_.mem_trend_slope(30);

    // Disk fill-rate estimation (bytes/min) and rough ETA-to-full.
    const int window_min = 30;
    const int64_t now = util::now_ms();
    const int64_t cutoff = now - (int64_t(window_min) * 60000LL);
    const auto snaps = history_.get_range(cutoff, now);

    auto linreg_slope = [](const std::vector<std::pair<double, double>>& points) -> double {
        if (points.size() < 2) return 0.0;
        double sum_x = 0, sum_y = 0, sum_xy = 0, sum_x2 = 0;
        const double n = static_cast<double>(points.size());
        for (const auto& [x, y] : points) {
            sum_x += x; sum_y += y; sum_xy += x * y; sum_x2 += x * x;
        }
        const double denom = n * sum_x2 - sum_x * sum_x;
        if (std::abs(denom) < 1e-10) return 0.0;
        return (n * sum_xy - sum_x * sum_y) / denom;
    };

    std::map<std::string, std::vector<std::pair<double, double>>> disk_points;
    std::map<std::string, uint64_t> latest_total, latest_used;

    if (!snaps.empty()) {
        for (const auto& d : snaps.back().disk.disks) {
            latest_total[d.mount_point] = d.total_bytes;
            latest_used[d.mount_point] = d.used_bytes;
        }
    }

    for (const auto& s : snaps) {
        const double x_min = static_cast<double>(s.timestamp_ms - cutoff) / 60000.0;
        for (const auto& d : s.disk.disks) {
            disk_points[d.mount_point].emplace_back(x_min, static_cast<double>(d.used_bytes));
        }
    }

    std::ostringstream j;
    j << "{\"cpu_trend_30m\":" << util::to_json_number(cs)
      << ",\"mem_trend_30m\":" << util::to_json_number(ms)
      << ",\"cpu_direction\":\"" << (cs>0.5?"rising":cs<-0.5?"falling":"stable") << "\""
      << ",\"mem_direction\":\"" << (ms>0.5?"rising":ms<-0.5?"falling":"stable") << "\""
      << ",\"disk_window_min\":" << window_min
      << ",\"disk_fill\":[";

    bool first = true;
    for (const auto& [mount, pts] : disk_points) {
        auto it_t = latest_total.find(mount);
        auto it_u = latest_used.find(mount);
        if (it_t == latest_total.end() || it_u == latest_used.end()) continue;

        const double slope_bytes_per_min = linreg_slope(pts);
        const double abs_slope = std::abs(slope_bytes_per_min);
        const char* dir = (abs_slope < (256.0 * 1024.0)) ? "stable" : (slope_bytes_per_min > 0 ? "filling" : "draining");

        if (!first) j << ",";
        first = false;

        j << "{\"mount\":\"" << util::escape_json(mount) << "\""
          << ",\"bytes_per_min\":" << util::to_json_number(slope_bytes_per_min)
          << ",\"direction\":\"" << dir << "\"";

        // ETA to full (only if filling and we have room left)
        if (slope_bytes_per_min > 0.0 && it_t->second > it_u->second) {
            const double remaining = static_cast<double>(it_t->second - it_u->second);
            const double eta_min = remaining / slope_bytes_per_min;
            const int64_t eta_sec = static_cast<int64_t>(eta_min * 60.0);
            j << ",\"eta_minutes\":" << util::to_json_number(eta_min)
              << ",\"eta_fmt\":\"" << util::escape_json(util::format_duration(eta_sec)) << "\"";
        } else {
            j << ",\"eta_minutes\":null,\"eta_fmt\":null";
        }

        j << "}";
    }

    j << "]"
      << ",\"samples\":" << history_.size() << "}";
    return j.str();
}

} // namespace clawguard
