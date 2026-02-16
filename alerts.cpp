#include "clawguard.h"
#include <array>
#include <cstdio>
#include <unistd.h>

namespace clawguard {

AlertEngine::AlertEngine(const Config& cfg) : config_(cfg) {}

namespace {

std::string trim_copy(const std::string& s) {
    size_t b = 0;
    while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) b++;
    size_t e = s.size();
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) e--;
    return s.substr(b, e - b);
}

bool config_is_readonly_mode(const Config& cfg) {
    std::string m = trim_copy(cfg.mode);
    std::transform(m.begin(), m.end(), m.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return m == "readonly" || m == "read-only" || m == "monitor" || m == "monitor-only";
}

std::string shell_quote_single(const std::string& s) {
    std::string out = "'";
    out.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '\'') out += "'\\''";
        else out.push_back(c);
    }
    out.push_back('\'');
    return out;
}

std::string run_capture_best_effort(const std::string& cmd) {
    std::array<char, 1024> buf{};
    std::string out;
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return out;
    while (fgets(buf.data(), static_cast<int>(buf.size()), p)) out += buf.data();
    pclose(p);
    return trim_copy(out);
}

std::string read_text_file_best_effort(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::vector<int> parse_version_nums(const std::string& v) {
    std::vector<int> out;
    std::regex num_re("(\\d+)");
    auto begin = std::sregex_iterator(v.begin(), v.end(), num_re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end && out.size() < 4; ++it) {
        out.push_back(std::stoi((*it)[1].str()));
    }
    return out;
}

int compare_versions(const std::string& a, const std::string& b) {
    auto pa = parse_version_nums(a);
    auto pb = parse_version_nums(b);
    const size_t n = std::max(pa.size(), pb.size());
    pa.resize(n, 0);
    pb.resize(n, 0);
    for (size_t i = 0; i < n; i++) {
        if (pa[i] < pb[i]) return -1;
        if (pa[i] > pb[i]) return 1;
    }
    return 0;
}

std::string extract_version_from_text(const std::string& text) {
    std::regex ver_re("\\b(\\d{4}\\.\\d+\\.\\d+)\\b");
    std::smatch m;
    if (std::regex_search(text, m, ver_re)) return m[1].str();
    return "";
}

bool extract_json_string_value_best_effort(const std::string& text, const std::string& key, std::string& out) {
    const std::string pat = "\"" + key + "\"";
    auto k = text.find(pat);
    if (k == std::string::npos) return false;
    auto colon = text.find(':', k + pat.size());
    if (colon == std::string::npos) return false;
    size_t i = colon + 1;
    while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i]))) i++;
    if (i >= text.size() || text[i] != '"') return false;
    i++;
    std::string v;
    bool esc = false;
    while (i < text.size()) {
        char c = text[i++];
        if (esc) {
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

bool extract_json_int64_value_best_effort(const std::string& text, const std::string& key, int64_t& out) {
    const std::string pat = "\"" + key + "\"";
    auto k = text.find(pat);
    if (k == std::string::npos) return false;
    auto colon = text.find(':', k + pat.size());
    if (colon == std::string::npos) return false;
    size_t i = colon + 1;
    while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i]))) i++;
    size_t j = i;
    while (j < text.size() && (std::isdigit(static_cast<unsigned char>(text[j])) || text[j] == '-')) j++;
    if (j == i) return false;
    try {
        out = std::stoll(text.substr(i, j - i));
        return true;
    } catch (...) {
        return false;
    }
}

std::string extract_object_after_key_best_effort(const std::string& text, const std::string& key) {
    auto k = text.find("\"" + key + "\"");
    if (k == std::string::npos) return "";
    auto b = text.find('{', k);
    if (b == std::string::npos) return "";
    int depth = 0;
    bool in_string = false;
    bool esc = false;
    for (size_t i = b; i < text.size(); i++) {
        char c = text[i];
        if (esc) { esc = false; continue; }
        if (c == '\\') { esc = true; continue; }
        if (c == '"') { in_string = !in_string; continue; }
        if (in_string) continue;
        if (c == '{') depth++;
        else if (c == '}') {
            depth--;
            if (depth == 0) return text.substr(b, i - b + 1);
        }
    }
    return "";
}

bool is_truthy_env(const char* name) {
    const char* v = std::getenv(name);
    if (!v) return false;
    std::string s(v);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return char(std::tolower(c)); });
    return s == "1" || s == "true" || s == "yes" || s == "y";
}

std::string sha256_file_best_effort(const std::string& path) {
    const std::string q = shell_quote_single(path);
    std::string out = run_capture_best_effort("shasum -a 256 " + q + " 2>/dev/null");
    if (out.empty()) out = run_capture_best_effort("sha256sum " + q + " 2>/dev/null");
    if (out.empty()) return "";
    std::istringstream ss(out);
    std::string hash;
    ss >> hash;
    if (hash.size() == 64) return hash;
    return "";
}

std::vector<std::string> collect_integrity_targets_best_effort() {
    std::vector<std::string> targets;
    const char* home = std::getenv("HOME");
    if (!home) return targets;

    auto add_if_file = [&](const std::filesystem::path& p) {
        std::error_code ec;
        if (std::filesystem::exists(p, ec) && std::filesystem::is_regular_file(p, ec)) {
            targets.push_back(p.string());
        }
    };

    const std::filesystem::path h(home);
    add_if_file(h / ".openclaw/openclaw.json");
    add_if_file(h / ".openclaw/exec-approvals.json");
    add_if_file(h / ".openclaw/cron/jobs.json");

    const auto skills = h / ".openclaw/workspace/skills";
    std::error_code ec;
    if (std::filesystem::exists(skills, ec) && std::filesystem::is_directory(skills, ec)) {
        std::vector<std::string> skill_md;
        for (const auto& ent : std::filesystem::directory_iterator(skills, ec)) {
            if (ec) break;
            if (!ent.is_directory(ec)) continue;
            auto p = ent.path() / "SKILL.md";
            if (std::filesystem::exists(p, ec) && std::filesystem::is_regular_file(p, ec)) {
                skill_md.push_back(p.string());
            }
        }
        std::sort(skill_md.begin(), skill_md.end());
        if (skill_md.size() > 200) skill_md.resize(200);
        targets.insert(targets.end(), skill_md.begin(), skill_md.end());
    }

    // Stable order + de-dupe.
    std::sort(targets.begin(), targets.end());
    targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
    return targets;
}

std::map<std::string, std::string> read_baseline_map_best_effort(const std::string& path) {
    std::map<std::string, std::string> out;
    std::ifstream f(path);
    if (!f.is_open()) return out;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto tab = line.find('\t');
        if (tab == std::string::npos) continue;
        const std::string hash = line.substr(0, tab);
        const std::string p = line.substr(tab + 1);
        if (hash.size() == 64 && !p.empty()) out[p] = hash;
    }
    return out;
}

bool write_baseline_map_best_effort(
    const std::string& path,
    const std::map<std::string, std::string>& hashes,
    std::string& err_out
) {
    std::error_code ec;
    auto parent = std::filesystem::path(path).parent_path();
    if (!parent.empty()) std::filesystem::create_directories(parent, ec);
    std::ofstream f(path, std::ios::trunc);
    if (!f.is_open()) {
        err_out = "failed to open baseline file for write";
        return false;
    }
    f << "# ClawGuard integrity baseline\n";
    f << "# hash<TAB>path\n";
    for (const auto& kv : hashes) {
        f << kv.second << '\t' << kv.first << '\n';
    }
    return true;
}

int severity_rank(const std::string& s) {
    if (s == "critical") return 3;
    if (s == "warn") return 2;
    if (s == "info") return 1;
    return 0;
}

int parse_port_from_alert_message_best_effort(const std::string& msg) {
    auto pos = msg.find("New listening TCP port detected:");
    if (pos == std::string::npos) return -1;
    auto colon = msg.find(':', pos);
    if (colon == std::string::npos) return -1;
    size_t i = colon + 1;
    while (i < msg.size() && !std::isdigit(static_cast<unsigned char>(msg[i]))) i++;
    size_t j = i;
    while (j < msg.size() && std::isdigit(static_cast<unsigned char>(msg[j]))) j++;
    if (j == i) return -1;
    try { return std::stoi(msg.substr(i, j - i)); } catch (...) { return -1; }
}

} // namespace

TrustedOpsPolicy AlertEngine::load_policy_best_effort(const std::string& path) const {
    TrustedOpsPolicy pol;
    pol.loaded_from = path;
    pol.loaded_ms = util::now_ms();

    if (path.empty()) return pol;
    std::ifstream f(path);
    if (!f.is_open()) return pol;

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        val.erase(0, val.find_first_not_of(" \t"));
        val.erase(val.find_last_not_of(" \t") + 1);

        if (key == "allow_port") {
            try {
                int p = std::stoi(val);
                if (p > 0 && p <= 65535) pol.allow_ports.insert(p);
            } catch (...) {}
        } else if (key == "allow_process") {
            if (!val.empty()) pol.allow_process.insert(val);
        } else if (key == "allow_skill") {
            if (!val.empty()) pol.allow_skill.insert(val);
        } else if (key == "allow_cmd_prefix") {
            if (!val.empty()) pol.allow_cmd_prefix.push_back(val);
        } else if (key == "allow_cmd_regex") {
            if (!val.empty()) pol.allow_cmd_regex.push_back(val);
        }
    }

    return pol;
}

std::vector<ListeningPort> AlertEngine::scan_listening_ports_best_effort() const {
    std::vector<ListeningPort> out;

#ifdef __linux__
    auto scan_proc = [&](const char* path) {
        std::ifstream f(path);
        if (!f.is_open()) return;
        std::string line;
        std::getline(f, line); // header
        while (std::getline(f, line)) {
            std::istringstream ss(line);
            std::string sl, local, rem, st;
            // sl local_address rem_address st ...
            ss >> sl >> local >> rem >> st;
            if (st != "0A") continue; // LISTEN
            auto colon = local.find(':');
            if (colon == std::string::npos) continue;
            std::string port_hex = local.substr(colon + 1);
            int port = 0;
            try {
                port = std::stoi(port_hex, nullptr, 16);
            } catch (...) {
                continue;
            }
            if (port <= 0 || port > 65535) continue;
            ListeningPort lp;
            lp.port = port;
            lp.proto = "tcp";
            out.push_back(lp);
        }
    };
    scan_proc("/proc/net/tcp");
    scan_proc("/proc/net/tcp6");
#endif

#ifdef __APPLE__
    // lsof is available on macOS and can provide process context without root in many cases.
    FILE* pipe = popen("lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null", "r");
    if (pipe) {
        char buf[1024];
        bool first = true;
        while (fgets(buf, sizeof(buf), pipe)) {
            if (first) { first = false; continue; } // header
            std::string line(buf);
            if (line.empty()) continue;

            // Expect: COMMAND PID USER ... NAME
            // NAME often: "TCP *:631 (LISTEN)" or "TCP 127.0.0.1:1234 (LISTEN)"
            std::istringstream ss(line);
            ListeningPort lp;
            ss >> lp.process;
            ss >> lp.pid;

            auto pos = line.rfind("TCP ");
            if (pos == std::string::npos) continue;
            auto name = line.substr(pos + 4);
            auto colon = name.rfind(':');
            if (colon == std::string::npos) continue;
            size_t i = colon + 1;
            std::string port_s;
            while (i < name.size() && std::isdigit(static_cast<unsigned char>(name[i]))) {
                port_s.push_back(name[i]);
                i++;
            }
            if (port_s.empty()) continue;
            int port = 0;
            try {
                port = std::stoi(port_s);
            } catch (...) {
                continue;
            }
            if (port <= 0 || port > 65535) continue;
            lp.port = port;
            lp.proto = "tcp";

            // Bind extraction best-effort: take token between "TCP " and ":PORT"
            auto bind_end = name.rfind(':');
            if (bind_end != std::string::npos) {
                auto bind_tok = name.substr(0, bind_end);
                // First token is bind address; strip trailing spaces
                auto sp = bind_tok.find(' ');
                if (sp != std::string::npos) bind_tok = bind_tok.substr(0, sp);
                // normalize common patterns
                if (bind_tok == "*") lp.bind = "*";
                else lp.bind = bind_tok;
            }

            out.push_back(lp);
        }
        pclose(pipe);
    }
#endif

    // De-dupe by port (keep first one with process info if present)
    std::sort(out.begin(), out.end(), [](const ListeningPort& a, const ListeningPort& b) {
        if (a.port != b.port) return a.port < b.port;
        // Prefer entries with a known pid/process
        return a.pid > b.pid;
    });
    out.erase(std::unique(out.begin(), out.end(), [](const ListeningPort& a, const ListeningPort& b) {
        return a.port == b.port;
    }), out.end());

    return out;
}

std::vector<ListeningPort> AlertEngine::get_listening_ports() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_listening_ports_;
}

TrustedOpsPolicy AlertEngine::get_policy() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return policy_;
}

SecurityReport AlertEngine::get_security_report() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_security_report_;
}

std::vector<ContainmentAction> AlertEngine::get_recent_containment_actions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return recent_containment_actions_;
}

std::string AlertEngine::detect_recent_skill_best_effort(int64_t now_ms, int64_t window_ms) const {
    if (config_.openclaw_event_log_file.empty()) return "";
    std::ifstream f(config_.openclaw_event_log_file);
    if (!f.is_open()) return "";

    const int max_events = std::max(1, config_.openclaw_event_tail_max);
    std::deque<std::string> tail;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        tail.push_back(line);
        while ((int)tail.size() > max_events) tail.pop_front();
    }

    for (int i = (int)tail.size() - 1; i >= 0; i--) {
        int64_t ts = 0;
        std::string skill;
        if (!extract_json_int64_value_best_effort(tail[i], "ts_ms", ts)) continue;
        if (!extract_json_string_value_best_effort(tail[i], "skill", skill)) continue;
        skill = trim_copy(skill);
        if (skill.empty()) continue;
        if (ts > now_ms) continue;
        if ((now_ms - ts) > window_ms) break;
        return skill;
    }
    return "";
}

void AlertEngine::record_containment_action_locked(const ContainmentAction& action) {
    recent_containment_actions_.push_back(action);
    while (recent_containment_actions_.size() > 200) {
        recent_containment_actions_.erase(recent_containment_actions_.begin());
    }
}

bool AlertEngine::append_containment_action_log_best_effort(const ContainmentAction& action) const {
    if (config_.containment_actions_log_file.empty()) return false;
    std::error_code ec;
    auto p = std::filesystem::path(config_.containment_actions_log_file);
    if (!p.parent_path().empty()) {
        std::filesystem::create_directories(p.parent_path(), ec);
    }
    std::ofstream f(config_.containment_actions_log_file, std::ios::app);
    if (!f.is_open()) return false;
    f << "{\"ts_ms\":" << action.timestamp_ms
      << ",\"id\":\"" << util::escape_json(action.id) << "\""
      << ",\"level\":\"" << util::escape_json(action.level) << "\""
      << ",\"action\":\"" << util::escape_json(action.action) << "\""
      << ",\"target\":\"" << util::escape_json(action.target) << "\""
      << ",\"reason\":\"" << util::escape_json(action.reason) << "\""
      << ",\"status\":\"" << util::escape_json(action.status) << "\""
      << ",\"detail\":\"" << util::escape_json(action.detail) << "\""
      << ",\"command\":\"" << util::escape_json(action.command) << "\""
      << ",\"rollback\":\"" << util::escape_json(action.rollback) << "\""
      << ",\"expires_at_ms\":" << action.expires_at_ms
      << "}\n";
    return true;
}

bool AlertEngine::execute_containment_action_best_effort(ContainmentAction& action) const {
    if (config_is_readonly_mode(config_)) {
        action.status = "skipped";
        action.detail = "readonly mode: containment execution disabled";
        return false;
    }

    if (action.action == "disable_skill") {
        std::string skill;
        if (action.target.rfind("skill:", 0) == 0) skill = action.target.substr(6);
        skill = trim_copy(skill);
        if (skill.empty()) {
            action.status = "error";
            action.detail = "missing skill name";
            return false;
        }
        const char* home = std::getenv("HOME");
        if (!home) {
            action.status = "error";
            action.detail = "HOME not set";
            return false;
        }
        std::filesystem::path src = std::filesystem::path(home) / ".openclaw/workspace/skills" / skill;
        std::filesystem::path dst_root = std::filesystem::path(home) / ".openclaw/workspace/skills-disabled";
        std::error_code ec;
        if (!std::filesystem::exists(src, ec)) {
            action.status = "error";
            action.detail = "skill path not found: " + src.string();
            return false;
        }
        std::filesystem::create_directories(dst_root, ec);
        std::filesystem::path dst = dst_root / (skill + "-" + std::to_string(action.timestamp_ms));
        std::filesystem::rename(src, dst, ec);
        if (ec) {
            action.status = "error";
            action.detail = "failed to disable skill: " + ec.message();
            return false;
        }
        action.status = "executed";
        action.detail = "skill moved to " + dst.string();
        action.rollback = "mv " + shell_quote_single(dst.string()) + " " + shell_quote_single(src.string());
        return true;
    }

    if (action.action == "kill_process") {
        int pid = -1;
        if (action.target.rfind("pid:", 0) == 0) {
            try { pid = std::stoi(action.target.substr(4)); } catch (...) { pid = -1; }
        }
        if (pid <= 1) {
            action.status = "error";
            action.detail = "invalid pid";
            return false;
        }
        if (kill(pid, SIGTERM) != 0) {
            action.status = "error";
            action.detail = "SIGTERM failed";
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        if (kill(pid, 0) == 0) {
            (void)kill(pid, SIGKILL);
        }
        action.status = "executed";
        action.detail = "process termination signaled";
        return true;
    }

    if (action.action == "block_port") {
        action.status = "skipped";
        action.detail = "block_port execution is disabled in v1.0 for safety (shell commands removed)";
        action.command.clear();
        action.rollback.clear();
        action.expires_at_ms = 0;
        return false;
    }

    action.status = "error";
    action.detail = "unknown containment action";
    return false;
}

SecurityReport AlertEngine::run_security_audit_best_effort(int64_t now_ms) const {
    SecurityReport report;
    report.timestamp_ms = now_ms;

    // OpenClaw version posture
    {
        OpenClawVersionStatus o;
        o.status = "warn";
        o.message = "OpenClaw version not detected; cannot validate against known vulnerable versions.";

        const std::string cmd_v1 = run_capture_best_effort("openclaw --version 2>/dev/null");
        std::string version = extract_version_from_text(cmd_v1);
        if (!version.empty()) {
            o.installed = true;
            o.version = version;
            o.source = "command";
        } else {
            const std::string cmd_v2 = run_capture_best_effort("openclaw version 2>/dev/null");
            version = extract_version_from_text(cmd_v2);
            if (!version.empty()) {
                o.installed = true;
                o.version = version;
                o.source = "command";
            }
        }

        std::string cfg_text;
        if (o.version.empty() && !config_.openclaw_config_file.empty()) {
            cfg_text = read_text_file_best_effort(config_.openclaw_config_file);
            std::string v;
            if (extract_json_string_value_best_effort(cfg_text, "lastTouchedVersion", v) && !v.empty()) {
                o.installed = true;
                o.version = v;
                o.source = "openclaw.json";
            } else if (extract_json_string_value_best_effort(cfg_text, "lastRunVersion", v) && !v.empty()) {
                o.installed = true;
                o.version = v;
                o.source = "openclaw.json";
            }
        }

        if (!o.version.empty()) {
            if (compare_versions(o.version, o.minimum_required) < 0) {
                o.status = "critical";
                o.message = "OpenClaw " + o.version + " is below required " + o.minimum_required +
                            " and may be vulnerable to known critical issues.";
            } else if (compare_versions(o.version, o.minimum_recommended) < 0) {
                o.status = "warn";
                o.message = "OpenClaw " + o.version + " is below recommended " + o.minimum_recommended +
                            ". Upgrade for the latest security fixes.";
            } else {
                o.status = "ok";
                o.message = "OpenClaw " + o.version + " meets the recommended security baseline.";
            }
        }

        report.openclaw = o;
    }

    // OpenClaw config risk checks (best-effort)
    {
        const std::string path = config_.openclaw_config_file;
        const std::string cfg_text = path.empty() ? "" : read_text_file_best_effort(path);
        if (!cfg_text.empty()) {
            const std::string gateway_obj = extract_object_after_key_best_effort(cfg_text, "gateway");
            if (!gateway_obj.empty()) {
                std::string bind;
                if (extract_json_string_value_best_effort(gateway_obj, "bind", bind)) {
                    const std::string b = trim_copy(bind);
                    if (!b.empty() && b != "loopback" && b != "127.0.0.1" && b != "localhost" && b != "::1") {
                        report.config_findings.push_back(SecurityFinding{
                            "gateway_bind_exposed", "critical",
                            "Gateway bind is '" + b + "' (not loopback). This may expose control endpoints.",
                            path
                        });
                    }
                }

                const std::string auth_obj = extract_object_after_key_best_effort(gateway_obj, "auth");
                if (!auth_obj.empty()) {
                    std::string mode;
                    if (extract_json_string_value_best_effort(auth_obj, "mode", mode)) {
                        std::string m = trim_copy(mode);
                        std::transform(m.begin(), m.end(), m.begin(), [](unsigned char c){ return char(std::tolower(c)); });
                        if (m == "off" || m == "none" || m == "disabled" || m == "noauth") {
                            report.config_findings.push_back(SecurityFinding{
                                "gateway_auth_disabled", "critical",
                                "Gateway authentication appears disabled.", path
                            });
                        }
                    }
                }
            }

            std::error_code ec;
            auto perms = std::filesystem::status(path, ec).permissions();
            if (!ec) {
                const bool others_read = (perms & std::filesystem::perms::others_read) != std::filesystem::perms::none;
                const bool others_write = (perms & std::filesystem::perms::others_write) != std::filesystem::perms::none;
                const bool group_write = (perms & std::filesystem::perms::group_write) != std::filesystem::perms::none;
                if (others_read) {
                    report.config_findings.push_back(SecurityFinding{
                        "config_world_readable", "warn",
                        "OpenClaw config is world-readable. Consider restricting file permissions.", path
                    });
                }
                if (others_write || group_write) {
                    report.config_findings.push_back(SecurityFinding{
                        "config_writable_by_others", "critical",
                        "OpenClaw config is writable by group/others. Lock permissions down immediately.", path
                    });
                }
            }
        }
    }

    // Integrity drift checks
    {
        IntegrityStatus ir;
        ir.baseline_path = config_.integrity_baseline_file;
        if (ir.baseline_path.empty()) {
            const char* home = std::getenv("HOME");
            ir.baseline_path = std::string(home ? home : "/tmp") + "/.clawguard/integrity-baseline.txt";
        }

        const auto targets = collect_integrity_targets_best_effort();
        std::map<std::string, std::string> current;
        for (const auto& p : targets) {
            const std::string h = sha256_file_best_effort(p);
            if (h.empty()) ir.errors.push_back("hash_failed:" + p);
            else current[p] = h;
        }
        ir.tracked_count = static_cast<int>(current.size());

        const bool force_rebaseline = is_truthy_env("CLAWGUARD_REBASELINE");
        std::error_code ec;
        const bool baseline_exists = std::filesystem::exists(ir.baseline_path, ec);

        if (force_rebaseline || !baseline_exists) {
            std::string err;
            if (!write_baseline_map_best_effort(ir.baseline_path, current, err)) {
                ir.status = "error";
                if (!err.empty()) ir.errors.push_back(err);
                ir.message = "Failed to write integrity baseline.";
            } else {
                ir.status = force_rebaseline ? "info" : "initialized";
                ir.message = force_rebaseline
                    ? "Integrity baseline rebuilt from current files."
                    : "Integrity baseline created. Re-run scan to detect drift.";
            }
            report.integrity = ir;
        } else {
            const auto baseline = read_baseline_map_best_effort(ir.baseline_path);
            for (const auto& kv : current) {
                auto it = baseline.find(kv.first);
                if (it == baseline.end()) ir.new_files.push_back(kv.first);
                else if (it->second != kv.second) ir.changed.push_back(kv.first);
            }
            for (const auto& kv : baseline) {
                if (current.find(kv.first) == current.end()) ir.missing.push_back(kv.first);
            }
            if (ir.changed.size() > 25) ir.changed.resize(25);
            if (ir.new_files.size() > 25) ir.new_files.resize(25);
            if (ir.missing.size() > 25) ir.missing.resize(25);

            if (!ir.changed.empty() || !ir.missing.empty()) ir.status = "warn";
            else if (!ir.new_files.empty()) ir.status = "info";
            else ir.status = "ok";
            ir.message = "Integrity check complete.";
            report.integrity = ir;
        }
    }

    // Recommendations + overall status
    report.status = "ok";
    if (severity_rank(report.openclaw.status) >= severity_rank("warn")) report.status = "warn";
    if (severity_rank(report.openclaw.status) >= severity_rank("critical")) report.status = "critical";
    for (const auto& f : report.config_findings) {
        if (severity_rank(f.severity) > severity_rank(report.status)) report.status = f.severity;
    }
    if (report.integrity.status == "warn" && severity_rank(report.status) < severity_rank("warn")) {
        report.status = "warn";
    }

    if (report.openclaw.status == "critical" || report.openclaw.status == "warn") {
        report.recommendations.push_back(
            "Upgrade OpenClaw to at least " + report.openclaw.minimum_recommended +
            " (current: " + (report.openclaw.version.empty() ? std::string("unknown") : report.openclaw.version) + ")."
        );
    }
    for (const auto& f : report.config_findings) {
        if (f.id == "gateway_bind_exposed") {
            report.recommendations.push_back("Set OpenClaw gateway bind to loopback/localhost only.");
        } else if (f.id == "gateway_auth_disabled") {
            report.recommendations.push_back("Enable OpenClaw gateway token auth immediately.");
        } else if (f.id == "config_world_readable") {
            report.recommendations.push_back("Restrict OpenClaw config permissions (owner-only read/write).");
        } else if (f.id == "config_writable_by_others") {
            report.recommendations.push_back("Remove group/other write permissions from OpenClaw config now.");
        }
    }
    if (report.integrity.status == "warn") {
        report.recommendations.push_back(
            "Investigate unexpected changes in tracked OpenClaw files/skills. If expected, run with CLAWGUARD_REBASELINE=1."
        );
    } else if (report.integrity.status == "initialized") {
        report.recommendations.push_back("Run ClawGuard again to begin detecting integrity drift.");
    }
    if (report.recommendations.empty()) {
        report.recommendations.push_back("Security posture looks healthy for current checks.");
    }

    return report;
}

std::vector<Alert> AlertEngine::evaluate(const SystemSnapshot& snap) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Alert> new_alerts;
    int64_t now = util::now_ms();
    
    auto maybe_alert = [&](AlertType type, AlertLevel level, double value,
                           double threshold, const std::string& msg,
                           const std::string& key = "") {
        // Check cooldown (either per-type or per-key).
        if (!key.empty()) {
            auto it = last_alert_key_time_.find(key);
            if (it != last_alert_key_time_.end() && (now - it->second) < ALERT_COOLDOWN_MS) {
                return;
            }
            last_alert_key_time_[key] = now;
        } else {
            auto it = last_alert_time_.find(type);
            if (it != last_alert_time_.end() && (now - it->second) < ALERT_COOLDOWN_MS) {
                return;
            }
            last_alert_time_[type] = now;
        }
        
        Alert alert;
        alert.level = level;
        alert.type = type;
        alert.value = value;
        alert.threshold = threshold;
        alert.message = msg;
        alert.timestamp_ms = now;
        
        new_alerts.push_back(alert);
        active_alerts_.push_back(alert);
    };

    // CPU alerts
    if (snap.cpu.usage_pct >= config_.cpu_crit_pct) {
        maybe_alert(AlertType::CPU, AlertLevel::CRITICAL, snap.cpu.usage_pct, config_.cpu_crit_pct,
            "CPU usage CRITICAL at " + util::to_json_number(snap.cpu.usage_pct) + "%");
    } else if (snap.cpu.usage_pct >= config_.cpu_warn_pct) {
        maybe_alert(AlertType::CPU, AlertLevel::WARNING, snap.cpu.usage_pct, config_.cpu_warn_pct,
            "CPU usage HIGH at " + util::to_json_number(snap.cpu.usage_pct) + "%");
    }
    
    // Memory alerts
    if (snap.mem.usage_pct >= config_.mem_crit_pct) {
        maybe_alert(AlertType::MEMORY, AlertLevel::CRITICAL, snap.mem.usage_pct, config_.mem_crit_pct,
            "Memory usage CRITICAL at " + util::to_json_number(snap.mem.usage_pct) + 
            "% (" + util::format_bytes(snap.mem.used_bytes) + " / " + util::format_bytes(snap.mem.total_bytes) + ")");
    } else if (snap.mem.usage_pct >= config_.mem_warn_pct) {
        maybe_alert(AlertType::MEMORY, AlertLevel::WARNING, snap.mem.usage_pct, config_.mem_warn_pct,
            "Memory usage HIGH at " + util::to_json_number(snap.mem.usage_pct) + "%");
    }
    
    // Disk alerts
    for (const auto& disk : snap.disk.disks) {
        if (disk.usage_pct >= config_.disk_crit_pct) {
            maybe_alert(AlertType::DISK, AlertLevel::CRITICAL, disk.usage_pct, config_.disk_crit_pct,
                "Disk " + disk.mount_point + " CRITICAL at " + util::to_json_number(disk.usage_pct) + 
                "% (" + util::format_bytes(disk.available_bytes) + " free)");
        } else if (disk.usage_pct >= config_.disk_warn_pct) {
            maybe_alert(AlertType::DISK, AlertLevel::WARNING, disk.usage_pct, config_.disk_warn_pct,
                "Disk " + disk.mount_point + " filling up at " + util::to_json_number(disk.usage_pct) + "%");
        }
    }

    // Pro signal: new listening ports (best-effort, baseline on first scan).
    if (config_.port_scan_interval_sec > 0 &&
        (last_port_scan_ms_ == 0 || (now - last_port_scan_ms_) >= (int64_t(config_.port_scan_interval_sec) * 1000LL))) {
        last_port_scan_ms_ = now;
        policy_ = load_policy_best_effort(config_.policy_file);
        last_listening_ports_ = scan_listening_ports_best_effort();

        std::set<int> current;
        for (const auto& lp : last_listening_ports_) {
            if (lp.port <= 0) continue;
            if (lp.port == config_.http_port) continue; // ClawGuard itself
            if (policy_.allow_ports.count(lp.port)) continue; // known-good
            if (!lp.process.empty() && policy_.allow_process.count(lp.process)) continue; // known-good
            current.insert(lp.port);
        }

        if (!ports_baselined_) {
            known_listen_ports_ = current;
            ports_baselined_ = true;
        } else {
            for (int port : current) {
                if (known_listen_ports_.count(port)) continue;
                known_listen_ports_.insert(port);

                std::string extra;
                for (const auto& lp : last_listening_ports_) {
                    if (lp.port != port) continue;
                    if (!lp.process.empty() && lp.pid > 0) {
                        extra = " (" + lp.process + " pid " + std::to_string(lp.pid) + ")";
                    }
                    break;
                }

                maybe_alert(AlertType::NETWORK, AlertLevel::WARNING, double(port), double(port),
                    "New listening TCP port detected: " + std::to_string(port) + extra,
                    "listen_port:" + std::to_string(port));
            }
        }
    }

    // Security posture checks (OpenClaw version/config/integrity).
    if (config_.security_scan_interval_sec > 0 &&
        (last_security_scan_ms_ == 0 ||
         (now - last_security_scan_ms_) >= (int64_t(config_.security_scan_interval_sec) * 1000LL))) {
        last_security_scan_ms_ = now;
        last_security_report_ = run_security_audit_best_effort(now);

        if (last_security_report_.openclaw.status == "critical") {
            maybe_alert(
                AlertType::SECURITY, AlertLevel::CRITICAL, 1.0, 1.0,
                last_security_report_.openclaw.message, "security:openclaw_version"
            );
        } else if (last_security_report_.openclaw.status == "warn") {
            maybe_alert(
                AlertType::SECURITY, AlertLevel::WARNING, 1.0, 1.0,
                last_security_report_.openclaw.message, "security:openclaw_version"
            );
        }

        for (const auto& f : last_security_report_.config_findings) {
            if (f.severity == "critical") {
                maybe_alert(AlertType::SECURITY, AlertLevel::CRITICAL, 1.0, 1.0, f.message, "security:" + f.id);
            } else if (f.severity == "warn") {
                maybe_alert(AlertType::SECURITY, AlertLevel::WARNING, 1.0, 1.0, f.message, "security:" + f.id);
            }
        }

        if (last_security_report_.integrity.status == "warn") {
            maybe_alert(
                AlertType::SECURITY, AlertLevel::WARNING, 1.0, 1.0,
                "Integrity drift detected in tracked OpenClaw files/skills.",
                "security:integrity_drift"
            );
        }
    }

    // Experimental containment (off by default). Uses explicit policy gates and rate limiting.
    if (config_.containment_enabled && !config_is_readonly_mode(config_)) {
        const auto containment_candidates = new_alerts;
        // 1-hour rate limiter window.
        if (containment_window_start_ms_ == 0 || (now - containment_window_start_ms_) >= 3600000LL) {
            containment_window_start_ms_ = now;
            containment_actions_in_window_ = 0;
        }

        for (const auto& a : containment_candidates) {
            if (a.type != AlertType::NETWORK) continue;
            if (a.message.find("New listening TCP port detected") == std::string::npos) continue;

            const int port = parse_port_from_alert_message_best_effort(a.message);
            if (port <= 0) continue;

            int pid = -1;
            std::string process;
            for (const auto& lp : last_listening_ports_) {
                if (lp.port != port) continue;
                if (lp.pid > 0) pid = lp.pid;
                if (!lp.process.empty()) process = lp.process;
                break;
            }

            const std::string skill = detect_recent_skill_best_effort(now, 120000);
            ContainmentAction ca;
            ca.timestamp_ms = now;
            ca.reason = "New listening TCP port " + std::to_string(port) + " detected.";

            if (!skill.empty()) {
                ca.level = "soft";
                ca.action = "disable_skill";
                ca.target = "skill:" + skill;
                ca.detail = "Mapped from recent OpenClaw activity.";
            } else if (!config_.containment_block_port_command.empty()) {
                ca.level = "soft";
                ca.action = "block_port";
                ca.target = "port:" + std::to_string(port);
                ca.detail = "No skill attribution found; using port block policy.";
            } else if (pid > 1) {
                ca.level = "hard";
                ca.action = "kill_process";
                ca.target = "pid:" + std::to_string(pid);
                ca.detail = "No skill attribution and no block command configured; process kill candidate.";
            } else {
                ca.level = "soft";
                ca.action = "block_port";
                ca.target = "port:" + std::to_string(port);
                ca.detail = "No actionable target available.";
            }

            ca.id = ca.action + ":" + ca.target;

            // De-dupe same containment key for 10 minutes.
            auto it_last = last_containment_action_ms_.find(ca.id);
            if (it_last != last_containment_action_ms_.end() && (now - it_last->second) < 600000LL) {
                continue;
            }
            last_containment_action_ms_[ca.id] = now;

            // Rate limit containment actions.
            if (containment_actions_in_window_ >= std::max(1, config_.containment_max_actions_per_hour)) {
                ca.status = "skipped";
                ca.detail = "Rate limited (containment_max_actions_per_hour reached).";
                record_containment_action_locked(ca);
                (void)append_containment_action_log_best_effort(ca);
                maybe_alert(
                    AlertType::SECURITY, AlertLevel::INFO, 0.0, 0.0,
                    "Containment skipped due to rate limit for " + ca.target,
                    "containment:" + ca.id + ":rate_limited"
                );
                continue;
            }

            bool attempted_execute = false;
            if (config_.containment_shadow_mode) {
                ca.status = "shadow";
            } else if (ca.level == "hard") {
                if (config_.containment_require_user_approval_for_hard || !config_.containment_auto_hard_actions) {
                    ca.status = "requires_approval";
                } else {
                    ca.status = "executed";
                    attempted_execute = true;
                }
            } else {
                if (!config_.containment_auto_soft_actions) {
                    ca.status = "requires_approval";
                } else {
                    ca.status = "executed";
                    attempted_execute = true;
                }
            }

            if (attempted_execute) {
                if (!execute_containment_action_best_effort(ca)) {
                    // execute_containment_action_best_effort sets status+detail
                    if (ca.status.empty()) ca.status = "error";
                }
            }

            record_containment_action_locked(ca);
            (void)append_containment_action_log_best_effort(ca);
            containment_actions_in_window_++;

            AlertLevel al = AlertLevel::INFO;
            if (ca.status == "executed") {
                al = (ca.level == "hard") ? AlertLevel::CRITICAL : AlertLevel::WARNING;
            } else if (ca.status == "error" || ca.status == "skipped") {
                al = AlertLevel::WARNING;
            }

            std::string msg = "Containment " + ca.status + ": " + ca.action + " -> " + ca.target;
            if (!ca.detail.empty()) msg += " (" + ca.detail + ")";
            maybe_alert(
                AlertType::SECURITY, al, 1.0, 1.0, msg,
                "containment:" + ca.id + ":" + ca.status
            );
        }
    }
    
    // Trim old alerts (keep last 100)
    while (active_alerts_.size() > 100) {
        active_alerts_.erase(active_alerts_.begin());
    }
    
    return new_alerts;
}

std::vector<Alert> AlertEngine::get_active_alerts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_alerts_;
}

void AlertEngine::acknowledge(size_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index < active_alerts_.size()) {
        active_alerts_[index].acknowledged = true;
    }
}

void AlertEngine::set_config(const Config& cfg) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = cfg;
    if (config_is_readonly_mode(config_)) {
        config_.containment_enabled = false;
        config_.containment_auto_soft_actions = false;
        config_.containment_auto_hard_actions = false;
    }
}

void AlertEngine::write_alert_file(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ofstream f(path);
    if (!f.is_open()) return;
    
    // Write alerts in a format OpenClaw can easily read
    f << "# ClawGuard Alerts - " << util::format_timestamp(util::now_ms()) << "\n";
    f << "# This file is auto-generated. Do not edit.\n\n";
    
    bool has_unacked = false;
    for (const auto& alert : active_alerts_) {
        if (alert.acknowledged) continue;
        has_unacked = true;
        
        std::string level_str;
        switch (alert.level) {
            case AlertLevel::INFO: level_str = "INFO"; break;
            case AlertLevel::WARNING: level_str = "WARNING"; break;
            case AlertLevel::CRITICAL: level_str = "CRITICAL"; break;
        }
        
        f << "[" << level_str << "] " << alert.message 
          << " (at " << util::format_timestamp(alert.timestamp_ms) << ")\n";
    }
    
    if (!has_unacked) {
        f << "ALL_CLEAR: No active alerts. System healthy.\n";
    }
}

} // namespace clawguard
