#pragma once

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <atomic>
#include <functional>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <thread>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <iostream>
#include <iomanip>
#include <set>
#include <unordered_set>
#include <regex>

#include <sys/utsname.h>

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/processor_info.h>
#include <mach/mach_host.h>
#include <sys/sysctl.h>
#include <sys/mount.h>
#elif __linux__
#include <sys/sysinfo.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <unistd.h>
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace clawguard {

constexpr const char* VERSION = "1.0.0";
constexpr const char* PRODUCT_NAME = "ClawGuard";

// ─── Configuration ────────────────────────────────────────────
struct Config {
    int poll_interval_sec = 5;
    int history_max_minutes = 1440;      // 24 hours
    std::string mode = "readonly";       // readonly|standard
    int http_port = 7677;
    std::string http_bind = "127.0.0.1"; // loopback-only by default
    bool allow_remote_http = false;      // must be explicitly enabled for non-loopback binds
    std::string api_auth_token = "";     // required when allow_remote_http=true
    bool api_rate_limit_enabled = true;
    int api_rate_limit_per_min = 120;    // per-client per minute
    std::string data_dir = "";

    // "Pro" signal: detect new listening ports without being chatty.
    int port_scan_interval_sec = 60;

    // OpenClaw correlation (optional): JSONL file with activity events.
    // Example line:
    // {"ts_ms":1700000000000,"skill":"mail-summarizer","tool":"exec","command":"...","status":"start","correlation_id":"..."}
    std::string openclaw_event_log_file = "";
    int openclaw_event_tail_max = 200;

    // Trusted ops policy: simple INI-like allowlist that both OpenClaw and ClawGuard can read.
    // See policy.example.ini.
    std::string policy_file = "";

    // Security posture checks for OpenClaw + integrity drift.
    int security_scan_interval_sec = 60;
    std::string openclaw_config_file = "";
    std::string integrity_baseline_file = "";

    // Experimental automatic containment (off by default).
    bool containment_enabled = false;
    bool containment_shadow_mode = true;
    bool containment_auto_soft_actions = false;
    bool containment_auto_hard_actions = false;
    bool containment_require_user_approval_for_hard = true;
    int containment_block_ttl_sec = 900;
    int containment_max_actions_per_hour = 6;
    std::string containment_block_port_command = "";
    std::string containment_actions_log_file = "";
    
    float cpu_warn_pct = 80.0f;
    float cpu_crit_pct = 95.0f;
    float mem_warn_pct = 80.0f;
    float mem_crit_pct = 95.0f;
    float disk_warn_pct = 85.0f;
    float disk_crit_pct = 95.0f;
    
    bool openclaw_alerts = true;
    std::string alert_file = "";
    
    static Config load(const std::string& path);
    void save(const std::string& path) const;
};

// ─── Metric Snapshots ─────────────────────────────────────────
struct CpuSnapshot {
    double usage_pct = 0.0;
    std::vector<double> per_core_pct;
    double load_1m = 0.0;
    double load_5m = 0.0;
    double load_15m = 0.0;
    int64_t timestamp_ms = 0;
};

struct MemSnapshot {
    uint64_t total_bytes = 0;
    uint64_t used_bytes = 0;
    uint64_t available_bytes = 0;
    double usage_pct = 0.0;
    uint64_t swap_total = 0;
    uint64_t swap_used = 0;
    int64_t timestamp_ms = 0;
};

struct DiskInfo {
    std::string mount_point;
    std::string filesystem;
    uint64_t total_bytes = 0;
    uint64_t used_bytes = 0;
    uint64_t available_bytes = 0;
    double usage_pct = 0.0;
};

struct DiskSnapshot {
    std::vector<DiskInfo> disks;
    int64_t timestamp_ms = 0;
};

struct NetworkSnapshot {
    uint64_t bytes_sent = 0;
    uint64_t bytes_recv = 0;
    uint64_t bytes_sent_rate = 0;
    uint64_t bytes_recv_rate = 0;
    int64_t timestamp_ms = 0;
};

struct OpenClawEvent {
    int64_t ts_ms = 0;
    std::string skill;
    std::string tool;
    std::string command;
    std::string status; // start|ok|error|denied|info
    std::string correlation_id;
};

struct TrustedOpsPolicy {
    std::set<int> allow_ports;
    std::unordered_set<std::string> allow_process;
    std::unordered_set<std::string> allow_skill;
    std::vector<std::string> allow_cmd_prefix;
    std::vector<std::string> allow_cmd_regex;
    std::string loaded_from;
    int64_t loaded_ms = 0;
};

struct SecurityFinding {
    std::string id;
    std::string severity; // info|warn|critical
    std::string message;
    std::string path;
};

struct OpenClawVersionStatus {
    bool installed = false;
    std::string version;
    std::string source; // command|openclaw.json|unknown
    std::string minimum_required = "2026.1.29";
    std::string minimum_recommended = "2026.1.30";
    std::string status = "warn"; // ok|warn|critical
    std::string message;
};

struct IntegrityStatus {
    std::string status = "ok"; // ok|info|warn|initialized|error
    std::string baseline_path;
    int tracked_count = 0;
    std::vector<std::string> changed;
    std::vector<std::string> new_files;
    std::vector<std::string> missing;
    std::vector<std::string> errors;
    std::string message;
};

struct SecurityReport {
    int64_t timestamp_ms = 0;
    std::string status = "ok"; // ok|warn|critical
    OpenClawVersionStatus openclaw;
    std::vector<SecurityFinding> config_findings;
    IntegrityStatus integrity;
    std::vector<std::string> recommendations;
};

struct ContainmentAction {
    std::string id;
    int64_t timestamp_ms = 0;
    std::string level;      // soft|hard
    std::string action;     // disable_skill|kill_process|block_port
    std::string target;     // skill:<name> | pid:<n> | port:<n>
    std::string reason;
    std::string status;     // shadow|executed|requires_approval|skipped|error
    std::string detail;
    std::string command;
    std::string rollback;
    int64_t expires_at_ms = 0;
};

struct ListeningPort {
    int port = 0;
    std::string proto = "tcp";
    int pid = -1;
    std::string process;
    std::string bind; // e.g. "*", "127.0.0.1", "[::]"
};

struct ProcessInfo {
    int pid;
    std::string name;
    double cpu_pct;
    uint64_t mem_bytes;
    double mem_pct;
};

struct ProcessSnapshot {
    std::vector<ProcessInfo> top_cpu;
    std::vector<ProcessInfo> top_mem;
    int total_processes = 0;
    int64_t timestamp_ms = 0;
};

struct SystemInfo {
    std::string hostname;
    std::string os;
    std::string kernel;
    std::string arch;
    int cpu_cores = 0;
    uint64_t total_ram = 0;
    int64_t uptime_seconds = 0;
};

struct SystemSnapshot {
    CpuSnapshot cpu;
    MemSnapshot mem;
    DiskSnapshot disk;
    NetworkSnapshot net;
    ProcessSnapshot procs;
    int64_t timestamp_ms = 0;
};

// ─── Alert System ─────────────────────────────────────────────
enum class AlertLevel { INFO, WARNING, CRITICAL };
enum class AlertType { CPU, MEMORY, DISK, NETWORK, PROCESS, SECURITY };

struct Alert {
    AlertLevel level;
    AlertType type;
    std::string message;
    double value;
    double threshold;
    int64_t timestamp_ms;
    bool acknowledged = false;
};

// ─── History Ring Buffer ──────────────────────────────────────
class MetricHistory {
public:
    MetricHistory(size_t max_entries = 17280);
    
    void push(const SystemSnapshot& snap);
    std::vector<SystemSnapshot> get_range(int64_t from_ms, int64_t to_ms) const;
    std::vector<SystemSnapshot> get_last_n(size_t n) const;
    SystemSnapshot get_latest() const;
    size_t size() const;
    double cpu_trend_slope(int minutes = 30) const;
    double mem_trend_slope(int minutes = 30) const;
    
private:
    mutable std::mutex mutex_;
    std::deque<SystemSnapshot> buffer_;
    size_t max_entries_;
};

// ─── System Collectors ────────────────────────────────────────
class SystemCollector {
public:
    SystemCollector();
    
    SystemInfo get_system_info();
    CpuSnapshot collect_cpu();
    MemSnapshot collect_memory();
    DiskSnapshot collect_disks();
    NetworkSnapshot collect_network();
    ProcessSnapshot collect_processes();
    SystemSnapshot collect_all();
    
private:
    uint64_t prev_net_sent_ = 0;
    uint64_t prev_net_recv_ = 0;
    int64_t prev_net_time_ = 0;

#ifdef __linux__
    // Process CPU% is computed using deltas between successive snapshots.
    std::unordered_map<int, uint64_t> prev_proc_ticks_;
    int64_t prev_proc_time_ms_ = 0;
    long proc_hz_ = 100;

    struct CpuTimes {
        uint64_t user=0, nice=0, system=0, idle=0, iowait=0, irq=0, softirq=0, steal=0;
        uint64_t total() const { return user+nice+system+idle+iowait+irq+softirq+steal; }
        uint64_t active() const { return total() - idle - iowait; }
    };
    CpuTimes prev_cpu_total_;
    std::vector<CpuTimes> prev_cpu_cores_;
    CpuTimes read_cpu_times(const std::string& line);
#endif
#ifdef __APPLE__
    uint64_t prev_cpu_user_=0, prev_cpu_sys_=0, prev_cpu_idle_=0;
#endif
};

// ─── Alert Engine ─────────────────────────────────────────────
class AlertEngine {
public:
    AlertEngine(const Config& cfg);
    
    std::vector<Alert> evaluate(const SystemSnapshot& snap);
    std::vector<Alert> get_active_alerts() const;
    std::vector<ListeningPort> get_listening_ports() const;
    TrustedOpsPolicy get_policy() const;
    SecurityReport get_security_report() const;
    std::vector<ContainmentAction> get_recent_containment_actions() const;
    void acknowledge(size_t index);
    void set_config(const Config& cfg);
    void write_alert_file(const std::string& path);
    
private:
    std::vector<ListeningPort> scan_listening_ports_best_effort() const;
    TrustedOpsPolicy load_policy_best_effort(const std::string& path) const;
    SecurityReport run_security_audit_best_effort(int64_t now_ms) const;
    std::string detect_recent_skill_best_effort(int64_t now_ms, int64_t window_ms) const;
    void record_containment_action_locked(const ContainmentAction& action);
    bool execute_containment_action_best_effort(ContainmentAction& action) const;
    bool append_containment_action_log_best_effort(const ContainmentAction& action) const;

    Config config_;
    mutable std::mutex mutex_;
    std::vector<Alert> active_alerts_;
    std::map<AlertType, int64_t> last_alert_time_;
    std::map<std::string, int64_t> last_alert_key_time_;
    static constexpr int64_t ALERT_COOLDOWN_MS = 300000;

    // Port watch state (Pro feature)
    bool ports_baselined_ = false;
    int64_t last_port_scan_ms_ = 0;
    std::set<int> known_listen_ports_;
    std::vector<ListeningPort> last_listening_ports_;
    TrustedOpsPolicy policy_;

    // Security posture state
    int64_t last_security_scan_ms_ = 0;
    SecurityReport last_security_report_;

    // Containment state
    std::vector<ContainmentAction> recent_containment_actions_;
    std::map<std::string, int64_t> last_containment_action_ms_;
    int64_t containment_window_start_ms_ = 0;
    int containment_actions_in_window_ = 0;
};

// ─── HTTP Server ──────────────────────────────────────────────
class HttpServer {
public:
    HttpServer(int port, MetricHistory& history, SystemCollector& collector, 
               AlertEngine& alerts, const Config& config);
    ~HttpServer();
    
    void start();
    void stop();
    
private:
    struct ApiRateState {
        int64_t window_start_ms = 0;
        int count = 0;
    };

    void serve_loop();
    std::string handle_request(const std::string& method, const std::string& path);
    bool request_authorized(const std::string& req_str) const;
    bool api_auth_required() const;
    bool api_rate_limited(const std::string& client_ip, const std::string& path);
    std::string json_current();
    std::string json_history(int minutes);
    std::string json_alerts();
    std::string json_activity();
    std::string json_security();
    std::string json_containment();
    std::string json_recommendations();
    std::string json_brief();
    std::string json_system_info();
    std::string json_trends();
    std::string serve_dashboard();

    void refresh_openclaw_events();
    static bool json_extract_string(const std::string& line, const std::string& key, std::string& out);
    static bool json_extract_int64(const std::string& line, const std::string& key, int64_t& out);
    static OpenClawEvent parse_openclaw_event_best_effort(const std::string& line);
    
    int port_;
    int server_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread server_thread_;
    MetricHistory& history_;
    SystemCollector& collector_;
    AlertEngine& alerts_;
    Config config_;
    std::string bind_ip_ = "127.0.0.1";
    bool remote_bind_enabled_ = false;
    std::unordered_map<std::string, ApiRateState> api_rate_state_;

    // Cached OpenClaw events (for correlation). Loaded from config_.openclaw_event_log_file.
    int64_t openclaw_events_loaded_ms_ = 0;
    std::vector<OpenClawEvent> openclaw_events_;
};

// ─── Main Daemon ──────────────────────────────────────────────
class ClawGuardDaemon {
public:
    ClawGuardDaemon(const Config& config);
    ~ClawGuardDaemon();
    
    void run();
    void stop();
    static void signal_handler(int sig);
    
private:
    void collect_loop();
    void print_banner();
    
    Config config_;
    SystemCollector collector_;
    MetricHistory history_;
    AlertEngine alert_engine_;
    std::unique_ptr<HttpServer> http_server_;
    static std::atomic<bool> running_;
};

// ─── Utility ──────────────────────────────────────────────────
namespace util {
    int64_t now_ms();
    std::string format_bytes(uint64_t bytes);
    std::string format_duration(int64_t seconds);
    std::string format_timestamp(int64_t ms);
    std::string escape_json(const std::string& s);
    std::string to_json_number(double v);
}

} // namespace clawguard
