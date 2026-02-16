#include "clawguard.h"

namespace clawguard {

std::atomic<bool> ClawGuardDaemon::running_{false};

namespace {

std::string mode_normalize(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    if (s == "read-only" || s == "monitor" || s == "monitor-only") return "readonly";
    if (s != "readonly" && s != "standard") return "readonly";
    return s;
}

bool is_loopback_bind(std::string ip) {
    std::transform(ip.begin(), ip.end(), ip.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    if (ip.empty() || ip == "localhost" || ip == "loopback") return true;
    if (ip == "127.0.0.1") return true;
    return ip.rfind("127.", 0) == 0;
}

} // namespace

ClawGuardDaemon::ClawGuardDaemon(const Config& config)
    : config_(config), alert_engine_(config) {
    config_.mode = mode_normalize(config_.mode);
    if (config_.mode == "readonly") {
        // Hard gate: no containment execution in readonly mode.
        config_.containment_enabled = false;
        config_.containment_auto_soft_actions = false;
        config_.containment_auto_hard_actions = false;
    }
    
    // Setup data directory
    if (config_.data_dir.empty()) {
        const char* home = getenv("HOME");
        if (home) {
            config_.data_dir = std::string(home) + "/.clawguard";
        } else {
            config_.data_dir = "/tmp/.clawguard";
        }
    }
    std::filesystem::create_directories(config_.data_dir);
    
    // Setup alert file path
    if (config_.alert_file.empty()) {
        config_.alert_file = config_.data_dir + "/alerts.txt";
    }

    // OpenClaw event log path (optional)
    if (config_.openclaw_event_log_file.empty()) {
        config_.openclaw_event_log_file = config_.data_dir + "/openclaw-events.jsonl";
    }

    // Trusted ops policy path (optional)
    if (config_.policy_file.empty()) {
        config_.policy_file = config_.data_dir + "/policy.ini";
    }

    // OpenClaw config file (for version/config posture checks)
    if (config_.openclaw_config_file.empty()) {
        const char* home = getenv("HOME");
        if (home) {
            config_.openclaw_config_file = std::string(home) + "/.openclaw/openclaw.json";
        } else {
            config_.openclaw_config_file = "/tmp/.openclaw/openclaw.json";
        }
    }

    // Integrity baseline file for tracked OpenClaw files/skills.
    if (config_.integrity_baseline_file.empty()) {
        config_.integrity_baseline_file = config_.data_dir + "/integrity-baseline.txt";
    }

    // Containment actions log file.
    if (config_.containment_actions_log_file.empty()) {
        config_.containment_actions_log_file = config_.data_dir + "/containment-actions.jsonl";
    }

    // Ensure AlertEngine uses the finalized runtime config (including readonly hard-gates).
    alert_engine_.set_config(config_);
}

ClawGuardDaemon::~ClawGuardDaemon() { stop(); }

void ClawGuardDaemon::signal_handler(int sig) {
    (void)sig;
    running_ = false;
}

void ClawGuardDaemon::print_banner() {
    std::cout << "\n"
    "  ┌─────────────────────────────────────────┐\n"
    "  │  🦞  ClawGuard v" << VERSION << "                     │\n"
    "  │  System Monitor for OpenClaw             │\n"
    "  ├─────────────────────────────────────────┤\n"
    "  │  Dashboard:  http://localhost:" << config_.http_port << "        │\n"
    "  │  API:        http://localhost:" << config_.http_port << "/api    │\n"
    "  │  Mode:       " << config_.mode
    << "                    │\n"
    "  │  Polling:    every " << config_.poll_interval_sec << "s"
    "                    │\n"
    "  │  History:    " << config_.history_max_minutes << " min"
    "                      │\n"
    "  │  Contain:    " << (config_.containment_enabled ? (config_.containment_shadow_mode ? "shadow" : "enforced") : "off")
    << "                    │\n"
    "  │  Alerts:     " << config_.alert_file << "\n"
    "  └─────────────────────────────────────────┘\n"
    << std::endl;
    
    auto info = collector_.get_system_info();
    std::cout << "  Host: " << info.hostname << "\n"
              << "  OS:   " << info.os << " (" << info.kernel << ")\n"
              << "  Arch: " << info.arch << "\n"
              << "  CPU:  " << info.cpu_cores << " cores\n"
              << "  RAM:  " << util::format_bytes(info.total_ram) << "\n"
              << "  Up:   " << util::format_duration(info.uptime_seconds) << "\n"
              << std::endl;

    if (is_loopback_bind(config_.http_bind) && !config_.allow_remote_http) {
        std::cout << "  [✓] REMOTE HTTP DISABLED (loopback-only)\n";
    } else {
        std::cout << "  [!] REMOTE HTTP ENABLED (" << config_.http_bind
                  << ") with token auth required\n";
    }
}

void ClawGuardDaemon::run() {
    running_ = true;
    
    // Install signal handlers
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    
    print_banner();
    
    // Start HTTP server
    http_server_ = std::make_unique<HttpServer>(
        config_.http_port, history_, collector_, alert_engine_, config_);
    http_server_->start();
    std::cout << "  [✓] HTTP server started on port " << config_.http_port << "\n";
    
    // Save default config if none exists
    std::string cfg_path = config_.data_dir + "/config.ini";
    if (!std::filesystem::exists(cfg_path)) {
        config_.save(cfg_path);
        std::cout << "  [✓] Default config saved to " << cfg_path << "\n";
    }
    
    std::cout << "  [✓] Monitoring started. Press Ctrl+C to stop.\n\n";
    
    // Main collection loop
    collect_loop();
    
    std::cout << "\n  [!] Shutting down ClawGuard...\n";
    http_server_->stop();
    std::cout << "  [✓] Goodbye! 🦞\n\n";
}

void ClawGuardDaemon::collect_loop() {
    int cycle = 0;
    while (running_) {
        auto snap = collector_.collect_all();
        history_.push(snap);
        
        // Evaluate alerts
        auto new_alerts = alert_engine_.evaluate(snap);
        
        // Write alert file for OpenClaw
        if (config_.openclaw_alerts) {
            alert_engine_.write_alert_file(config_.alert_file);
        }
        
        // Print new alerts to console
        for (const auto& alert : new_alerts) {
            std::string level = alert.level == AlertLevel::CRITICAL ? "CRIT" :
                               alert.level == AlertLevel::WARNING ? "WARN" : "INFO";
            std::cout << "  [" << level << "] " << alert.message << "\n";
        }
        
        // Periodic status to console (every 12 cycles = ~1 min at 5s intervals)
        if (cycle % 12 == 0) {
            std::cout << "  [" << util::format_timestamp(snap.timestamp_ms) << "] "
                      << "CPU: " << util::to_json_number(snap.cpu.usage_pct) << "% | "
                      << "MEM: " << util::to_json_number(snap.mem.usage_pct) << "% | "
                      << "NET: ▼" << util::format_bytes(snap.net.bytes_recv_rate) << "/s "
                      << "▲" << util::format_bytes(snap.net.bytes_sent_rate) << "/s | "
                      << "Procs: " << snap.procs.total_processes << "\n";
        }
        
        cycle++;
        
        // Sleep with early exit check
        for (int i = 0; i < config_.poll_interval_sec * 10 && running_; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

void ClawGuardDaemon::stop() {
    running_ = false;
}

} // namespace clawguard

// ─── MAIN ─────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    // Parse args (CLI overrides config file).
    std::string config_path;
    bool no_alerts = false;
    int port_override = -1;
    int interval_override = -1;
    std::string data_dir_override;
    std::string mode_override;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            std::cout << "ClawGuard v" << clawguard::VERSION << " — System Monitor for OpenClaw\n\n"
                      << "Usage: clawguard [options]\n\n"
                      << "Options:\n"
                      << "  -p, --port PORT     HTTP port (default: 7677)\n"
                      << "  -i, --interval SEC  Poll interval (default: 5)\n"
                      << "  -c, --config FILE   Config file path\n"
                      << "  -d, --data-dir DIR  Data directory\n"
                      << "  -m, --mode MODE     Operation mode: readonly|standard\n"
                      << "  --no-alerts         Disable OpenClaw alert file\n"
                      << "  -h, --help          Show this help\n"
                      << "  -v, --version       Show version\n";
            return 0;
        }
        if (arg == "-v" || arg == "--version") {
            std::cout << "ClawGuard v" << clawguard::VERSION << "\n";
            return 0;
        }
        if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            config_path = argv[++i];
            continue;
        }
        if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            try {
                port_override = std::stoi(argv[++i]);
            } catch (...) {
                std::cerr << "Invalid port value for " << arg << "\n";
                return 2;
            }
            continue;
        }
        if ((arg == "-i" || arg == "--interval") && i + 1 < argc) {
            try {
                interval_override = std::stoi(argv[++i]);
            } catch (...) {
                std::cerr << "Invalid interval value for " << arg << "\n";
                return 2;
            }
            continue;
        }
        if ((arg == "-d" || arg == "--data-dir") && i + 1 < argc) {
            data_dir_override = argv[++i];
            continue;
        }
        if ((arg == "-m" || arg == "--mode") && i + 1 < argc) {
            mode_override = argv[++i];
            continue;
        }
        if (arg == "--no-alerts") {
            no_alerts = true;
            continue;
        }
    }

    clawguard::Config config;
    if (!config_path.empty()) {
        config = clawguard::Config::load(config_path);
    }
    if (port_override > 0) config.http_port = port_override;
    if (interval_override > 0) config.poll_interval_sec = interval_override;
    if (!data_dir_override.empty()) config.data_dir = data_dir_override;
    if (!mode_override.empty()) config.mode = mode_override;
    if (no_alerts) config.openclaw_alerts = false;

    clawguard::ClawGuardDaemon daemon(config);
    daemon.run();
    
    return 0;
}
