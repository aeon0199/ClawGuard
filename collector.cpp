#include "clawguard.h"

#include <unistd.h> // gethostname (macOS, Linux)

#ifdef __APPLE__
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#endif

namespace clawguard {

SystemCollector::SystemCollector() {
#ifdef __linux__
    // Used for process CPU% calculations.
    proc_hz_ = sysconf(_SC_CLK_TCK);
    prev_proc_time_ms_ = util::now_ms();
#endif

    // Initialize with a first read so deltas work
    collect_cpu();
    collect_network();
}

SystemInfo SystemCollector::get_system_info() {
    SystemInfo info;
    
    // Hostname
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        info.hostname = hostname;
    }
    
#ifdef __linux__
    // OS info
    std::ifstream os_release("/etc/os-release");
    std::string line;
    while (std::getline(os_release, line)) {
        if (line.find("PRETTY_NAME=") == 0) {
            info.os = line.substr(13);
            if (!info.os.empty() && info.os.back() == '"') info.os.pop_back();
            break;
        }
    }
    
    // Kernel
    std::ifstream version("/proc/version");
    if (std::getline(version, line)) {
        auto space = line.find(' ', line.find(' ') + 1);
        auto space2 = line.find(' ', space + 1);
        info.kernel = line.substr(space + 1, space2 - space - 1);
    }
    
    // Architecture
    struct utsname uts;
    if (uname(&uts) == 0) {
        info.arch = uts.machine;
    }
    
    // CPU cores
    info.cpu_cores = std::thread::hardware_concurrency();
    
    // Total RAM
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        info.total_ram = si.totalram * si.mem_unit;
        info.uptime_seconds = si.uptime;
    }
#endif

#ifdef __APPLE__
    info.os = "macOS";
    
    size_t size;
    char buf[256];
    
    // Kernel version
    size = sizeof(buf);
    if (sysctlbyname("kern.osrelease", buf, &size, nullptr, 0) == 0) {
        info.kernel = buf;
    }
    
    // Architecture
    size = sizeof(buf);
    if (sysctlbyname("hw.machine", buf, &size, nullptr, 0) == 0) {
        info.arch = buf;
    }
    
    info.cpu_cores = std::thread::hardware_concurrency();
    
    int64_t memsize;
    size = sizeof(memsize);
    if (sysctlbyname("hw.memsize", &memsize, &size, nullptr, 0) == 0) {
        info.total_ram = memsize;
    }
    
    struct timeval boottime;
    size = sizeof(boottime);
    if (sysctlbyname("kern.boottime", &boottime, &size, nullptr, 0) == 0) {
        info.uptime_seconds = time(nullptr) - boottime.tv_sec;
    }
#endif
    
    return info;
}

// ─── CPU Collection ───────────────────────────────────────────

#ifdef __linux__
SystemCollector::CpuTimes SystemCollector::read_cpu_times(const std::string& line) {
    CpuTimes t;
    std::istringstream ss(line);
    std::string label;
    ss >> label >> t.user >> t.nice >> t.system >> t.idle >> t.iowait >> t.irq >> t.softirq >> t.steal;
    return t;
}
#endif

CpuSnapshot SystemCollector::collect_cpu() {
    CpuSnapshot snap;
    snap.timestamp_ms = util::now_ms();
    
#ifdef __linux__
    std::ifstream f("/proc/stat");
    std::string line;
    
    // Total CPU
    if (std::getline(f, line) && line.substr(0, 3) == "cpu") {
        auto curr = read_cpu_times(line);
        if (prev_cpu_total_.total() > 0) {
            uint64_t total_delta = curr.total() - prev_cpu_total_.total();
            uint64_t active_delta = curr.active() - prev_cpu_total_.active();
            if (total_delta > 0) {
                snap.usage_pct = 100.0 * static_cast<double>(active_delta) / static_cast<double>(total_delta);
            }
        }
        prev_cpu_total_ = curr;
    }
    
    // Per-core
    std::vector<CpuTimes> cores;
    while (std::getline(f, line)) {
        if (line.substr(0, 3) != "cpu") break;
        cores.push_back(read_cpu_times(line));
    }
    
    if (!prev_cpu_cores_.empty() && prev_cpu_cores_.size() == cores.size()) {
        for (size_t i = 0; i < cores.size(); i++) {
            uint64_t total_delta = cores[i].total() - prev_cpu_cores_[i].total();
            uint64_t active_delta = cores[i].active() - prev_cpu_cores_[i].active();
            if (total_delta > 0) {
                snap.per_core_pct.push_back(
                    100.0 * static_cast<double>(active_delta) / static_cast<double>(total_delta)
                );
            } else {
                snap.per_core_pct.push_back(0.0);
            }
        }
    }
    prev_cpu_cores_ = cores;
    
    // Load average
    std::ifstream loadavg("/proc/loadavg");
    if (loadavg.is_open()) {
        loadavg >> snap.load_1m >> snap.load_5m >> snap.load_15m;
    }
#endif

#ifdef __APPLE__
    host_cpu_load_info_data_t cpuinfo;
    mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
    if (host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, 
                        (host_info_t)&cpuinfo, &count) == KERN_SUCCESS) {
        uint64_t user = cpuinfo.cpu_ticks[CPU_STATE_USER];
        uint64_t sys = cpuinfo.cpu_ticks[CPU_STATE_SYSTEM];
        uint64_t idle = cpuinfo.cpu_ticks[CPU_STATE_IDLE];
        
        if (prev_cpu_user_ > 0) {
            uint64_t du = user - prev_cpu_user_;
            uint64_t ds = sys - prev_cpu_sys_;
            uint64_t di = idle - prev_cpu_idle_;
            uint64_t total = du + ds + di;
            if (total > 0) {
                snap.usage_pct = 100.0 * static_cast<double>(du + ds) / static_cast<double>(total);
            }
        }
        prev_cpu_user_ = user;
        prev_cpu_sys_ = sys;
        prev_cpu_idle_ = idle;
    }
    
    double loadavg[3];
    if (getloadavg(loadavg, 3) == 3) {
        snap.load_1m = loadavg[0];
        snap.load_5m = loadavg[1];
        snap.load_15m = loadavg[2];
    }
#endif
    
    return snap;
}

// ─── Memory Collection ────────────────────────────────────────
MemSnapshot SystemCollector::collect_memory() {
    MemSnapshot snap;
    snap.timestamp_ms = util::now_ms();
    
#ifdef __linux__
    std::ifstream f("/proc/meminfo");
    std::string line;
    uint64_t total = 0, free_mem = 0, available = 0, buffers = 0, cached = 0;
    uint64_t swap_total = 0, swap_free = 0;
    
    while (std::getline(f, line)) {
        std::istringstream ss(line);
        std::string key;
        uint64_t val;
        ss >> key >> val;
        
        if (key == "MemTotal:") total = val * 1024;
        else if (key == "MemFree:") free_mem = val * 1024;
        else if (key == "MemAvailable:") available = val * 1024;
        else if (key == "Buffers:") buffers = val * 1024;
        else if (key == "Cached:") cached = val * 1024;
        else if (key == "SwapTotal:") swap_total = val * 1024;
        else if (key == "SwapFree:") swap_free = val * 1024;
    }
    
    snap.total_bytes = total;
    snap.available_bytes = available > 0 ? available : (free_mem + buffers + cached);
    snap.used_bytes = total - snap.available_bytes;
    snap.usage_pct = total > 0 ? 100.0 * static_cast<double>(snap.used_bytes) / total : 0;
    snap.swap_total = swap_total;
    snap.swap_used = swap_total - swap_free;
#endif

#ifdef __APPLE__
    int64_t memsize;
    size_t size = sizeof(memsize);
    sysctlbyname("hw.memsize", &memsize, &size, nullptr, 0);
    snap.total_bytes = memsize;
    
    vm_size_t page_size;
    vm_statistics64_data_t vm_stat;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    host_page_size(mach_host_self(), &page_size);
    
    if (host_statistics64(mach_host_self(), HOST_VM_INFO64, 
                          (host_info64_t)&vm_stat, &count) == KERN_SUCCESS) {
        uint64_t active = vm_stat.active_count * page_size;
        uint64_t wired = vm_stat.wire_count * page_size;
        uint64_t compressed = vm_stat.compressor_page_count * page_size;
        snap.used_bytes = active + wired + compressed;
        snap.available_bytes = snap.total_bytes - snap.used_bytes;
        snap.usage_pct = 100.0 * static_cast<double>(snap.used_bytes) / snap.total_bytes;
    }
    
    // macOS swap via sysctl
    struct xsw_usage swap;
    size = sizeof(swap);
    if (sysctlbyname("vm.swapusage", &swap, &size, nullptr, 0) == 0) {
        snap.swap_total = swap.xsu_total;
        snap.swap_used = swap.xsu_used;
    }
#endif
    
    return snap;
}

// ─── Disk Collection ──────────────────────────────────────────
DiskSnapshot SystemCollector::collect_disks() {
    DiskSnapshot snap;
    snap.timestamp_ms = util::now_ms();
    
#ifdef __linux__
    std::ifstream f("/proc/mounts");
    std::string line;
    std::set<std::string> seen;
    
    while (std::getline(f, line)) {
        std::istringstream ss(line);
        std::string device, mount, fstype;
        ss >> device >> mount >> fstype;
        
        // Only real filesystems
        if (fstype != "ext4" && fstype != "ext3" && fstype != "xfs" && 
            fstype != "btrfs" && fstype != "zfs" && fstype != "vfat" &&
            fstype != "ntfs" && fstype != "tmpfs" && fstype != "overlay") continue;
        if (mount.find("/snap/") == 0 || mount.find("/sys") == 0) continue;
        if (seen.count(device)) continue;
        seen.insert(device);
        
        struct statvfs stat;
        if (statvfs(mount.c_str(), &stat) == 0) {
            DiskInfo di;
            di.mount_point = mount;
            di.filesystem = fstype;
            di.total_bytes = stat.f_blocks * stat.f_frsize;
            di.available_bytes = stat.f_bavail * stat.f_frsize;
            di.used_bytes = di.total_bytes - (stat.f_bfree * stat.f_frsize);
            di.usage_pct = di.total_bytes > 0 ? 
                100.0 * static_cast<double>(di.used_bytes) / di.total_bytes : 0;
            
            if (di.total_bytes > 0) {
                snap.disks.push_back(di);
            }
        }
    }
#endif

#ifdef __APPLE__
    struct statfs* mounts;
    int count = getmntinfo(&mounts, MNT_NOWAIT);
    for (int i = 0; i < count; i++) {
        std::string fstype = mounts[i].f_fstypename;
        std::string mount = mounts[i].f_mntonname;
        
        if (fstype != "apfs" && fstype != "hfs" && fstype != "msdos") continue;
        if (mount.find("/private/var/vm") == 0) continue;
        
        DiskInfo di;
        di.mount_point = mount;
        di.filesystem = fstype;
        di.total_bytes = mounts[i].f_blocks * mounts[i].f_bsize;
        di.available_bytes = mounts[i].f_bavail * mounts[i].f_bsize;
        di.used_bytes = di.total_bytes - (mounts[i].f_bfree * mounts[i].f_bsize);
        di.usage_pct = di.total_bytes > 0 ? 
            100.0 * static_cast<double>(di.used_bytes) / di.total_bytes : 0;
        
        if (di.total_bytes > 0) {
            snap.disks.push_back(di);
        }
    }
#endif
    
    return snap;
}

// ─── Network Collection ───────────────────────────────────────
NetworkSnapshot SystemCollector::collect_network() {
    NetworkSnapshot snap;
    snap.timestamp_ms = util::now_ms();
    
#ifdef __linux__
    std::ifstream f("/proc/net/dev");
    std::string line;
    std::getline(f, line); // header 1
    std::getline(f, line); // header 2
    
    uint64_t total_recv = 0, total_sent = 0;
    while (std::getline(f, line)) {
        std::istringstream ss(line);
        std::string iface;
        ss >> iface;
        if (iface == "lo:") continue; // skip loopback
        
        uint64_t recv_bytes, recv_packets, recv_errs, recv_drop;
        uint64_t recv_fifo, recv_frame, recv_compressed, recv_multicast;
        uint64_t sent_bytes;
        ss >> recv_bytes >> recv_packets >> recv_errs >> recv_drop
           >> recv_fifo >> recv_frame >> recv_compressed >> recv_multicast
           >> sent_bytes;
        
        total_recv += recv_bytes;
        total_sent += sent_bytes;
    }
    
    snap.bytes_recv = total_recv;
    snap.bytes_sent = total_sent;
    
    if (prev_net_time_ > 0) {
        double elapsed = (snap.timestamp_ms - prev_net_time_) / 1000.0;
        if (elapsed > 0) {
            snap.bytes_recv_rate = static_cast<uint64_t>((total_recv - prev_net_recv_) / elapsed);
            snap.bytes_sent_rate = static_cast<uint64_t>((total_sent - prev_net_sent_) / elapsed);
        }
    }
    
    prev_net_recv_ = total_recv;
    prev_net_sent_ = total_sent;
    prev_net_time_ = snap.timestamp_ms;
#endif

#ifdef __APPLE__
    // macOS: sum per-interface counters via getifaddrs (no shelling out).
    uint64_t total_recv = 0, total_sent = 0;
    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) == 0 && ifap) {
        for (auto* ifa = ifap; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || !ifa->ifa_data) continue;
            if (ifa->ifa_addr->sa_family != AF_LINK) continue;
            if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) continue;

            const auto* data = static_cast<const struct if_data*>(ifa->ifa_data);
            total_recv += static_cast<uint64_t>(data->ifi_ibytes);
            total_sent += static_cast<uint64_t>(data->ifi_obytes);
        }
        freeifaddrs(ifap);
    }

    snap.bytes_recv = total_recv;
    snap.bytes_sent = total_sent;

    if (prev_net_time_ > 0) {
        double elapsed = (snap.timestamp_ms - prev_net_time_) / 1000.0;
        if (elapsed > 0) {
            if (total_recv >= prev_net_recv_) {
                snap.bytes_recv_rate = static_cast<uint64_t>((total_recv - prev_net_recv_) / elapsed);
            }
            if (total_sent >= prev_net_sent_) {
                snap.bytes_sent_rate = static_cast<uint64_t>((total_sent - prev_net_sent_) / elapsed);
            }
        }
    }

    prev_net_recv_ = total_recv;
    prev_net_sent_ = total_sent;
    prev_net_time_ = snap.timestamp_ms;
#endif
    
    return snap;
}

// ─── Process Collection ───────────────────────────────────────
ProcessSnapshot SystemCollector::collect_processes() {
    ProcessSnapshot snap;
    snap.timestamp_ms = util::now_ms();
    
#ifdef __linux__
    const int64_t now_ms = snap.timestamp_ms;
    const double elapsed = (prev_proc_time_ms_ > 0) ? (now_ms - prev_proc_time_ms_) / 1000.0 : 0.0;
    std::unordered_map<int, uint64_t> curr_proc_ticks;

    std::vector<ProcessInfo> all_procs;
    
    // Get total memory for percentage calc
    uint64_t total_mem = 0;
    {
        std::ifstream f("/proc/meminfo");
        std::string key;
        uint64_t val;
        f >> key >> val;
        total_mem = val * 1024;
    }
    
    // Scan /proc for processes
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        if (!entry.is_directory()) continue;
        std::string name = entry.path().filename().string();
        
        // Only numeric (PID) directories
        bool is_pid = !name.empty() && std::all_of(name.begin(), name.end(), ::isdigit);
        if (!is_pid) continue;
        
        ProcessInfo pi;
        pi.pid = std::atoi(name.c_str());
        if (pi.pid <= 0) continue;
        
        // Read process name from /proc/PID/comm
        std::ifstream comm(entry.path() / "comm");
        if (comm.is_open()) {
            std::getline(comm, pi.name);
        }
        
        // Read memory from /proc/PID/statm
        std::ifstream statm(entry.path() / "statm");
        if (statm.is_open()) {
            uint64_t size, resident;
            statm >> size >> resident;
            pi.mem_bytes = resident * 4096; // page size
            pi.mem_pct = total_mem > 0 ? 100.0 * static_cast<double>(pi.mem_bytes) / total_mem : 0;
        }
        
        // Read CPU from /proc/PID/stat (simplified - snapshot based)
        std::ifstream stat_file(entry.path() / "stat");
        if (stat_file.is_open()) {
            std::string stat_line;
            std::getline(stat_file, stat_line);
            // Find closing paren (end of comm field)
            auto paren = stat_line.rfind(')');
            if (paren != std::string::npos) {
                std::istringstream ss(stat_line.substr(paren + 2));
                std::string state;
                int ppid, pgrp, session, tty, tpgid;
                unsigned long flags, minflt, cminflt, majflt, cmajflt;
                uint64_t utime = 0, stime = 0;
                ss >> state >> ppid >> pgrp >> session >> tty >> tpgid
                   >> flags >> minflt >> cminflt >> majflt >> cmajflt
                   >> utime >> stime;

                const uint64_t total_ticks = utime + stime;
                curr_proc_ticks[pi.pid] = total_ticks;

                // CPU% since the last snapshot (can exceed 100 for multi-threaded processes).
                pi.cpu_pct = 0.0;
                if (elapsed > 0.0) {
                    auto it = prev_proc_ticks_.find(pi.pid);
                    if (it != prev_proc_ticks_.end() && total_ticks >= it->second) {
                        const uint64_t delta_ticks = total_ticks - it->second;
                        const double cpu_seconds = static_cast<double>(delta_ticks) / static_cast<double>(proc_hz_);
                        pi.cpu_pct = (cpu_seconds / elapsed) * 100.0;
                    }
                }
            }
        }
        
        if (!pi.name.empty()) {
            all_procs.push_back(pi);
        }
    }
    
    snap.total_processes = all_procs.size();
    
    // Update state for the next call and avoid unbounded growth by replacing the map each time.
    prev_proc_ticks_.swap(curr_proc_ticks);
    prev_proc_time_ms_ = now_ms;

    // Top memory
    auto by_mem = all_procs;
    std::sort(by_mem.begin(), by_mem.end(),
              [](const ProcessInfo& a, const ProcessInfo& b) { return a.mem_bytes > b.mem_bytes; });
    for (size_t i = 0; i < std::min(size_t(10), by_mem.size()); i++) {
        snap.top_mem.push_back(by_mem[i]);
    }

    // Top CPU
    auto by_cpu = all_procs;
    std::sort(by_cpu.begin(), by_cpu.end(),
              [](const ProcessInfo& a, const ProcessInfo& b) { return a.cpu_pct > b.cpu_pct; });
    for (size_t i = 0; i < std::min(size_t(10), by_cpu.size()); i++) {
        snap.top_cpu.push_back(by_cpu[i]);
    }
#endif

#ifdef __APPLE__
    // macOS: use ps for process info.
    // top_cpu: sorted by CPU (-r), top_mem: sorted by memory (-m)
    auto parse_ps = [&](const char* cmd, std::vector<ProcessInfo>& out) {
        FILE* pipe = popen(cmd, "r");
        if (!pipe) return;
        char buf[512];
        bool first = true;
        while (fgets(buf, sizeof(buf), pipe)) {
            if (first) { first = false; continue; }
            ProcessInfo pi;
            char name[256];
            unsigned long long rss_kb = 0;
            if (sscanf(buf, "%d %lf %lf %llu %255s", &pi.pid, &pi.cpu_pct, &pi.mem_pct, &rss_kb, name) >= 5) {
                pi.name = name;
                pi.mem_bytes = static_cast<uint64_t>(rss_kb) * 1024; // RSS is in KB
                out.push_back(pi);
            }
        }
        pclose(pipe);
    };

    parse_ps("ps -eo pid,pcpu,pmem,rss,comm -r 2>/dev/null | head -11", snap.top_cpu);
    parse_ps("ps -eo pid,pcpu,pmem,rss,comm -m 2>/dev/null | head -11", snap.top_mem);
    
    // Total process count
    FILE* cnt = popen("ps -e | wc -l", "r");
    if (cnt) {
        char buf[64];
        if (fgets(buf, sizeof(buf), cnt)) {
            int total = 0;
            if (sscanf(buf, "%d", &total) == 1 && total > 0) {
                snap.total_processes = total - 1;
            }
        }
        pclose(cnt);
    }
#endif
    
    return snap;
}

// ─── Collect All ──────────────────────────────────────────────
SystemSnapshot SystemCollector::collect_all() {
    SystemSnapshot snap;
    snap.cpu = collect_cpu();
    snap.mem = collect_memory();
    snap.disk = collect_disks();
    snap.net = collect_network();
    snap.procs = collect_processes();
    snap.timestamp_ms = util::now_ms();
    return snap;
}

} // namespace clawguard
