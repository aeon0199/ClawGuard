#!/usr/bin/env python3
import json
import os
import platform
import re
import socket
import subprocess
import time


def sh(cmd: str) -> str:
    return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True)


def now_ms() -> int:
    return int(time.time() * 1000)


def cpu_snapshot() -> dict:
    sysname = platform.system()
    usage = 0.0
    load_1m = load_5m = load_15m = 0.0

    try:
        load_1m, load_5m, load_15m = os.getloadavg()
    except Exception:
        pass

    if sysname == "Linux":
        def read_cpu():
            with open("/proc/stat", "r", encoding="utf-8") as f:
                line = f.readline().strip()
            parts = line.split()
            # cpu user nice system idle iowait irq softirq steal ...
            nums = list(map(int, parts[1:9]))
            user, nice, system, idle, iowait, irq, softirq, steal = nums
            total = sum(nums)
            active = total - idle - iowait
            return total, active

        try:
            t0, a0 = read_cpu()
            time.sleep(0.20)
            t1, a1 = read_cpu()
            dt = max(1, t1 - t0)
            da = max(0, a1 - a0)
            usage = 100.0 * da / dt
        except Exception:
            usage = 0.0

    elif sysname == "Darwin":
        # Parse "CPU usage: 7.65% user, 6.57% sys, 85.76% idle"
        try:
            out = sh("top -l 1 -n 0")
            m = re.search(r"CPU usage:\s+([0-9.]+)%\s+user,\s+([0-9.]+)%\s+sys,\s+([0-9.]+)%\s+idle", out)
            if m:
                idle = float(m.group(3))
                usage = max(0.0, min(100.0, 100.0 - idle))
        except Exception:
            usage = 0.0

    return {
        "usage_pct": round(usage, 2),
        "load_1m": round(load_1m, 2),
        "load_5m": round(load_5m, 2),
        "load_15m": round(load_15m, 2),
    }


def mem_snapshot() -> dict:
    sysname = platform.system()
    total = used = available = swap_total = swap_used = 0

    if sysname == "Linux":
        try:
            meminfo = {}
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    k, v, *_ = line.split()
                    meminfo[k.rstrip(":")] = int(v) * 1024
            total = meminfo.get("MemTotal", 0)
            available = meminfo.get("MemAvailable", 0)
            used = max(0, total - available)
            swap_total = meminfo.get("SwapTotal", 0)
            swap_free = meminfo.get("SwapFree", 0)
            swap_used = max(0, swap_total - swap_free)
        except Exception:
            pass

    elif sysname == "Darwin":
        try:
            total = int(sh("sysctl -n hw.memsize").strip())
            vm = sh("vm_stat")
            # vm_stat reports pages; parse page size
            page_size = 4096
            m = re.search(r"page size of (\d+) bytes", vm)
            if m:
                page_size = int(m.group(1))

            def pages(label):
                mm = re.search(rf"^{re.escape(label)}:\s+(\d+)\.", vm, re.M)
                return int(mm.group(1)) if mm else 0

            active = pages("Pages active") * page_size
            wired = pages("Pages wired down") * page_size
            compressed = pages("Pages occupied by compressor") * page_size
            free = pages("Pages free") * page_size
            inactive = pages("Pages inactive") * page_size

            used = active + wired + compressed
            available = max(0, free + inactive)

            # swap usage from sysctl
            sw = sh("sysctl -n vm.swapusage").strip()
            mm = re.search(r"total = ([0-9.]+)([MG])", sw)
            mu = re.search(r"used = ([0-9.]+)([MG])", sw)
            if mm and mu:
                def to_bytes(val, unit):
                    n = float(val)
                    return int(n * (1024 ** 3 if unit == "G" else 1024 ** 2))
                swap_total = to_bytes(mm.group(1), mm.group(2))
                swap_used = to_bytes(mu.group(1), mu.group(2))
        except Exception:
            pass

    usage_pct = (100.0 * used / total) if total else 0.0
    return {
        "total_bytes": int(total),
        "used_bytes": int(used),
        "available_bytes": int(available),
        "usage_pct": round(usage_pct, 2),
        "swap_total_bytes": int(swap_total),
        "swap_used_bytes": int(swap_used),
    }


def disk_snapshot() -> list:
    disks = []
    try:
        out = sh("df -kP")
        lines = out.strip().splitlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue
            fs, blocks, used, avail, cap, mount = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
            if fs.startswith("devfs") or fs.startswith("map") or fs in ("tmpfs", "overlay"):
                continue
            try:
                total_b = int(blocks) * 1024
                used_b = int(used) * 1024
                avail_b = int(avail) * 1024
            except Exception:
                continue
            usage_pct = (100.0 * used_b / total_b) if total_b else 0.0
            disks.append(
                {
                    "mount": mount,
                    "filesystem": fs,
                    "total_bytes": total_b,
                    "used_bytes": used_b,
                    "available_bytes": avail_b,
                    "usage_pct": round(usage_pct, 2),
                }
            )
    except Exception:
        pass
    return disks


def network_snapshot() -> dict:
    sysname = platform.system()
    recv_b = sent_b = 0

    if sysname == "Linux":
        try:
            with open("/proc/net/dev", "r", encoding="utf-8") as f:
                lines = f.read().splitlines()[2:]
            for line in lines:
                if ":" not in line:
                    continue
                iface, rest = line.split(":", 1)
                iface = iface.strip()
                if iface == "lo":
                    continue
                cols = rest.split()
                if len(cols) < 16:
                    continue
                recv_b += int(cols[0])
                sent_b += int(cols[8])
        except Exception:
            pass

    elif sysname == "Darwin":
        # netstat -ib is annoying; we take the max counters per interface and sum them.
        try:
            out = sh("netstat -ib")
            lines = out.strip().splitlines()
            if not lines:
                return {"bytes_recv": 0, "bytes_sent": 0}

            hdr = re.split(r"\s+", lines[0].strip())
            # Find columns (best effort)
            def idx(name):
                try:
                    return hdr.index(name)
                except ValueError:
                    return -1

            i_if = idx("Name")
            i_ib = idx("Ibytes")
            i_ob = idx("Obytes")
            if i_if < 0 or i_ib < 0 or i_ob < 0:
                return {"bytes_recv": 0, "bytes_sent": 0}

            per = {}
            for line in lines[1:]:
                parts = re.split(r"\s+", line.strip())
                if len(parts) <= max(i_if, i_ib, i_ob):
                    continue
                name = parts[i_if]
                if name.startswith("lo"):
                    continue
                try:
                    ib = int(parts[i_ib])
                    ob = int(parts[i_ob])
                except Exception:
                    continue
                prev = per.get(name)
                if not prev:
                    per[name] = (ib, ob)
                else:
                    per[name] = (max(prev[0], ib), max(prev[1], ob))

            recv_b = sum(v[0] for v in per.values())
            sent_b = sum(v[1] for v in per.values())
        except Exception:
            pass

    return {"bytes_recv": int(recv_b), "bytes_sent": int(sent_b)}


def top_processes() -> dict:
    sysname = platform.system()

    def parse_ps(out: str) -> list:
        items = []
        for line in out.strip().splitlines()[1:]:
            parts = line.strip().split(None, 4)
            if len(parts) < 5:
                continue
            pid_s, pcpu_s, pmem_s, rss_s, comm = parts
            try:
                pid = int(pid_s)
                pcpu = float(pcpu_s)
                pmem = float(pmem_s)
                rss_kb = int(rss_s)
            except Exception:
                continue
            items.append(
                {
                    "pid": pid,
                    "name": comm,
                    "cpu_pct": round(pcpu, 2),
                    "mem_pct": round(pmem, 2),
                    "mem_bytes": int(rss_kb * 1024),
                }
            )
        return items

    try:
        if sysname == "Linux":
            top_cpu = parse_ps(sh("ps -eo pid,pcpu,pmem,rss,comm --sort=-pcpu | head -11"))
            top_mem = parse_ps(sh("ps -eo pid,pcpu,pmem,rss,comm --sort=-rss | head -11"))
            total = int(sh("ps -e --no-headers | wc -l").strip() or "0")
        else:
            top_cpu = parse_ps(sh("ps -eo pid,pcpu,pmem,rss,comm -r | head -11"))
            top_mem = parse_ps(sh("ps -eo pid,pcpu,pmem,rss,comm -m | head -11"))
            total = int(sh("ps -e | wc -l").strip() or "0") - 1
    except Exception:
        top_cpu, top_mem, total = [], [], 0

    return {"total": max(0, total), "top_cpu": top_cpu, "top_mem": top_mem}


def main():
    host = socket.gethostname()
    sysname = platform.system()
    arch = platform.machine()
    cores = os.cpu_count() or 0

    payload = {
        "timestamp_ms": now_ms(),
        "system": {
            "hostname": host,
            "os": sysname,
            "arch": arch,
            "cpu_cores": cores,
        },
        "cpu": cpu_snapshot(),
        "memory": mem_snapshot(),
        "disks": disk_snapshot(),
        "network": network_snapshot(),
        "processes": top_processes(),
    }

    print(json.dumps(payload, separators=(",", ":"), sort_keys=False))


if __name__ == "__main__":
    main()
