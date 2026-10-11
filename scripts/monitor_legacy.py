#!/usr/bin/env python3
"""Read-only fallback for legacy named systemd units, no fabricated ICMP counters."""
import json
import pathlib
import re
import subprocess
import sys
import time

def get_systemd(unit, prop):
    try:
        x = subprocess.run(["systemctl", "show", "--value", "--property=" + prop, unit],
                           capture_output=True, text=True, timeout=2)
        return x.stdout.strip() if x.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""

def read_int(filename):
    try:
        return int(pathlib.Path(filename).read_text().strip())
    except (OSError, ValueError):
        return None

def process_stats(pid):
    if not pid or pid <= 0:
        return {"pid":None, "rss_bytes":None, "cpu_ticks":None}
    try:
        st = pathlib.Path("/proc/" + str(pid) + "/stat").read_text().rsplit(") ", 1)[1].split()
        return {"pid":pid, "rss_bytes":read_int("/proc/" + str(pid) + "/statm"),
                "cpu_ticks":int(st[11])+int(st[12])}
    except (OSError, IndexError, ValueError):
        return {"pid":None, "rss_bytes":None, "cpu_ticks":None}

def sample(unit):
    state=get_systemd(unit,"ActiveState") or "unknown"
    command=get_systemd(unit,"ExecStart")
    # A device is verified from the actual ExecStart argument, not a guessed name.
    found=re.search(r"(?:^|\s)-T(?:\s+|=)([A-Za-z0-9_-]{1,15})(?:\s|$)",command)
    dev=found.group(1) if found else None
    if dev and not pathlib.Path("/sys/class/net",dev).exists():
        dev=None
    counters={}
    if dev:
        for key in ("rx_packets","tx_packets","rx_dropped","tx_dropped","rx_bytes","tx_bytes"):
            counters[key]=read_int("/sys/class/net/"+dev+"/statistics/"+key)
    try:
        pid=int(get_systemd(unit,"MainPID"))
    except ValueError:
        pid=0
    process=process_stats(pid)
    if pid:
        rss=None
        try:
            for line in pathlib.Path("/proc/"+str(pid)+"/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    rss=int(line.split()[1])*1024
                    break
        except OSError:
            pass
        process["rss_bytes"]=rss
    return {"unit":unit, "systemd_active_state":state, "interface":dev,
            "timestamp_ms":int(time.monotonic()*1000),
            "kernel_interface_counters":counters, "process":process,
            "internal_icmp_metrics_available":False, "internal_queue_drops":None,
            "application_goodput_mbps":None, "latency_p95_ms":None,
            "latency_p99_ms":None, "health":"unknown",
            "limitations":["legacy binary does not expose internal counters",
                           "systemd state is not proof of tunnel reachability",
                           "no device inferred when ExecStart lacks explicit -T"]}

def main():
    if len(sys.argv)!=4:
        sys.exit("usage: monitor_legacy.py stats|monitor <unit> [--json-or-empty]")
    mode, unit, fmt=sys.argv[1:]
    if not re.fullmatch(r"[A-Za-z0-9_-]+\.service",unit):
        sys.exit("provide the exact legacy systemd unit name, including .service")
    prev=None
    while True:
        current=sample(unit)
        if prev:
            dt=max(0.001,(current["timestamp_ms"]-prev["timestamp_ms"])/1000)
            current["kernel_rates_per_second"]={
                k:max(0,(v-prev["kernel_interface_counters"][k])/dt)
                for k,v in current["kernel_interface_counters"].items()
                if v is not None and prev["kernel_interface_counters"].get(k) is not None}
            p,old=current["process"],prev["process"]
            if p["pid"] and p["pid"]==old["pid"] and p["cpu_ticks"] is not None:
                import os
                p["cpu_percent_one_core"]=round(
                    100*max(0,p["cpu_ticks"]-old["cpu_ticks"])/os.sysconf("SC_CLK_TCK")/dt,1)
        current["process"].pop("cpu_ticks",None)
        if fmt=="--json":
            print(json.dumps(current,ensure_ascii=False),flush=True)
        else:
            print("LEGACY",unit, "systemd="+current["systemd_active_state"],
                  "device="+str(current["interface"]), "health=UNKNOWN",flush=True)
            print("  Kernel interface:",current["kernel_interface_counters"],flush=True)
            print("  Internal ICMP metrics: UNAVAILABLE; application goodput/latency: NOT MEASURED",flush=True)
        if mode=="stats":
            break
        prev=sample(unit)
        time.sleep(1)

if __name__=="__main__":
    main()
