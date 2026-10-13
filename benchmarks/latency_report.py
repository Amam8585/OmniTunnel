#!/usr/bin/env python3
"""Offline RTT quantiles from ping logs or explicit OPT-IN lab ICMP probes.

Usage:
  python3 benchmarks/latency_report.py --file ping-output.txt --sent 200
  python3 benchmarks/latency_report.py --target LAB_PEER_IP --allow-network --sent 200
Network mode MUST be used on authorized lab peers only.
"""
import argparse
import json
import math
import re
import subprocess
import sys

RX = re.compile(r"\btime[=<]\s*(\d+(?:\.\d+)?)\s*ms\b", re.IGNORECASE)

def quantile(values, proportion):
    sorted_values = sorted(values)
    if not sorted_values:
        return None
    p = (len(sorted_values)-1) * proportion
    i = math.floor(p)
    j = math.ceil(p)
    return round(sorted_values[i]*(j-p)+sorted_values[j]*(p-i), 12) if i != j else sorted_values[i]

def summarize(text, sent):
    if not (1 <= sent <= 100000):
        raise ValueError("invalid requested packet count")
    samples = [float(x) for x in RX.findall(text)]
    if any(not math.isfinite(n) or n < 0 for n in samples):
        raise ValueError("invalid RTT sample")
    if len(samples) > sent:
        raise ValueError("more replies than transmitted (combined logs?)")
    return {
        "sent_packets":sent, "received_packets":len(samples),
        "loss_percent":round(100*(sent-len(samples))/sent,3),
        "rtt_mean_ms":round(sum(samples)/len(samples),3) if samples else None,
        "rtt_p95_ms":round(quantile(samples,0.95),3) if samples else None,
        "rtt_p99_ms":round(quantile(samples,0.99),3) if samples else None,
        "inter_sample_jitter_ms":round(sum(abs(samples[i]-samples[i-1]) for i in range(1,len(samples)))/(len(samples)-1),3)
                                    if len(samples)>1 else None,
        "application_goodput_mbps":None,
        "limitations":["ICMP RTT is not application latency",
                       "network performance improvements require matched offered load and repeated A/B trials"]
    }

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    target=parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--file",help="offline ping output (no network access)")
    target.add_argument("--target",help="explicit AUTHORIZED LAB peer for active ping")
    parser.add_argument("--allow-network",action="store_true")
    parser.add_argument("--sent",type=int,default=200)
    parser.add_argument("--interval",type=float,default=0.2)
    args=parser.parse_args()
    if args.target:
        if not args.allow_network:
            parser.error("active probing requires --allow-network and lab authorization")
        if args.sent<10 or args.sent>1000 or args.interval<0.1 or args.interval>10:
            parser.error("probe rate/count outside safe laboratory bounds")
        proc=subprocess.run(["ping","-n","-c",str(args.sent),
                             "-i",str(args.interval),"-W","2",args.target],
                            capture_output=True,text=True,
                            timeout=args.sent*(args.interval+2)+10)
        content=proc.stdout
    else:
        with open(args.file,encoding="utf-8") as handle:
            content=handle.read()
    print(json.dumps(summarize(content,args.sent),indent=2,sort_keys=True))

if __name__=="__main__":
    try:
        main()
    except (OSError,subprocess.TimeoutExpired,ValueError) as exc:
        print("Latency measurement failed:",exc,file=sys.stderr)
        sys.exit(1)
