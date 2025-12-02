import argparse
import socket
import struct
import time
import os
import json

# constants
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

class OnlineStats:
    def __init__(self):
        self.n = 0; self.mean = 0.0; self.M2 = 0.0
        self.min = float('inf'); self.max = float('-inf')
    def add(self, x):
        self.n += 1
        d = x - self.mean
        self.mean += d / self.n
        self.M2 += d * (x - self.mean)
        self.min = min(self.min, x); self.max = max(self.max, x)
    def summary(self):
        var = self.M2 / (self.n - 1) if self.n > 1 else 0.0
        return {"count": self.n, "min": self.min, "avg": self.mean,
                "max": self.max, "stddev": var ** 0.5}

def checksum(data):
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(int.from_bytes(data[i:i+2], "big") for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF

def jwrite(path, obj):
    if path is None:
        return
    obj.setdefault("ts", time.time())
    with open(path, "a") as f:
        f.write(json.dumps(obj) + "\n")

def ping_once(sock, addr, seq, ident, timeout, json_path):
    # ICMP header: type(8) - 1 byte, code(0) - 1 byte, checksum(16b) - 2 bytes, identifier - 2 bytes, seq - 2 bytes
    payload = struct.pack("!d", time.time())  # send timestamp
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    chksum = checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chksum, ident, seq)

    packet = header + payload
    ts_send = time.time()
    sock.sendto(packet, (addr, 1))

    sock.settimeout(timeout)
    try:
        reply, _ = sock.recvfrom(1024)
        ts_recv = time.time()
    except socket.timeout:
        print(f"seq={seq} timeout")
        jwrite(json_path, {
            "tool": "ping",
            "seq": seq,
            "dst_ip": addr,
            "ts_send": ts_send,
            "ts_recv": None,
            "err": "timeout"
        })
        return None

    # Parse response
    icmp_header = reply[20:28]
    r_type, r_code, _, r_ident, r_seq = struct.unpack("!BBHHH", icmp_header)

    if r_type == ICMP_ECHO_REPLY and r_ident == ident and r_seq == seq:
        sent_ts = struct.unpack("!d", reply[28:36])[0]
        rtt = (ts_recv - sent_ts) * 1000
        ttl = reply[8]
        print(f"seq={seq} rtt={rtt:.2f} ms ttl={ttl}")
        jwrite(json_path, {
            "tool": "ping",
            "seq": seq,
            "dst_ip": addr,
            "ts_send": ts_send,
            "ts_recv": ts_recv,
            "rtt_ms": rtt,
            "ttl_reply": ttl,
            "icmp_type": r_type,
            "icmp_code": r_code,
            "err": None
        })
        return rtt
    else:
        print(f"seq={seq} non-echo type={r_type} code={r_code}")
        return None

def main():
    parser = argparse.ArgumentParser(description="ICMP Ping")
    arg_list = [
        ("target", {"help": "Hostname or IP to ping"}),
        ("--count", {"type": int, "default": 4, "help": "Number of probes"}),
        ("--interval", {"type": float, "default": 1.0}),
        ("--timeout", {"type": float, "default": 1.0}),
        ("--json", {"type": str}),
        ("--qps-limit", {"type": float, "default": 1.0}),
        ("--no-color", {"action": "store_true"}),
    ]

    for arg, options in arg_list:
        parser.add_argument(arg, **options)
    args = parser.parse_args()

    try:
        addr = socket.gethostbyname(args.target)
    except socket.gaierror:
        print("Could not resolve target")
        return

    print(f"Pinging {args.target} ({addr}) with count={args.count}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    ident = os.getpid() & 0xFFFF

    s = OnlineStats()

    min_interval = max(args.interval, 1.0 / args.qps_limit)

    for seq in range(args.count):
        rtt = ping_once(sock, addr, seq, ident, args.timeout, args.json)
        if rtt is not None:
            s.add(rtt)
        time.sleep(min_interval)

    stats = s.summary()

    # Summary
    if stats["count"] > 0:
        print(f"\n--- {args.target} ping statistics ---")
        print(f"{stats['count']}/{args.count} received, loss={(1 - stats['count']/args.count)*100:.1f}%")
        print(f"min: {stats['min']:.2f} ms, max: {stats['max']:.2f} ms, avg: {stats['avg']:.2f} ms, stddev: {stats['stddev']:.2f}")
    else:
        print("All packets lost")

if __name__ == "__main__":
    main()
