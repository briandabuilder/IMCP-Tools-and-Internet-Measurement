import argparse
import socket
import struct
import time
import os
import json

ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11
ICMP_ECHO_REPLY = 0

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

def send_probe(sock, ttl, addr, seq, ident, flow_id):
    payload = struct.pack("!dI", time.time(), flow_id)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    chksum = checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chksum, ident, seq)
    packet = header + payload

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    sock.sendto(packet, (addr, 1))
    return time.time()

def recv_probe(sock, timeout):
    sock.settimeout(timeout)
    try:
        data, src = sock.recvfrom(1024)
        return time.time(), data, src[0]
    except socket.timeout:
        return None, None, None

def main():
    parser = argparse.ArgumentParser(description="ICMP Traceroute")
    parser.add_argument("target")
    parser.add_argument("--max-ttl", type=int, default=30)
    parser.add_argument("--probes", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("-n", action="store_true")
    parser.add_argument("--rdns", action="store_true")
    parser.add_argument("--flow-id", type=int, default=0)
    parser.add_argument("--json", type=str)
    parser.add_argument("--qps-limit", type=float, default=1.0)
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    try:
        addr = socket.gethostbyname(args.target)
    except:
        print("Could not resolve host")
        return

    print(f"Traceroute to {args.target} ({addr}), max {args.max_ttl} hops")

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    ident = os.getpid() & 0xFFFF
    global_seq = 0
    min_interval = max(1.0 / args.qps_limit, 0.1)

    reached = False

    for ttl in range(1, args.max_ttl + 1):
        print(f"{ttl:2d} ", end="", flush=True)

        hop_times = []
        hop_addr = None

        for p in range(args.probes):
            ts_send = send_probe(sock, ttl, addr, global_seq, ident, args.flow_id)
            ts_recv, data, src_ip = recv_probe(sock, args.timeout)
            global_seq += 1
            time.sleep(min_interval)

            if data is None:
                print("* ", end="")
                continue

            icmp = data[20:28]
            r_type = icmp[0]

            rtt = (ts_recv - ts_send) * 1000
            hop_times.append(rtt)
            hop_addr = src_ip

            print(f"{rtt:.2f}ms ", end="")

            jwrite(args.json, {
                "tool": "trace",
                "hop": ttl,
                "probe": p,
                "router_ip": src_ip,
                "rtt_ms": rtt,
                "icmp_type": r_type,
                "flow_id": args.flow_id,
            })

            if r_type == ICMP_ECHO_REPLY:
                reached = True

        if hop_addr:
            if args.rdns and not args.n:
                try:
                    host = socket.gethostbyaddr(hop_addr)[0]
                except:
                    host = hop_addr
            else:
                host = hop_addr
            print(f"{host}")
        else:
            print("")

        if reached:
            break

if __name__ == "__main__":
    main()
