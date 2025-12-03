import argparse
import socket
import os
import sys
import struct
import time
import select
import binascii
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


def jwrite(path, obj):
    if path is None:
        return
    obj.setdefault("ts", time.time())
    with open(path, "a") as f:
        f.write(json.dumps(obj) + "\n")

def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = string[count+1] * 256 + string[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(string):
        csum = csum + ord(string[len(string) - 1])
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer


def receive_one_ping(mySocket, ID, timeout, destAddr, json_path):
    while 1:
        what_ready = select.select([mySocket], [], [], timeout)
        if what_ready[0] == []:  # Timeout
            return "Request timed out."
        recPacket, addr = mySocket.recvfrom(1024)

        # TODO: read the packet and parse the source IP address, you will need this part for traceroute
        ipHeader = recPacket[:20]
        ipAddress = socket.inet_ntoa(ipHeader[12:16])

        # TODO: calculate and return the round trip time for this ping
        # TODO: handle different response type and error code, display error message to the user
        icmpHeader = recPacket[20:28]
        icmpVal = struct.unpack("bbHHh", icmpHeader)

        if icmpVal[3] == ID:
            if icmpVal[0] == 0 and icmpVal[1] == 0:
                # d is 8 bytes
                then_time = struct.unpack("d", recPacket[28:36])[0]
                recv_time = time.time()
                rtt = (recv_time - then_time) * 1000
                print(f"seq={icmpVal[4]} rtt={rtt:.2f} ms")
                jwrite(json_path, {
                    "tool": "ping",
                    "seq": icmpVal[4],
                    "dst_ip": addr,
                    "ts_send": then_time,
                    "ts_recv": recv_time,
                    "rtt_ms": rtt,
                    "icmp_type": icmpVal[0],
                    "icmp_code": icmpVal[1],
                    "err": None
                })
                return rtt

            if icmpVal[0] == 3:
                jwrite(json_path, {
                    "tool": "ping",
                    "seq": icmpVal[4],
                    "dst_ip": addr,
                    "ts_send": then_time,
                    "ts_recv": recv_time,
                    "rtt_ms": rtt,
                    "icmp_type": icmpVal[0],
                    "icmp_code": icmpVal[1],
                    "err": "Destination unreachable"
                })
                return f"ICMP Error: Destination unreachable (code {icmpVal[1]})"
            elif icmpVal[0] == 11:
                jwrite(json_path, {
                    "tool": "ping",
                    "seq": icmpVal[4],
                    "dst_ip": addr,
                    "ts_send": then_time,
                    "ts_recv": recv_time,
                    "rtt_ms": rtt,
                    "icmp_type": icmpVal[0],
                    "icmp_code": icmpVal[1],
                    "err": "Time exceeded"
                })
                return f"ICMP Error: Time exceeded (code {icmpVal[1]})"
            elif icmpVal[0] == 12:
                jwrite(json_path, {
                    "tool": "ping",
                    "seq": icmpVal[4],
                    "dst_ip": addr,
                    "ts_send": then_time,
                    "ts_recv": recv_time,
                    "rtt_ms": rtt,
                    "icmp_type": icmpVal[0],
                    "icmp_code": icmpVal[1],
                    "err": "IP header parameter invalid"
                })
                return f"ICMP Error: IP header parameter invalid (code {icmpVal[1]})"
            else:
                jwrite(json_path, {
                    "tool": "ping",
                    "seq": icmpVal[4],
                    "dst_ip": addr,
                    "ts_send": then_time,
                    "ts_recv": recv_time,
                    "rtt_ms": rtt,
                    "icmp_type": icmpVal[0],
                    "icmp_code": icmpVal[1],
                    "err": "Unkown"
                })
                return f"ICMP Error: Type {icmpVal[0]} (code {icmpVal[1]})"

def send_one_ping(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0
    # Make a dummy header with a 0 checksum

    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)
    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network byte order
        myChecksum = socket.htons(myChecksum) & 0xffff
    else:
        myChecksum = socket.htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    # AF_INET address must be tuple, not str # Both LISTS and TUPLES consist of a number of objects
    mySocket.sendto(packet, (destAddr, 1))
    # which can be referenced by their position number within the object.


def do_one_ping(destAddr, timeout, json_path):
    icmp = socket.getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details: http://sock- raw.org/papers/sock_raw
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    # Return the current process i
    myID = os.getpid() & 0xFFFF
    send_one_ping(mySocket, destAddr, myID)
    delay = receive_one_ping(mySocket, myID, timeout, destAddr, json_path)

    mySocket.close()
    return delay

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

    s = OnlineStats()

    min_interval = max(args.interval, 1.0 / args.qps_limit)

    for seq in range(args.count):
        rtt = do_one_ping(addr, args.timeout, args.json)
        if isinstance(rtt, str):
            print(rtt)
        else:
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
