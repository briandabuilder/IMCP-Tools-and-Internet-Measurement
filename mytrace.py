import argparse
import socket
import sys
import struct
import time
import os
import json

ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11
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
        csum = csum + string[len(string) - 1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer

def build_packet(flowId):
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.
    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.
    # So the function ending should look like this
    if flowId == 0:
        ID = os.getpid() & 0xFFFF
    else:
        ID = flowId & 0xFFFF
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, ID, 1)
    data = struct.pack("I", flowId)
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
    return packet

def get_route(hostname, timeout, max_hops, probe, json_path, n, flowId, rdns, probeRate):
    icmp = socket.getprotobyname("icmp")
    timeLeft = timeout

    try:
        destAddr = socket.gethostbyname(hostname)
    except:
        print("Could not resolve host")
        return
    
    hopList = []
    
    for ttl in range(1, max_hops):
        print(f"{ttl:2d} ", end="", flush=True)
        s = OnlineStats()
        for tries in range(probe):

            # TODO: create ICMP socket, connect to destination IP, set timeout and time-to-live
            mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            mySocket.settimeout(timeout)
            time.sleep(probeRate)

            try:

                # TODO: create ICMP ping packet, record the time delay of getting response detect timeout
                pkt = build_packet(flowId)
                send_time = time.time()
                mySocket.sendto(pkt, (destAddr, 1))
                recPacket, src = mySocket.recvfrom(1024)
                recv_time = time.time()
                rtt = (recv_time - send_time) * 1000

                print(f"{rtt:.2f}ms ", end="")

            except socket.timeout:
                jwrite(json_path, {
                        "tool": "trace",
                        "hop": ttl,
                        "probe": tries,
                        "ts_send": send_time,
                        "ts_recv": recv_time,
                        "dst": None,
                        "router_ip": src[0],
                        "rtt_ms": rtt,
                        "icmp_type": None,
                        "flow_id": flowId,
                        "err": "Scoket Timeout"
                })
                print("* ", end="")
            else:

                # TODO: parse and handle different response type
                # Hint: use wireshark to get the byte location of the response type
                ipHeader = recPacket[:20]
                ipAddress = socket.inet_ntoa(ipHeader[12:16])
                icmpHeader = recPacket[20:28]
                icmpVal = struct.unpack("bbHHh", icmpHeader)
                s.add(rtt)

                if n:
                    host = ipAddress
                else:
                    host = ipAddress
                    try:
                        startDns = time.time()
                        name = socket.gethostbyaddr(ipAddress)[0]
                        if not rdns:
                            host = name
                        else:
                            if time.time() - startDns <= 0.2:
                                host = name
                    except socket.herror:
                        host = ipAddress

                addrDisplay = f"{host} ({ipAddress})" if host != ipAddress else f"{ipAddress}"
                if icmpVal[0] == 0:
                    jwrite(json_path, {
                        "tool": "trace",
                        "hop": ttl,
                        "probe": tries,
                        "ts_send": send_time,
                        "ts_recv": recv_time,
                        "dst": host,
                        "router_ip": src[0],
                        "rtt_ms": rtt,
                        "icmp_type": icmpVal[0],
                        "flow_id": flowId,
                        "err": None
                    })
                    hopList.append(ipAddress)
                    writeHopList(hostname, hopList)
                    print(f"Destination reached {addrDisplay}\n")
                    return
                elif icmpVal[0] == 3:
                    jwrite(json_path, {
                        "tool": "trace",
                        "hop": ttl,
                        "probe": tries,
                        "ts_send": send_time,
                        "ts_recv": recv_time,
                        "dst": host,
                        "router_ip": src[0],
                        "rtt_ms": rtt,
                        "icmp_type": icmpVal[0],
                        "flow_id": flowId,
                        "err": "Destination unreachable"
                    })
                    hopList.append(ipAddress)
                    writeHopList(hostname, hopList)
                    print(f"Destination unreachable {addrDisplay}\n")
                    return
                elif icmpVal[0] == 11:
                    jwrite(json_path, {
                        "tool": "trace",
                        "hop": ttl,
                        "probe": tries,
                        "ts_send": send_time,
                        "ts_recv": recv_time,
                        "dst": host,
                        "router_ip": src[0],
                        "rtt_ms": rtt,
                        "icmp_type": icmpVal[0],
                        "flow_id": flowId,
                        "err": None
                    })
                    if tries == probe-1:
                        hopList.append(ipAddress)
                        print(f"{addrDisplay} ")
                        h = s.summary()
                        print(f"rtt mean: {h["avg"]:2f}, rtt stddev: {h["stddev"]:2f}")
                else:
                    print(f"ICMP Error: Type {icmpVal[0]} (code {icmpVal[1]}) {addrDisplay}\n")
                    break 
            
            finally:

                # TODO: close the sockets
                mySocket.close()
        print()
    writeHopList(hostname, hopList)

def jwrite(path, obj):
    if path is None:
        return
    obj.setdefault("ts", time.time())
    with open(path, "a") as f:
        f.write(json.dumps(obj) + "\n")

def jload(path):
    with open(path) as f:
        return json.load(f)

def writeHopList(target, hopList):
    ts = int(time.time())
    targetName = str(target).replace(".", "-")
    fileName = "trace_" + targetName + "_" + str(ts)
    jwrite(fileName, {"hop": hopList})

def main():
    parser = argparse.ArgumentParser(description="ICMP Traceroute")
    arg_list = [
        (["target"], {"help": "Hostname or IP to trace"}),
        (["--max-ttl"], {"type": int, "default": 30, "help": "Maximum TTL (hops)"}),
        (["--probes"], {"type": int, "default": 3, "help": "Probes per hop"}),
        (["--timeout"], {"type": float, "default": 2.0, "help": "Per-probe timeout (s)"}),
        (["-n"], {"action": "store_true", "help": "Do not resolve hostnames (show IP only)"}),
        (["--rdns"], {"action": "store_true", "help": "Enable reverse DNS (200 ms budget per hop)"}),
        (["--flow-id"], {"type": int, "default": 0, "help": "Flow ID to keep probes consistent (Paris-style)"}),
        (["--json"], {"type": str, "help": "Write per-probe results to JSONL file"}),
        (["--qps-limit"], {"type": float, "default": 1.0, "help": "Max probe rate (queries per second)"}),
        (["--i-accept-the-risk"], {"action": "store_true", "help": "Allow probe rates faster than 1 per second (ETHICS & SAFETY REQUIREMENT)"}),
        (["--no-color"], {"action": "store_true", "help": "Disable color in output"}),
        (["--diff"], {"nargs": 2, "help": "Compare two trace files and computes Jaccard similarity"})
    ]

    for names, options in arg_list:
        parser.add_argument(*names, **options)
    args = parser.parse_args()

    # ETHICS & SAFETY REQUIREMENT
    if args.qps_limit > 1.0 and not args.i_accept_the_risk:
        print("Ethics Warning: Probe rates exceeding 1/second require explicit acknowledgment of risk with a flag.")
        sys.exit(1)

    if args.diff:
        hop1 = jload(args.diff[0])
        hop2 = jload(args.diff[1])

        s1 = set(hop1["hop"])
        s2 = set(hop2["hop"])

        intersection = s1 & s2
        union = s1 | s2

        jaccard = len(intersection) / len(union)
        print(f"Jaccard similarity: {jaccard:.2f}")
        return

    try:
        addr = socket.gethostbyname(args.target)
    except:
        print("Could not resolve host")
        return

    print(f"Traceroute to {args.target} ({addr}), max {args.max_ttl} hops")
    min_interval = max(1.0 / args.qps_limit, 0.2)

    get_route(args.target, args.timeout, args.max_ttl, args.probes, args.json, args.n, args.flow_id, args.rdns, min_interval)

if __name__ == "__main__":
    main()
