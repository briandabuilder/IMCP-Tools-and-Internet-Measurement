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
    ID = (os.getpid()^flowId) & 0xFFFF
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, ID, 1)
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
    return packet

def get_route(hostname, timeout, max_hops, probe, json_path, n, flowId, rdns, probeRate):
    icmp = socket.getprotobyname("icmp")
    timeLeft = timeout

    try:
        destAddr = socket.gethostbyname(hostname)
    except:
        print("Could not resolve host")
        return
    
    for ttl in range(1, max_hops):
        print(f"{ttl:2d} ", end="", flush=True)
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
                print("* ", end="")
            else:

                # TODO: parse and handle different response type
                # Hint: use wireshark to get the byte location of the response type
                ipHeader = recPacket[:20]
                ipAddress = socket.inet_ntoa(ipHeader[12:16])
                icmpHeader = recPacket[20:28]
                icmpVal = struct.unpack("bbHHh", icmpHeader)

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

                addrDisplay = f"{host} ({ipAddress})" if not n else f"{ipAddress}"
                if icmpVal[0] == 0:
                    jwrite(json_path, {
                        "tool": "trace",
                        "hop": ttl,
                        "probe": tries,
                        "router_ip": src[0],
                        "rtt_ms": rtt,
                        "icmp_type": icmpVal[0],
                        "flow_id": flowId,
                        "err": None
                    })
                    print(f"Destination reached {addrDisplay}\n")
                    return
                elif icmpVal[0] == 3:
                    jwrite(json_path, {
                        "tool": "trace",
                        "hop": ttl,
                        "probe": tries,
                        "router_ip": src[0],
                        "rtt_ms": rtt,
                        "icmp_type": icmpVal[0],
                        "flow_id": flowId,
                        "err": "Destination unreachable"
                    })
                    print(f"Destination unreachable {addrDisplay}\n")
                    return
                elif icmpVal[0] == 11:
                    jwrite(json_path, {
                        "tool": "trace",
                        "hop": ttl,
                        "probe": tries,
                        "router_ip": src[0],
                        "rtt_ms": rtt,
                        "icmp_type": icmpVal[0],
                        "flow_id": flowId,
                        "err": None
                    })
                    if tries == probe-1:
                        print(f"{host} ({ipAddress})")
                else:
                    print(f"ICMP Error: Type {icmpVal[0]} (code {icmpVal[1]}) {addrDisplay}\n")
                    break 
            
            finally:

                # TODO: close the sockets
                mySocket.close()
        print()

def jwrite(path, obj):
    if path is None:
        return
    obj.setdefault("ts", time.time())
    with open(path, "a") as f:
        f.write(json.dumps(obj) + "\n")

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
        (["--no-color"], {"action": "store_true", "help": "Disable color in output"}),
    ]

    for names, options in arg_list:
        parser.add_argument(*names, **options)
    args = parser.parse_args()

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
