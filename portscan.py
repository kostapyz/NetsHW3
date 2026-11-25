import argparse
import os
import random
import selectors
import socket
import struct
import sys
import time

IS_WINDOWS = os.name == "nt"


# ---- admin / npcap checks -----------------------------------------------

def is_admin() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def check_npcap_or_die():
    try:
        import scapy.all as scapy
    except ImportError:
        print(
            "error: 'scapy' is not installed.\n"
            "       Run: pip install scapy",
            file=sys.stderr,
        )
        sys.exit(2)

    try:
        use_pcap = bool(scapy.conf.use_pcap)
    except Exception:
        use_pcap = False

    if not use_pcap:
        print(
            "error: Npcap not detected by Scapy.\n"
            "       Install from https://npcap.com/#download\n"
            "       and check 'Install Npcap in WinPcap API-compatible Mode'.",
            file=sys.stderr,
        )
        sys.exit(2)

    if not is_admin():
        print(
            "error: Administrator privileges required for SYN scan via Npcap.",
            file=sys.stderr,
        )
        sys.exit(2)


# ---- DNS helpers --------------------------------------------------------

def build_dns_query(txid=None):
    if txid is None:
        txid = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b""
    for part in "example.com".split("."):
        p = part.encode()
        qname += bytes([len(p)]) + p
    qname += b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)


def dns_txid(q):
    return struct.unpack("!H", q[:2])[0]


def is_dns_response(data, txid):
    if len(data) < 12:
        return False
    rid, flags = struct.unpack("!HH", data[:4])
    return rid == txid and bool(flags & 0x8000)


# ---- protocol guessing (HTTP / DNS / ECHO) -----------------

def guess_tcp_protocol(ip, port, timeout, dns_query, txid):
    # HTTP
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(
            f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: portscan\r\n\r\n"
            .encode()
        )
        if s.recv(1024).startswith(b"HTTP/"):
            s.close()
            return "HTTP"
        s.close()
    except Exception:
        pass

    # ECHO
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        payload = b"PORTSCAN_ECHO_TEST\n"
        s.sendall(payload)
        data = b""
        while len(data) < len(payload):
            c = s.recv(len(payload) - len(data))
            if not c:
                break
            data += c
        s.close()
        if data == payload:
            return "ECHO"
    except Exception:
        pass

    # DNS
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(struct.pack("!H", len(dns_query)) + dns_query)
        hdr = b""
        while len(hdr) < 2:
            c = s.recv(2 - len(hdr))
            if not c:
                break
            hdr += c
        if len(hdr) == 2:
            n = struct.unpack("!H", hdr)[0]
            if 0 < n <= 4096:
                data = b""
                while len(data) < n:
                    c = s.recv(n - len(data))
                    if not c:
                        break
                    data += c
                if is_dns_response(data, txid):
                    s.close()
                    return "DNS"
        s.close()
    except Exception:
        pass

    return "-"


def guess_udp_protocol(response, request, txid):
    if response == request:
        return "ECHO"
    if is_dns_response(response, txid):
        return "DNS"
    if response.startswith(b"HTTP/"):
        return "HTTP"
    return "-"


# ---- CLI helpers --------------------------------------------------------

def parse_port_spec(spec):
    proto, sep, ports_part = spec.partition("/")
    proto = proto.lower()
    if proto not in ("tcp", "udp"):
        raise ValueError(f"unknown protocol: {spec}")
    if not sep or ports_part == "":
        return proto, set(range(1, 65536))
    ports = set()
    for part in ports_part.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            left, right = int(a), int(b)
            if left < 1 or right > 65535 or left > right:
                raise ValueError(f"bad range: {part}")
            ports.update(range(left, right + 1))
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"bad port: {part}")
            ports.add(p)
    return proto, ports


# ---- Npcap TCP SYN scan -------------------------------------------------

def tcp_syn_scan_npcap(target_ip, ports, timeout, batch_size):
    from scapy.layers.inet import IP, TCP
    from scapy.sendrecv import sr
    from scapy.config import conf as sconf
    sconf.verb = 0

    results = {}
    ports_list = sorted(ports)
    if not ports_list:
        return results

    batch_size = max(1, min(batch_size, 5000))

    for i in range(0, len(ports_list), batch_size):
        batch = ports_list[i:i + batch_size]
        packets = [IP(dst=target_ip) / TCP(dport=p, flags="S") for p in batch]

        try:
            answered, _ = sr(
                packets, timeout=timeout, verbose=0, inter=0.001, retry=0,
            )
        except Exception as e:
            print(f"error: npcap sr() failed: {e}", file=sys.stderr)
            sys.exit(3)

        for sent, recv in answered:
            if recv.haslayer(TCP) and recv[TCP].flags == 0x12:  # SYN+ACK
                port = sent[TCP].dport
                t = None
                st = getattr(sent, "sent_time", None)
                if st is not None:
                    t = float(recv.time) - float(st)
                results[port] = t

    return results


# ---- UDP scan -----------------------------------------------------------

def udp_scan(ip, ports, payload, timeout, max_inflight):
    if not ports:
        return {}

    results, pending = {}, {}
    sel = selectors.DefaultSelector()
    it = iter(sorted(ports))

    def start_next():
        while len(pending) < max_inflight:
            try:
                port = next(it)
            except StopIteration:
                break
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setblocking(False)
            try:
                s.connect((ip, port))
                s.send(payload)
            except OSError:
                s.close()
                continue
            pending[s] = (port, time.time())
            sel.register(s, selectors.EVENT_READ)

    start_next()
    try:
        while pending:
            for key, _ in sel.select(0.02):
                s = key.fileobj
                port, sent = pending.pop(s)
                sel.unregister(s)
                try:
                    data = s.recv(65535)
                    results[port] = {
                        "time": time.time() - sent,
                        "response": data,
                    }
                except (ConnectionResetError, ConnectionRefusedError, OSError):
                    pass
                s.close()
                start_next()

            now = time.time()
            for s, (port, sent) in list(pending.items()):
                if now - sent >= timeout:
                    sel.unregister(s)
                    s.close()
                    del pending[s]
                    results[port] = {"time": None, "response": None}
                    start_next()
    finally:
        sel.close()
    return results


def main():
    parser = argparse.ArgumentParser(prog="portscan")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("-j", "--num-threads", type=int, default=500)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-g", "--guess", action="store_true")
    parser.add_argument("ip_address")
    parser.add_argument("specs", nargs="+")
    args = parser.parse_args()

    if args.timeout <= 0 or args.num_threads <= 0:
        parser.error("timeout and num-threads must be positive")

    if not IS_WINDOWS:
        print(
            "error: this build targets Windows (Npcap + Scapy).",
            file=sys.stderr,
        )
        sys.exit(2)

    try:
        target_ip = socket.gethostbyname(args.ip_address)
    except OSError as e:
        print(f"error: cannot resolve address: {e}", file=sys.stderr)
        sys.exit(1)

    port_map = {"tcp": set(), "udp": set()}
    try:
        for spec in args.specs:
            proto, ports = parse_port_spec(spec)
            port_map[proto].update(ports)
    except ValueError as e:
        parser.error(str(e))

    tcp_ports = sorted(port_map["tcp"])
    udp_ports = sorted(port_map["udp"])
    if not tcp_ports and not udp_ports:
        print("error: no ports to scan", file=sys.stderr)
        sys.exit(1)

    select_max = min(args.num_threads, 500)  # под лимит select() на Windows
    npcap_batch = max(1, min(args.num_threads, 5000))

    dns_query = build_dns_query()
    txid = dns_txid(dns_query)
    udp_payload = dns_query if args.guess else b"PORTSCAN"

    results = {"tcp": {}, "udp": {}}

    # TCP
    if tcp_ports:
        check_npcap_or_die()
        if args.verbose:
            print("# tcp strategy: npcap SYN scan", file=sys.stderr)
        r = tcp_syn_scan_npcap(target_ip, tcp_ports, args.timeout, npcap_batch)
        for port, t in r.items():
            results["tcp"][port] = {"time": t, "proto": "-"}

    # UDP
    if udp_ports:
        r = udp_scan(target_ip, udp_ports, udp_payload, args.timeout, select_max)
        for port, v in r.items():
            results["udp"][port] = {
                "time": v.get("time"),
                "response": v.get("response"),
                "request": udp_payload,
                "proto": "-",
            }

    # Guess: HTTP / DNS / ECHO
    if args.guess:
        for port, v in results["tcp"].items():
            v["proto"] = guess_tcp_protocol(
                target_ip, port, args.timeout, dns_query, txid
            )
        for port, v in results["udp"].items():
            if v.get("response") is not None:
                v["proto"] = guess_udp_protocol(
                    v["response"], v.get("request", b""), txid
                )
            else:
                v["proto"] = "-"

    # Output: TCP|UDP PORT [TIME,ms] [PROTOCOL|-]
    for proto in ("tcp", "udp"):
        for port in sorted(results[proto].keys()):
            v = results[proto][port]
            parts = [proto.upper(), str(port)]
            if args.verbose:
                t = v.get("time")
                parts.append(f"{t * 1000:.2f}" if t is not None else "-")
            if args.guess:
                parts.append(v.get("proto", "-"))
            print(" ".join(parts))


if __name__ == "__main__":
    main()