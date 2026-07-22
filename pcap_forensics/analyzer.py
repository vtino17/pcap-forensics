import json
import csv
import io
from collections import defaultdict
from datetime import datetime


class PcapAnalyzer:

    def __init__(self):
        self.sessions = defaultdict(list)
        self.dns_queries = []
        self.http_requests = []
        self.tls_handshakes = []
        self.beacon_candidates = []
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)

    def analyze(self, packets):
        self.packet_count = len(packets)
        ip_stats = defaultdict(lambda: {"tx": 0, "rx": 0, "ports": set()})

        for pkt in packets:
            if not hasattr(pkt, "haslayer"):
                continue

            if pkt.haslayer("IP"):
                ip = pkt["IP"]
                proto = "TCP" if pkt.haslayer("TCP") else "UDP" if pkt.haslayer("UDP") else "OTHER"
                self.protocol_stats[proto] += 1

                src = ip.src
                dst = ip.dst
                size = len(pkt)
                ip_stats[src]["tx"] += size
                ip_stats[dst]["rx"] += size

                if pkt.haslayer("TCP"):
                    tcp = pkt["TCP"]
                    ip_stats[src]["ports"].add(tcp.sport)
                    ip_stats[dst]["ports"].add(tcp.dport)

                    if pkt.haslayer("Raw"):
                        payload = pkt["Raw"].load
                        self._check_http(pkt, payload)
                        self._check_tls(payload)

                if pkt.haslayer("DNS") and pkt["DNS"].qr == 0:
                    self._extract_dns(pkt)

        self._detect_beaconing(ip_stats)
        return ip_stats

    def _check_http(self, pkt, payload):
        try:
            decoded = payload.decode("utf-8", errors="ignore")
            if decoded.startswith(("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS")):
                lines = decoded.split("\r\n")
                request_line = lines[0] if lines else ""
                host = ""
                for line in lines:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                        break
                self.http_requests.append({
                    "request": request_line,
                    "host": host,
                    "src": pkt["IP"].src,
                    "dst": pkt["IP"].dst,
                    "timestamp": str(datetime.now()),
                })
        except Exception:
            pass

    def _check_tls(self, payload):
        if len(payload) < 1:
            return
        first_byte = payload[0]
        if first_byte == 0x16:
            content_type = "Handshake"
            if len(payload) > 5:
                handshake_type = payload[5]
                if handshake_type == 1:
                    self.tls_handshakes.append({
                        "type": "ClientHello",
                        "sni": self._extract_sni(payload),
                    })
                elif handshake_type == 2:
                    self.tls_handshakes.append({
                        "type": "ServerHello",
                    })

    def _extract_sni(self, payload):
        try:
            if len(payload) < 50:
                return ""
            idx = payload.find(b"\x00\x00")
            if idx < 0:
                return ""
            ext_len = int.from_bytes(payload[idx + 2 : idx + 4], "big")
            ext_data = payload[idx + 4 : idx + 4 + ext_len]
            sni_start = ext_data.find(b"\x00")
            if sni_start < 0:
                return ""
            sni_len = int.from_bytes(ext_data[sni_start + 1 : sni_start + 3], "big")
            sni = ext_data[sni_start + 3 : sni_start + 3 + sni_len]
            return sni.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def _extract_dns(self, pkt):
        dns = pkt["DNS"]
        if dns.qdcount > 0 and dns.qd:
            qname = dns.qd[0].name.decode("utf-8", errors="ignore") if isinstance(dns.qd[0].name, bytes) else str(dns.qd[0].name)
            self.dns_queries.append({
                "query": qname,
                "type": dns.qd[0].type,
                "src": pkt["IP"].src,
                "dst": pkt["IP"].dst,
            })

    def _detect_beaconing(self, ip_stats):
        threshold_tx = 100000
        for ip, stats in ip_stats.items():
            if stats["tx"] > threshold_tx and len(stats["ports"]) > 5:
                self.beacon_candidates.append({
                    "ip": ip,
                    "total_tx_bytes": stats["tx"],
                    "unique_ports": list(stats["ports"]),
                    "reason": "High outbound volume on multiple ports",
                })

    def summary(self):
        return {
            "total_packets": self.packet_count,
            "protocols": dict(self.protocol_stats),
            "dns_queries": len(self.dns_queries),
            "http_requests": len(self.http_requests),
            "tls_handshakes": len(self.tls_handshakes),
            "beacon_candidates": len(self.beacon_candidates),
        }

    def report_json(self, path):
        report = {
            "summary": self.summary(),
            "dns_queries": self.dns_queries[:100],
            "http_requests": self.http_requests[:100],
            "tls_handshakes": len(self.tls_handshakes),
            "beacon_candidates": self.beacon_candidates,
        }
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        return path

    def report_csv(self, path):
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["type", "source", "destination", "detail"])
            for r in self.http_requests[:100]:
                writer.writerow(["HTTP", r["src"], r["dst"], r["request"]])
            for q in self.dns_queries[:100]:
                writer.writerow(["DNS", q["src"], q["dst"], q["query"]])
        return path
