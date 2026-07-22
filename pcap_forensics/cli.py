import argparse
import sys
from pathlib import Path


def build_parser():
    parser = argparse.ArgumentParser(
        description="PCAP Forensic Analysis Tool for Incident Responders",
    )
    parser.add_argument("pcap", help="Path to PCAP or PCAPNG file")
    parser.add_argument("--report", "-r", choices=["json", "csv"], default="json",
                        help="Output format")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print analysis summary to stdout")
    return parser


def validate_pcap(path):
    p = Path(path)
    if not p.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)
    if p.suffix.lower() not in (".pcap", ".pcapng", ".cap"):
        print(f"Warning: unrecognized extension: {p.suffix}", file=sys.stderr)
    return str(p)


def run(args):
    from scapy.utils import rdpcap
    from pcap_forensics.analyzer import PcapAnalyzer

    path = validate_pcap(args.pcap)
    print(f"Reading {path}...", file=sys.stderr)

    try:
        packets = rdpcap(path)
    except Exception as e:
        print(f"Error reading pcap: {e}", file=sys.stderr)
        sys.exit(1)

    analyzer = PcapAnalyzer()
    analyzer.analyze(packets)

    summary = analyzer.summary()
    if args.verbose:
        print(f"Packets: {summary['total_packets']}", file=sys.stderr)
        print(f"DNS Queries: {summary['dns_queries']}", file=sys.stderr)
        print(f"HTTP Requests: {summary['http_requests']}", file=sys.stderr)
        print(f"TLS Handshakes: {summary['tls_handshakes']}", file=sys.stderr)
        print(f"Beacon Candidates: {summary['beacon_candidates']}", file=sys.stderr)

    if args.output:
        if args.report == "json":
            path = analyzer.report_json(args.output)
        else:
            path = analyzer.report_csv(args.output)
        print(f"Report saved: {path}", file=sys.stderr)
    else:
        default = f"report_{Path(args.pcap).stem}.{args.report}"
        if args.report == "json":
            path = analyzer.report_json(default)
        else:
            path = analyzer.report_csv(default)
        print(f"Report saved: {path}", file=sys.stderr)
