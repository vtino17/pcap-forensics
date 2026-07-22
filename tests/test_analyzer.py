import json
import tempfile
import os
from pcap_forensics.analyzer import PcapAnalyzer


def test_empty_packets():
    analyzer = PcapAnalyzer()
    result = analyzer.analyze([])
    summary = analyzer.summary()
    assert summary["total_packets"] == 0
    assert summary["dns_queries"] == 0
    assert summary["http_requests"] == 0


def test_summary_structure():
    analyzer = PcapAnalyzer()
    analyzer.analyze([])
    s = analyzer.summary()
    assert "total_packets" in s
    assert "protocols" in s
    assert "dns_queries" in s
    assert "http_requests" in s
    assert "tls_handshakes" in s
    assert "beacon_candidates" in s


def test_json_report():
    analyzer = PcapAnalyzer()
    analyzer.analyze([])
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        path = f.name
    try:
        result = analyzer.report_json(path)
        assert result == path
        with open(path) as f:
            data = json.load(f)
        assert "summary" in data
        assert data["summary"]["total_packets"] == 0
    finally:
        os.unlink(path)


def test_csv_report():
    analyzer = PcapAnalyzer()
    analyzer.analyze([])
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as f:
        path = f.name
    try:
        result = analyzer.report_csv(path)
        assert result == path
        with open(path) as f:
            content = f.read()
        assert "type,source,destination,detail" in content
    finally:
        os.unlink(path)
