import json
import tempfile
import unittest
from pathlib import Path

from blackhex.parsers import (
    parse_httpx,
    parse_katana,
    parse_masscan,
    parse_massdns,
    parse_nmap,
    parse_nuclei,
    parse_sqlmap,
)
from blackhex.scope import Scope, host_from_target, normalize_target


class ParserTests(unittest.TestCase):
    def write(self, name, content):
        d = Path(tempfile.mkdtemp())
        p = d / name
        p.write_text(content, encoding="utf-8")
        return p

    def test_nmap_xml(self):
        p = self.write("nmap.xml", """<?xml version='1.0'?><nmaprun><host><address addr='192.0.2.10'/><hostnames><hostname name='app.example.test'/></hostnames><ports><port protocol='tcp' portid='443'><state state='open'/><service name='https' product='nginx' version='1.24'><cpe>cpe:/a:nginx:nginx:1.24</cpe></service><script id='vulners' output='CVE-X CVSS: 9.8'/></port></ports></host></nmaprun>""")
        f = parse_nmap(p)
        self.assertEqual(len(f), 2)
        self.assertEqual(f[0].kind, "service")
        self.assertEqual(f[1].severity, "critical")

    def test_jsonl_parsers(self):
        nuclei = self.write("nuclei.jsonl", json.dumps({"template-id":"test-cve","info":{"name":"Test CVE","severity":"high"},"matched-at":"https://a.example.test"})+"\n")
        self.assertEqual(parse_nuclei(nuclei)[0].severity, "high")

        httpx = self.write("httpx.jsonl", json.dumps({"url":"https://a.example.test","status_code":200,"title":"A","tech":["nginx"]})+"\n")
        hf, urls = parse_httpx(httpx)
        self.assertEqual(urls, ["https://a.example.test"])
        self.assertIn("status=200", hf[0].evidence)

        katana = self.write("katana.jsonl", json.dumps({"request":{"endpoint":"https://a.example.test/x?id=1"}})+"\n")
        _, urls = parse_katana(katana)
        self.assertEqual(urls, ["https://a.example.test/x?id=1"])

        massdns = self.write("massdns.jsonl", json.dumps({"name":"api.example.test.","data":{"answers":[{"data":"192.0.2.20"}]}})+"\n")
        self.assertEqual(parse_massdns(massdns)[0].target, "api.example.test")

    def test_masscan_json(self):
        p = self.write("masscan.json", json.dumps([{"ip":"192.0.2.10","ports":[{"port":443,"proto":"tcp","status":"open"}]}]))
        f = parse_masscan(p)
        self.assertEqual(f[0].target, "192.0.2.10")

    def test_sqlmap_detection(self):
        p = self.write("sqlmap.log", "sqlmap identified the following injection point\nParameter: id (GET)\nType: boolean-based blind\n")
        f = parse_sqlmap(p, "https://example.test/?id=1")
        self.assertEqual(f[0].severity, "high")


class ScopeTests(unittest.TestCase):
    def test_domain_scope(self):
        s = Scope("https://example.test")
        self.assertTrue(s.allows_url("https://api.example.test/x"))
        self.assertFalse(s.allows_url("https://example.test.evil.invalid/x"))

    def test_cidr_scope(self):
        s = Scope("192.0.2.0/24")
        self.assertTrue(s.allows_host("192.0.2.5"))
        self.assertFalse(s.allows_host("192.0.3.5"))

    def test_target_normalization(self):
        self.assertEqual(normalize_target("https://example.test/"), "https://example.test")
        self.assertEqual(host_from_target("https://example.test:8443/x"), "example.test")


if __name__ == "__main__":
    unittest.main()
