"""
AI-Driven NGFW - Automated Test Suite
Run: python test_ngfw.py
Tests live API at https://ai-ngfw.onrender.com
"""

import requests
import time
import sys
import os
from datetime import datetime

API_BASE = "https://ai-ngfw.onrender.com"
API_KEY = os.environ.get("NGFW_API_KEY", "ngfw-secret-2026")
HEADERS = {"Content-Type": "application/json", "X-API-Key": API_KEY}
results = []

def test(name, passed, expected="", actual=""):
    status = "PASS" if passed else "FAIL"
    print("  [{}] {}".format(status, name))
    if not passed and (expected or actual):
        print("       Expected : {}".format(expected))
        print("       Got      : {}".format(actual))
    results.append({"name": name, "passed": passed})

def section(title):
    print("")
    print("=" * 55)
    print("  " + title)
    print("=" * 55)

def post_analyze(payload):
    r = requests.post(API_BASE + "/analyze", json=payload, headers=HEADERS, timeout=15)
    return r.status_code, r.json()

section("1. Health & Model Status")
try:
    r = requests.get(API_BASE + "/health", headers=HEADERS, timeout=10)
    data = r.json()
    test("API is online", r.status_code == 200, "200", str(r.status_code))
    test("Status is ok", data.get("status") == "ok", "ok", str(data.get("status")))
    test("Random Forest model loaded", data.get("models_loaded", {}).get("random_forest") == True)
    test("Autoencoder model loaded", data.get("models_loaded", {}).get("autoencoder") == True)
except Exception as e:
    test("API reachable", False, "Connection OK", str(e))
    sys.exit(1)

section("2. Flow Analysis - Zero Trust Presets")

presets = [
    {"name": "Normal Traffic", "payload": {"src_ip":"192.168.1.10","dst_ip":"8.8.8.8","src_port":54321,"dst_port":443,"protocol":"TCP","packet_count":80,"byte_volume":12000,"duration":5.0,"fwd_bwd_ratio":1.2}, "expected_action": "allow", "expected_threat": "Benign", "risk_min": 0.0, "risk_max": 0.25},
    {"name": "DDoS Attack", "payload": {"src_ip":"10.0.0.1","dst_ip":"192.168.1.1","src_port":12345,"dst_port":80,"protocol":"TCP","packet_count":50000,"byte_volume":5000000,"duration":2.0,"fwd_bwd_ratio":10.0}, "expected_action": "block", "expected_threat": "DoS", "risk_min": 0.70, "risk_max": 1.0},
    {"name": "Suspicious DB Access", "payload": {"src_ip":"192.168.1.50","dst_ip":"10.0.0.100","src_port":33333,"dst_port":3306,"protocol":"TCP","packet_count":200,"byte_volume":5000,"duration":3.0,"fwd_bwd_ratio":1.5}, "expected_action": "adaptive_auth", "expected_threat": "Probe", "risk_min": 0.25, "risk_max": 0.50},
    {"name": "SSH Brute Force", "payload": {"src_ip":"203.0.113.1","dst_ip":"192.168.1.10","src_port":49152,"dst_port":22,"protocol":"TCP","packet_count":1500,"byte_volume":37500,"duration":8.0,"fwd_bwd_ratio":1.5}, "expected_action": "restrict", "expected_threat": "Brute Force", "risk_min": 0.50, "risk_max": 0.70},
]

actions_seen = set()
for p in presets:
    print("\n  >> " + p["name"])
    try:
        code, data = post_analyze(p["payload"])
        test("  API returns 200", code == 200, "200", str(code))
        test("  Correct threat: " + p["expected_threat"], data.get("threat_class") == p["expected_threat"], p["expected_threat"], str(data.get("threat_class")))
        test("  Correct action: " + p["expected_action"], data.get("action") == p["expected_action"], p["expected_action"], str(data.get("action")))
        risk = data.get("risk_score", 0)
        test("  Risk {:.0%}-{:.0%} (got {:.1%})".format(p["risk_min"], p["risk_max"], risk), p["risk_min"] <= risk <= p["risk_max"])
        test("  Explanation present", bool(data.get("explanation")))
        test("  Latency present", data.get("policy_latency_ms") is not None)
        actions_seen.add(data.get("action"))
        time.sleep(0.5)
    except Exception as e:
        test("  Request failed", False, "OK", str(e))

section("3. Zero Trust - All 4 Actions")
for action in ["allow", "adaptive_auth", "restrict", "block"]:
    test("Action '{}' observed".format(action), action in actions_seen)

section("4. Input Validation")
try:
    r = requests.post(API_BASE + "/analyze", json={"src_ip":"1.2.3.4","dst_ip":"5.6.7.8","src_port":80,"dst_port":80,"protocol":"TCP","packet_count":0,"byte_volume":1000,"duration":0,"fwd_bwd_ratio":1.0}, headers=HEADERS, timeout=15)
    test("Rejects zero packet_count/duration", r.status_code == 400, "400", str(r.status_code))
except Exception as e:
    test("Validation test", False, "OK", str(e))

section("5. Alerts & Statistics")
try:
    r = requests.get(API_BASE + "/alerts", headers=HEADERS, timeout=10)
    data = r.json()
    test("Alerts endpoint 200", r.status_code == 200)
    test("Has alerts key", "alerts" in data)
    test("Has count key", "count" in data)
except Exception as e:
    test("Alerts endpoint", False, "OK", str(e))

try:
    r = requests.get(API_BASE + "/stats", headers=HEADERS, timeout=10)
    data = r.json()
    test("Stats endpoint 200", r.status_code == 200)
    test("Has total_alerts", "total_alerts" in data)
    test("Has high_risk_count", "high_risk_count" in data)
except Exception as e:
    test("Stats endpoint", False, "OK", str(e))

section("6. Model Metrics")
try:
    r = requests.get(API_BASE + "/model/metrics", headers=HEADERS, timeout=10)
    data = r.json()
    test("Metrics endpoint 200", r.status_code == 200)
    acc = data.get("accuracy", 0)
    test("Accuracy >= 90% (got {:.1%})".format(acc), acc >= 0.90)
    prec = data.get("precision", 0)
    test("Precision >= 90% (got {:.1%})".format(prec), prec >= 0.90)
except Exception as e:
    test("Metrics endpoint", False, "OK", str(e))

section("7. Zero Trust Policy")
try:
    r = requests.get(API_BASE + "/policy", headers=HEADERS, timeout=10)
    data = r.json()
    test("Policy GET 200", r.status_code == 200)
    test("Has low_threshold", "low_threshold" in data)
    test("Has medium_threshold", "medium_threshold" in data)
    test("Has high_threshold", "high_threshold" in data)
except Exception as e:
    test("Policy endpoint", False, "OK", str(e))

section("8. Performance")
times = []
for i in range(3):
    try:
        start = time.time()
        post_analyze({"src_ip":"1.2.3.4","dst_ip":"5.6.7.8","src_port":1234,"dst_port":80,"protocol":"TCP","packet_count":100,"byte_volume":5000,"duration":2.0,"fwd_bwd_ratio":1.0})
        times.append((time.time() - start) * 1000)
        time.sleep(0.3)
    except:
        pass
if times:
    avg = sum(times) / len(times)
    test("Avg response < 3000ms (got {:.0f}ms)".format(avg), avg < 3000)

section("FINAL REPORT")
total  = len(results)
passed = sum(1 for r in results if r["passed"])
score  = (passed / total * 100) if total else 0
print("")
print("  Total Tests  : {}".format(total))
print("  Passed       : {}".format(passed))
print("  Failed       : {}".format(total - passed))
print("  Score        : {:.1f}%".format(score))
print("  Timestamp    : {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
print("")
if total - passed == 0:
    print("  ALL TESTS PASSED!")
elif score >= 80:
    print("  System mostly working.")
else:
    print("  Check failures above.")
print("")
