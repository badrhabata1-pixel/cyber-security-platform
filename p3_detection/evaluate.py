import json
import time
import os
import sys

sys.path.insert(0, os.path.abspath("."))

from p3_detection.engine import DetectionEngine

def run_evaluation():
    engine = DetectionEngine()
    
    # 1. قراءة الحقيقة والأحداث
    with open("p3_detection/truth.json") as f:
        ground_truth = json.load(f)["attacks"]

    with open("p3_detection/mock_events.json") as f:
        events = json.load(f)

    # 2. قياس زمن التحليل (Latency)
    start_time = time.time()
    alerts = engine.analyze(events)
    elapsed_ms = (time.time() - start_time) * 1000

    # 3. حساب Recall
    expected_rules = {a["rule"]: a["target_ip"] for a in ground_truth}
    detected_rules = {(a["rule"], a["ip"]) for a in alerts}

    hits = 0
    for r, ip in expected_rules.items():
        if (r, ip) in detected_rules:
            hits += 1

    recall = (hits / len(ground_truth)) * 100 if ground_truth else 0

    # 4. حساب False Positives (الترافيك الطبيعي IP 192.168.1.100 لا يجوز أن يطلق تنبيهاً)
    normal_ip = "192.168.1.100"
    false_positives = [a for a in alerts if a["ip"] == normal_ip]

    print("\n" + "="*45)
    print("📊 SECURITY DETECTION EVALUATION REPORT")
    print("="*45)
    print(f"Total Attacks in Ground Truth : {len(ground_truth)}")
    print(f"Successfully Detected (Hits)  : {hits}")
    print(f"Recall (Detection Rate)       : {recall:.1f}%")
    print(f"False Positives               : {len(false_positives)}")
    print(f"Processing Latency            : {elapsed_ms:.2f} ms")
    print("="*45)

    if recall == 100.0 and len(false_positives) == 0:
        print("🏆 PERFECT SCORE! All requirements fully met.")
    print("="*45 + "\n")

if __name__ == "__main__":
    run_evaluation()
