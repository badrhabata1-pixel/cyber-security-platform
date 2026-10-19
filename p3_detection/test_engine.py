import json
import os
import sys

# التأكد من مسار المجلد
sys.path.insert(0, os.path.abspath("."))

from p3_detection.engine import DetectionEngine

with open("p3_detection/mock_events.json") as f:
    events = json.load(f)

engine = DetectionEngine()
alerts = engine.analyze(events)

print(f"\n🚨 Detected {len(alerts)} alerts successfully!\n")
for a in alerts:
    print(f" - [{a['severity'].upper()}] {a['rule']} from {a['ip']}: {a['description']}")
