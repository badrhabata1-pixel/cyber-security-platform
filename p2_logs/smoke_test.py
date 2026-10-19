"""Run after installing requirements: verifies parsing, resilience, and summary truth."""
import os
import tempfile
from pathlib import Path

os.environ["AUTH_DISABLED"] = "true"
previous_directory = os.getcwd()
with tempfile.TemporaryDirectory() as directory:
    os.chdir(directory)
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    import database
    database.DB_PATH = Path(directory) / "test.sqlite3"
    import main
    main.initialise()
    payload = {"source": "ssh", "lines": [
        "Oct 15 14:32:10 srv sshd[812]: Failed password for admin from 203.0.113.5",
        "Oct 15 14:32:11 srv sshd[813]: Accepted password for alice from 198.51.100.8",
        "broken line",
    ]}
    result = main.ingest(main.IngestLines(**payload))
    assert result == {"accepted": 3, "created": 2, "unparsed": 1}, result
    stats = main.summary()
    assert stats["total_events"] == 2 and stats["failed_logins"] == 1, stats
    os.chdir(previous_directory)
print("smoke test: ok")
