import winreg
import json
import time
from datetime import datetime

KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"

added_count = 0
deleted_count = 0
modified_count = 0
malware_count = 0


def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"[{timestamp}] {message}")

    with open("registry_log.txt", "a") as log:
        log.write(f"[{timestamp}] {message}\n")


def get_registry_values():

    values = {}

    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            KEY_PATH
        )

        i = 0

        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                values[name] = value
                i += 1

            except OSError:
                break

        winreg.CloseKey(key)

    except Exception as e:
        log_event(f"Registry Error: {e}")

    return values


def check_malware_patterns(path):

    suspicious_patterns = [
        "appdata",
        "temp",
        "powershell",
        ".bat",
        ".vbs",
        ".js",
        ".ps1"
    ]

    path = path.lower()

    for pattern in suspicious_patterns:
        if pattern in path:
            return True

    return False


with open("baseline.json", "r") as f:
    baseline = json.load(f)

log_event("Registry Monitoring Started")

while True:

    current = get_registry_values()

    # Added Entries
    for name, value in current.items():

        if name not in baseline:

            added_count += 1

            log_event(
                f"NEW AUTORUN ENTRY DETECTED: {value}"
            )

            if check_malware_patterns(value):

                malware_count += 1

                log_event(
                    f"MALWARE ALERT: Suspicious autorun entry -> {value}"
                )

    # Deleted Entries
    for name in baseline:

        if name not in current:

            deleted_count += 1

            log_event(
                f"ENTRY DELETED: {name}"
            )

    # Modified Entries
    for name in current:

        if name in baseline:

            if current[name] != baseline[name]:

                modified_count += 1

                log_event(
                    f"INTEGRITY FAILURE: Value mismatch from baseline"
                )

                log_event(
                    f"Registry key altered -> {name}"
                )

                log_event(
                    f"Baseline Value: {baseline[name]}"
                )

                log_event(
                    f"Current Value : {current[name]}"
                )

                if "defender" in name.lower():

                    log_event(
                        "Registry key altered: Windows Defender disabled"
                    )

    # Create Summary Report
    with open("summary_report.txt", "w") as report:

        report.write(
            "===== WINDOWS REGISTRY CHANGE MONITORING REPORT =====\n\n"
        )

        report.write(
            f"Added Entries: {added_count}\n"
        )

        report.write(
            f"Deleted Entries: {deleted_count}\n"
        )

        report.write(
            f"Modified Entries: {modified_count}\n"
        )

        report.write(
            f"Malware Alerts: {malware_count}\n\n"
        )

        report.write(
            "Integrity Check Results\n"
        )

        if modified_count == 0:
            report.write("PASS\n")
        else:
            report.write("FAILED\n")

    time.sleep(10)
