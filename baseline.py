import winreg
import json

KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"

def get_registry_values():
    values = {}

    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY_PATH)

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
        print("Error:", e)

    return values

baseline = get_registry_values()

with open("baseline.json", "w") as f:
    json.dump(baseline, f, indent=4)

print("Baseline saved successfully!")
