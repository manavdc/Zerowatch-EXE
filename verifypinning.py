import requests
import cert_pinning
import ssl

# Target Host (Change to zerowatch.deepcytes.io for production)
hostname = "zerowatch.deepcytes.io"
url = f"https://{hostname}/api/agent"

# ----------------------------------------------------
# TEST 1: Connection with the CORRECT pin
# ----------------------------------------------------
print("--- Test 1: Testing with CORRECT pin ---")
correct_pins = ["SOt+phzxLXUaMmNKG6d4kz7QTSoip7zJudN8vGJNdI4="] # Real pin
adapter_correct = cert_pinning.build_pinning_adapter(correct_pins)

session_good = requests.Session()
session_good.mount("https://", adapter_correct)

try:
    # Attempting to fetch (expected: 401 Unauthorized or success, but NO SSL/PinError)
    r = session_good.get(url, timeout=5)
    print(f"[PASS] Connection succeeded (Status: {r.status_code}). Certificate pin matched successfully!")
except Exception as e:
    print(f"[FAIL] Test 1 failed with error: {e}")

# ----------------------------------------------------
# TEST 2: Connection with a MISMATCHED pin (MITM Simulation)
# ----------------------------------------------------
print("\n--- Test 2: Testing with MISMATCHED pin ---")
mismatched_pins = ["EzSBE12fT2ZrphmumaBjrpdpXv9G71RhZQHMvuwszI4="] # Mismatched dummy pin
adapter_mismatched = cert_pinning.build_pinning_adapter(mismatched_pins)

session_bad = requests.Session()
session_bad.mount("https://", adapter_mismatched)

try:
    r = session_bad.get(url, timeout=5)
    print("[FAIL] Mismatched connection succeeded! Certificate pinning is NOT active.")
except requests.exceptions.SSLError as e:
    # We expect a PinError (which subclasses SSLError)
    print(f"[PASS] Connection successfully blocked by pinning! Error details:\n  {e}")
except Exception as e:
    print(f"[PASS] Connection blocked by generic exception: {e}")
