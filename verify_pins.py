import sys
import base64

def check_pins(preset):
    try:
        sys.path.append('.')
        from sentinel_agent import SPKI_PINS
    except Exception as e:
        print(f"[ERROR] Failed to import SPKI_PINS from sentinel_agent: {e}")
        return 1

    if not isinstance(SPKI_PINS, dict) or not SPKI_PINS:
        print("[ERROR] SPKI_PINS must be a non-empty dictionary.")
        return 1

    has_errors = False
    
    # Critical hosts to validate per build preset
    preset_hosts = {
        "prod": ["zerowatch.deepcytes.io"],
        "demo": ["zerowatch-testing.eastasia.cloudapp.azure.com"]
    }
    
    critical_hosts = preset_hosts.get(preset.lower(), [])

    for hostname, pins in SPKI_PINS.items():
        is_critical = hostname in critical_hosts
        
        # If not critical and contains placeholders, skip validation
        has_placeholders = any("PLACEHOLDER" in str(pin) for pin in pins)
        if not is_critical and has_placeholders:
            print(f"[INFO] Skipping validation for host '{hostname}' (non-critical target containing placeholders).")
            continue
            
        if not isinstance(pins, list) or not pins:
            print(f"[ERROR] Host '{hostname}' must have a non-empty list of SPKI pins.")
            has_errors = True
            continue
            
        seen_pins = set()
        for idx, pin in enumerate(pins):
            # Check placeholders on critical host
            if "PLACEHOLDER" in pin:
                if is_critical:
                    print(f"[ERROR] Host '{hostname}' is critical for preset '{preset}' but contains placeholder pin: '{pin}'")
                    has_errors = True
                continue
                
            # Check duplicates
            if pin in seen_pins:
                print(f"[ERROR] Host '{hostname}' contains duplicate pin: '{pin}'")
                has_errors = True
                continue
            seen_pins.add(pin)
            
            # Check Base64 format and decoded length
            try:
                decoded = base64.b64decode(pin)
                if len(decoded) != 32:
                    print(f"[ERROR] Host '{hostname}' pin '{pin}' decodes to {len(decoded)} bytes (expected 32 bytes for SHA-256).")
                    has_errors = True
            except Exception as e:
                print(f"[ERROR] Host '{hostname}' pin '{pin}' is not valid base64: {e}")
                has_errors = True

    if has_errors:
        print("[FAIL] Pin validation failed.")
        return 1

    print(f"[SUCCESS] SPKI pins verified for preset '{preset}' (valid base64, correct length, no duplicates).")
    return 0

if __name__ == "__main__":
    preset = sys.argv[1] if len(sys.argv) > 1 else "dev"
    sys.exit(check_pins(preset))
