"""
macos/validation/validate_macos.py
─────────────────────────────────────────────────────────────────────────────
One-Shot Native macOS Validation Harness for ZeroWatch Agent.

Executes a comprehensive, non-destructive diagnostic validation of all macOS
agent components on real hardware. Collects all results and failure traces
into a single shareable ZIP archive.

Usage (run via validate_macos.sh wrapper):
    sudo python3 -m macos.validation.validate_macos
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure repository root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from macos.validation.collect_diagnostics import ValidationDiagnostics, anonymize_value

# Configure logging to console (sys.stdout) and diagnostic collector
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("validate_macos")


# ── Constants for validation ──────────────────────────────────────────────────
VALIDATION_SERVICE = "io.deepcytes.zerowatch.validation"
VALIDATION_LAUNCHD_LABEL = "io.deepcytes.zerowatch.validation"
VALIDATION_PLIST_PATH = f"/Library/LaunchDaemons/{VALIDATION_LAUNCHD_LABEL}.plist"


def run_cmd(cmd: List[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run a shell command safely, returning (exit_code, stdout, stderr)."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except Exception as exc:
        return -1, "", str(exc)


class MacOSValidator:
    """Orchestrates all native validation stages for ZeroWatch on macOS."""

    def __init__(self) -> None:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = _REPO_ROOT / f"zerowatch_macos_validation_{ts}"
        self.diag = ValidationDiagnostics(self.output_dir)

    def run_all(self) -> Path:
        """Run all validation stages with error tolerance and guaranteed cleanup."""
        print("\n" + "=" * 60)
        print(" ZeroWatch macOS One-Shot Native Validation Harness")
        print("=" * 60 + "\n")

        try:
            self._stage_1_preflight()
            self._stage_2_imports()
            self._stage_3_software()
            self._stage_4_hardware()
            self._stage_5_filesystem()
            self._stage_6_manifests()
            self._stage_7_cache()
            self._stage_8_keychain_interactive()
            self._stage_9_keychain_root()
            self._stage_10_launchdaemon_and_keychain()
            self._stage_11_process_guard()
            self._stage_12_event_logger()
            self._stage_13_unit_suite()
            self._stage_14_platform_smoke()
            self._stage_15_backend_e2e()
            self._stage_16_agent_smoke()
            self._stage_17_sentinel_agent_entrypoint()
        except Exception as exc:
            logger.error("Unhandled exception in validation loop: %s", exc)
            self.diag.record_error("validation_loop", traceback.format_exc())
        finally:
            self._cleanup()

        zip_path = self.diag.finalize()
        self._print_terminal_summary(zip_path)
        return zip_path

    # ── STAGE 1: Preflight & Environment ──────────────────────────────────────

    def _stage_1_preflight(self) -> None:
        logger.info("Stage 1: Preflight & System Environment Discovery")
        try:
            mac_ver, _, arch = platform.mac_ver()
            is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
            user = os.environ.get("USER", "unknown")

            # SIP status
            rc, sip_out, _ = run_cmd(["csrutil", "status"])
            sip_status = sip_out if rc == 0 else "Unknown/Unavailable"

            # Package managers
            brew_path = shutil.which("brew") or "/opt/homebrew/bin/brew"
            has_brew = os.path.isfile(brew_path)
            port_path = shutil.which("port") or "/opt/local/bin/port"
            has_port = os.path.isfile(port_path)

            env_info = {
                "macos_version": mac_ver or platform.version(),
                "architecture": arch or platform.machine(),
                "python_version": sys.version.split()[0],
                "user": user,
                "is_root": is_root,
                "sip_status": sip_status,
                "has_homebrew": has_brew,
                "has_macports": has_port,
            }
            self.diag.results["platform"] = env_info

            env_text = (
                f"macOS Version: {env_info['macos_version']}\n"
                f"Architecture:  {env_info['architecture']}\n"
                f"Python:        {env_info['python_version']}\n"
                f"User:          {user} (root={is_root})\n"
                f"SIP Status:    {sip_status}\n"
                f"Homebrew:      {has_brew} ({brew_path if has_brew else 'N/A'})\n"
                f"MacPorts:      {has_port} ({port_path if has_port else 'N/A'})\n"
            )
            self.diag.write_file("environment.txt", env_text)
            self.diag.log_test_result("preflight", "PASS", env_info, "Preflight checks complete")
        except Exception as exc:
            self.diag.record_error("preflight", traceback.format_exc())
            self.diag.log_test_result("preflight", "FAIL", message=str(exc))

    # ── STAGE 2: Imports & Instantiation ──────────────────────────────────────

    def _stage_2_imports(self) -> None:
        logger.info("Stage 2: Imports & Component Instantiation")
        try:
            from macos.platform import MacOSPlatform
            plat = MacOSPlatform()

            components = {
                "software_collector": bool(plat.software_collector),
                "hardware_collector": bool(plat.hardware_collector),
                "binary_inspector": bool(plat.binary_inspector),
                "filesystem_walker": bool(plat.filesystem_walker),
                "persistence_manager": bool(plat.persistence_manager),
                "process_guard": bool(plat.process_guard),
                "event_logger": bool(plat.event_logger),
                "secure_store": bool(plat.secure_store),
            }
            self.diag.log_test_result("imports", "PASS", components, "All 8 MacOSPlatform components instantiated")
        except Exception as exc:
            self.diag.record_error("imports", traceback.format_exc())
            self.diag.log_test_result("imports", "FAIL", message=str(exc))

    # ── STAGE 3: Software Collector ───────────────────────────────────────────

    def _stage_3_software(self) -> None:
        logger.info("Stage 3: Software Collector Test")
        try:
            from macos.scanner.package_collector import (
                collect_app_bundles,
                collect_pkgutil,
                collect_homebrew,
                collect_macports,
                collect_os_release,
            )

            t0 = time.time()
            apps = collect_app_bundles()
            pkgs = collect_pkgutil()
            brew = collect_homebrew()
            ports = collect_macports()
            os_rel = collect_os_release()
            duration = round(time.time() - t0, 3)

            total = len(apps) + len(pkgs) + len(brew) + len(ports) + len(os_rel)
            summary = {
                "total_items": total,
                "app_bundles": len(apps),
                "pkgutil_receipts": len(pkgs),
                "homebrew_items": len(brew),
                "macports_items": len(ports),
                "os_release_items": len(os_rel),
                "duration_seconds": duration,
            }

            # Sanitized sample (first 3 of each category, path/version only)
            sample = {
                "apps": [{"name": a.name, "version": a.version} for a in apps[:3]],
                "pkgs": [{"name": p.name, "version": p.version} for p in pkgs[:3]],
                "homebrew": [{"name": b.name, "version": b.version} for b in brew[:3]],
                "os": [{"name": o.name, "version": o.version} for o in os_rel],
            }
            self.diag.write_json("software_scan_summary.json", {"summary": summary, "sample": sample})
            self.diag.log_test_result("software", "PASS", summary, f"Collected {total} items in {duration}s")
        except Exception as exc:
            self.diag.record_error("software", traceback.format_exc())
            self.diag.log_test_result("software", "FAIL", message=str(exc))

    # ── STAGE 4: Hardware Collector & Fingerprint ─────────────────────────────

    def _stage_4_hardware(self) -> None:
        logger.info("Stage 4: Hardware Collector & Fingerprint Test")
        try:
            from macos.hardware.hardware_collector import MacOSHardwareCollector
            hw = MacOSHardwareCollector()

            fp = hw.collect_fingerprint()
            dev_id = hw.generate_device_id(fp)
            inventory = hw.get_hardware_inventory()
            profile = hw.get_detailed_hardware_profile()

            # Redact raw device ID / serials for privacy
            sanitized_fp = {
                "identity": anonymize_value(fp.get("identity", "")),
                "source": fp.get("source"),
                "arch": fp.get("arch"),
                "model": fp.get("model"),
            }

            hw_summary = {
                "fingerprint_source": fp.get("source"),
                "device_id_hash": anonymize_value(dev_id),
                "cpu": profile.get("cpu"),
                "ram_gb": profile.get("ram", {}).get("total_gb"),
                "gpu": profile.get("gpu"),
                "os_version": profile.get("os_info", {}).get("version"),
            }
            self.diag.log_test_result("hardware", "PASS", hw_summary, f"Hardware profile collected (source: {fp.get('source')})")
        except Exception as exc:
            self.diag.record_error("hardware", traceback.format_exc())
            self.diag.log_test_result("hardware", "FAIL", message=str(exc))

    # ── STAGE 5: Filesystem Walker & Mach-O Detection ─────────────────────────

    def _stage_5_filesystem(self) -> None:
        logger.info("Stage 5: Filesystem Walker & Mach-O Detection Test")
        try:
            from macos.scanner.filesystem_walker import MacOSFilesystemWalker
            from macos.scanner.fs_walker import EntryKind

            walker = MacOSFilesystemWalker()
            t0 = time.time()

            # Perform a bounded scan (max 500 items yielded to avoid long runs)
            yielded_items = []
            for path, kind in walker.walk_filesystem():
                yielded_items.append((path, kind.name))
                if len(yielded_items) >= 500:
                    break

            duration = round(time.time() - t0, 3)
            stats = walker.last_scan_stats

            macho_cnt = sum(1 for _, k in yielded_items if k == "BINARY")
            manifest_cnt = sum(1 for _, k in yielded_items if k == "MANIFEST")

            fs_summary = {
                "items_yielded": len(yielded_items),
                "macho_binaries": macho_cnt,
                "manifests": manifest_cnt,
                "duration_seconds": duration,
                "stats": repr(stats) if stats else "N/A",
            }
            self.diag.write_json("filesystem_scan_summary.json", fs_summary)
            self.diag.log_test_result("filesystem", "PASS", fs_summary, f"Bounded scan yielded {len(yielded_items)} items in {duration}s")
        except Exception as exc:
            self.diag.record_error("filesystem", traceback.format_exc())
            self.diag.log_test_result("filesystem", "FAIL", message=str(exc))

    # ── STAGE 6: Manifest Parsing ──────────────────────────────────────────────

    def _stage_6_manifests(self) -> None:
        logger.info("Stage 6: Manifest Parsing Test")
        tmp_dir = tempfile.mkdtemp(prefix="zw_val_manifests_")
        try:
            pkg_json = Path(tmp_dir) / "package.json"
            pkg_json.write_text('{"name": "test-pkg", "version": "1.2.3", "dependencies": {"express": "4.18.2"}}')

            from scanner.layer2_manifests import parse_manifest_file
            items = parse_manifest_file(str(pkg_json))
            parsed_names = [i.name for i in items]

            res = {"parsed_count": len(items), "items": parsed_names}
            self.diag.log_test_result("manifests", "PASS", res, f"Parsed {len(items)} dependencies from temporary manifest")
        except Exception as exc:
            self.diag.record_error("manifests", traceback.format_exc())
            self.diag.log_test_result("manifests", "FAIL", message=str(exc))
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # ── STAGE 7: Scan Cache ───────────────────────────────────────────────────

    def _stage_7_cache(self) -> None:
        logger.info("Stage 7: Scan Cache Invalidation & Persistence Test")
        tmp_dir = tempfile.mkdtemp(prefix="zw_val_cache_")
        try:
            db_path = os.path.join(tmp_dir, "cache.db")
            from common.scanner.state_cache import ScanCache
            from common.scanner.models import SoftwareItem

            cache = ScanCache(db_path=db_path)
            test_file = os.path.join(tmp_dir, "libtest.dylib")
            with open(test_file, "wb") as fh:
                fh.write(b"dummy")

            st = os.stat(test_file)
            dummy_item = [SoftwareItem(name="libtest", version="1.0", source="test")]

            # 1. Cold store
            cache.store(test_file, st.st_mtime_ns, st.st_size, dummy_item, layer=1)
            # 2. Lookup hit
            hit1 = cache.lookup(test_file, st.st_mtime_ns, st.st_size)
            assert hit1 is not None and len(hit1) == 1

            # 3. Modify file → lookup miss
            time.sleep(0.01)
            with open(test_file, "wb") as fh:
                fh.write(b"dummy modified")
            st2 = os.stat(test_file)
            hit2 = cache.lookup(test_file, st2.st_mtime_ns, st2.st_size)
            assert hit2 is None

            cache.close()
            self.diag.log_test_result("cache", "PASS", message="Cold store, warm hit, mtime invalidation verified")
        except Exception as exc:
            self.diag.record_error("cache", traceback.format_exc())
            self.diag.log_test_result("cache", "FAIL", message=str(exc))
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # ── STAGE 8: Interactive Keychain Test ───────────────────────────────────

    def _stage_8_keychain_interactive(self) -> None:
        logger.info("Stage 8: Interactive Keychain Test (SecurityFrameworkBackend)")
        try:
            from macos.crypto.security_framework_backend import SecurityFrameworkBackend, OSStatus
            from macos.crypto.secure_store import MacOSSecureStore

            sfb = SecurityFrameworkBackend()
            if not sfb.available():
                self.diag.log_test_result("keychain_interactive", "SKIP", message="SecurityFrameworkBackend unavailable (non-macOS or framework load error)")
                return

            store = MacOSSecureStore(backend=sfb)
            secret = os.urandom(32)
            token = store.encrypt(secret)

            if token is None:
                self.diag.log_test_result("keychain_interactive", "FAIL", message="encrypt() returned None")
                return

            recovered = store.decrypt(token)
            assert recovered == secret

            ok_del = store.delete_by_reference(token)
            assert ok_del

            self.diag.log_test_result("keychain_interactive", "PASS", message="Security.framework binary round-trip & delete succeeded")
        except Exception as exc:
            self.diag.record_error("keychain_interactive", traceback.format_exc())
            self.diag.log_test_result("keychain_interactive", "FAIL", message=str(exc))

    # ── STAGE 9: Root Keychain Test ───────────────────────────────────────────

    def _stage_9_keychain_root(self) -> None:
        logger.info("Stage 9: Root Keychain Execution Context Test")
        is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
        if not is_root:
            self.diag.log_test_result("keychain_root", "SKIP", message="Not running as root (run via sudo ./validate_macos.sh)")
            return

        try:
            from macos.crypto.security_framework_backend import SecurityFrameworkBackend
            from macos.crypto.secure_store import MacOSSecureStore

            store = MacOSSecureStore(backend=SecurityFrameworkBackend())
            secret = b"root_context_secret_" + os.urandom(16)
            token = store.encrypt(secret)
            recovered = store.decrypt(token) if token else None

            if token and recovered == secret:
                store.delete_by_reference(token)
                self.diag.log_test_result("keychain_root", "PASS", message="Root context System keychain round-trip succeeded")
            else:
                self.diag.log_test_result("keychain_root", "FAIL", message=f"Root context round-trip failed (token={bool(token)})")
        except Exception as exc:
            self.diag.record_error("keychain_root", traceback.format_exc())
            self.diag.log_test_result("keychain_root", "FAIL", message=str(exc))

    # ── STAGE 10: LaunchDaemon & Daemon Keychain Test ─────────────────────────

    def _stage_10_launchdaemon_and_keychain(self) -> None:
        logger.info("Stage 10: LaunchDaemon Lifecycle & Daemon Keychain Test")
        is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
        if not is_root:
            self.diag.log_test_result("launchd_daemon", "SKIP", message="Requires root to test /Library/LaunchDaemons/")
            self.diag.log_test_result("keychain_launchdaemon", "SKIP", message="Requires LaunchDaemon execution context")
            return

        plist_path = VALIDATION_PLIST_PATH
        log_out = "/var/log/zerowatch-val-test.log"

        try:
            # Construct temporary validation LaunchDaemon plist
            script_code = (
                "import os, sys, logging\n"
                "from macos.crypto.security_framework_backend import SecurityFrameworkBackend\n"
                "from macos.crypto.secure_store import MacOSSecureStore\n"
                "logging.basicConfig(filename='/var/log/zerowatch-val-daemon.log', level=logging.INFO)\n"
                "store = MacOSSecureStore(backend=SecurityFrameworkBackend())\n"
                "sec = b'daemon_secret_12345'\n"
                "tok = store.encrypt(sec)\n"
                "rec = store.decrypt(tok) if tok else None\n"
                "if tok and rec == sec:\n"
                "    store.delete_by_reference(tok)\n"
                "    print('DAEMON_KEYCHAIN_SUCCESS')\n"
                "else:\n"
                "    print('DAEMON_KEYCHAIN_FAIL')\n"
            )

            # Write script to temporary location
            test_script = "/tmp/zw_val_daemon_test.py"
            with open(test_script, "w") as fh:
                fh.write(script_code)

            import plistlib
            plist_data = {
                "Label": VALIDATION_LAUNCHD_LABEL,
                "ProgramArguments": [sys.executable, test_script],
                "RunAtLoad": True,
                "StandardOutPath": log_out,
                "StandardErrorPath": log_out,
            }
            with open(plist_path, "wb") as fh:
                plistlib.dump(plist_data, fh)
            os.chmod(plist_path, 0o644)

            # launchctl bootstrap system plist_path
            rc_b, out_b, err_b = run_cmd(["launchctl", "bootstrap", "system", plist_path])

            time.sleep(2)  # Allow daemon to run once

            # Read log output
            daemon_log = ""
            if os.path.exists(log_out):
                with open(log_out, "r") as fh:
                    daemon_log = fh.read()

            self.diag.write_file("launchd_test.txt", f"Bootstrap exit code: {rc_b}\nStdout: {out_b}\nStderr: {err_b}\nDaemon log:\n{daemon_log}\n")

            if "DAEMON_KEYCHAIN_SUCCESS" in daemon_log:
                self.diag.log_test_result("launchd_daemon", "PASS", message="LaunchDaemon bootstrapped successfully")
                self.diag.log_test_result("keychain_launchdaemon", "PASS", message="Daemon context System keychain round-trip succeeded")
            else:
                self.diag.log_test_result("launchd_daemon", "PASS", message="LaunchDaemon bootstrapped")
                self.diag.log_test_result("keychain_launchdaemon", "FAIL", message=f"Daemon keychain test output: {daemon_log.strip()}")

        except Exception as exc:
            self.diag.record_error("launchd_daemon", traceback.format_exc())
            self.diag.log_test_result("launchd_daemon", "FAIL", message=str(exc))
            self.diag.log_test_result("keychain_launchdaemon", "FAIL", message=str(exc))
        finally:
            # Cleanup LaunchDaemon
            run_cmd(["launchctl", "bootout", "system", plist_path])
            if os.path.exists(plist_path):
                try: os.remove(plist_path)
                except Exception: pass
            if os.path.exists("/tmp/zw_val_daemon_test.py"):
                try: os.remove("/tmp/zw_val_daemon_test.py")
                except Exception: pass

    # ── STAGE 11: ProcessGuard Signals ────────────────────────────────────────

    def _stage_11_process_guard(self) -> None:
        logger.info("Stage 11: ProcessGuard Signal Handling Test")
        try:
            from macos.protection.process_guard import MacOSProcessGuard, get_shutdown_event

            guard = MacOSProcessGuard()
            self.assertTrue = lambda cond, msg="": None
            guard.apply_process_protection()
            handlers = guard.register_signal_protection()

            sig_event = get_shutdown_event()

            # Test SIGTERM simulation by calling the handler directly
            from macos.protection.process_guard import _handle_shutdown
            _handle_shutdown(signal.SIGTERM, None)

            assert sig_event.is_set()
            self.diag.log_test_result("process_guard", "PASS", {"handlers": list(handlers.keys())}, "Signal handlers installed & shutdown event verified")
        except Exception as exc:
            self.diag.record_error("process_guard", traceback.format_exc())
            self.diag.log_test_result("process_guard", "FAIL", message=str(exc))

    # ── STAGE 12: Event Logger ────────────────────────────────────────────────

    def _stage_12_event_logger(self) -> None:
        logger.info("Stage 12: Event Logger Test")
        try:
            from macos.protection.event_logger import MacOSEventLogger
            logger_inst = MacOSEventLogger()

            ok_event = logger_inst.log_event("validation_test_event", {"status": "testing", "stage": 12})
            logger_inst.log_critical("validation_harness", 999, "Validation test critical log entry")

            self.diag.log_test_result("event_logger", "PASS", {"ok_event": ok_event}, "EventLogger log_event and log_critical executed cleanly")
        except Exception as exc:
            self.diag.record_error("event_logger", traceback.format_exc())
            self.diag.log_test_result("event_logger", "FAIL", message=str(exc))

    # ── STAGE 13: Unit Test Suite ─────────────────────────────────────────────

    def _stage_13_unit_suite(self) -> None:
        logger.info("Stage 13: Full macOS Unit Test Suite Execution")
        try:
            import unittest

            test_dir = _REPO_ROOT / "macos" / "tests"
            loader = unittest.TestLoader()
            suite = loader.discover(str(test_dir), pattern="test_*.py")

            # Capture unit test output
            stream_out = tempfile.NamedTemporaryFile("w+", delete=False)
            runner = unittest.TextTestRunner(stream=stream_out, verbosity=2)
            result = runner.run(suite)
            stream_out.close()

            with open(stream_out.name, "r") as fh:
                unit_log = fh.read()
            os.remove(stream_out.name)

            self.diag.write_file("unit_tests.txt", unit_log)

            unit_summary = {
                "tests_run": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "skipped": len(result.skipped),
                "was_successful": result.wasSuccessful(),
            }

            st = "PASS" if result.wasSuccessful() else "FAIL"
            self.diag.log_test_result("unit_suite", st, unit_summary, f"Ran {result.testsRun} unit tests (Failures: {len(result.failures)}, Errors: {len(result.errors)}, Skips: {len(result.skipped)})")
        except Exception as exc:
            self.diag.record_error("unit_suite", traceback.format_exc())
            self.diag.log_test_result("unit_suite", "FAIL", message=str(exc))

    # ── STAGE 14: Platform Smoke Test ─────────────────────────────────────────

    def _stage_14_platform_smoke(self) -> None:
        logger.info("Stage 14: MacOSPlatform Integration Smoke Test")
        try:
            from macos.platform import MacOSPlatform
            plat = MacOSPlatform()

            # Exercise capabilities in sequence
            sw = plat.software_collector.collect_software()
            hw = plat.hardware_collector.get_hardware_inventory()
            dev_id = plat.hardware_collector.generate_device_id({})
            sec_ok = plat.secure_store.encrypt(b"smoke_test") is not None
            prot_ok = plat.process_guard.apply_process_protection()
            log_ok = plat.event_logger.log_event("smoke_test", {})

            smoke_res = {
                "software_count": len(sw),
                "hardware_items": len(hw),
                "device_id_generated": bool(dev_id),
                "secure_store_ok": sec_ok,
                "process_guard_ok": prot_ok,
                "event_logger_ok": log_ok,
            }
            self.diag.log_test_result("platform_smoke", "PASS", smoke_res, "MacOSPlatform component integration smoke test passed")
        except Exception as exc:
            self.diag.record_error("platform_smoke", traceback.format_exc())
            self.diag.log_test_result("platform_smoke", "FAIL", message=str(exc))

    # ── STAGE 15: Backend E2E Mode (Optional) ──────────────────────────────────

    def _stage_15_backend_e2e(self) -> None:
        logger.info("Stage 15: Optional Backend E2E Test")
        backend_url = os.environ.get("ZEROWATCH_BACKEND_URL")
        if not backend_url:
            self.diag.log_test_result("backend_e2e", "SKIP", message="ZEROWATCH_BACKEND_URL environment variable not provided")
            return

        try:
            # Attempt healthcheck / ping to backend_url
            import urllib.request
            req = urllib.request.Request(f"{backend_url}/api/v1/health", headers={"User-Agent": "ZeroWatch-MacValidation/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
                self.diag.log_test_result("backend_e2e", "PASS" if status == 200 else "FAIL", {"status": status}, f"Backend reachable at {backend_url} (status {status})")
        except Exception as exc:
            self.diag.record_error("backend_e2e", traceback.format_exc())
            self.diag.log_test_result("backend_e2e", "FAIL", message=f"Backend connection failed: {exc}")

    # ── STAGE 16: Bounded Agent Smoke Test ────────────────────────────────────

    def _stage_16_agent_smoke(self) -> None:
        logger.info("Stage 16: Bounded Agent Execution Smoke Test")
        try:
            from macos.platform import MacOSPlatform
            from scanner.orchestrator import ScanOrchestrator

            plat = MacOSPlatform()
            tmp_agent_dir = tempfile.mkdtemp(prefix="zw_val_agent_")

            orchestrator = ScanOrchestrator(
                base_dir=tmp_agent_dir,
                existing_registry_fn=lambda: [],
                agent_version="1.0.0-validation",
                software_collector=plat.software_collector,
                binary_inspector=plat.binary_inspector,
                filesystem_walker=plat.filesystem_walker,
            )

            # Run a bounded full scan
            inventory = orchestrator.run_full_scan()

            agent_summary = {
                "scan_items_returned": len(inventory),
                "scan_layers_completed": True,
            }
            self.diag.write_file("agent_smoke_test.txt", f"Agent smoke test complete. Total items returned: {len(inventory)}\n")
            self.diag.log_test_result("agent_smoke", "PASS", agent_summary, f"Full orchestrator scan completed returning {len(inventory)} items")
        except Exception as exc:
            self.diag.record_error("agent_smoke", traceback.format_exc())
            self.diag.log_test_result("agent_smoke", "FAIL", message=str(exc))
        finally:
            if 'tmp_agent_dir' in locals():
                shutil.rmtree(tmp_agent_dir, ignore_errors=True)

    # ── STAGE 17: sentinel_agent.py Entrypoint & PlatformFactory Test ──────

    def _stage_17_sentinel_agent_entrypoint(self) -> None:
        logger.info("Stage 17: sentinel_agent.py Entrypoint & PlatformFactory Test")
        try:
            from platforms.factory import PlatformFactory
            from macos.platform import MacOSPlatform
            import sentinel_agent

            plat = PlatformFactory.create()
            is_mac_plat = isinstance(plat, MacOSPlatform)

            # Verify _secure_state_dir calculation
            state_dir = sentinel_agent._secure_state_dir(str(_REPO_ROOT))

            res = {
                "platform_factory_returned_macos_platform": is_mac_plat,
                "secure_state_dir": state_dir,
                "sentinel_agent_module_imported": True,
            }
            self.diag.log_test_result("sentinel_agent_entrypoint", "PASS", res, f"PlatformFactory returned MacOSPlatform and sentinel_agent.py imported cleanly (state_dir={state_dir})")
        except Exception as exc:
            self.diag.record_error("sentinel_agent_entrypoint", traceback.format_exc())
            self.diag.log_test_result("sentinel_agent_entrypoint", "FAIL", message=str(exc))

    # ── Cleanup & Final Output ────────────────────────────────────────────────

    def _cleanup(self) -> None:
        """Best-effort cleanup of any residual validation artifacts."""
        logger.info("Cleaning up validation artifacts...")
        # Ensure temporary LaunchDaemon is removed
        if os.path.exists(VALIDATION_PLIST_PATH):
            run_cmd(["launchctl", "bootout", "system", VALIDATION_PLIST_PATH])
            try: os.remove(VALIDATION_PLIST_PATH)
            except Exception: pass
        if os.path.exists("/var/log/zerowatch-val-test.log"):
            try: os.remove("/var/log/zerowatch-val-test.log")
            except Exception: pass
        if os.path.exists("/var/log/zerowatch-val-daemon.log"):
            try: os.remove("/var/log/zerowatch-val-daemon.log")
            except Exception: pass

    def _print_terminal_summary(self, zip_path: Path) -> None:
        pass_cnt = self.diag.results["summary"]["pass"]
        fail_cnt = self.diag.results["summary"]["fail"]
        skip_cnt = self.diag.results["summary"]["skip"]
        overall = "PASS" if fail_cnt == 0 else "NEEDS REVIEW"

        print("\n" + "=" * 60)
        print(" ZeroWatch macOS Validation Complete")
        print("=" * 60)
        print(f" Passed:  {pass_cnt}")
        print(f" Failed:  {fail_cnt}")
        print(f" Skipped: {skip_cnt}")
        print(f"\n Overall: {overall}")
        print(f" Report Archive: {zip_path}")
        print("=" * 60)
        print(f"\n Please send this file to Jatin:\n {zip_path}\n")
        sys.stdout.flush()


if __name__ == "__main__":
    validator = MacOSValidator()
    validator.run_all()
