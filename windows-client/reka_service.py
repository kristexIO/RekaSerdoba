import argparse
import json
import logging
import os
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path

from client_core import CarrierScores, ManifestState, RekaSession, load_manifest
from network_policy import NetworkPolicy
from secret_store import import_bundle, load_bundle
from version import VERSION
from wintun_adapter import WintunAdapter

try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
except ImportError:
    servicemanager = None
    win32event = None
    win32service = None
    win32serviceutil = None


SERVICE_NAME = "RekaSerdoba"
DISPLAY_NAME = "RekaSerdoba Secure Tunnel"
ROOT = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "RekaSerdoba"
BUNDLE = ROOT / "device.dpapi"
MANIFEST_STATE = ROOT / "manifest-state.json"
SCORES = ROOT / "carrier-scores.json"
POLICY_STATE = ROOT / "network-policy.json"
LOG_PATH = ROOT / "service.log"
SETTINGS = ROOT / "settings.json"
STATUS = ROOT / "status.json"


def write_status(state, carrier=None, reason=None, endpoint=None, traffic=None):
    ROOT.mkdir(parents=True, exist_ok=True)
    value = {
        "version": VERSION,
        "state": state,
        "updated_at": int(time.time()),
    }
    if carrier:
        value["carrier"] = carrier
    if reason:
        value["reason"] = reason
    if endpoint:
        value["endpoint"] = endpoint
    if traffic:
        value["traffic"] = traffic
    temporary = STATUS.with_suffix(".new")
    temporary.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
    os.replace(temporary, STATUS)


def read_status():
    try:
        return json.loads(STATUS.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {"version": VERSION, "state": "unknown"}


def redact_log(value):
    redacted = []
    for line in value.splitlines():
        lowered = line.lower()
        if any(
            marker in lowered
            for marker in (
                "gate_key",
                "signing_seed",
                "authorization",
                "bearer ",
                "device.dpapi",
            )
        ):
            redacted.append("[redacted]")
        else:
            redacted.append(line[-2000:])
    return "\n".join(redacted[-2000:]) + "\n"


def create_diagnostics(output):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    service = subprocess.run(
        ["sc.exe", "query", SERVICE_NAME],
        check=False,
        capture_output=True,
        text=True,
    ) if os.name == "nt" else None
    report = {
        "version": VERSION,
        "platform": sys.platform,
        "python": sys.version,
        "status": read_status(),
        "service": service.stdout[-8000:] if service else "not-windows",
    }
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report.json", json.dumps(report, indent=2, sort_keys=True))
        for path in (SCORES, SETTINGS):
            try:
                archive.writestr(path.name, path.read_text(encoding="utf-8")[-65536:])
            except OSError:
                pass
        try:
            archive.writestr(
                "service.log",
                redact_log(LOG_PATH.read_text(encoding="utf-8", errors="replace")),
            )
        except OSError:
            pass
    return output


def transport_mode(path=SETTINGS):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        mode = str(value.get("transport", "auto")).lower()
    except (OSError, ValueError, TypeError):
        mode = "auto"
    return mode if mode in {"auto", "h3", "h2", "wss"} else "auto"


def select_transport_choices(choices, mode):
    if mode == "auto":
        return list(choices)
    selected = [choice for choice in choices if choice.name == mode]
    if not selected:
        raise ValueError(f"transport is unavailable: {mode}")
    return selected


def configure_logging():
    ROOT.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=LOG_PATH,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )


class TunnelRuntime:
    def __init__(self, stop_event, use_tun=True):
        self.stop_event = stop_event
        self.use_tun = use_tun
        self.adapter = None
        self.policy = None
        self.session = None
        self.runtime_bundle = None
        self.carrier_name = None

    def run(self):
        configure_logging()
        write_status("starting")
        bundle = load_bundle(BUNDLE)
        state = ManifestState(MANIFEST_STATE)
        scores = CarrierScores(SCORES)
        host, port, addresses, server_public, choices = load_manifest(bundle, state)
        mode = transport_mode()
        choices = select_transport_choices(choices, mode)
        logging.info("transport mode=%s", mode)
        if not addresses:
            raise ValueError("manifest has no endpoint addresses")
        self.runtime_bundle = self._materialize_bundle(bundle)
        try:
            if self.use_tun:
                dll = Path(sys.executable).resolve().parent / "wintun.dll"
                if not dll.exists():
                    dll = Path(__file__).resolve().parent / "wintun.dll"
                self.adapter = WintunAdapter(dll)
                address, prefix = bundle["tunnel_ipv4"].split("/", 1)
                self.adapter.configure(address, int(prefix), 1280)
                bridge = Path(sys.executable).resolve().parent / "h3_bridge.exe"
                self.policy = NetworkPolicy(
                    POLICY_STATE,
                    sys.executable,
                    self.adapter.name,
                    [bridge] if bridge.exists() else [],
                )
                self.policy.recover()
            while not self.stop_event.is_set():
                attempted = False
                for endpoint_ip, choice in scores.order_candidates(addresses, choices):
                    if self.stop_event.is_set():
                        break
                    if scores.wait_seconds(
                        choice.name, endpoint=endpoint_ip
                    ) > 0:
                        continue
                    attempted = True
                    try:
                        write_status(
                            "connecting", choice.name, endpoint=endpoint_ip
                        )
                        if self.policy:
                            self.policy.prepare(endpoint_ip)
                            logging.info(
                                "endpoint route prepared address=%s", endpoint_ip
                            )
                        bridge = Path(sys.executable).resolve().parent / "h3_bridge.exe"
                        if not bridge.exists():
                            bridge = Path(__file__).resolve().parent / "h3_bridge.exe"
                        self.session = RekaSession.connect(
                            self.runtime_bundle,
                            choice,
                            host,
                            port,
                            endpoint_ip,
                            server_public,
                            bridge if bridge.exists() else None,
                        )
                        scores.success(choice.name, endpoint_ip)
                        self.carrier_name = choice.name
                        write_status(
                            "connected", choice.name, endpoint=endpoint_ip
                        )
                        logging.info(
                            "carrier connected name=%s address=%s",
                            choice.name,
                            endpoint_ip,
                        )
                        self._pump(endpoint_ip)
                    except Exception as error:
                        scores.failure(choice.name, endpoint_ip)
                        write_status(
                            "reconnecting",
                            choice.name,
                            type(error).__name__,
                            endpoint_ip,
                        )
                        logging.warning(
                            "carrier failed name=%s address=%s reason=%r",
                            choice.name,
                            endpoint_ip,
                            error,
                        )
                    finally:
                        if self.policy:
                            try:
                                self.policy.recover()
                            except Exception:
                                logging.exception("network policy recovery failed")
                        if self.session:
                            self.session.close()
                            self.session = None
                        self.carrier_name = None
                if not self.stop_event.is_set():
                    delay = (
                        2
                        if attempted
                        else scores.next_retry_seconds(
                            choices, endpoints=addresses
                        )
                    )
                    self.stop_event.wait(min(max(delay, 1), 30))
        finally:
            write_status("stopped")
            if self.session:
                self.session.close()
            if self.adapter:
                self.adapter.close()
            if self.policy:
                try:
                    self.policy.recover()
                except Exception:
                    logging.exception("final network policy recovery failed")
            if self.runtime_bundle:
                self.runtime_bundle.unlink(missing_ok=True)

    def _pump(self, endpoint_ip=None):
        if not self.use_tun:
            self.session.send_keepalive()
            self.session.receive()
            return
        work = queue.Queue(maxsize=4096)
        failure = queue.Queue(maxsize=1)
        pump_stop = threading.Event()
        traffic = {
            "tx_packets": 0,
            "tx_bytes": 0,
            "rx_packets": 0,
            "rx_bytes": 0,
        }

        def read_adapter():
            try:
                while not self.stop_event.is_set() and not pump_stop.is_set():
                    packet = self.adapter.receive(500)
                    if packet and _valid_ipv4_packet(
                        packet, self.session.parameters.ipv4
                    ):
                        work.put((True, packet), timeout=1)
            except Exception as error:
                _put_failure(failure, error)

        def read_carrier():
            try:
                while not self.stop_event.is_set() and not pump_stop.is_set():
                    packets = self.session.receive()
                    for packet in packets or []:
                        work.put((False, packet), timeout=1)
            except Exception as error:
                _put_failure(failure, error)

        threads = [
            threading.Thread(target=read_adapter, daemon=True),
            threading.Thread(target=read_carrier, daemon=True),
        ]
        for thread in threads:
            thread.start()
        try:
            if self.policy and endpoint_ip:
                self.policy.install(endpoint_ip)
            keepalive = time.monotonic() + 15
            status_heartbeat = time.monotonic() + 10
            while (
                not self.stop_event.is_set()
                and failure.empty()
                and not self.session.expired()
            ):
                try:
                    outbound, packet = work.get(timeout=0.25)
                    if outbound:
                        self.session.send_packet(packet)
                        traffic["tx_packets"] += 1
                        traffic["tx_bytes"] += len(packet)
                    else:
                        self.adapter.send(packet)
                        traffic["rx_packets"] += 1
                        traffic["rx_bytes"] += len(packet)
                except queue.Empty:
                    pass
                if time.monotonic() >= keepalive:
                    self.session.send_keepalive()
                    keepalive = time.monotonic() + 15
                if time.monotonic() >= status_heartbeat:
                    write_status(
                        "connected",
                        self.carrier_name,
                        endpoint=endpoint_ip,
                        traffic=traffic,
                    )
                    status_heartbeat = time.monotonic() + 10
            if not failure.empty():
                raise failure.get()
        finally:
            pump_stop.set()

    def _materialize_bundle(self, bundle):
        for stale in ROOT.glob("rs-device-*.json"):
            stale.unlink(missing_ok=True)
        descriptor, name = tempfile.mkstemp(prefix="rs-device-", suffix=".json", dir=ROOT)
        os.close(descriptor)
        path = Path(name)
        try:
            path.write_text(json.dumps(bundle, separators=(",", ":")), encoding="utf-8")
            if os.name == "nt" and os.environ.get("REKASERDOBA_DEV_ACL") != "1":
                import subprocess

                subprocess.run(
                    [
                        "icacls.exe",
                        str(path),
                        "/inheritance:r",
                        "/grant:r",
                        "*S-1-5-18:F",
                        "*S-1-5-32-544:F",
                    ],
                    check=True,
                    capture_output=True,
                )
            return path
        except Exception:
            path.unlink(missing_ok=True)
            raise


def _put_failure(target, error):
    try:
        target.put_nowait(error)
    except queue.Full:
        pass


def _valid_ipv4_packet(packet, expected_source):
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return False
    header_length = (packet[0] & 0x0F) * 4
    total_length = int.from_bytes(packet[2:4], "big")
    if header_length < 20 or total_length < header_length or total_length > len(packet):
        return False
    return packet[12:16] == socket.inet_aton(expected_source)


if win32serviceutil:
    class RekaService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = DISPLAY_NAME
        _svc_description_ = "RekaSerdoba authenticated multi-carrier tunnel"

        def __init__(self, args):
            super().__init__(args)
            self.stop_handle = win32event.CreateEvent(None, 0, 0, None)
            self.stop_event = threading.Event()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stop_event.set()
            win32event.SetEvent(self.stop_handle)

        def SvcDoRun(self):
            servicemanager.LogInfoMsg("RekaSerdoba service starting")
            try:
                TunnelRuntime(self.stop_event).run()
            except Exception:
                configure_logging()
                logging.exception("service terminated")
                raise


def connection_check():
    configure_logging()
    bundle = load_bundle(BUNDLE)
    with tempfile.TemporaryDirectory() as temporary:
        state = ManifestState(Path(temporary) / "state.json")
        host, port, addresses, server_public, choices = load_manifest(bundle, state)
        runtime = Path(temporary) / "bundle.json"
        runtime.write_text(json.dumps(bundle), encoding="utf-8")
        bridge = Path(sys.executable).resolve().parent / "h3_bridge.exe"
        if not bridge.exists():
            bridge = Path(__file__).resolve().parent / "h3_bridge.exe"
        results = {}
        for address in addresses:
            for choice in choices:
                key = f"{address}/{choice.name}"
                try:
                    session = RekaSession.connect(
                        runtime,
                        choice,
                        host,
                        port,
                        address,
                        server_public,
                        bridge if bridge.exists() else None,
                    )
                    session.send_keepalive()
                    session.receive()
                    session.close()
                    results[key] = "ok"
                except Exception as error:
                    results[key] = type(error).__name__
        print(json.dumps(results, sort_keys=True))
        if not any(value == "ok" for value in results.values()):
            raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    load = sub.add_parser("import")
    load.add_argument("bundle", type=Path)
    sub.add_parser("check")
    diagnostics = sub.add_parser("diagnostics")
    diagnostics.add_argument(
        "output",
        type=Path,
        nargs="?",
        default=ROOT / "diagnostics.zip",
    )
    sub.add_parser("status")
    sub.add_parser("version")
    sub.add_parser("console")
    sub.add_parser("recover")
    sub.add_parser("install")
    sub.add_parser("remove")
    sub.add_parser("start")
    sub.add_parser("stop")
    sub.add_parser("service")
    args = parser.parse_args()
    if args.command == "import":
        import_bundle(args.bundle, BUNDLE)
        print(BUNDLE)
    elif args.command == "check":
        connection_check()
    elif args.command == "diagnostics":
        print(create_diagnostics(args.output))
    elif args.command == "status":
        print(json.dumps(read_status(), sort_keys=True))
    elif args.command == "version":
        print(VERSION)
    elif args.command == "console":
        TunnelRuntime(threading.Event()).run()
    elif args.command == "recover":
        NetworkPolicy(POLICY_STATE, sys.executable, "RekaSerdoba").recover()
    elif win32serviceutil is None:
        raise SystemExit("pywin32 is required for service management")
    elif args.command == "install":
        subprocess.run(
            [
                "sc.exe",
                "create",
                SERVICE_NAME,
                "binPath=",
                f'"{sys.executable}" service',
                "start=",
                "demand",
                "obj=",
                "LocalSystem",
                "DisplayName=",
                DISPLAY_NAME,
            ],
            check=True,
        )
        subprocess.run(
            ["sc.exe", "description", SERVICE_NAME, RekaService._svc_description_],
            check=True,
        )
    elif args.command == "remove":
        subprocess.run(["sc.exe", "delete", SERVICE_NAME], check=True)
    elif args.command == "start":
        subprocess.run(["sc.exe", "start", SERVICE_NAME], check=True)
    elif args.command == "stop":
        subprocess.run(["sc.exe", "stop", SERVICE_NAME], check=False)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            query = subprocess.run(
                ["sc.exe", "query", SERVICE_NAME],
                check=False,
                capture_output=True,
                text=True,
            )
            if "STOPPED" in query.stdout:
                break
            time.sleep(0.5)
        NetworkPolicy(POLICY_STATE, sys.executable, "RekaSerdoba").recover()
    elif args.command == "service":
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(RekaService)
        servicemanager.StartServiceCtrlDispatcher()


if __name__ == "__main__":
    main()
