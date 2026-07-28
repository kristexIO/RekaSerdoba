import ipaddress
import json
import os
import subprocess
from pathlib import Path


class NetworkPolicy:
    def __init__(self, state_path, executable, adapter_name, extra_programs=None):
        self.state_path = Path(state_path)
        self.programs = [str(Path(executable).resolve())]
        self.programs.extend(str(Path(value).resolve()) for value in extra_programs or [])
        self.adapter_name = adapter_name

    def prepare(self, endpoint_ip):
        ipaddress.ip_address(endpoint_ip)
        if self.state_path.exists():
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
            if state.get("endpoint_ip") == endpoint_ip:
                return
            self.recover()
        route = json.loads(
            _ps(
                "$p=@(Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up'} "
                "| Select-Object -ExpandProperty ifIndex);"
                "$r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
                "| Where-Object {$p -contains $_.InterfaceIndex} "
                "| Sort-Object RouteMetric | Select-Object -First 1 InterfaceIndex,NextHop;"
                "if($null -eq $r){throw 'No active physical IPv4 default route'};"
                "$r | ConvertTo-Json -Compress"
            )
        )
        state = {"endpoint_route": route, "endpoint_ip": endpoint_ip, "active": False}
        self._write_state(state)
        _ps(
            f"$endpoint=Get-NetRoute -DestinationPrefix '{endpoint_ip}/32' "
            f"-InterfaceIndex {int(route['InterfaceIndex'])} -ErrorAction SilentlyContinue;"
            "if($null -eq $endpoint){"
            f"New-NetRoute -DestinationPrefix '{endpoint_ip}/32' "
            f"-InterfaceIndex {int(route['InterfaceIndex'])} "
            f"-NextHop {_quote(route['NextHop'])} -PolicyStore ActiveStore "
            "-RouteMetric 1 -ErrorAction Stop | Out-Null}"
        )

    def install(self, endpoint_ip, tunnel_dns="1.1.1.1"):
        ipaddress.ip_address(endpoint_ip)
        self.prepare(endpoint_ip)
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        _ps(
            f"$i=Get-NetAdapter -Name {_quote(self.adapter_name)};"
            "$low=Get-NetRoute -DestinationPrefix '0.0.0.0/1' "
            "-InterfaceIndex $i.ifIndex -ErrorAction SilentlyContinue;"
            "if($null -eq $low){New-NetRoute -DestinationPrefix '0.0.0.0/1' "
            "-InterfaceIndex $i.ifIndex -NextHop 0.0.0.0 -PolicyStore ActiveStore "
            "-RouteMetric 1 -ErrorAction Stop | Out-Null};"
            "$high=Get-NetRoute -DestinationPrefix '128.0.0.0/1' "
            "-InterfaceIndex $i.ifIndex -ErrorAction SilentlyContinue;"
            "if($null -eq $high){New-NetRoute -DestinationPrefix '128.0.0.0/1' "
            "-InterfaceIndex $i.ifIndex -NextHop 0.0.0.0 -PolicyStore ActiveStore "
            "-RouteMetric 1 -ErrorAction Stop | Out-Null};"
            f"try{{Set-DnsClientServerAddress -InterfaceIndex $i.ifIndex "
            f"-ServerAddresses {_quote(tunnel_dns)} -ErrorAction Stop}}catch{{}}"
        )
        state["active"] = True
        self._write_state(state)

    def _write_state(self, state):
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(".new")
        temporary.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
        os.replace(temporary, self.state_path)

    def recover(self):
        if not self.state_path.exists():
            return
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        commands = [
            "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/1','128.0.0.0/1' "
            "-ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false",
            f"Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '{state['endpoint_ip']}/32' "
            "-ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false",
        ]
        for profile in state.get("firewall", []):
            action = str(profile["DefaultOutboundAction"])
            if action not in {"Allow", "Block", "NotConfigured"}:
                action = "Allow"
            commands.append(
                f"Set-NetFirewallProfile -Profile {_quote(profile['Name'])} "
                f"-DefaultOutboundAction {action}"
            )
        _ps(";".join(commands) + ";exit 0")
        self.state_path.unlink(missing_ok=True)


def _quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def _ps(command):
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"PowerShell network command failed: {detail}")
    return result.stdout.strip()
