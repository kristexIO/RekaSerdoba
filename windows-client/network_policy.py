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
        if ipaddress.ip_address(endpoint_ip).version != 4:
            raise ValueError("endpoint must be IPv4")
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
                f"$e=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '{endpoint_ip}/32' "
                "-InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue "
                "| Where-Object {$_.NextHop -eq $r.NextHop});"
                "[pscustomobject]@{InterfaceIndex=[int]$r.InterfaceIndex;"
                "NextHop=[string]$r.NextHop;EndpointExists=($e.Count -gt 0)} "
                "| ConvertTo-Json -Compress"
            )
        )
        route["Created"] = not bool(route.pop("EndpointExists", False))
        state = {"endpoint_route": route, "endpoint_ip": endpoint_ip, "active": False}
        self._write_state(state)
        if route["Created"]:
            _ps(
            f"New-NetRoute -DestinationPrefix '{endpoint_ip}/32' "
            f"-InterfaceIndex {int(route['InterfaceIndex'])} "
            f"-NextHop {_quote(route['NextHop'])} -PolicyStore ActiveStore "
                "-RouteMetric 1 -ErrorAction Stop | Out-Null"
            )

    def install(self, endpoint_ip, tunnel_dns="1.1.1.1"):
        if ipaddress.ip_address(endpoint_ip).version != 4:
            raise ValueError("endpoint must be IPv4")
        if ipaddress.ip_address(tunnel_dns).version != 4:
            raise ValueError("tunnel DNS must be IPv4")
        self.prepare(endpoint_ip)
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        current = json.loads(
            _ps(
                f"$i=Get-NetAdapter -Name {_quote(self.adapter_name)} -ErrorAction Stop;"
                "$low=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/1' "
                "-InterfaceIndex $i.ifIndex -ErrorAction SilentlyContinue "
                "| Where-Object {$_.NextHop -eq '0.0.0.0'});"
                "$high=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '128.0.0.0/1' "
                "-InterfaceIndex $i.ifIndex -ErrorAction SilentlyContinue "
                "| Where-Object {$_.NextHop -eq '0.0.0.0'});"
                "$dns=Get-DnsClientServerAddress -InterfaceIndex $i.ifIndex "
                "-AddressFamily IPv4 -ErrorAction Stop;"
                f"$physical=@(Get-NetAdapter -Physical | Where-Object {{$_.Status -eq 'Up' -and $_.Name -ne {_quote(self.adapter_name)}}} "
                "| Select-Object -ExpandProperty Name);"
                "[pscustomobject]@{InterfaceIndex=[int]$i.ifIndex;"
                "LowExists=($low.Count -gt 0);HighExists=($high.Count -gt 0);"
                "Dns=@($dns.ServerAddresses);PhysicalAliases=$physical} "
                "| ConvertTo-Json -Compress"
            )
        )
        dns_before = current.get("Dns", [])
        if isinstance(dns_before, str):
            dns_before = [dns_before]
        aliases = current.get("PhysicalAliases", [])
        if isinstance(aliases, str):
            aliases = [aliases]
        identifier = os.urandom(8).hex()
        state["tunnel"] = {
            "InterfaceIndex": int(current["InterfaceIndex"]),
            "LowCreated": not bool(current.get("LowExists")),
            "HighCreated": not bool(current.get("HighExists")),
            "DnsBefore": dns_before,
        }
        state["rules"] = {
            "Ipv6": f"RekaSerdoba IPv6 {identifier}",
            "DnsUdp": f"RekaSerdoba DNS UDP {identifier}",
            "DnsTcp": f"RekaSerdoba DNS TCP {identifier}",
        }
        self._write_state(state)
        index = int(current["InterfaceIndex"])
        commands = []
        if state["tunnel"]["LowCreated"]:
            commands.append(
                "New-NetRoute -DestinationPrefix '0.0.0.0/1' "
                f"-InterfaceIndex {index} -NextHop 0.0.0.0 -PolicyStore ActiveStore "
                "-RouteMetric 1 -ErrorAction Stop | Out-Null"
            )
        if state["tunnel"]["HighCreated"]:
            commands.append(
                "New-NetRoute -DestinationPrefix '128.0.0.0/1' "
                f"-InterfaceIndex {index} -NextHop 0.0.0.0 -PolicyStore ActiveStore "
                "-RouteMetric 1 -ErrorAction Stop | Out-Null"
            )
        commands.append(
            f"Set-DnsClientServerAddress -InterfaceIndex {index} "
            f"-ServerAddresses {_quote(tunnel_dns)} -ErrorAction Stop"
        )
        commands.append(
            f"New-NetFirewallRule -DisplayName {_quote(state['rules']['Ipv6'])} "
            "-Direction Outbound -Action Block -RemoteAddress '::/0' "
            "-Profile Any -ErrorAction Stop | Out-Null"
        )
        if aliases:
            encoded_aliases = ",".join(_quote(value) for value in aliases)
            commands.append(
                f"New-NetFirewallRule -DisplayName {_quote(state['rules']['DnsUdp'])} "
                "-Direction Outbound -Action Block -Protocol UDP -RemotePort 53 "
                f"-InterfaceAlias @({encoded_aliases}) -Profile Any -ErrorAction Stop | Out-Null"
            )
            commands.append(
                f"New-NetFirewallRule -DisplayName {_quote(state['rules']['DnsTcp'])} "
                "-Direction Outbound -Action Block -Protocol TCP -RemotePort 53 "
                f"-InterfaceAlias @({encoded_aliases}) -Profile Any -ErrorAction Stop | Out-Null"
            )
        try:
            _ps(";".join(commands))
        except Exception:
            self.recover()
            raise
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
        commands = []
        tunnel = state.get("tunnel", {})
        index = tunnel.get("InterfaceIndex")
        if index is not None and tunnel.get("LowCreated"):
            commands.append(
                "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/1' "
                f"-InterfaceIndex {int(index)} -ErrorAction SilentlyContinue "
                "| Where-Object {$_.NextHop -eq '0.0.0.0'} "
                "| Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue"
            )
        if index is not None and tunnel.get("HighCreated"):
            commands.append(
                "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '128.0.0.0/1' "
                f"-InterfaceIndex {int(index)} -ErrorAction SilentlyContinue "
                "| Where-Object {$_.NextHop -eq '0.0.0.0'} "
                "| Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue"
            )
        if index is not None:
            dns_before = tunnel.get("DnsBefore", [])
            if dns_before:
                addresses = ",".join(_quote(value) for value in dns_before)
                commands.append(
                    f"Set-DnsClientServerAddress -InterfaceIndex {int(index)} "
                    f"-ServerAddresses @({addresses}) -ErrorAction SilentlyContinue"
                )
            else:
                commands.append(
                    f"Set-DnsClientServerAddress -InterfaceIndex {int(index)} "
                    "-ResetServerAddresses -ErrorAction SilentlyContinue"
                )
        route = state.get("endpoint_route", {})
        if route.get("Created"):
            commands.append(
                f"Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '{state['endpoint_ip']}/32' "
                f"-InterfaceIndex {int(route['InterfaceIndex'])} -ErrorAction SilentlyContinue "
                f"| Where-Object {{$_.NextHop -eq {_quote(route['NextHop'])}}} "
                "| Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue"
            )
        for name in state.get("rules", {}).values():
            commands.append(
                f"Get-NetFirewallRule -DisplayName {_quote(name)} -ErrorAction SilentlyContinue "
                "| Remove-NetFirewallRule -ErrorAction SilentlyContinue"
            )
        for profile in state.get("firewall", []):
            action = str(profile["DefaultOutboundAction"])
            if action not in {"Allow", "Block", "NotConfigured"}:
                action = "Allow"
            commands.append(
                f"Set-NetFirewallProfile -Profile {_quote(profile['Name'])} "
                f"-DefaultOutboundAction {action}"
            )
        if commands:
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
