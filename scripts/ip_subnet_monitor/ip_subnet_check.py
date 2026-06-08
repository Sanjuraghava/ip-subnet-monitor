#!/usr/bin/env python3
import argparse
import concurrent.futures
import ipaddress
import json
import platform
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class ScanStatus(str, Enum):
    IN_USE = "in_use"
    FREE = "free"


@dataclass
class ScanResult:
    name: str
    cidr: str
    description: str
    hosts_scanned: int
    in_use: list[str]
    free: list[str]
    conflicts: list[dict]
    missing: list[dict]
    untracked: list[str]


def ping_command(ip: str, timeout_ms: int) -> list[str]:
    system = platform.system().lower()
    if system == "darwin":
        return ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    if system == "windows":
        return ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    timeout_seconds = max(1, round(timeout_ms / 1000))
    return ["ping", "-c", "1", "-W", str(timeout_seconds), ip]


def is_reachable(ip: str, timeout_ms: int) -> bool:
    try:
        completed = subprocess.run(
            ping_command(ip, timeout_ms),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except FileNotFoundError:
        raise RuntimeError("ping command is not available on this machine")
    return completed.returncode == 0


def status_for(ip: str, live_ips: set[str]) -> ScanStatus:
    return ScanStatus.IN_USE if ip in live_ips else ScanStatus.FREE


def normalize_records(records: list[dict]) -> dict[str, dict]:
    normalized = {}
    for record in records:
        ip = str(ipaddress.ip_address(record["ip"]))
        expected = record.get("expected")
        if expected not in {None, ScanStatus.IN_USE.value, ScanStatus.FREE.value}:
            raise ValueError(f"{ip} has invalid expected value: {expected}")
        normalized[ip] = record | {"ip": ip}
    return normalized


def scan_subnet(subnet: dict, timeout_ms: int, workers: int) -> ScanResult:
    network = ipaddress.ip_network(subnet["cidr"], strict=False)
    hosts = [str(host) for host in network.hosts()]
    records = normalize_records(subnet.get("records", []))

    live_ips: set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_ip = {
            executor.submit(is_reachable, ip, timeout_ms): ip
            for ip in hosts
        }
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            if future.result():
                live_ips.add(ip)

    conflicts = []
    missing = []
    for ip, record in records.items():
        actual = status_for(ip, live_ips).value
        expected = record.get("expected")
        if expected and expected != actual:
            issue = record | {"actual": actual}
            if expected == ScanStatus.FREE.value:
                conflicts.append(issue)
            else:
                missing.append(issue)

    untracked = sorted(ip for ip in live_ips if ip not in records)
    in_use = sorted(live_ips)
    free = sorted(ip for ip in hosts if ip not in live_ips)

    return ScanResult(
        name=subnet["name"],
        cidr=str(network),
        description=subnet.get("description", ""),
        hosts_scanned=len(hosts),
        in_use=in_use,
        free=free,
        conflicts=conflicts,
        missing=missing,
        untracked=untracked,
    )


def render_report(results: list[ScanResult]) -> str:
    lines = [
        "IP subnet monitor report",
        "",
        "Per subnet",
    ]
    for result in results:
        lines.append(
            "- {name} {cidr} -- in_use={in_use}, free={free}, "
            "conflicts={conflicts}, missing={missing}".format(
                name=result.name,
                cidr=result.cidr,
                in_use=len(result.in_use),
                free=len(result.free),
                conflicts=len(result.conflicts),
                missing=len(result.missing),
            )
        )

    conflict_count = sum(len(result.conflicts) for result in results)
    missing_count = sum(len(result.missing) for result in results)
    lines.extend(["", f"Total conflicts: {conflict_count}", f"Total missing: {missing_count}"])

    if conflict_count:
        lines.extend(["", "Conflicts"])
        for result in results:
            for item in result.conflicts:
                lines.append(f"- {result.name} {item['ip']} expected=free actual={item['actual']}")

    if missing_count:
        lines.extend(["", "Missing expected in-use IPs"])
        for result in results:
            for item in result.missing:
                lines.append(f"- {result.name} {item['ip']} expected=in_use actual={item['actual']}")

    return "\n".join(lines)


def should_notify(config: dict, results: list[ScanResult]) -> bool:
    notify_on = config.get("notify_on", "conflicts_only")
    if notify_on == "always":
        return True
    if notify_on == "never":
        return False
    if notify_on != "conflicts_only":
        raise ValueError(f"Invalid notify_on value: {notify_on}")
    return any(result.conflicts or result.missing for result in results)


def send_webex(token: str, room_id: str, markdown: str) -> None:
    payload = json.dumps({"roomId": room_id, "markdown": f"```\n{markdown}\n```"}).encode()
    request = urllib.request.Request(
        "https://webexapis.com/v1/messages",
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status >= 300:
                raise RuntimeError(f"Webex returned HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise RuntimeError(f"Webex returned HTTP {exc.code}: {body}") from exc


def load_config(path: Path) -> dict:
    with path.open() as handle:
        config = json.load(handle)
    if "subnets" not in config or not isinstance(config["subnets"], list):
        raise ValueError("Config must contain a subnets array")
    return config


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan configured subnets and report IP usage.")
    parser.add_argument("--config", default=Path(__file__).with_name("subnets.json"), type=Path)
    parser.add_argument("--dry-run", action="store_true", help="Print report without sending Webex")
    parser.add_argument("--timeout-ms", default=1000, type=int)
    parser.add_argument("--workers", default=128, type=int)
    args = parser.parse_args()

    config = load_config(args.config)
    results = [
        scan_subnet(subnet, timeout_ms=args.timeout_ms, workers=args.workers)
        for subnet in config["subnets"]
    ]
    report = render_report(results)
    print(report)

    if args.dry_run or not should_notify(config, results):
        return 0

    import os

    token = os.environ.get("WEBEX_BOT_TOKEN")
    room_id = os.environ.get("WEBEX_ROOM_ID")
    if not token or not room_id:
        print("WEBEX_BOT_TOKEN and WEBEX_ROOM_ID are required to send notifications.", file=sys.stderr)
        return 2

    send_webex(token, room_id, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
