# IP Subnet Monitor

Scans configured subnets and reports in-use, free, conflict, and missing counts.

## Configured test subnets

| Name | CIDR | Usable hosts |
| --- | --- | ---: |
| automation-pool-196 | 10.196.4.0/23 | 510 |
| automation-pool-196-6 | 10.196.6.0/24 | 254 |
| lab-pool-78-85 | 10.78.85.0/24 | 254 |
| lab-pool-78-27 | 10.78.27.0/24 | 254 |

Total per run: 1,272 usable IPs.

## Manual run

```bash
# Preview report
./scripts/ip_subnet_monitor/run_ip_subnet_check.sh --dry-run

# Send Webex notification
export WEBEX_BOT_TOKEN="your-token"
export WEBEX_ROOM_ID="your-room-id"
./scripts/ip_subnet_monitor/run_ip_subnet_check.sh
```

## Jenkins

Use `Jenkinsfile.ip-subnet-monitor`.

Required Jenkins credentials for notification runs:

| Credential ID | Type |
| --- | --- |
| webex-bot-token | Secret text |
| webex-room-id | Secret text |

For the first phase, `notify_on` is set to `always` in `subnets.json`. After adding registered IP records with expected states, change it to `conflicts_only` to send Webex messages only when something is wrong.

## Add more subnets

Append entries to the `subnets` array in `subnets.json`:

```json
{
  "name": "your-subnet-name",
  "cidr": "x.x.x.0/24",
  "description": "optional note",
  "scan_mode": "full_subnet",
  "records": []
}
```

## Add expected IP records

Use `expected: "free"` to detect a conflict when an IP responds, or `expected: "in_use"` to detect a missing host when an IP does not respond.

```json
{
  "ip": "10.78.85.10",
  "owner": "example-host",
  "expected": "in_use"
}
```
