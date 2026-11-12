# SOC L1 Investigation: Suspicious PowerShell Launched by Microsoft Word

A beginner-friendly Security Operations Center (SOC) Level 1 investigation using Splunk and simulated endpoint/proxy logs.

## Project overview

This project documents an L1 investigation of an alert in which Microsoft Word (`winword.exe`) launched PowerShell (`powershell.exe`). The investigation follows a practical SOC workflow:

1. Identify the affected host, user, and process relationship.
2. Review the PowerShell command line and decode the Base64 command.
3. Correlate endpoint activity with proxy logs.
4. Identify repeated outbound HTTP requests.
5. Calculate request intervals to assess possible beaconing.
6. Document findings and recommend escalation to L2.

> **Lab disclaimer:** This is a training/portfolio investigation using simulated lab data. The findings are indicators of suspicious activity, not proof of a real compromise, malware infection, data theft, or confirmed command-and-control.

## Alert details

| Field | Value |
|---|---|
| Alert | PowerShell launched by Microsoft Office |
| Severity | High (as supplied by the lab alert) |
| Host | `WS-ACC07` |
| User | `ravi.k` |
| Source IP | `10.10.3.17` |
| PowerShell event | `2026-10-24 09:15:40` |
| Parent process | `winword.exe` |
| Child process | `powershell.exe` |

## Key findings

- Microsoft Word launched PowerShell at `09:15:40`.
- The command line included `-nop`, `-w hidden`, and `-enc`.
- The Base64 command decoded to `Write-Output 'lab-stage1-beacon'`.
- A request for `http://invoice-portal-secure.example/Invoice_8821.zip` was observed at `09:14:22`, shortly before the process event.
- Proxy logs showed repeated HTTP POST requests to `http://update-check.example/beacon`.
- Requests were recorded once per minute from `09:16:00` through `09:35:00`, with `312` bytes recorded for each request.
- The regular timing is consistent with beacon-like activity, but does not independently prove C2.

## Timeline

| Timestamp (2026-10-24) | Event |
|---|---|
| 09:14:22 | GET request to `invoice-portal-secure.example/Invoice_8821.zip` |
| 09:15:40 | `winword.exe` launches `powershell.exe` on `WS-ACC07` |
| 09:16:00 | First observed POST to `update-check.example/beacon` |
| 09:17:00–09:35:00 | Repeated POST requests at 60-second intervals |

## Repository structure

```text
SOC-L1-Splunk-Suspicious-PowerShell-Investigation/
├── README.md
├── spl/
│   └── ticket-02-investigation.spl
├── reports/
│   └── ticket-02-l1-investigation-report.md
├── evidence/
│   └── evidence-summary.md
└── screenshots/
    └── README.md
```

## How to reproduce in Splunk

1. Import the lab CSV files into Splunk (the lab used `index=main`).
2. Set the time picker to include **24 October 2026, 09:00–09:36**.
3. Open `spl/ticket-02-investigation.spl`.
4. Run each search separately, in order.
5. Save screenshots using the names listed in `screenshots/README.md`.

The SPL assumes the fields shown in the lab are available. If your field names differ, adjust them to match your data.

## MITRE ATT&CK mapping (tentative)

| Technique | Name | Why it may apply | Confidence |
|---|---|---|---|
| T1059.001 | PowerShell | PowerShell process execution was observed | Observed behavior; intent unconfirmed |
| T1071.001 | Web Protocols | Repeated HTTP POST traffic was observed | Possible; C2 purpose unconfirmed |
| T1105 | Ingress Tool Transfer | A ZIP URL request was observed before the process event | Possible; successful download/execution not confirmed |
| T1204.002 | Malicious File | A document-related process chain was observed | Hypothesis only; user execution of a malicious file not confirmed |

Do not present the tentative mappings as confirmed attacker techniques. Reassess them if additional endpoint, file, or network evidence becomes available.

## L1 conclusion and escalation

**Disposition:** Suspicious activity — escalate to L2 for validation.

The evidence shows an unusual Office-to-PowerShell process relationship, a preceding ZIP request, and repeated outbound HTTP POST requests at exact 60-second intervals. These findings warrant further investigation.

### Recommended next steps for L2

- Retrieve the full process tree and original command-line telemetry.
- Identify the downloaded ZIP file on disk and calculate its SHA-256 hash.
- Check the file, domain, and IP reputation using approved threat-intelligence sources.
- Review DNS, firewall, proxy, and endpoint telemetry for related activity.
- Check for persistence, additional child processes, and lateral movement.
- Determine whether any sensitive data was accessed or transferred.
- Contain the host or block indicators only under the organization's incident-response policy.

### L1 handling boundary

The L1 analyst collects evidence, records timestamps and indicators, assesses alert context, and escalates. Do not claim to have reverse-engineered malware, confirmed exfiltration, or contained the host unless those actions were actually performed and authorized.

## Skills demonstrated

- Splunk Search Processing Language (SPL)
- Endpoint process investigation
- Parent-child process analysis
- Basic Base64 command interpretation
- Proxy log analysis
- Event timeline correlation
- Beaconing pattern identification using `delta`
- MITRE ATT&CK mapping
- L1 incident documentation and escalation

## Data and privacy

Use only authorized lab data. Before publishing screenshots or logs, remove real usernames, hostnames, IP addresses, email addresses, tokens, and other sensitive information. The `.example` domains and private IP in this write-up are lab indicators.
