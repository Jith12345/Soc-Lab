# Splunk Investigation Screenshots

This folder contains the screenshots captured during the Ticket 2 SOC L1 investigation.

## Screenshot checklist

| Filename | Evidence to capture |
|---|---|
| 01_process_identification.png | Word launching PowerShell, including timestamp, host and user |
| 02_raw_event_encoded_command.png | Raw endpoint event with encoded PowerShell command |
| 03_proxy_user_timeline.png | Proxy activity around 09:00–09:20 |
| 04_proxy_download_event.png | ZIP URL request at 09:14:22 |
| 05_beacon_network_activity.png | Repeated POST requests to update-check.example |
| 06_beacon_interval_delta.png | Splunk delta output showing 60-second intervals |

## Screenshot guidelines

- Capture the Splunk search query and its results.
- Keep the timestamp and relevant field names visible.
- Use PNG format.
- Use the exact filenames listed above.
- Do not modify the search results.
- Hide unrelated personal information or sensitive account details.

These screenshots serve as evidence for the investigation findings documented in the main project README.
