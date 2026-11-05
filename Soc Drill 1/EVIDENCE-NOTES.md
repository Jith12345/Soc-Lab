# Evidence notes

- E-01: 142 failed logons from 198.51.100.77.
- E-02: Multiple target account names in failed logon events.
- E-03: Successful 4624 event for svc.backup from the same IP; Logon Type 10.
- E-04: Scheduled task creation references C:\\Windows\\Temp\\upd.exe and /ru SYSTEM.
- E-05: No process-execution event for upd.exe found in the available uploaded logs.
- Data-quality note: parsed host value differs from raw event hostname in at least one authentication event.

Only include evidence personally verified in Splunk. Separate observations from interpretations.
