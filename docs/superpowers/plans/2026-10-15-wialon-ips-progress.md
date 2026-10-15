# SDD ledger — plan: docs/superpowers/plans/2026-10-15-wialon-ips.md

Pre-flight: Task 2 consumes Get-IpsCrc16 and New-IpsLoginPacket from Task 1; signatures agree.

Ruling: Work directly in the supplied empty project directory without Git helper scripts or commits — there is no Git repository, as already noted in the approved plan — cost if wrong: repository setup must be performed separately.

Task 1: complete. Windows PowerShell 5.1 packet tests: 6 passed, 0 failed. Before implementation: 6 failed because functions were absent. BOM-related parse failure reproduced and corrected by saving UTF-8 with BOM as specified.

Task 2: complete. Network/validation RED: 6 packet tests passed, 32 integration tests failed because the script did not yet execute a probe or validate input. Final Windows PowerShell 5.1.26100.9711 run: 41 passed, 0 failed (`powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-WialonIps.Tests.ps1`). Both PS1 files passed the PowerShell parser and UTF-8 BOM checks.

IPv6 regression: the default .NET Framework TcpClient failed both literal and bracketed IPv6 tests before the dual-mode socket change; both passed afterward. Localhost fallback takes more than one second on this Windows machine; its test uses the specified default timeout of five seconds. Production timeout semantics remain unchanged.

Final review: independent reviewer completed; no Critical, Important or Minor findings. Reviewed code, tests, README, spec and plan; no files changed by reviewer. No external server was contacted.

Final: Ruling: Real-server acceptance and IMEI registration remain unverified — no external target was supplied and the approved verification uses loopback — cost if wrong: deployment-specific rejection may still need diagnosis on the intended server.

Final: Ruling: Visual masking in a real interactive terminal was not manually inspected — production uses the standard Read-Host -AsSecureString path; automated checks cover output redaction — cost if wrong: terminal-specific display behavior remains unverified.

Final: no deferred minor issues. Working files retained in the supplied project directory; no Git initialization, merge or publishing performed.
