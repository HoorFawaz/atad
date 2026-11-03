"""Hand-written event XML in the exact shape python-evtx produces.

All values are SIMULATED (lab host LAB-WS-01, lab IPs, demo users).
"""

NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'


def event(channel: str, event_id: int, time: str, data: dict[str, str],
          record_id: int = 1, computer: str = "LAB-WS-01",
          provider: str = "Microsoft-Windows-Security-Auditing") -> str:
    fields = "".join(f'<Data Name="{k}">{v}</Data>\n' for k, v in data.items())
    return (
        f'<Event {NS}><System><Provider Name="{provider}"></Provider>\n'
        f'<EventID Qualifiers="">{event_id}</EventID>\n'
        f'<TimeCreated SystemTime="{time}"></TimeCreated>\n'
        f'<EventRecordID>{record_id}</EventRecordID>\n'
        f'<Channel>{channel}</Channel>\n<Computer>{computer}</Computer>\n'
        f'</System>\n<EventData>{fields}</EventData>\n</Event>'
    )


SEC = "Security"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"


def failed_logon(i: int, minute: int = 2) -> str:
    return event(SEC, 4625, f"2026-11-07 10:{minute:02d}:{i:02d}.000000+00:00", {
        "TargetUserName": "bob", "TargetDomainName": "LAB", "LogonType": "3",
        "IpAddress": "10.66.0.9", "IpPort": "51515", "WorkstationName": "ATTACKER-PC",
        "Status": "0xc000006d", "ProcessName": "-",
    }, record_id=100 + i)


SUCCESS_LOGON = event(SEC, 4624, "2026-11-07T10:06:00.1234567Z", {
    "TargetUserName": "bob", "TargetDomainName": "LAB", "LogonType": "10",
    "IpAddress": "10.66.0.9", "WorkstationName": "ATTACKER-PC",
    "ProcessName": "C:\\Windows\\System32\\svchost.exe",
}, record_id=200)

PROCESS_4688 = event(SEC, 4688, "2026-11-07 10:07:00+00:00", {
    "SubjectUserName": "bob", "SubjectDomainName": "LAB",
    "NewProcessId": "0x1018", "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "ParentProcessName": "C:\\Windows\\explorer.exe",
    "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
}, record_id=201)

USER_CREATED = event(SEC, 4720, "2026-11-07 10:09:00+00:00", {
    "TargetUserName": "svc-backup2", "TargetDomainName": "LAB",
    "SubjectUserName": "bob", "SubjectDomainName": "LAB",
}, record_id=202)

SYSMON_PROCESS = event(SYSMON, 1, "2026-11-07 10:07:00.500000+00:00", {
    "ProcessGuid": "{AAAA1111-0000-0000-0000-000000000001}", "ProcessId": "4120",
    "Image": "C:\\Users\\bob\\AppData\\Local\\Temp\\invoice.pdf.exe",
    "CommandLine": "invoice.pdf.exe", "User": "LAB\\bob",
    "ParentImage": "C:\\Windows\\explorer.exe",
    "Hashes": "SHA1=" + "1" * 40 + ",MD5=" + "A" * 32 + ",SHA256=" + "B" * 64 + ",IMPHASH=" + "C" * 32,
}, provider=SYSMON_PROVIDER, record_id=300)

SYSMON_NETWORK = event(SYSMON, 3, "2026-11-07 10:08:00+00:00", {
    "ProcessGuid": "{AAAA1111-0000-0000-0000-000000000001}", "ProcessId": "4120",
    "Image": "C:\\Users\\bob\\AppData\\Local\\Temp\\invoice.pdf.exe", "User": "LAB\\bob",
    "Protocol": "tcp", "Initiated": "true",
    "SourceIp": "192.168.1.15", "SourcePort": "50123",
    "DestinationIp": "10.66.0.9", "DestinationHostname": "c2.lab.test", "DestinationPort": "443",
}, provider=SYSMON_PROVIDER, record_id=301)

SYSMON_FILE = event(SYSMON, 11, "2026-11-07 10:08:30+00:00", {
    "ProcessGuid": "{AAAA1111-0000-0000-0000-000000000001}", "ProcessId": "4120",
    "Image": "C:\\Users\\bob\\AppData\\Local\\Temp\\invoice.pdf.exe",
    "TargetFilename": "C:\\Users\\bob\\AppData\\Roaming\\update.ps1",
}, provider=SYSMON_PROVIDER, record_id=302)

UNSUPPORTED = event(SEC, 4672, "2026-11-07 10:06:01+00:00", {"SubjectUserName": "bob"})
