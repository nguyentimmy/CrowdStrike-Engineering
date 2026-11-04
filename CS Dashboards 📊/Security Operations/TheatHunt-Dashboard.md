# 🔎 Threat Hunt – Pilot

CrowdStrike Falcon dashboard for proactive, technique-level hunting. Pilot version, built to prove out the hunts before they're turned into scheduled detections.

---

## 🎯 Why this exists

Detections only catch what someone already wrote a rule for. Threat hunting goes after the rest: the noisier, lower-confidence activity that never reaches the bar for an alert, and the activity that goes undetected because no rule matches it.

That's also what keeps it from becoming alert fatigue. A rule that is loose enough to catch this stuff would page someone all day. A hunt puts the same activity in front of an analyst on a schedule, as a short list to review, so unusual behavior gets investigated without being turned into more alerts.

| | 🚨 Detection / alert | 🔎 Threat hunt |
| --- | --- | --- |
| Trigger | A rule fires on its own | An analyst runs the hunt |
| Confidence | High, already matched a rule | Low to medium, a lead to check |
| Volume | Has to stay low or people tune it out | Can be noisy, since it's reviewed on purpose |
| Finds | Known bad patterns | Unusual behavior with no rule behind it |
| Output | An alert to respond to | A list of leads to investigate |

> 💡 A hunt hit is a lead, not a verdict. The goal is to spot what looks off, decide if it's benign, and only escalate what isn't.

---

## 🧭 What it hunts for

All seven are daily hunts, ordered roughly as an attack unfolds: get in, execute, evade, persist, call out.

| # | Hunt | Question it answers | Technique |
| --- | --- | --- | --- |
| 1 | 📧 **Office Shell Spawn** | *Is an Office app launching a shell?* | T1204 |
| 2 | ⚡ **Highly Executed PowerShell** | *What PowerShell is running, and what's unusual in it?* | T1059 |
| 3 | 🥷 **EDR Evasion** | *Is anything tampering with endpoint protection or clearing logs?* | T1562 / T1070 |
| 4 | 🧩 **BYOVD / Unsigned Driver** | *Is a driver loading that shouldn't be?* | T1014 / T1547.006 |
| 5 | 🔧 **Rare Process as Service** | *Is something new persisting as a service or scheduled task?* | T1543 / T1053 |
| 6 | 🖥️ **Unapproved Remote Access Tools** | *Is a remote tool or tunnel running that IT didn't sanction?* | T1219 / T1572 |
| 7 | 🌐 **LOLBin Network Egress** | *Are built-in binaries reaching out to the internet?* | T1071 / T1105 |

---

## 🎛️ Parameters

| Parameter | Use |
| --- | --- |
| `?Hostname` | Scope every widget to one host. Default `*` hunts fleet-wide |
| `?User` | Scope to one account. Default `*`. Useful once a hunt points at a specific identity |

---

## 🧪 The hunts (CQL)

> ⚠️ Adapted from the Defender daily-hunts KQL and written for Falcon event fields. Untested against your tenant. Check field names (especially `UserName` and the driver fields) in Advanced event search before saving widgets.

### 1. 📧 Office Shell Spawn

Classic phishing execution. Often the first event in a chain that later shows up as PowerShell or persistence.

```
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname UserName=?User
| in(ParentBaseFileName, values=["winword.exe","excel.exe","outlook.exe","powerpnt.exe","mspub.exe","visio.exe","onenote.exe"], ignoreCase=true)
| in(FileName, values=["cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe"], ignoreCase=true)
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, SHA256HashData], limit=200)
| sort(@timestamp, order=desc)
```

### 2. ⚡ Highly Executed PowerShell

Two views. The first surfaces suspicious patterns. The second counts by command line, so the rare, one-off commands stand out from the routine noise.

```
// 2a. Suspicious patterns
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname UserName=?User
| in(FileName, values=["powershell.exe","pwsh.exe"], ignoreCase=true)
| CommandLine=/(DownloadFile|DownloadString|DownloadData|Invoke-Expression|\biex\b|EncodedCommand|\s-enc\s|\s-ec\s|FromBase64String|Net\.WebClient|Start-BitsTransfer|Invoke-WebRequest)/i
    OR (CommandLine=/-WindowStyle\s+Hidden/i AND CommandLine=/-ExecutionPolicy\s+Bypass/i)
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine], limit=200)
| sort(@timestamp, order=desc)
```

```
// 2b. Frequency view: rare command lines sort to the top
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname UserName=?User
| in(FileName, values=["powershell.exe","pwsh.exe"], ignoreCase=true)
| groupBy([CommandLine], function=[count(as=Executions), count(ComputerName, distinct=true, as=Hosts)])
| sort(Executions, order=asc, limit=100)
```

### 3. 🥷 EDR Evasion

Highest-value hunt. An attacker blinding your tooling is time-sensitive.

```
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname UserName=?User
| CommandLine=/(DisableRealtimeMonitoring|DisableBehaviorMonitoring|Set-MpPreference|Add-MpPreference\s+-ExclusionPath|DisableAntiSpyware|DisableAntiVirus|wevtutil\s+cl|Clear-EventLog|auditpol\s+\/clear|fsutil\s+usn\s+deletejournal|TamperProtection|AmsiScanBuffer|amsiInitFailed|Remove-MpPreference)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=200)
| sort(@timestamp, order=desc)
```

### 4. 🧩 BYOVD / Unsigned Driver

Bring-your-own-vulnerable-driver is a common way to kill EDR outright. Drivers should be rare and stable, so new ones are worth a look.

```
#event_simpleName=DriverLoad
| ComputerName=?Hostname
| groupBy([ImageFileName, SHA256HashData], function=[count(ComputerName, distinct=true, as=Hosts), min(@timestamp, as=FirstSeen)])
| sort(Hosts, order=asc, limit=100)
```

Low host count plus a recent `FirstSeen` is the lead. Add a signature filter if your `DriverLoad` events expose signing status.

### 5. 🔧 Rare Process as Service

Persistence usually gets planted the same day as initial access.

```
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname UserName=?User
| CommandLine=/(schtasks\s+\/create|\/sc\s+onlogon|\/sc\s+onstart|\/ru\s+system|New-ScheduledTask|Register-ScheduledTask|sc\s+create|New-Service)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=200)
| sort(@timestamp, order=desc)
```

### 6. 🖥️ Unapproved Remote Access Tools

Often the difference between "employee installed something" and "someone has hands on keyboard." TeamViewer and BeyondTrust are excluded as approved. Edit that list to match what IT actually sanctions.

```
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname UserName=?User
| in(FileName, values=["AnyDesk.exe","RustDesk.exe","QuickAssist.exe","AeroAdmin.exe","Supremo.exe","ammyy.exe","ScreenConnect.Client.exe","ConnectWiseControl.Client.exe","SplashtopSOS.exe","LogMeIn.exe","GoToAssist.exe","ZohoAssist.exe","RemotePC.exe","meshagent.exe","dwagent.exe","rutserv.exe","Radmin.exe","winvnc.exe","tvnserver.exe","uvnc_service.exe","vncviewer.exe","ngrok.exe","frpc.exe","chisel.exe","cloudflared.exe","plink.exe"], ignoreCase=true)
| Tool := if(in(FileName, values=["ngrok.exe","frpc.exe","chisel.exe","cloudflared.exe","plink.exe"], ignoreCase=true), then="Tunneling Tool", else="Remote Tool")
| table([@timestamp, ComputerName, UserName, Tool, FileName, CommandLine, SHA256HashData], limit=200)
| sort(@timestamp, order=desc)
```

### 7. 🌐 LOLBin Network Egress

The "phoning home" signal: built-in binaries talking to public IPs.

```
#event_simpleName=NetworkConnectIP4
| ComputerName=?Hostname
| in(ContextBaseFileName, values=["powershell.exe","pwsh.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","certutil.exe"], ignoreCase=true)
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16"])
| groupBy([ComputerName, ContextBaseFileName, RemoteAddressIP4, RemotePort], function=[count(as=Connections), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)])
| sort(Connections, order=asc, limit=200)
```

---

## 🚀 How to use it

1. Set `?Hostname` and/or `?User`, or leave both at `*` for a fleet-wide sweep.
2. Run **EDR Evasion** first. A hit there raises the priority of everything else.
3. Work down the rest of the list. Skim for what looks unusual, not for what's definitely bad.
4. When something looks off, pivot to the process tree and process timeline in Falcon for parent/child context and what ran before and after.
5. Decide: benign (note why), contain (isolate via Real Time Response), or escalate to IR.

> 💡 One hit on one hunt means little. The same host or user showing up across two or three hunts is the signal.

---

## 📌 Notes

- This is a **pilot**. Expect to tune it as real data comes back.
- Exclusions and known-good parents are environment-specific. Keep them current, or the hunts will drown in noise.
- These are hunting aids, not detections. They surface activity for a human to review and don't alert on their own.
- Anything that proves high-fidelity should graduate into a scheduled search or custom IOA so it doesn't depend on someone remembering to look. That's how the hunt output stays small instead of becoming alert fatigue.
