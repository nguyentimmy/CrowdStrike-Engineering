# 🔎 Daily Threat Hunts

CrowdStrike Falcon dashboard for proactive, technique-level hunting. It covers the full attack path: execution, evasion, identity, persistence, and lateral movement.

---

## 🎯 Why this exists

Detections only catch what someone already wrote a rule for. Threat hunting goes after the rest: the noisier, lower-confidence activity that never reaches the bar for an alert, and the activity that goes undetected because no rule matches it.

That's also what keeps it from becoming alert fatigue. A rule loose enough to catch this stuff would page someone all day. A hunt puts the same activity in front of an analyst on a schedule, as a short list to review, so unusual behavior gets investigated without being turned into more alerts.

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

| # | Hunt | Question it answers | Technique |
| --- | --- | --- | --- |
| | **⚔️ Execution & Evasion** | | |
| 1 | 📧 Office Shell Spawn | Is an Office app launching a shell? | T1204 |
| 2 | ⚡ Highly Executed PowerShell | What PowerShell is running, and what's unusual in it? | T1059 |
| 3 | 🥷 EDR Evasion | Is anything tampering with endpoint protection or clearing logs? | T1562 / T1070 |
| 4 | 🧩 BYOVD / Unsigned Driver | Is a driver loading that shouldn't be? | T1014 / T1547.006 |
| 5 | 🔧 Rare Process as Service | Is something new persisting as a service or task via the command line? | T1543 / T1053 |
| 6 | 🖥️ Unapproved Remote Access Tools | Is a remote tool or tunnel running that IT didn't sanction? | T1219 / T1572 |
| 7 | 🌐 LOLBin Network Egress | Are built-in binaries reaching out to the internet? | T1071 / T1105 |
| | **🔑 Identity & Credentials** | | |
| 8 | 🕸️ Logon Fan-Out | Is one account logging into an unusual number of hosts? | T1078 |
| 9 | 👑 First-Seen Admin Logons | Is an admin logging in somewhere new? | T1078.002 |
| 10 | 🧪 Credential Dumping | Is anything touching LSASS or using dumping tools? | T1003 |
| 11 | 🎟️ Kerberoasting Signs | Is someone requesting or cracking service tickets? | T1558.003 |
| | **📌 Persistence** | | |
| 12 | 🗝️ Run Key / ASEP Changes | Did something add itself to autostart? | T1547.001 |
| 13 | ⏰ New Scheduled Tasks | What tasks were registered, and what do they run? | T1053.005 |
| 14 | 🧵 WMI Subscriptions | Is there WMI event persistence? | T1546.003 |
| 15 | 📂 Startup Folder Drops | Did a file land in a startup folder? | T1547.001 |
| | **↔️ Lateral Movement** | | |
| 16 | 🛠️ Remote Execution Tools | PsExec, remote services, WinRM, WMI, admin shares? | T1021 / T1569 |
| 17 | 🌉 RDP / SMB Fan-Out | Is one source reaching many hosts over RDP or network logon? | T1021.001 / .002 |

---

## 🎛️ Parameters

| Parameter | Use |
| --- | --- |
| `?Hostname` | Scope every widget to one host. Default `*` hunts fleet-wide |
| `?User` | Scope to one account. Default `*`. Useful once a hunt points at a specific identity |

> ⚠️ Endpoint hunts search raw sensor events (`ProcessRollup2`, `UserLogon`, `NetworkConnectIP4`, and so on). Every query uses a `?User` filter that defaults a missing `UserName` to `-`, so events without a user field are not dropped. If a hunt returns nothing, remove one filter line at a time to find the field that does not exist on that event, then swap in the real field name.

---

## ⚔️ Execution & Evasion

### 1. 📧 Office Shell Spawn

Classic phishing execution. Often the first event in a chain that later shows up as PowerShell or persistence.

```
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname
| default(field=UserName, value="-")
| UserName=?User
| in(ParentBaseFileName, values=["winword.exe","excel.exe","outlook.exe","powerpnt.exe","mspub.exe","visio.exe","onenote.exe"], ignoreCase=true)
| in(FileName, values=["cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe"], ignoreCase=true)
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, SHA256HashData], limit=200)
| sort(@timestamp, order=desc)
```

### 2. ⚡ Highly Executed PowerShell

Two views. The first surfaces suspicious patterns. The second counts by command line, so rare one-off commands stand out from routine noise.

```
// 2a. Suspicious patterns
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname
| default(field=UserName, value="-")
| UserName=?User
| in(FileName, values=["powershell.exe","pwsh.exe"], ignoreCase=true)
| (CommandLine=/(DownloadFile|DownloadString|DownloadData|Invoke-Expression|\biex\b|EncodedCommand|\s-enc\s|\s-ec\s|FromBase64String|Net\.WebClient|Start-BitsTransfer|Invoke-WebRequest)/i OR (CommandLine=/-WindowStyle\s+Hidden/i AND CommandLine=/-ExecutionPolicy\s+Bypass/i))
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine], limit=200)
| sort(@timestamp, order=desc)
```

```
// 2b. Frequency view: rare command lines sort to the top
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname
| default(field=UserName, value="-")
| UserName=?User
| in(FileName, values=["powershell.exe","pwsh.exe"], ignoreCase=true)
| groupBy([CommandLine], function=[count(as=Executions), count(ComputerName, distinct=true, as=Hosts)])
| sort(Executions, order=asc, limit=100)
```

### 3. 🥷 EDR Evasion

Highest-value hunt. An attacker blinding your tooling is time-sensitive.

```
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname
| default(field=UserName, value="-")
| UserName=?User
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

Persistence usually gets planted the same day as initial access. This catches it from the command line. Hunts 12 to 15 catch it from system events.

```
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname
| default(field=UserName, value="-")
| UserName=?User
| CommandLine=/(schtasks\s+\/create|\/sc\s+onlogon|\/sc\s+onstart|\/ru\s+system|New-ScheduledTask|Register-ScheduledTask|sc\s+create|New-Service)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=200)
| sort(@timestamp, order=desc)
```

### 6. 🖥️ Unapproved Remote Access Tools

Often the difference between "employee installed something" and "someone has hands on keyboard." TeamViewer and BeyondTrust are excluded as approved. Edit the list to match what IT actually sanctions.

```
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname
| default(field=UserName, value="-")
| UserName=?User
| in(FileName, values=["AnyDesk.exe","RustDesk.exe","QuickAssist.exe","AeroAdmin.exe","Supremo.exe","ammyy.exe","ScreenConnect.Client.exe","ConnectWiseControl.Client.exe","SplashtopSOS.exe","LogMeIn.exe","GoToAssist.exe","ZohoAssist.exe","RemotePC.exe","meshagent.exe","dwagent.exe","rutserv.exe","Radmin.exe","winvnc.exe","tvnserver.exe","uvnc_service.exe","vncviewer.exe","ngrok.exe","frpc.exe","chisel.exe","cloudflared.exe","plink.exe"], ignoreCase=true)
| case {
    in(FileName, values=["ngrok.exe","frpc.exe","chisel.exe","cloudflared.exe","plink.exe"], ignoreCase=true) | Tool := "Tunneling Tool";
    * | Tool := "Remote Tool" }
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

## 🔑 Identity & Credentials

### 8. 🕸️ Logon Fan-Out

Accounts that log into many different hosts. Normal for admins and service accounts. Unusual for everyone else. Sort by host count, then ask whether that account should be touching that many machines.

```
#event_simpleName=UserLogon
| ComputerName=?Hostname
| default(field=UserName, value="-")
| UserName=?User
| not UserName=/\$$/
| not UserName=/^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-.*|UMFD-.*)$/i
| groupBy([UserName], function=[count(ComputerName, distinct=true, as=HostsLoggedInto), count(as=Logons), min(@timestamp, as=FirstLogon)])
| test(HostsLoggedInto >= 5)
| sort(HostsLoggedInto, order=desc, limit=100)
```

### 9. 👑 First-Seen Admin Logons

Admin accounts logging in somewhere they haven't before. Run over a long window (30 days) so "first seen" means something.

```
#event_simpleName=UserLogon
| ComputerName=?Hostname
| default(field=UserName, value="-")
| UserName=?User
| UserIsAdmin=1
| not UserName=/\$$/
| groupBy([UserName, ComputerName], function=[min(@timestamp, as=FirstSeen), count(as=Logons)])
| now(as=NowMs)
| eval(AgeMs = NowMs - FirstSeen)
| test(AgeMs < 86400000)
| FirstSeen := formatTime("%Y-%m-%d %H:%M", field=FirstSeen)
| sort(FirstSeen, order=desc, limit=200)
```

### 10. 🧪 Credential Dumping

LSASS access and dumping tools. Highest-value identity hunt, since a hit here usually means credentials are already being taken.

```
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname
| default(field=UserName, value="-")
| UserName=?User
| CommandLine=/(mimikatz|sekurlsa|logonpasswords|lsadump|procdump.*lsass|comsvcs.*MiniDump|MiniDumpWriteDump|nanodump|lsass\.dmp|Out-Minidump|pypykatz|lsassy|Invoke-Mimikatz|DumpCreds)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, SHA256HashData], limit=200)
| sort(@timestamp, order=desc)
```

### 11. 🎟️ Kerberoasting Signs

Endpoint-side tooling for requesting and cracking service tickets. Ticket-level detection belongs in Falcon Identity Protection. This catches the tools.

```
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname
| default(field=UserName, value="-")
| UserName=?User
| CommandLine=/(Invoke-Kerberoast|GetUserSPNs|Rubeus.*kerberoast|setspn\s+-[ql]|Get-DomainSPNTicket|Request-SPNTicket)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=200)
| sort(@timestamp, order=desc)
```

---

## 📌 Persistence

### 12. 🗝️ Run Key / ASEP Changes

Autostart registry changes, grouped so one-off values stand out from routine software installs.

```
#event_simpleName=AsepValueUpdate
| ComputerName=?Hostname
| RegObjectName=/(\\Run|\\RunOnce|Winlogon|AppInit_DLLs|Image File Execution Options)/i
| groupBy([RegObjectName, RegValueName, RegStringValue], function=[count(ComputerName, distinct=true, as=Hosts), min(@timestamp, as=FirstSeen)])
| sort(Hosts, order=asc, limit=200)
```

### 13. ⏰ New Scheduled Tasks

Registered tasks and what they execute. Look for tasks pointing at user-writable paths, scripts, or odd binaries.

```
#event_simpleName=ScheduledTaskRegistered
| ComputerName=?Hostname
| default(field=UserName, value="-")
| UserName=?User
| table([@timestamp, ComputerName, UserName, TaskName, TaskExecCommand, TaskExecArguments], limit=200)
| sort(@timestamp, order=desc)
```

### 14. 🧵 WMI Subscriptions

WMI event subscriptions are a quiet, fileless persistence method. Legitimate use is rare, so hits are worth checking.

```
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname
| default(field=UserName, value="-")
| UserName=?User
| CommandLine=/(__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|__FilterToConsumerBinding|Register-WmiEvent|Set-WmiInstance)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=200)
| sort(@timestamp, order=desc)
```

### 15. 📂 Startup Folder Drops

Executables or scripts written into a startup folder.

```
#event_simpleName=/^(NewExecutableWritten|NewScriptWritten)$/
| ComputerName=?Hostname
| TargetFileName=/\\Start Menu\\Programs\\Startup\\/i
| table([@timestamp, ComputerName, ContextBaseFileName, TargetFileName, SHA256HashData], limit=200)
| sort(@timestamp, order=desc)
```

---

## ↔️ Lateral Movement

### 16. 🛠️ Remote Execution Tools

PsExec and its clones, remote service creation, WinRM, WMI remote execution, and admin share access.

```
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname
| default(field=UserName, value="-")
| UserName=?User
| (in(FileName, values=["psexec.exe","psexesvc.exe","paexec.exe","winrs.exe"], ignoreCase=true) OR CommandLine=/(Invoke-Command|Enter-PSSession|New-PSSession|wmic\s+\/node|Invoke-WmiMethod|Invoke-SMBExec|sc(\.exe)?\s+\\\\|\\\\[^\\\s]+\\(admin|c)\$)/i)
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=200)
| sort(@timestamp, order=desc)
```

### 17. 🌉 RDP / SMB Fan-Out

One source reaching many hosts through network or remote interactive logons. This is the "analyst follows the attacker from host to host" view.

```
#event_simpleName=UserLogon
| ComputerName=?Hostname
| default(field=UserName, value="-")
| UserName=?User
| in(LogonType, values=["3","10"])
| RemoteAddressIP4=*
| !cidr(RemoteAddressIP4, subnet=["127.0.0.0/8"])
| not UserName=/\$$/
| groupBy([RemoteAddressIP4, UserName], function=[count(ComputerName, distinct=true, as=HostsReached), count(as=Logons), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)])
| test(HostsReached >= 3)
| sort(HostsReached, order=desc, limit=100)
```

---

## 🚀 How to use it

1. Set `?Hostname` and/or `?User`, or leave both at `*` for a fleet-wide sweep.
2. Run **EDR Evasion** and **Credential Dumping** first. A hit on either raises the priority of everything else.
3. Work down the rest. Skim for what looks unusual, not for what's definitely bad.
4. When something looks off, pivot to the process tree and process timeline in Falcon for parent/child context and what ran before and after.
5. For identity leads, check the account in Falcon Identity Protection or Entra to confirm whether the activity is expected.
6. Decide: benign (note why), contain (isolate via Real Time Response), or escalate to IR.

> 💡 One hit on one hunt means little. The same host or user showing up across two or three hunts is the signal. For example: a first-seen admin logon (9), then a remote execution tool (16), then a new scheduled task (13) on the next host.

---

## 📌 Notes

- Some hunts (identity, ASEP, persistence) work best over a **7 to 30 day** range. Run the execution hunts at **24 hours** for a daily review.
- Exclusions and known-good parents are environment-specific. Keep them current, or the hunts will drown in noise.
- These are hunting aids, not detections. They surface activity for a human to review and don't alert on their own.
- Anything that proves high-fidelity should graduate into a scheduled search or custom IOA so it doesn't depend on someone remembering to look. That's how the hunt output stays small instead of becoming alert fatigue.
