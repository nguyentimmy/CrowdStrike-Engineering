# 🛡️ Endpoint Defense Posture

All-in-one CrowdStrike Falcon dashboard for endpoint security health. It answers one question: **is our endpoint protection running everywhere, working as intended, and tuned well?**

---

## 🎯 Why this exists

Hunting finds what protection misses. This dashboard checks the protection itself. A sensor that isn't reporting, a rule that's too noisy, or a policy sitting in detect-only mode all create quiet gaps that nothing alerts on.

It brings four views into one place, ordered from the foundation up:

| # | Section | Question it answers |
| --- | --- | --- |
| 1 | 🩺 **Sensor Health** | Is the sensor running and healthy on every host? |
| 2 | 📈 **Detection Trends & Timeline** | What's firing, how severe, where is the noise, and what should I triage first? |
| 3 | 🎯 **Custom IOA / IOC Health** | Which of our own rules are working, noisy, or dead weight? |
| 4 | 🧱 **Prevention Coverage** | Are we blocking, or only detecting? Are settings actually on? |

> 💡 Read it bottom-up when troubleshooting: if a host's sensor is unhealthy, nothing above it can be trusted for that host.

---

## 🎛️ Parameters and time range

| Setting | Use |
| --- | --- |
| `?Hostname` | Filter to one host. Default `*` for the whole fleet |
| Time range | **30 days** for Sensor Health (the silent-host widgets need a long window). **7 to 30 days** for detections and IOA/IOC |

> ⚠️ Detection queries use the `detections` repo and `Event_EppDetectionSummaryEvent`. In your tenant the host field is `Hostname` (confirmed by a working query). Other detection fields (`Name`, `FileName`, `PatternDispositionDescription`, `Tactic`, `Technique`, `UserName`) follow that same working query. If a column shows blank in a widget, that field doesn't exist on your events, so swap it for the real one.

---

## 🩺 1. Sensor Health

### 🟢 Active Hosts (24h)
*Single value.*

```
#event_simpleName=SensorHeartbeat
| ComputerName=?Hostname
| now(as=NowMs)
| eval(AgeMs = NowMs - @timestamp)
| test(AgeMs < 86400000)
| count(aid, distinct=true, as=ActiveHosts)
```

### 🔴 Silent 3+ Days
*Single value.*

```
#event_simpleName=SensorHeartbeat
| ComputerName=?Hostname
| groupBy([aid], function=max(@timestamp, as=LastSeen))
| now(as=NowMs)
| eval(SilentMs = NowMs - LastSeen)
| test(SilentMs > 259200000)
| count(aid, as=SilentHosts)
```

### 📈 Hosts Reporting Over Time
*Time chart.* A drop is an outage or failed rollout. A slow decline is hosts quietly falling off.

```
#event_simpleName=SensorHeartbeat
| ComputerName=?Hostname
| timeChart(span=1d, function=count(aid, distinct=true, as=HostsReporting))
```

### 🧬 Sensor Version Distribution
*Pie or bar chart.* Small slices are the hosts to chase.

```
#event_simpleName=SensorHeartbeat
| ComputerName=?Hostname
| groupBy([aid], function=[])
| match(file="aid_master_main.csv", field=[aid], include=[AgentVersion], strict=false)
| groupBy([AgentVersion], function=count(aid, as=Hosts))
| sort(Hosts, order=desc)
```

### 🖥️ Workstations vs Servers vs DCs
*Pie chart.*

```
#event_simpleName=SensorHeartbeat
| ComputerName=?Hostname
| groupBy([aid], function=[])
| match(file="aid_master_main.csv", field=[aid], include=[ProductType], strict=false)
| case {
    ProductType = "1" | HostType := "Workstation";
    ProductType = "2" | HostType := "Domain Controller";
    ProductType = "3" | HostType := "Server";
    * | HostType := "Unknown"}
| groupBy([HostType], function=count(aid, as=Hosts))
```

### ⏳ Silent-Host Aging
*Bar chart.* Quiet for a day is usually a laptop. Quiet for weeks is a real gap.

```
#event_simpleName=SensorHeartbeat
| ComputerName=?Hostname
| groupBy([aid], function=max(@timestamp, as=LastSeen))
| now(as=NowMs)
| eval(DaysSilent = (NowMs - LastSeen) / 86400000)
| case {
    DaysSilent < 1  | Bucket := "0-1 days";
    DaysSilent < 3  | Bucket := "1-3 days";
    DaysSilent < 7  | Bucket := "3-7 days";
    DaysSilent < 14 | Bucket := "7-14 days";
    * | Bucket := "14+ days"}
| groupBy([Bucket], function=count(aid, as=Hosts))
```

### 🚨 Unhealthy Sensors

The work queue. Four ways a sensor can be unhealthy.

**A. Stale hosts.** Gone quiet. *Table.*

```
#event_simpleName=SensorHeartbeat
| ComputerName=?Hostname
| groupBy([aid, ComputerName], function=max(@timestamp, as=LastSeen))
| now(as=NowMs)
| eval(DaysSilent = (NowMs - LastSeen) / 86400000)
| test(DaysSilent >= 3)
| format("%.0f", field=[DaysSilent], as=DaysSilent)
| match(file="aid_master_main.csv", field=[aid], include=[AgentVersion, Version, MachineDomain, OU], strict=false)
| LastSeen := formatTime("%Y-%m-%d %H:%M", field=LastSeen)
| table([ComputerName, DaysSilent, LastSeen, AgentVersion, Version, MachineDomain, OU], limit=200)
| sort(DaysSilent, order=desc)
```

**B. Alive but not sending telemetry.** Heartbeating, but no process events. The sensor is up and not collecting, which is worse than a host that's simply offline. *Table.*

```
#event_simpleName=/^(SensorHeartbeat|ProcessRollup2)$/
| ComputerName=?Hostname
| groupBy([aid, ComputerName], function=[
    {#event_simpleName=SensorHeartbeat | count(as=Heartbeats)},
    {#event_simpleName=ProcessRollup2 | count(as=ProcessEvents)}
  ], limit=max)
| default(field=ProcessEvents, value=0)
| test(Heartbeats > 0)
| test(ProcessEvents == 0)
| sort(Heartbeats, order=desc, limit=200)
```

**C. Reconnect-heavy hosts.** Flapping. Usually a flaky network or proxy issue, sleep behavior, or a sensor restarting. *Table.*

```
#event_simpleName=AgentOnline
| ComputerName=?Hostname
| groupBy([aid, ComputerName], function=[count(as=Reconnects), max(@timestamp, as=LastOnline)])
| LastOnline := formatTime("%Y-%m-%d %H:%M", field=LastOnline)
| sort(Reconnects, order=desc, limit=50)
```

**D. Outdated sensors.** Hosts on a version other than the fleet's most common one. *Table.*

```
#event_simpleName=SensorHeartbeat
| ComputerName=?Hostname
| groupBy([aid, ComputerName], function=[])
| match(file="aid_master_main.csv", field=[aid], include=[AgentVersion, Version], strict=false)
| groupBy([AgentVersion], function=[count(aid, as=Hosts), collect([ComputerName], limit=25)])
| sort(Hosts, order=asc)
```

---

## 📈 2. Detection Trends & Timeline

### 🧭 Detections by Severity Over Time
*Time chart (stacked).* Watch for spikes and for severity creeping up.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| timeChart(span=1d, series=SeverityName, function=count(as=Detections))
```

### 🎯 Detections by Tactic
*Bar chart.* Shows which parts of the attack path are generating the most activity.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| groupBy([Tactic], function=count(as=Detections))
| sort(Detections, order=desc)
```

### 🖥️ Detections by Host Type
*Pie chart.* Servers and DCs generating detections matter more than laptops.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| match(file="aid_master_main.csv", field=Hostname, column=ComputerName, include=[ProductType], strict=false)
| case {
    ProductType = "1" | HostType := "Workstation";
    ProductType = "2" | HostType := "Domain Controller";
    ProductType = "3" | HostType := "Server";
    * | HostType := "Unknown"}
| groupBy([HostType], function=count(as=Detections))
```

### 🔥 What's Firing (All Detections)
*Table.* Every detection type that fired, by category and technique, with how many hosts it hit and when it last fired. The quickest read on what's active.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| groupBy([Name, Technique], function=[count(as=Fires), count(Hostname, distinct=true, as=Hosts), max(@timestamp, as=LastFired)])
| LastFired := formatTime("%Y-%m-%d %H:%M", field=LastFired)
| sort(Fires, order=desc, limit=50)
```

### 🔊 Noisiest Detections
*Table.* The top tuning candidates. `Name` is a broad category (Suspicious Activity, Ransomware), so `Technique` carries the detail. High count on many hosts usually means a benign tool or a rule that needs an exclusion.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| groupBy([Technique, Tactic, Name, SeverityName], function=[count(as=Detections), count(Hostname, distinct=true, as=Hosts)])
| sort(Detections, order=desc, limit=25)
```

### 🔁 Top Repeat Hosts
*Table.* The same host showing up again and again means either a real problem or a tool that keeps tripping.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| groupBy([Hostname], function=[count(as=Detections), count(Name, distinct=true, as=UniqueDetections), max(@timestamp, as=LastDetection)])
| LastDetection := formatTime("%Y-%m-%d %H:%M", field=LastDetection)
| sort(Detections, order=desc, limit=25)
```

### ⏱️ Detection Timeline (Triage)
*Table.* The main triage view. Newest first, severity flagged, with the context an analyst needs to decide quickly. Narrow it with `?Hostname` or the time range.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| case {
    SeverityName = "Critical" | Sev := "🔴 Critical";
    SeverityName = "High"     | Sev := "🟠 High";
    SeverityName = "Medium"   | Sev := "🟡 Medium";
    * | Sev := "⚪ Low"}
| Time := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp)
| table([Time, Sev, Hostname, UserName, Tactic, Technique, Name, FileName, CommandLine, PatternDispositionDescription], limit=500)
| sort(Time, order=desc)
```

### 🧵 Host Attack Path (Single Host)
*Table.* Set `?Hostname` to one host. Oldest first, so the detections read as a story: what happened first, and how it progressed through the tactics.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| Time := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp)
| table([Time, Tactic, Technique, Name, SeverityName, FileName, CommandLine, PatternDispositionDescription], limit=500)
| sort(Time, order=asc)
```

### 🚨 Hosts Hitting Multiple Tactics
*Table.* A host with detections across three or more tactics looks like an attack progressing, not a one-off. Triage these first.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| groupBy([Hostname], function=[count(Tactic, distinct=true, as=TacticsHit), count(as=Detections), collect([Tactic], limit=10), max(@timestamp, as=LastDetection)])
| test(TacticsHit >= 3)
| LastDetection := formatTime("%Y-%m-%d %H:%M", field=LastDetection)
| sort(TacticsHit, order=desc, limit=50)
```

### 🧠 Detections by Technique
*Bar chart.* The top techniques seen, which maps directly to MITRE ATT&CK.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| groupBy([Technique], function=count(as=Detections))
| sort(Detections, order=desc, limit=15)
```

### 🆕 New Detection Types (Last 7 Days)
*Table.* Techniques that first appeared this week. New behavior in your environment is worth a look, since it's either a new threat or a new tool. Use a 30-day range.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| groupBy([Technique, Tactic, Name, SeverityName], function=[min(@timestamp, as=FirstSeen), count(as=Detections), count(Hostname, distinct=true, as=Hosts)])
| now(as=NowMs)
| eval(AgeMs = NowMs - FirstSeen)
| test(AgeMs < 604800000)
| FirstSeen := formatTime("%Y-%m-%d %H:%M", field=FirstSeen)
| sort(Detections, order=desc, limit=50)
```

### 🕒 Detections by Hour of Day
*Bar chart.* Detections clustering outside business hours can point to hands-on-keyboard activity or automation running off-schedule.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| Hour := formatTime("%H", field=@timestamp)
| groupBy([Hour], function=count(as=Detections))
| sort(Hour, order=asc)
```

### 👤 Detections by User
*Table.* Accounts tied to the most detections. Useful for spotting a compromised account or a user who keeps running risky tools.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| UserName=*
| groupBy([UserName], function=[count(as=Detections), count(Hostname, distinct=true, as=Hosts), count(Name, distinct=true, as=UniqueDetections)])
| sort(Detections, order=desc, limit=25)
```

### 🧾 Top Triggering Files
*Bar chart.* The files and processes behind the most detections. A common benign binary at the top usually means a tuning opportunity.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| groupBy([FileName], function=[count(as=Detections), count(Hostname, distinct=true, as=Hosts)])
| sort(Detections, order=desc, limit=15)
```

---

## 🎯 3. Custom IOA / IOC Health

Custom rules normally show up in detection events under the **Custom Intelligence** tactic. The filter below also catches "indicator" techniques and detections with "custom" in the name. If nothing has fired in the window, these widgets stay empty. That is expected, not a bug. Use a 30 to 90 day range, or trigger a test rule to confirm.

### 🔥 What's Firing
*Table.* Every custom rule that has fired, with volume and reach.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| (Tactic="Custom Intelligence" OR Technique=/indicator of (attack|compromise)/i OR Name=/custom/i)
| groupBy([Name, Technique], function=[count(as=Fires), count(Hostname, distinct=true, as=Hosts), max(@timestamp, as=LastFired)])
| LastFired := formatTime("%Y-%m-%d %H:%M", field=LastFired)
| sort(Fires, order=desc, limit=50)
```

### 🔊 Noisy Custom Rules
*Bar chart.* Rules firing far more than anything else are tuning candidates, or are catching something real that's being ignored.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| (Tactic="Custom Intelligence" OR Technique=/indicator of (attack|compromise)/i OR Name=/custom/i)
| groupBy([Name], function=count(as=Fires))
| sort(Fires, order=desc, limit=15)
```

### 📉 Custom Rule Activity Over Time
*Time chart.* A rule that fired daily and went quiet might be fixed, or might be broken.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| (Tactic="Custom Intelligence" OR Technique=/indicator of (attack|compromise)/i OR Name=/custom/i)
| timeChart(span=1d, series=Name, function=count(as=Fires))
```

### 💤 Rules That Never Fire

Event data can only show rules that **did** fire, so it can't list rules that never did. To find the dead ones:

1. Export your custom IOA rules and IOC list from the console (or with the API or PSFalcon).
2. Compare that list to **What's Firing** above.
3. Rules with no hits over 30 to 90 days are candidates to review, retire, or fix.

> 💡 A rule that never fires isn't automatically bad. A rule for a rare threat should be quiet. What matters is whether you know *why* it's quiet.

---

## 🧱 4. Prevention Coverage

Event data shows what prevention **did**. Policy settings live in the console. This section uses both.

### 🛑 Blocked vs Detected Only
*Pie chart.* A large "detected only" share on high-severity detections is the clearest sign of a prevention gap.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| groupBy([PatternDispositionDescription], function=count(as=Detections))
| sort(Detections, order=desc)
```

### ⚠️ High-Severity Detections That Weren't Blocked
*Table.* The work queue. Each row is something serious that got through to detection only.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| in(SeverityName, values=["High","Critical"], ignoreCase=true)
| PatternDispositionDescription=/detection/i
| not PatternDispositionDescription=/blocked|prevented|quarantined|killed/i
| table([@timestamp, Hostname, SeverityName, Tactic, Name, FileName, CommandLine, PatternDispositionDescription], limit=200)
| sort(@timestamp, order=desc)
```

### 🏷️ Detect-Only Hosts

A policy in detect-only mode can't be seen from event data, so check these in the console:

| Check | Where to look |
| --- | --- |
| Hosts by prevention policy | Host Management, filter by policy |
| Prevention settings turned off | Endpoint Security, Prevention Policies, review each toggle |
| Hosts on a default or unexpected policy | Host Management, group by policy and host group |
| Hosts not in any host group | Host Management, filter for no group |
| Sensor update policy compliance | Sensor Update Policies, review the version per group |
| Reduced functionality mode | Host Management, filter by RFM state |

For a repeatable report, pull policies with the API or PSFalcon (for example `Get-FalconPreventionPolicy -Detailed -All`) and review them as a table.

---

## 🚀 How to use it

1. **Start with Sensor Health.** If hosts are silent or alive-but-not-collecting, fix those first, since nothing else can be trusted for them.
2. **Check Detection Trends.** Look for spikes, severity creep, and the noisiest detections.
3. **Review custom rules.** Tune the noisy ones. Compare against your exported rule list to find the dead ones.
4. **Check Prevention.** Work the "high severity, not blocked" list, then review policy settings in the console.
5. Turn what you tune into changes: exclusions, rule edits, policy fixes. Record each change so you can show the effect later.

---

## 📌 Notes

- A silent host isn't always unhealthy. Laptops, travel, and PTO create gaps. Judge by pattern, not by one host.
- Clean decommissioned hosts out of Falcon so they don't inflate the silent count.
- The version, OS, and host-type widgets depend on `aid_master_main.csv`. Adjust the `include=` lists if columns differ in your tenant.
- Detection data lives in the `detections` repo. Identity detections (`Event_IdpDetectionSummaryEvent`) and correlation rule detections (`Event_CorrelationRuleDetectionSummaryEvent`) are also available, and could become their own widgets.
- **Next step:** a coverage % against a baseline, using your AD or Intune host list as a lookup file. That needs the list uploaded to Falcon.