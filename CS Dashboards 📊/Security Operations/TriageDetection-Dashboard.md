# 🚨 Triage & Detection KPI

CrowdStrike Falcon dashboard for working the detection queue and measuring what's being detected. It answers two questions: **what should I triage first?** and **where is the noise and where are the trends?**

---

## 🎯 Why this exists

The Endpoint Defense Posture dashboard checks whether protection is healthy. This one covers what that protection is producing and how to handle it.

It has two sections:

| # | Section | Question it answers |
| --- | --- | --- |
| 1 | 🚨 **Triage** | What do I look at first, and what's the story on this host? |
| 2 | 📈 **Detection KPIs** | What's firing, how severe, and where is the noise worth tuning? |

> 💡 Some widgets also appear on Endpoint Defense Posture. That's intentional. They give context there, and the full view lives here.

---

## 🎛️ Parameters and time range

| Setting | Use |
| --- | --- |
| `?Hostname` | Filter to one host. Default `*` for the whole fleet. Set it to a single host for the Host Attack Path |
| Time range | **7 days** for triage. **30 days** for KPIs and the new-detection widget |

> ⚠️ Detection queries use the `detections` repo and `Event_EppDetectionSummaryEvent`. In your tenant the host field is `Hostname` (confirmed by a working query). Other detection fields (`Name`, `FileName`, `PatternDispositionDescription`, `Tactic`, `Technique`, `UserName`) follow that same working query. If a column shows blank in a widget, that field doesn't exist on your events, so swap it for the real one.

---

## 🚨 1. Triage

### ⏱️ Detection Timeline
*Table.* The main triage view. Newest first, severity flagged, with the context an analyst needs to decide quickly.

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

### 🧵 Host Attack Path
*Table.* Set `?Hostname` to one host. Oldest first, so the detections read as a story: what happened first and how it progressed through the tactics.

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

### ⚠️ High-Severity Detections That Weren't Blocked
*Table.* Each row is something serious that got through to detection only.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| in(SeverityName, values=["High","Critical"], ignoreCase=true)
| PatternDispositionDescription=/detection/i
| not PatternDispositionDescription=/blocked|prevented|quarantined|killed/i
| table([@timestamp, Hostname, SeverityName, Tactic, Name, FileName, CommandLine, PatternDispositionDescription], limit=200)
| sort(@timestamp, order=desc)
```

### 🆕 New Detection Types (Last 7 Days)
*Table.* Techniques that first appeared this week. New behavior is either a new threat or a new tool. Use a 30-day range.

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

---

## 📈 2. Detection KPIs

### 🧭 Detections by Severity Over Time
*Time chart (stacked).* Watch for spikes and for severity creeping up.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| timeChart(span=1d, series=SeverityName, function=count(as=Detections))
```

### 🎯 Detections by Tactic
*Bar chart.* Shows which parts of the attack path generate the most activity.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| groupBy([Tactic], function=count(as=Detections))
| sort(Detections, order=desc)
```

### 🧠 Detections by Technique
*Bar chart.* The top techniques seen, which maps directly to MITRE ATT&CK.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| groupBy([Technique], function=count(as=Detections))
| sort(Detections, order=desc, limit=15)
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

### 🛑 Blocked vs Detected Only
*Pie chart.* A large "detected only" share on high-severity detections is the clearest sign of a prevention gap.

```
#repo=detections #event_simpleName=Event_EppDetectionSummaryEvent
| Hostname=?Hostname
| groupBy([PatternDispositionDescription], function=count(as=Detections))
| sort(Detections, order=desc)
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

## 🚀 How to use it

1. **Start with the triage list.** Check Hosts Hitting Multiple Tactics and High-Severity Detections That Weren't Blocked first.
2. **Open the Detection Timeline** for the rest of the queue, newest first.
3. **Pick a host and read its Host Attack Path** to understand the progression before deciding to contain or escalate.
4. **Check New Detection Types** for anything that wasn't there last week.
5. **Review the KPI charts** weekly. Tune the noisiest detections and top triggering files, and watch severity and tactic trends.

---

## 🔜 Next: status-based KPIs

These need detection status data from the console or API, not the event stream, so they come later:

- Open vs closed detections
- Time to triage and time to close
- False positive rate (needs consistent analyst tagging)
- Detections per 100 hosts
- Blocked vs detected-only trend over time

---

## 📌 Notes

- A hit is a lead, not a verdict. Triage decides whether it's benign, contained, or escalated.
- Noisy detections are tuning opportunities, but confirm each one is truly benign before adding an exclusion.
- Detection data lives in the `detections` repo. Identity detections (`Event_IdpDetectionSummaryEvent`) and correlation rule detections (`Event_CorrelationRuleDetectionSummaryEvent`) are also available, and could become their own widgets.
- The version and host-type widgets depend on `aid_master_main.csv`. Adjust the `include=` list if columns differ in your tenant.