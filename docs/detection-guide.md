# IPv6 Rotational C2 Detection Guide

This guide covers detection strategies for IPv6 rotational C2 traffic.

## Detection Overview

| Indicator | Detection Difficulty | Confidence |
|-----------|---------------------|------------|
| Multiple IPv6 → same MAC | Easy | High |
| Link-local HTTP traffic | Easy | Medium |
| Periodic connections | Medium | Medium |
| IP rotation pattern | Medium | High |
| Payload variation | Hard | Low |

## Network-Based Detection

### 1. MAC Address Correlation

Multiple IPv6 addresses pointing to the same MAC address is the primary indicator.

#### Zeek Script

```zeek
# ipv6_alias_detection.zeek
module IPv6_Alias;

export {
    redef enum Notice::Type += {
        IPv6_Aliasing_Detected
    };

    const alias_threshold = 3 &redef;
}

# Track IPv6 to MAC mappings
global ipv6_to_mac: table[addr] of string &create_expire=1hr;
global mac_to_ipv6: table[string] of set[addr] &create_expire=1hr;

event ndp_neighbor_advert(c: connection, icmp6: icmp6_info,
                          tgt: addr, options: icmp6_nd_options) {
    if (options?$link_layer) {
        local mac = options$link_layer;

        ipv6_to_mac[tgt] = mac;

        if (mac !in mac_to_ipv6)
            mac_to_ipv6[mac] = set();

        add mac_to_ipv6[mac][tgt];

        if (|mac_to_ipv6[mac]| >= alias_threshold) {
            NOTICE([
                $note=IPv6_Aliasing_Detected,
                $msg=fmt("MAC %s has %d IPv6 addresses (aliasing suspected)",
                        mac, |mac_to_ipv6[mac]|),
                $conn=c
            ]);
        }
    }
}
```

#### Splunk Query

```spl
index=network sourcetype=zeek:conn id.resp_h="fe80::*"
| stats dc(id.resp_h) as unique_ipv6, values(id.resp_h) as ipv6_list by resp_mac
| where unique_ipv6 > 2
| table resp_mac, unique_ipv6, ipv6_list
```

### 2. Link-Local HTTP Detection

HTTP traffic to link-local (fe80::) addresses is suspicious for external communication.

#### Suricata Rules

```
# Detect HTTP to link-local IPv6
alert http any any -> [fe80::/10] any (
    msg:"IPV6-C2 - HTTP to link-local IPv6 address";
    flow:established,to_server;
    classtype:trojan-activity;
    sid:1000001;
    rev:1;
)

# Detect periodic POST to IPv6
alert http any any -> any any (
    msg:"IPV6-C2 - HTTP POST to IPv6 address";
    flow:established,to_server;
    http.method;
    content:"POST";
    threshold:type both, track by_src, count 10, seconds 300;
    classtype:trojan-activity;
    sid:1000002;
    rev:1;
)
```

#### Zeek Script

```zeek
# link_local_http.zeek
module LinkLocal_HTTP;

export {
    redef enum Notice::Type += {
        LinkLocal_HTTP_Detected
    };
}

const link_local_prefix = fe80::/10;

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) {
    local dest = c$id$resp_h;

    if (dest in link_local_prefix) {
        NOTICE([
            $note=LinkLocal_HTTP_Detected,
            $msg=fmt("HTTP %s to link-local %s%s",
                    method, dest, original_URI),
            $conn=c
        ]);
    }
}
```

### 3. Rotation Pattern Detection

Detecting the staggered rotation pattern requires connection correlation.

#### Python Detection Script

```python
#!/usr/bin/env python3
"""Detect IPv6 rotational C2 patterns."""

from collections import defaultdict
from datetime import datetime, timedelta
import statistics

class IPv6RotationDetector:
    def __init__(self):
        self.connections = defaultdict(list)  # src -> [(time, dest_ipv6)]
        self.rotation_threshold = 3  # Different IPs

    def add_connection(self, src_ip, dest_ipv6, timestamp):
        self.connections[src_ip].append((timestamp, dest_ipv6))

    def analyze(self):
        suspicious = []

        for src_ip, conns in self.connections.items():
            if len(conns) < 20:
                continue

            # Sort by time
            conns = sorted(conns, key=lambda x: x[0])

            # Count unique destination IPs
            dest_ips = set(c[1] for c in conns)

            if len(dest_ips) >= self.rotation_threshold:
                # Check for staggered pattern
                pattern = self._detect_stagger(conns)

                if pattern:
                    suspicious.append({
                        'src_ip': src_ip,
                        'dest_ips': list(dest_ips),
                        'connection_count': len(conns),
                        'stagger_size': pattern['avg_burst'],
                        'confidence': 'HIGH' if pattern['consistent'] else 'MEDIUM'
                    })

        return suspicious

    def _detect_stagger(self, conns):
        """Detect staggered rotation pattern."""
        current_ip = conns[0][1]
        burst_sizes = []
        current_burst = 1

        for i in range(1, len(conns)):
            if conns[i][1] == current_ip:
                current_burst += 1
            else:
                burst_sizes.append(current_burst)
                current_ip = conns[i][1]
                current_burst = 1

        burst_sizes.append(current_burst)

        if len(burst_sizes) < 2:
            return None

        avg_burst = statistics.mean(burst_sizes)
        stdev = statistics.stdev(burst_sizes) if len(burst_sizes) > 1 else 0

        # Consistent burst sizes indicate staggered rotation
        consistent = stdev / avg_burst < 0.3 if avg_burst > 0 else False

        return {
            'avg_burst': avg_burst,
            'burst_sizes': burst_sizes,
            'consistent': consistent
        }

# Example usage
detector = IPv6RotationDetector()

# Simulate connections
from datetime import datetime
base_time = datetime.now()
ips = ['fe80::1111', 'fe80::2222', 'fe80::3333']

for i in range(60):
    ip_idx = i // 20  # Change every 20 connections
    timestamp = base_time + timedelta(seconds=i*15)
    detector.add_connection('192.168.1.100', ips[ip_idx % len(ips)], timestamp)

results = detector.analyze()
for r in results:
    print(f"[ROTATION] {r['src_ip']} -> {len(r['dest_ips'])} IPv6 addresses")
    print(f"           Pattern: ~{r['stagger_size']:.0f} conns/IP ({r['confidence']})")
```

### 4. Timing Analysis

Detect jittered but periodic connections.

#### Splunk Query

```spl
index=network sourcetype=zeek:conn id.resp_h="fe80::*"
| sort _time
| streamstats current=f last(_time) as prev_time by id.orig_h
| eval interval = _time - prev_time
| where interval > 0
| stats avg(interval) as avg_interval,
        stdev(interval) as stdev_interval,
        count
  by id.orig_h
| where count > 10
| eval cv = stdev_interval / avg_interval
| where avg_interval >= 10 AND avg_interval <= 30 AND cv < 0.5
| table id.orig_h, count, avg_interval, stdev_interval, cv
```

### 5. Payload Size Variation

Random payload sizes indicate anti-fingerprinting.

#### Zeek Script

```zeek
# payload_variance.zeek
module Payload_Variance;

export {
    redef enum Notice::Type += {
        High_Payload_Variance
    };
}

global http_sizes: table[addr] of vector of count &create_expire=1hr;

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) {
    local src = c$id$orig_h;

    if (src !in http_sizes)
        http_sizes[src] = vector();

    # Record content length
    if (c?$http && c$http?$request_body_len) {
        http_sizes[src] += c$http$request_body_len;

        if (|http_sizes[src]| >= 10) {
            # Calculate variance
            local sizes = http_sizes[src];
            local sum = 0.0;
            for (i in sizes)
                sum += sizes[i];
            local mean = sum / |sizes|;

            local variance = 0.0;
            for (i in sizes)
                variance += (sizes[i] - mean) * (sizes[i] - mean);
            variance /= |sizes|;

            # High variance with HTTP to IPv6 is suspicious
            if (variance > 10000 && c$id$resp_h in fe80::/10) {
                NOTICE([
                    $note=High_Payload_Variance,
                    $msg=fmt("High payload size variance from %s (var=%.0f)",
                            src, variance),
                    $conn=c
                ]);
            }
        }
    }
}
```

## Host-Based Detection

### Sysmon Configuration

```xml
<Sysmon schemaversion="4.50">
    <EventFiltering>
        <!-- Network connections to IPv6 -->
        <NetworkConnect onmatch="include">
            <DestinationIp condition="begin with">fe80:</DestinationIp>
            <DestinationIp condition="begin with">2001:</DestinationIp>
        </NetworkConnect>

        <!-- HTTP POST activity -->
        <NetworkConnect onmatch="include">
            <DestinationPort condition="is">8080</DestinationPort>
            <Initiated condition="is">true</Initiated>
        </NetworkConnect>
    </EventFiltering>
</Sysmon>
```

### Windows Event Queries

```powershell
# Find connections to IPv6 addresses
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 3  # Network connection
} | Where-Object {
    $_.Message -match 'fe80::|2001:'
} | Select-Object TimeCreated, Message

# Count unique IPv6 destinations per process
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 3
} | Where-Object {
    $_.Message -match 'DestinationIp: (fe80|2001)'
} | Group-Object { $_.Message -match 'Image: (.+)' | Out-Null; $matches[1] }
```

## SIEM Rules

### Sigma Rule: IPv6 Aliasing

```yaml
title: Multiple IPv6 Addresses to Same MAC
id: a1b2c3d4-ipv6-alias-detection
status: experimental
description: Detects potential IPv6 aliasing used for C2 evasion
logsource:
    category: network
    product: zeek
detection:
    selection:
        event_type: ndp
    condition: selection
    # Additional logic needed for MAC correlation
falsepositives:
    - Legitimate IPv6 address assignment
level: medium
tags:
    - attack.command_and_control
    - attack.t1090.003
```

### Sigma Rule: Link-Local HTTP

```yaml
title: HTTP Traffic to IPv6 Link-Local Address
id: b2c3d4e5-linklocal-http
status: experimental
description: Detects HTTP traffic to link-local IPv6 addresses
logsource:
    category: proxy
detection:
    selection:
        dest_ip|startswith: 'fe80:'
        http_method: POST
    condition: selection
level: high
tags:
    - attack.command_and_control
    - attack.t1071.001
```

## IOC Summary

### Network Indicators

| Indicator | Type | Confidence |
|-----------|------|------------|
| HTTP to fe80::/10 | Protocol | High |
| Multiple IPv6 → 1 MAC | Network | High |
| Periodic HTTP POST | Behavior | Medium |
| Staggered IP rotation | Pattern | High |
| Variable payload sizes | Traffic | Low |

### Host Indicators

| Indicator | Detection |
|-----------|-----------|
| Process with IPv6 connections | Sysmon Event 3 |
| Periodic network activity | Process monitoring |
| HTTP client behavior | Network forensics |

### MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Proxy | T1090.003 | Multi-hop proxy (IPv6 aliasing) |
| Application Layer Protocol | T1071.001 | HTTP for C2 |
| Data Obfuscation | T1001 | Payload randomization |
| Non-Standard Port | T1571 | Port 8080 |

## Hunting Workflow

### Step 1: Identify IPv6 HTTP Traffic

```
Search for HTTP to IPv6 addresses
→ Focus on fe80::/10 (link-local)
→ Check for POST method
```

### Step 2: MAC Address Correlation

```
For suspicious IPv6 destinations:
→ Correlate via NDP/neighbor cache
→ Check if multiple IPv6 → same MAC
→ Count unique addresses per MAC
```

### Step 3: Pattern Analysis

```
For sources with multiple IPv6 destinations:
→ Build connection timeline
→ Look for burst patterns (N conns per IP)
→ Calculate timing statistics
```

### Step 4: Validate Findings

```
Investigate suspicious hosts:
→ Check running processes
→ Review network connections
→ Examine process creation history
```

## Next Steps

- [Architecture](architecture.md) - System design
- [Agent Guide](agent-guide.md) - Agent behavior
- [Configuration Reference](configuration.md) - All options
