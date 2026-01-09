# IPv6 Rotational C2 Simulator

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://golang.org/) [![License](https://img.shields.io/badge/License-Educational-orange.svg)](LICENSE) [![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/)

> **WARNING: EDUCATIONAL PURPOSE ONLY**
>
> This tool is designed exclusively for security research, threat hunting education, and authorized penetration testing. Unauthorized use of this tool against systems you do not own or have explicit permission to test is illegal and unethical.

## Overview

IPv6 Rotational C2 is a proof-of-concept Command and Control (C2) simulator that demonstrates how IPv6 address aliasing combined with rotational staggering can be used to evade network-based detection. The project serves as an educational tool for cybersecurity professionals, threat hunters, and network defenders to understand and detect advanced IPv6-based evasion techniques.

This tool is an accompaniment to the Active Countermeasures *Malware of the Day* report, which can be found [here](https://www.activecountermeasures.com/malware-of-the-day-ipv6-address-aliasing/).

### Key Features

- **IPv6 Address Aliasing**: Leverages multiple IPv6 addresses mapped to a single network interface
- **Rotational Staggering**: Maintains connections to one address for N requests before rotating, evading per-connection detection
- **Configurable Timing**: Sleep intervals with jitter to evade pattern-based detection
- **Variable Payload Sizes**: Random data sizes to avoid static traffic fingerprinting
- **Cross-Platform**: Agent and server support Windows, Linux, and macOS
- **Embedded Configuration**: Config file compiled into binary for operational simplicity
- **Random Initial Selection**: Agent starts with a randomly selected IPv6 address

## Quick Start

### Prerequisites

- Go 1.23 or higher
- IPv6-enabled network interface
- Administrative/root privileges for IPv6 address aliasing

### Installation

```bash
# Clone the repository
git clone https://github.com/faanross/IPv6_rotationalC2.git
cd IPv6_rotationalC2

# Install dependencies
go mod download

# Build server (Linux)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/server server/main.go

# Build agent (Linux)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/agent agent/main.go

# Build agent (Windows)
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o bin/agent.exe agent/main.go

# Build agent (macOS Apple Silicon)
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o bin/agent agent/main.go
```

### Configuration

#### Server Setup - IPv6 Address Aliasing

The server must have multiple IPv6 addresses configured on the same interface:

**Linux:**
```bash
sudo ip -6 addr add fe80::1111/64 dev eth0
sudo ip -6 addr add fe80::2222/64 dev eth0
sudo ip -6 addr add fe80::3333/64 dev eth0
# Repeat for additional addresses...
```

**macOS:**
```bash
sudo ifconfig en0 inet6 fe80::1111/64 alias
sudo ifconfig en0 inet6 fe80::2222/64 alias
sudo ifconfig en0 inet6 fe80::3333/64 alias
# Repeat for additional addresses...
```

**Windows:**
```powershell
netsh interface ipv6 add address "Ethernet" fe80::1111
netsh interface ipv6 add address "Ethernet" fe80::2222
netsh interface ipv6 add address "Ethernet" fe80::3333
# Repeat for additional addresses...
```

#### Agent Configuration

Edit `agent/config.json` before building:

```json
{
  "serverIPs": [
    "[fe80::1111]",
    "[fe80::2222]",
    "[fe80::3333]",
    "[fe80::4444]",
    "[fe80::5555]",
    "[fe80::6666]"
  ],
  "port": 8080,
  "sleep": 10,
  "jitter": 10,
  "data_jitter": 1000,
  "rotation_counter": 20
}
```

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serverIPs` | Array of IPv6 addresses (must be in square brackets) | Various fe80:: addresses |
| `port` | Server port to connect to | 8080 |
| `sleep` | Base sleep time in seconds between connections | 10 |
| `jitter` | Maximum random additional sleep time in seconds | 10 |
| `data_jitter` | Maximum size in bytes for random payload data | 1000 |
| `rotation_counter` | Number of connections before rotating to a new IP | 20 |

### Running the Demo

**Start the Server:**
```bash
./server
# Server starting on [::]:8080...
```

**Start the Agent:**
```bash
./agent
# Trying to connect to [fe80::3333] (remaining connections before rotation: 20)
# [14:32:05] Connected successfully to [fe80::3333] with 847 bytes of data
```

## How It Works

### IPv6 Address Aliasing

IPv6 allows multiple addresses to be assigned to a single network interface. Unlike IPv4 NAT, these are legitimate routable addresses. The server binds to `[::]` (all interfaces) and accepts connections on any of its aliased addresses.

```
                    Single Network Interface
                    ┌───────────────────────┐
                    │       eth0 / en0      │
                    │                       │
                    │  fe80::1111           │
                    │  fe80::2222           │
                    │  fe80::3333           │◄── All addresses
                    │  fe80::4444           │    reach same host
                    │  fe80::5555           │
                    │  fe80::6666           │
                    └───────────────────────┘
```

### Rotational Staggering

The key evasion technique is **staggered rotation** rather than per-connection rotation:

```
Traditional Rotation (Easily Detected):
  Connection 1 → fe80::1111
  Connection 2 → fe80::2222  ← Different IP every time = obvious pattern
  Connection 3 → fe80::3333
  ...

Staggered Rotation (Harder to Detect):
  Connections 1-20  → fe80::3333  ← Looks like normal traffic to one host
  Connections 21-40 → fe80::1111  ← Then shifts to another
  Connections 41-60 → fe80::5555
  ...
```

### Communication Flow

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              IPv6 Rotational C2 Flow                                │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────┐                              ┌─────────────────────┐
│       Agent         │                              │       Server        │
│     (Windows)       │                              │      (Linux)        │
│                     │                              │                     │
│  ┌───────────────┐  │                              │  ┌───────────────┐  │
│  │ Load Config   │  │                              │  │ Listen on     │  │
│  │ (embedded)    │  │                              │  │ [::]:8080     │  │
│  └───────┬───────┘  │                              │  └───────────────┘  │
│          │          │                              │          ▲          │
│          ▼          │                              │          │          │
│  ┌───────────────┐  │    HTTP POST + Random Data   │          │          │
│  │ Select Random │  │  ─────────────────────────►  │          │          │
│  │ Initial IP    │  │      fe80::3333:8080         │          │          │
│  └───────┬───────┘  │                              │  ┌───────┴───────┐  │
│          │          │                              │  │ Log Request   │  │
│          │          │                              │  │ IP + Size     │  │
│          │          │  ◄─────────────────────────  │  └───────────────┘  │
│          │          │      "Request received"      │                     │
│          ▼          │                              │                     │
│  ┌───────────────┐  │                              │                     │
│  │ Decrement     │  │    rotation_counter = 19     │                     │
│  │ Counter       │  │                              │                     │
│  └───────┬───────┘  │                              │                     │
│          │          │                              │                     │
│          ▼          │                              │                     │
│  ┌───────────────┐  │                              │                     │
│  │ Sleep         │  │    sleep + jitter (10-20s)   │                     │
│  │ (with jitter) │  │                              │                     │
│  └───────┬───────┘  │                              │                     │
│          │          │                              │                     │
│          ▼          │                              │                     │
│  ┌───────────────┐  │                              │                     │
│  │ Counter = 0?  │──┼─► No: Same IP, repeat        │                     │
│  │               │  │                              │                     │
│  │               │──┼─► Yes: Select new random IP  │                     │
│  └───────────────┘  │      Reset counter to 20     │                     │
│                     │                              │                     │
└─────────────────────┘                              └─────────────────────┘
```

### Evasion Mechanisms

| Mechanism | Description |
|-----------|-------------|
| **Address Rotation** | Cycles through multiple IPv6 addresses to distribute traffic |
| **Staggered Rotation** | Maintains each address for N connections before switching |
| **Timing Jitter** | Randomizes sleep intervals to avoid periodic patterns |
| **Payload Jitter** | Varies request payload sizes to avoid traffic fingerprinting |
| **Random Start** | Initial address is randomly selected, not sequential |

## Detection Guide

### Network-Based Detection

#### IPv6 Traffic Anomalies

**Detection Logic:**
- Multiple IPv6 addresses resolving to same MAC address
- HTTP traffic to link-local (fe80::) addresses from external networks
- Periodic connections with slight timing variations to related addresses

**Zeek Script Example:**
```zeek
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    if (is_v6_addr(c$id$resp_h) && /^fe80::/ in cat(c$id$resp_h))
    {
        NOTICE([$note=Potential_IPv6_C2,
                $msg=fmt("HTTP to link-local IPv6: %s", c$id$resp_h),
                $conn=c]);
    }
}
```

#### Traffic Pattern Analysis

**Indicators:**
- Multiple distinct IPv6 addresses contacted from same source
- All destination addresses share common prefix or pattern
- Periodic connection timing with jitter variance
- POST requests with varying payload sizes to same port

**Suricata Rule:**
```
alert http $HOME_NET any -> any any (msg:"Possible IPv6 Rotation C2";
    flow:established,to_server; http.method; content:"POST";
    ip6; threshold:type threshold,track by_src,count 5,seconds 300;
    sid:1000002; rev:1;)
```

### Host-Based Detection

#### Process Behavior

**Detection Points:**
- Process making periodic HTTP connections to IPv6 addresses
- Multiple distinct IPv6 destination addresses from single process
- Embedded configuration files in Go binaries
- Unsigned binaries with HTTP client capabilities

**Windows Event IDs:**
- 5156: Windows Filtering Platform allowed connection (IPv6)
- 4688: Process creation (correlate with network activity)

**Sysmon Configuration:**
```xml
<RuleGroup name="IPv6-C2-Detection" groupRelation="or">
    <NetworkConnect onmatch="include">
        <DestinationPort condition="is">8080</DestinationPort>
        <DestinationIsIpv6 condition="is">true</DestinationIsIpv6>
    </NetworkConnect>
</RuleGroup>
```

### Threat Hunting Queries

```sql
-- Hunt for IPv6 rotation patterns
SELECT
    source_ip,
    COUNT(DISTINCT dest_ipv6) as unique_destinations,
    COUNT(*) as connection_count,
    AVG(bytes_sent) as avg_payload_size,
    STDDEV(timestamp_diff) as timing_variance
FROM network_logs
WHERE dest_ipv6 LIKE 'fe80::%'
    AND timestamp > NOW() - INTERVAL '24 hours'
GROUP BY source_ip
HAVING COUNT(DISTINCT dest_ipv6) > 3
    AND COUNT(*) > 20;
```

## Mitigation Strategies

### Network Controls

1. **IPv6 Filtering**
   - Block or monitor link-local IPv6 traffic at network boundaries
   - Implement IPv6-aware egress filtering
   - Alert on multiple IPv6 addresses with same MAC

2. **Traffic Analysis**
   - Monitor for connection patterns to multiple related IPv6 addresses
   - Baseline normal IPv6 usage in your environment
   - Correlate IPv6 addresses with MAC/interface mappings

### Host Controls

1. **Application Whitelisting**
   - Restrict which applications can make IPv6 connections
   - Monitor for unsigned binaries with network capabilities

2. **Endpoint Detection**
   ```python
   # EDR pseudo-logic
   if (process.makes_http_requests and
       process.uses_ipv6 and
       process.destination_count > threshold and
       process.not_in_whitelist):
       alert_and_investigate()
   ```

## Project Structure

```
IPv6_rotationalC2/
├── agent/
│   ├── main.go        # Agent implementation
│   └── config.json    # Embedded configuration
├── server/
│   └── main.go        # Server implementation
├── go.mod             # Go module definition
├── go.sum             # Dependency checksums
├── README.md          # This file
└── LICENSE            # MIT License
```

## Limitations

### Technical Limitations

1. **IPv6 Requirement**
   - Both agent and server must have IPv6 connectivity
   - Link-local addresses require same network segment

2. **Configuration**
   - Config is embedded at build time
   - Changes require recompilation

3. **No Encryption**
   - HTTP traffic is plaintext (by design for educational visibility)
   - Production C2 would use TLS

### Detection Surface

Despite evasion attempts, this tool is detectable via:
- Multiple IPv6 addresses correlating to same MAC address
- HTTP traffic patterns to link-local addresses
- Timing analysis revealing jitter patterns
- Process monitoring for periodic connection behavior
- Network flow behavioral analysis

## Legal Disclaimer

This tool is provided for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before using this tool. The authors assume no liability for misuse or damage caused by this program.

**By using this software, you agree to:**

- Use it only in authorized environments
- Comply with all applicable laws and regulations
- Take full responsibility for your actions
- Not use it for malicious purposes

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by real-world evasion techniques leveraging IPv6 capabilities
- Built for the cybersecurity education community
- Part of the Active Countermeasures Malware of the Day series

## References

- [IPv6 Address Architecture RFC 4291](https://tools.ietf.org/html/rfc4291)
- [Active Countermeasures - IPv6 Address Aliasing](https://www.activecountermeasures.com/malware-of-the-day-ipv6-address-aliasing/)
- [MITRE ATT&CK - Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)

## Contact

For questions, issues, or security concerns, please open an issue on GitHub.
