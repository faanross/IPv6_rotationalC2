# IPv6 Rotational C2 Architecture

This document describes the system architecture and the IPv6 address aliasing technique.

## Overview

IPv6 Rotational C2 demonstrates a novel evasion technique combining:

1. **IPv6 Address Aliasing**: Multiple IPv6 addresses on a single interface
2. **Staggered Rotation**: Maintaining connections before switching addresses
3. **Timing Jitter**: Randomized delays to avoid pattern detection
4. **Payload Variation**: Random data sizes to prevent fingerprinting

## IPv6 Address Aliasing

### How It Works

Unlike IPv4 NAT, IPv6 allows multiple legitimate addresses on a single interface:

```
Physical Interface (eth0/en0)
    │
    ├── [fe80::1111]  ─┐
    ├── [fe80::2222]  ─┤
    ├── [fe80::3333]  ─├─► All route to same server
    ├── [fe80::4444]  ─┤   listening on [::]
    ├── [fe80::5555]  ─┤
    └── [fe80::6666]  ─┘
```

When the server binds to `[::]` (IPv6 wildcard), it accepts connections on ALL aliased addresses.

### Setup Commands

**Linux:**
```bash
sudo ip -6 addr add fe80::1111/64 dev eth0
sudo ip -6 addr add fe80::2222/64 dev eth0
sudo ip -6 addr add fe80::3333/64 dev eth0
```

**macOS:**
```bash
sudo ifconfig en0 inet6 fe80::1111/64 alias
sudo ifconfig en0 inet6 fe80::2222/64 alias
sudo ifconfig en0 inet6 fe80::3333/64 alias
```

**Windows:**
```powershell
netsh interface ipv6 add address "Ethernet" fe80::1111
netsh interface ipv6 add address "Ethernet" fe80::2222
netsh interface ipv6 add address "Ethernet" fe80::3333
```

## System Components

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              TARGET NETWORK                                  │
│                                                                             │
│    ┌──────────────┐                                                         │
│    │    AGENT     │                                                         │
│    │              │                                                         │
│    │  - Beacon    │                                                         │
│    │  - Rotate IP │                                                         │
│    │  - Jitter    │                                                         │
│    └──────┬───────┘                                                         │
│           │                                                                 │
│           │ HTTP POST (random payload)                                      │
│           │                                                                 │
└───────────┼─────────────────────────────────────────────────────────────────┘
            │
            │ Rotation: Same IP for N connections, then switch
            │
            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              C2 SERVER                                       │
│                                                                             │
│    Physical Interface with Multiple IPv6 Addresses                          │
│    ┌─────────────────────────────────────────────────────────────────┐      │
│    │                                                                 │      │
│    │   [fe80::1111]  [fe80::2222]  [fe80::3333]                     │      │
│    │   [fe80::4444]  [fe80::5555]  [fe80::6666]                     │      │
│    │                                                                 │      │
│    │                All addresses → Same server                      │      │
│    │                                                                 │      │
│    └─────────────────────────────────────────────────────────────────┘      │
│                                                                             │
│    ┌──────────────┐                                                         │
│    │ HTTP Server  │  Listens on [::]:8080                                   │
│    │ (chi router) │  Accepts from any aliased address                       │
│    └──────────────┘                                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Server Component

Simple HTTP server using chi router:

```go
type Server struct {
    addr string  // "[::]" - all IPv6 interfaces
    port int     // 8080
}
```

**Endpoints:**
- `POST /` - Receives beacon data

### Agent Component

Beacon agent with staggered rotation:

```go
type Config struct {
    ServerIPs        []string  // Array of IPv6 targets
    Port             int       // 8080
    Sleep            int       // Base sleep seconds
    Jitter           int       // Additional random seconds
    DataJitter       int       // Random payload size
    RotationCounter  int       // Connections per IP
}
```

## Staggered Rotation Algorithm

### Traditional Rotation (Easily Detected)

```
Connection 1 → fe80::1111
Connection 2 → fe80::2222  ← Different every time
Connection 3 → fe80::3333
Connection 4 → fe80::4444

Detection: 1 unique IP per connection = obvious pattern
```

### Staggered Rotation (Harder to Detect)

```
Connections 1-20  → fe80::3333  ← Looks like normal traffic
Connections 21-40 → fe80::1111  ← Then shifts
Connections 41-60 → fe80::5555
Connections 61-80 → fe80::2222

Detection: Requires analyzing across many connections
```

### Algorithm Implementation

```go
// Initial selection: random IP
currentIPIdx := rand.Intn(len(config.ServerIPs))
remainingConnections := config.RotationCounter

for {
    // Make request to current IP
    makeRequest(config.ServerIPs[currentIPIdx])

    remainingConnections--

    // Rotation check
    if remainingConnections <= 0 {
        // Reset counter
        remainingConnections = config.RotationCounter

        // Select NEW random IP (different from current)
        newIPIdx := currentIPIdx
        for newIPIdx == currentIPIdx && len(config.ServerIPs) > 1 {
            newIPIdx = rand.Intn(len(config.ServerIPs))
        }
        currentIPIdx = newIPIdx
    }

    // Jittered sleep
    sleepTime := config.Sleep + rand.Intn(config.Jitter+1)
    time.Sleep(time.Duration(sleepTime) * time.Second)
}
```

## Communication Flow

```
AGENT                                                            SERVER
  │                                                                │
  │  1. Select random initial IP (fe80::3333)                      │
  │  2. Set remaining_connections = 20                             │
  │                                                                │
  │──── HTTP POST to [fe80::3333]:8080 ───────────────────────────►│
  │     + random payload (847 bytes)                               │
  │                                                                │
  │  3. Decrement counter (19)                                     │  4. Log request
  │  4. Sleep 10-20 seconds                                        │
  │                                                                │
  │◄──── "Request received" ───────────────────────────────────────│
  │                                                                │
  │  [Counter > 0, same IP]                                        │
  │                                                                │
  │──── HTTP POST to [fe80::3333]:8080 ───────────────────────────►│
  │     + random payload (234 bytes)                               │
  │                                                                │
  │     [Repeat 19 more times to same IP]                          │
  │                                                                │
  │  [Counter reaches 0]                                           │
  │  5. Select NEW random IP (fe80::1111)                          │
  │  6. Reset counter to 20                                        │
  │                                                                │
  │──── HTTP POST to [fe80::1111]:8080 ───────────────────────────►│
  │     + random payload (512 bytes)                               │
  │                                                                │
  │     [New cycle begins]                                         │
```

## Evasion Mechanisms

### 1. Staggered Rotation

- Each IP sees a "burst" of legitimate-looking connections
- Pattern analysis must span multiple rotation cycles
- Harder to correlate than per-connection rotation

### 2. Timing Jitter

```go
// Base sleep + random additional time
sleepTime := config.Sleep + rand.Intn(config.Jitter+1)

// With defaults (10 + 0-10):
// Range: 10-20 seconds between connections
```

### 3. Payload Randomization

```go
// Random data size: 0 to DataJitter bytes
size := rand.Intn(config.DataJitter + 1)
payload := make([]byte, size)
rand.Read(payload)
```

Prevents traffic fingerprinting based on packet sizes.

### 4. Random Initial Selection

```go
// Start with random IP, not first in list
currentIPIdx := rand.Intn(len(config.ServerIPs))
```

Avoids predictable startup patterns.

## Detection Surface

Despite evasion mechanisms, indicators exist:

| Indicator | Detection Method |
|-----------|------------------|
| Multiple IPv6 → same MAC | ARP/NDP correlation |
| Link-local HTTP traffic | Protocol anomaly |
| Periodic connections | Time-series analysis |
| IP rotation pattern | Connection correlation |

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Connection interval | 10-20 seconds |
| Connections per IP | 20 (configurable) |
| Payload size | 0-1000 bytes |
| Dial timeout | 5 seconds |
| Request timeout | 2 seconds |

## Security Considerations

### Advantages for Red Teams

- IPv6 traffic less monitored than IPv4
- Multiple IPs appear as different sources
- Staggered pattern harder to detect
- Timing jitter obscures patterns

### Detection Opportunities

- MAC address correlation reveals aliasing
- Link-local addresses unusual for external traffic
- HTTP to IPv6 link-local is suspicious
- Pattern analysis across time reveals rotation

## Next Steps

- [Server Guide](server-guide.md) - Setting up the server
- [Agent Guide](agent-guide.md) - Building and deploying agents
- [Detection Guide](detection-guide.md) - Detection strategies
