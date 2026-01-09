# IPv6 Rotational C2 Agent Guide

This guide covers building, configuring, and deploying the agent.

## Overview

The agent is a beacon that:
- Rotates through multiple IPv6 addresses
- Uses staggered rotation (N connections per IP)
- Adds timing jitter to evade detection
- Sends random-sized payloads

## Build Process

### Building the Agent

```bash
# Clone repository
git clone https://github.com/faanross/IPv6_rotationalC2.git
cd IPv6_rotationalC2

# Build for current platform
go build -o bin/agent agent/main.go

# Cross-compile for Windows
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o bin/agent.exe agent/main.go

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/agent agent/main.go

# Cross-compile for macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o bin/agent_mac agent/main.go
```

## Configuration

### Embedded Configuration

The agent uses Go's `embed` package to compile configuration at build time.

Edit `agent/config.json` **before building**:

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

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `serverIPs` | []string | 6 addresses | Array of IPv6 target addresses |
| `port` | int | 8080 | Target server port |
| `sleep` | int | 10 | Base sleep time (seconds) |
| `jitter` | int | 10 | Maximum additional sleep (seconds) |
| `data_jitter` | int | 1000 | Maximum random payload size (bytes) |
| `rotation_counter` | int | 20 | Connections before rotating IP |

### IPv6 Address Format

Addresses **must** be in brackets:

```json
"serverIPs": [
    "[fe80::1111]",    // Correct
    "fe80::1111",      // WRONG - will fail validation
    "[2001:db8::1]",   // Correct (global address)
]
```

### Timing Calculations

```
Actual sleep = sleep + rand(0, jitter)

With defaults (sleep=10, jitter=10):
  Minimum: 10 + 0 = 10 seconds
  Maximum: 10 + 10 = 20 seconds
  Average: ~15 seconds
```

### Rotation Behavior

```
With rotation_counter=20:
  Connections 1-20:  → First random IP
  Connections 21-40: → Second random IP (different)
  Connections 41-60: → Third random IP (different)
  ...
```

## Agent Behavior

### Main Loop

```
┌─────────────────────────────────────────────────────────┐
│                     BEACON LOOP                          │
├─────────────────────────────────────────────────────────┤
│                                                          │
│   ┌──────────────────────────────────┐                   │
│   │ 1. Load embedded config.json     │                   │
│   │ 2. Validate IPv6 addresses       │                   │
│   │ 3. Select random initial IP      │                   │
│   │ 4. Set remaining = rotation_counter                  │
│   └──────────────┬───────────────────┘                   │
│                  │                                       │
│                  ▼                                       │
│   ┌──────────────────────────────────┐                   │
│   │ Generate random payload          │◄──────────────┐   │
│   │ (0 to data_jitter bytes)         │               │   │
│   └──────────────┬───────────────────┘               │   │
│                  │                                   │   │
│                  ▼                                   │   │
│   ┌──────────────────────────────────┐               │   │
│   │ POST to current IP:port          │               │   │
│   └──────────────┬───────────────────┘               │   │
│                  │                                   │   │
│                  ▼                                   │   │
│   ┌──────────────────────────────────┐               │   │
│   │ Decrement remaining              │               │   │
│   └──────────────┬───────────────────┘               │   │
│                  │                                   │   │
│          remaining <= 0?                             │   │
│           /            \                             │   │
│         NO              YES                          │   │
│          │               │                           │   │
│          │               ▼                           │   │
│          │   ┌──────────────────────────────────┐    │   │
│          │   │ Reset remaining = rotation_counter   │   │
│          │   │ Select NEW random IP              │    │   │
│          │   └──────────────┬───────────────────┘    │   │
│          │                  │                        │   │
│          └────────┬─────────┘                        │   │
│                   │                                  │   │
│                   ▼                                  │   │
│   ┌──────────────────────────────────┐               │   │
│   │ Sleep: base + rand(0, jitter)    │───────────────┘   │
│   └──────────────────────────────────┘                   │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Code Flow

```go
func main() {
    // Load embedded config
    config := loadConfig()

    // Validate IPv6 addresses
    for _, ip := range config.ServerIPs {
        if !ipv6Regex.Match([]byte(ip)) {
            log.Fatal("Invalid IPv6 format: " + ip)
        }
    }

    // Create HTTP client with timeout
    transport := &http.Transport{
        DialContext: (&net.Dialer{
            Timeout: 5 * time.Second,
        }).DialContext,
    }
    client := &http.Client{
        Transport: transport,
        Timeout:   2 * time.Second,
    }

    // Select random initial IP
    currentIPIdx := rand.Intn(len(config.ServerIPs))
    remainingConnections := config.RotationCounter

    // Main beacon loop
    for {
        // Log current state
        log.Printf("IP: %s, Remaining: %d",
            config.ServerIPs[currentIPIdx],
            remainingConnections)

        // Make request
        makeRequest(client, config.ServerIPs[currentIPIdx], config.Port)

        // Decrement counter
        remainingConnections--

        // Check for rotation
        if remainingConnections <= 0 {
            remainingConnections = config.RotationCounter

            // Select different IP
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
}
```

### Request Function

```go
func makeRequest(client *http.Client, ip string, port int) {
    // Generate random payload
    payload := generateRandomData(config.DataJitter)

    // Build URL
    url := fmt.Sprintf("http://%s:%d/", ip, port)

    // Create request
    req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
    if err != nil {
        log.Printf("Error creating request: %v", err)
        return
    }

    // Send request
    resp, err := client.Do(req)
    if err != nil {
        log.Printf("Error: %v", err)
        return
    }
    defer resp.Body.Close()

    log.Printf("Success: %s (%d bytes)", ip, len(payload))
}
```

## Deployment

### Pre-Deployment Checklist

1. **Configure IPv6 addresses**
   - Must match addresses on server
   - Use brackets: `[fe80::1111]`

2. **Adjust timing for stealth**
   ```json
   {
     "sleep": 60,
     "jitter": 30,
     "rotation_counter": 50
   }
   ```

3. **Build for target platform**
   ```bash
   GOOS=windows go build -o agent.exe agent/main.go
   ```

### Running the Agent

```bash
# Windows
.\agent.exe

# Linux/macOS
./agent
```

### Expected Output

```
[AGENT] Starting beacon loop
[AGENT] IP: [fe80::3333], Remaining: 20
[AGENT] Success: [fe80::3333] (847 bytes)
[AGENT] IP: [fe80::3333], Remaining: 19
[AGENT] Success: [fe80::3333] (234 bytes)
...
[AGENT] IP: [fe80::3333], Remaining: 1
[AGENT] Success: [fe80::3333] (512 bytes)
[AGENT] Rotating to new IP
[AGENT] IP: [fe80::1111], Remaining: 20
[AGENT] Success: [fe80::1111] (789 bytes)
```

### Quiet Mode

Build with logging disabled or redirect output:

```bash
# Windows
.\agent.exe > nul 2>&1

# Linux/macOS
./agent > /dev/null 2>&1 &
```

## Example Configurations

### Default (Lab Testing)

```json
{
  "serverIPs": ["[fe80::1111]", "[fe80::2222]", "[fe80::3333]"],
  "port": 8080,
  "sleep": 10,
  "jitter": 10,
  "data_jitter": 1000,
  "rotation_counter": 20
}
```

### High Stealth

```json
{
  "serverIPs": [
    "[2001:db8::1]",
    "[2001:db8::2]",
    "[2001:db8::3]",
    "[2001:db8::4]"
  ],
  "port": 443,
  "sleep": 300,
  "jitter": 180,
  "data_jitter": 500,
  "rotation_counter": 100
}
```

### Fast Testing

```json
{
  "serverIPs": ["[::1]"],
  "port": 8080,
  "sleep": 1,
  "jitter": 0,
  "data_jitter": 100,
  "rotation_counter": 5
}
```

## Troubleshooting

### Connection Refused

1. **Verify server is running**
   ```bash
   curl -X POST http://[fe80::1111%eth0]:8080/
   ```

2. **Check IPv6 connectivity**
   ```bash
   ping6 fe80::1111%eth0
   ```

3. **Verify address exists on server**
   ```bash
   ip -6 addr show | grep fe80::1111
   ```

### Invalid IPv6 Format

Ensure addresses are in brackets:
```json
"[fe80::1111]"  // Correct
"fe80::1111"    // Wrong
```

### Agent Crashes on Start

Check config.json is valid JSON:
```bash
cat agent/config.json | python3 -m json.tool
```

## Security Considerations

### Host Artifacts

- Running process (agent.exe)
- Network connections to IPv6 addresses
- Periodic HTTP POST traffic

### Network Artifacts

- HTTP to multiple IPv6 addresses
- Same MAC address for all destinations
- Periodic connection pattern

### Evasion Notes

Current implementation is educational. For operational use:
- Remove verbose logging
- Rename binary
- Add process injection
- Use HTTPS instead of HTTP

## Next Steps

- [Server Guide](server-guide.md) - Server setup
- [Detection Guide](detection-guide.md) - Understanding detection
- [Configuration Reference](configuration.md) - All options
