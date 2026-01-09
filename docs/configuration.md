# IPv6 Rotational C2 Configuration Reference

Complete reference for all configuration options.

## Configuration Files

| File | Purpose | Location |
|------|---------|----------|
| Agent config | Agent settings | `agent/config.json` |
| Server constants | Server settings | `server/main.go` |

## Agent Configuration

### Configuration File

Located at `agent/config.json` (embedded at build time):

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
| `serverIPs` | []string | 6 addresses | IPv6 target addresses (must be in brackets) |
| `port` | int | 8080 | Target HTTP port |
| `sleep` | int | 10 | Base sleep time in seconds |
| `jitter` | int | 10 | Maximum additional random sleep in seconds |
| `data_jitter` | int | 1000 | Maximum random payload size in bytes |
| `rotation_counter` | int | 20 | Connections before rotating to new IP |

### IPv6 Address Format

**Required format:** Addresses must be enclosed in brackets.

```json
// Correct
"serverIPs": [
    "[fe80::1111]",
    "[2001:db8::1]",
    "[::1]"
]

// Incorrect - will fail validation
"serverIPs": [
    "fe80::1111",      // Missing brackets
    "[fe80::1111",     // Missing closing bracket
    "fe80::1111]"      // Missing opening bracket
]
```

### Validation Rules

```go
// IPv6 validation regex
ipv6Regex := regexp.MustCompile(`^\[[:0-9a-fA-F]+\]$`)

// Validation checks:
// 1. At least one IP address required
// 2. All addresses must match regex
// 3. rotation_counter must be positive
```

### Timing Calculations

**Sleep Duration:**
```
actual_sleep = sleep + rand(0, jitter)

Examples with defaults (sleep=10, jitter=10):
  Minimum: 10 + 0 = 10 seconds
  Maximum: 10 + 10 = 20 seconds
  Average: ~15 seconds
```

**Payload Size:**
```
payload_size = rand(0, data_jitter)

Examples with default (data_jitter=1000):
  Minimum: 0 bytes (empty)
  Maximum: 1000 bytes
  Average: ~500 bytes
```

### Rotation Behavior

```
Connections 1 to rotation_counter:    Use first IP
Connection rotation_counter+1:         Switch to new random IP
Connections to 2*rotation_counter:     Use second IP
...

Note: New IP is always different from current (if multiple IPs configured)
```

## Server Configuration

### Server Constants

Located in `server/main.go`:

```go
const (
    addr = "[::]"   // Listen on all IPv6 interfaces
    port = 8080     // HTTP port
)
```

| Option | Value | Description |
|--------|-------|-------------|
| `addr` | `[::]` | IPv6 wildcard address |
| `port` | `8080` | HTTP listen port |

### Binding Explanation

```go
// "[::]" is the IPv6 equivalent of "0.0.0.0"
// It binds to ALL IPv6 addresses on ALL interfaces

// This means the server accepts connections on:
// - fe80::1111
// - fe80::2222
// - fe80::3333
// - Any other IPv6 address assigned to any interface
```

## HTTP Client Configuration

### Timeout Settings

```go
// Dial timeout for connections
transport := &http.Transport{
    DialContext: (&net.Dialer{
        Timeout: 5 * time.Second,
    }).DialContext,
}

// Overall request timeout
client := &http.Client{
    Transport: transport,
    Timeout:   2 * time.Second,
}
```

| Timeout | Value | Description |
|---------|-------|-------------|
| Dial | 5 seconds | TCP connection establishment |
| Request | 2 seconds | Overall HTTP request |

## Example Configurations

### Default (Lab Testing)

```json
{
  "serverIPs": [
    "[fe80::1111]",
    "[fe80::2222]",
    "[fe80::3333]"
  ],
  "port": 8080,
  "sleep": 10,
  "jitter": 10,
  "data_jitter": 1000,
  "rotation_counter": 20
}
```

**Behavior:**
- 3 IPv6 addresses
- 10-20 second intervals
- 0-1000 byte payloads
- 20 connections per IP
- ~20 minutes per rotation cycle

### High Stealth

```json
{
  "serverIPs": [
    "[2001:db8::1]",
    "[2001:db8::2]",
    "[2001:db8::3]",
    "[2001:db8::4]",
    "[2001:db8::5]",
    "[2001:db8::6]",
    "[2001:db8::7]",
    "[2001:db8::8]"
  ],
  "port": 443,
  "sleep": 300,
  "jitter": 180,
  "data_jitter": 256,
  "rotation_counter": 100
}
```

**Behavior:**
- 8 global IPv6 addresses
- 5-8 minute intervals
- Small payloads (≤256 bytes)
- 100 connections per IP
- ~14 hours per rotation cycle

### Fast Testing

```json
{
  "serverIPs": [
    "[::1]"
  ],
  "port": 8080,
  "sleep": 1,
  "jitter": 0,
  "data_jitter": 100,
  "rotation_counter": 5
}
```

**Behavior:**
- Localhost only
- 1 second intervals (no jitter)
- Small payloads
- 5 connections before "rotation"

### Minimal (Single IP)

```json
{
  "serverIPs": [
    "[fe80::1111]"
  ],
  "port": 8080,
  "sleep": 10,
  "jitter": 5,
  "data_jitter": 500,
  "rotation_counter": 50
}
```

**Behavior:**
- Single target (no rotation)
- 10-15 second intervals
- rotation_counter has no effect with single IP

## Environment Variables

The project does not use environment variables. All configuration is via:
- `config.json` for agent (embedded at build)
- Constants in source for server

## Build Configuration

### Go Build Flags

```bash
# Standard build
go build -o agent agent/main.go

# Static linking (no external dependencies)
CGO_ENABLED=0 go build -o agent agent/main.go

# Strip debug info (smaller binary)
go build -ldflags="-s -w" -o agent agent/main.go

# All optimizations
CGO_ENABLED=0 go build -ldflags="-s -w" -o agent agent/main.go
```

### Cross-Compilation

```bash
# Windows x64
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o agent.exe agent/main.go

# Linux x64
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o agent agent/main.go

# macOS Intel
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o agent_mac agent/main.go

# macOS Apple Silicon
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o agent_mac_arm agent/main.go
```

## Directory Structure

```
IPv6_rotationalC2/
├── agent/
│   ├── main.go         # Agent source
│   └── config.json     # Agent configuration (embedded)
├── server/
│   └── main.go         # Server source
├── bin/                # Build output (gitignored)
├── go.mod
├── go.sum
└── README.md
```

## Validation

### Agent Startup Validation

```go
// 1. Load config.json
config, err := loadConfig()

// 2. Validate IPv6 format
ipv6Regex := regexp.MustCompile(`^\[[:0-9a-fA-F]+\]$`)
for _, ip := range config.ServerIPs {
    if !ipv6Regex.Match([]byte(ip)) {
        log.Fatal("Invalid IPv6 format: " + ip)
    }
}

// 3. Validate at least one IP
if len(config.ServerIPs) == 0 {
    log.Fatal("At least one server IP required")
}

// 4. Validate rotation counter
if config.RotationCounter <= 0 {
    log.Fatal("rotation_counter must be positive")
}
```

### Server Startup Validation

- Server has no configuration file
- Validates port availability at startup
- Logs binding address on success

## Performance Tuning

### For Stealth

```json
{
  "sleep": 300,          // Long base interval
  "jitter": 180,         // Wide jitter range
  "rotation_counter": 100 // Many connections per IP
}
```

### For Throughput

```json
{
  "sleep": 5,            // Short interval
  "jitter": 2,           // Minimal jitter
  "rotation_counter": 10 // Frequent rotation
}
```

### For Testing

```json
{
  "sleep": 1,
  "jitter": 0,
  "rotation_counter": 3
}
```

## Next Steps

- [Agent Guide](agent-guide.md) - Agent deployment
- [Server Guide](server-guide.md) - Server setup
- [Detection Guide](detection-guide.md) - Detection strategies
