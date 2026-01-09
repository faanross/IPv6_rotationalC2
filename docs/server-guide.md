# IPv6 Rotational C2 Server Guide

This guide covers setting up and operating the C2 server.

## Overview

The server is a simple HTTP endpoint that:
- Listens on all IPv6 interfaces (`[::]`)
- Accepts POST requests from agents
- Logs connection metadata

## Prerequisites

### System Requirements

- Go 1.23 or higher
- Linux server (recommended)
- IPv6 connectivity
- Root privileges (for adding IPv6 addresses)

### Network Requirements

- IPv6 enabled on network interface
- Ability to add alias addresses
- Port 8080 open in firewall

## Installation

### Building the Server

```bash
# Clone repository
git clone https://github.com/faanross/IPv6_rotationalC2.git
cd IPv6_rotationalC2

# Install dependencies
go mod download

# Build for Linux
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/server server/main.go

# Build for current platform
go build -o bin/server server/main.go
```

## IPv6 Address Setup

### Adding Alias Addresses

The server receives connections on multiple IPv6 addresses. Add them to your interface:

**Linux:**
```bash
# Add multiple fe80:: addresses
sudo ip -6 addr add fe80::1111/64 dev eth0
sudo ip -6 addr add fe80::2222/64 dev eth0
sudo ip -6 addr add fe80::3333/64 dev eth0
sudo ip -6 addr add fe80::4444/64 dev eth0
sudo ip -6 addr add fe80::5555/64 dev eth0
sudo ip -6 addr add fe80::6666/64 dev eth0

# Verify addresses
ip -6 addr show dev eth0
```

**macOS:**
```bash
# Add alias addresses
sudo ifconfig en0 inet6 fe80::1111/64 alias
sudo ifconfig en0 inet6 fe80::2222/64 alias
sudo ifconfig en0 inet6 fe80::3333/64 alias

# Verify
ifconfig en0 | grep inet6
```

**Windows (PowerShell as Admin):**
```powershell
netsh interface ipv6 add address "Ethernet" fe80::1111
netsh interface ipv6 add address "Ethernet" fe80::2222
netsh interface ipv6 add address "Ethernet" fe80::3333

# Verify
netsh interface ipv6 show addresses
```

### Making Addresses Persistent

**Linux (systemd-networkd):**

Create `/etc/systemd/network/10-eth0.network`:
```ini
[Match]
Name=eth0

[Network]
Address=fe80::1111/64
Address=fe80::2222/64
Address=fe80::3333/64
Address=fe80::4444/64
Address=fe80::5555/64
Address=fe80::6666/64
```

```bash
sudo systemctl restart systemd-networkd
```

**Linux (netplan):**

Edit `/etc/netplan/01-netcfg.yaml`:
```yaml
network:
  version: 2
  ethernets:
    eth0:
      addresses:
        - fe80::1111/64
        - fe80::2222/64
        - fe80::3333/64
        - fe80::4444/64
        - fe80::5555/64
        - fe80::6666/64
```

```bash
sudo netplan apply
```

## Configuration

### Server Constants

The server has minimal configuration in `server/main.go`:

```go
const (
    addr = "[::]"   // Listen on all IPv6 addresses
    port = 8080     // HTTP port
)
```

| Option | Value | Description |
|--------|-------|-------------|
| `addr` | `[::]` | IPv6 wildcard (all interfaces) |
| `port` | `8080` | HTTP listen port |

## Running the Server

### Basic Startup

```bash
./bin/server
```

### Expected Output

```
[SERVER] Starting HTTP server on [::]:8080
[SERVER] Ready to receive connections
```

### Connection Logs

```
[REQUEST] 2024-01-20 14:32:05 | Source: [fe80::3333]:52841 | Size: 847 bytes
[REQUEST] 2024-01-20 14:32:18 | Source: [fe80::3333]:52842 | Size: 234 bytes
[REQUEST] 2024-01-20 14:32:31 | Source: [fe80::3333]:52843 | Size: 512 bytes
...
[REQUEST] 2024-01-20 14:45:12 | Source: [fe80::1111]:52860 | Size: 789 bytes
```

Note how the source IP changes after multiple connections (rotation).

### Running as Service

Create systemd service `/etc/systemd/system/ipv6-c2.service`:

```ini
[Unit]
Description=IPv6 Rotational C2 Server
After=network.target

[Service]
Type=simple
User=nobody
WorkingDirectory=/opt/ipv6-c2
ExecStart=/opt/ipv6-c2/server
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable ipv6-c2
sudo systemctl start ipv6-c2
sudo systemctl status ipv6-c2
```

## Server Implementation Details

### Handler Function

```go
func RootHandler(w http.ResponseWriter, r *http.Request) {
    // Read request body
    body, _ := io.ReadAll(r.Body)

    // Log connection details
    log.Printf("[REQUEST] %s | Source: %s | Size: %d bytes",
        time.Now().Format("2006-01-02 15:04:05"),
        r.RemoteAddr,
        len(body))

    // Respond
    w.Write([]byte("Request received"))
}
```

### Router Setup

```go
func SetupRoutes() *chi.Mux {
    r := chi.NewRouter()
    r.Post("/", RootHandler)
    return r
}
```

### Server Binding

```go
func main() {
    router := SetupRoutes()
    address := fmt.Sprintf("%s:%d", addr, port)

    log.Printf("[SERVER] Starting HTTP server on %s", address)
    http.ListenAndServe(address, router)
}
```

The key is binding to `[::]` which accepts connections on ANY IPv6 address assigned to the interface.

## Verification

### Test Single Address

```bash
curl -X POST -d "test" http://[fe80::1111%eth0]:8080/
```

Note: Link-local addresses require zone ID (`%eth0`).

### Test Multiple Addresses

```bash
for ip in fe80::1111 fe80::2222 fe80::3333; do
    curl -X POST -d "test from $ip" "http://[$ip%eth0]:8080/"
done
```

All should respond - same server, different addresses.

### Check Server Logs

```bash
journalctl -u ipv6-c2 -f
```

## Troubleshooting

### Port Already in Use

```bash
# Find process using port
sudo lsof -i :8080

# Kill if needed
sudo kill -9 <PID>
```

### IPv6 Not Working

```bash
# Check IPv6 is enabled
cat /proc/sys/net/ipv6/conf/all/disable_ipv6
# Should be 0

# Enable if disabled
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
```

### Addresses Not Persisting

```bash
# Check network manager
systemctl status NetworkManager

# If using NetworkManager, use nmcli instead
nmcli connection modify "Wired" +ipv6.addresses "fe80::1111/64"
```

### Firewall Blocking

```bash
# UFW
sudo ufw allow 8080/tcp

# firewalld
sudo firewall-cmd --add-port=8080/tcp --permanent
sudo firewall-cmd --reload

# iptables
sudo ip6tables -A INPUT -p tcp --dport 8080 -j ACCEPT
```

## Security Considerations

### Operational Security

1. **Use dedicated infrastructure**
2. **Monitor for scanning attempts**
3. **Rotate IPv6 addresses periodically**
4. **Use non-standard ports if possible**

### Network Indicators

The server generates:
- HTTP responses on port 8080
- Connections from multiple IPv6 addresses
- Same MAC for all addresses

## Next Steps

- [Agent Guide](agent-guide.md) - Deploying agents
- [Detection Guide](detection-guide.md) - Detection strategies
- [Architecture](architecture.md) - System design
