# IPv6 Rotational C2 Simulator

- A proof-of-concept tool that demonstrates how IPv6 can be used for command and control (C2) communications with multiple addresses mapping to the same interface (aliasing).
- Additionally, by staggering the rotations vs doing so on a per connection basis, a great degree of stealth can be achieved.
- The tool is an accompaniment to the [following blog article](https://www.activecountermeasures.com/malware-of-the-day-ipv6-address-aliasing/), which fully details its conceptualization, development, and intended use

## Overview

This simulator consists of two components:
- **Agent**: Rotates through a list of IPv6 addresses when making connections
- **Server**: Listens for connections and logs details about incoming traffic

By rotating through different IPv6 addresses in a staggered manner (see `rotation_counter` below), this simulator demonstrates a technique that could potentially make traffic analysis and filtering more difficult in real-world scenarios.

> **Note**: This tool is for educational and research purposes only. It should be used only in controlled environments with proper authorization.

## Features

- IPv6 address rotation for outbound connections
- Configurable `sleep` time between connections
- Random `jitter` to vary connection timing
- Configurable random data sizes (`data_jitter`)
- `rotation_counter` allows for amount of connections to a specific IP before randomly selecting a new one
- Separate JSON config file for easy configuration (`agent/config.json`)

## Setup Requirements

### Server Setup

The server must have IPv6 enabled and multiple IPv6 addresses configured on the same interface. To add IPv6 addresses to your interface:

#### Linux
```bash
# Add an IPv6 address to the interface
sudo ip -6 addr add fe80::1111/64 dev eth0

# Repeat for additional addresses
sudo ip -6 addr add fe80::2222/64 dev eth0
```

#### macOS
```bash
# Add an IPv6 address to the interface
sudo ifconfig en0 inet6 fe80::1111/64 alias

# Repeat for additional addresses
sudo ifconfig en0 inet6 fe80::2222/64 alias
```

#### Windows
```powershell
# Add an IPv6 address to the interface
netsh interface ipv6 add address "Ethernet" fe80::1111

# Repeat for additional addresses
netsh interface ipv6 add address "Ethernet" fe80::2222
```

## Installation

### Building from Source

#### Prerequisites
- Go 1.16 or higher


#### Building for Different Platforms

For Windows:
```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o bin/agent.exe agent/main.go
```

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o bin/server.exe server/main.go
```

For Linux:
```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/agent agent/main.go
```

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/server server/main.go
```


For macOS Intel Silicon:
```bash
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o bin/agent agent/main.go
```

```bash
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o bin/server server/main.go
```


For macOS Apple Silicon:
```bash
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o bin/agent agent/main.go
```

```bash
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o bin/server server/main.go
```

## Configuration

The agent uses a `config.json` file that is embedded into the binary at build time. Here's an example configuration file:

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

### Configuration Parameters

| Parameter | Description                                                     | Default |
|-----------|-----------------------------------------------------------------|---------|
| `serverIPs` | Array of IPv6 addresses (must be in square brackets)            | Various fe80:: addresses |
| `port` | The port to connect to on the server                            | 8080 |
| `sleep` | Base sleep time in seconds between connections                  | 10 |
| `jitter` | Maximum random additional sleep time in seconds                 | 10 |
| `data_jitter` | Maximum size in bytes for random data sent with each request    | 1000 |
| `rotation_counter` | Connection counts before rotating to a new randomly-selected IP | 20 | 

## Usage

### Running the Server
```bash
./server
```
The server will start and listen on all IPv6 addresses (`[::]`) on port 8080.

### Running the Agent
```bash
./agent
```
- The agent will begin by connecting to an IPv6 address randomly selected from list, sending a random-sized data payload.
- It will disconnect and wait until (`sleep` + `jitter`) seconds pass before reconnecting.
- It will also decrement `rotation_counter`.
- It will continue to connect to the same IP in this fashion until `rotation_counter` reaches 0, whereafter it will randomly select a new IP from the list.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is designed for educational and research purposes only. It should only be used in controlled environments with proper authorization. The authors are not responsible for any misuse or damage caused by this tool.