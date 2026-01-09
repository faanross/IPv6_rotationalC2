# IPv6 Rotational C2 Documentation

Welcome to the IPv6 Rotational C2 documentation. This guide provides comprehensive information about the IPv6 address aliasing evasion technique.

## Documentation Index

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | System design and IPv6 aliasing technique |
| [Server Guide](server-guide.md) | Setting up the C2 server |
| [Agent Guide](agent-guide.md) | Building and configuring agents |
| [Detection Guide](detection-guide.md) | Detection strategies for blue teams |
| [Configuration Reference](configuration.md) | Complete configuration options |

## Quick Links

- [Main README](../README.md) - Project overview and quick start
- [GitHub Repository](https://github.com/faanross/IPv6_rotationalC2)
- [Related Research](https://www.activecountermeasures.com/)

## Background

IPv6 Rotational C2 demonstrates how IPv6 address aliasing can be combined with staggered rotation for evasion. Understanding this technique helps:

- **Red Teams**: Learn IPv6-based evasion techniques
- **Blue Teams**: Develop detection for IPv6 abuse
- **Security Researchers**: Study network protocol manipulation
- **Students**: Understand IPv6 and C2 architecture

## The Technique

Traditional IP rotation changes addresses every connection, which is easily detected. Staggered rotation maintains the same address for N connections before switching, mimicking legitimate traffic patterns.

```
Traditional (Detectable):
  Conn 1 → IP-A
  Conn 2 → IP-B  ← Different every time
  Conn 3 → IP-C

Staggered (Harder to Detect):
  Conn 1-20  → IP-A  ← Looks normal
  Conn 21-40 → IP-B  ← Then shifts
  Conn 41-60 → IP-C
```

## Getting Help

If you have questions:

1. Check the relevant documentation section
2. Search existing GitHub issues
3. Open a new issue with the `question` label
