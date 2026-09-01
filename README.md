# CodeAlpha Security Tasks

A small Python security-learning portfolio focused on **networking, packet analysis, and local system inspection**.

[![CI](https://github.com/Wonderadroit/codealpha_tasks/actions/workflows/ci.yml/badge.svg)](https://github.com/Wonderadroit/codealpha_tasks/actions/workflows/ci.yml)

## Projects

### Network Sniffer

A lightweight Scapy-based packet-capture exercise that inspects IPv4 packets and reports TCP, UDP, and ICMP metadata.

```text
Interface → Capture → IPv4 detection → Protocol parsing → Metadata
```

### Process Utility

`ps.py` contains a separate exercise related to local process/system inspection.

## Requirements

- Python 3.11+
- Scapy

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Run the packet sniffer

Capture packets on an interface you are authorized to inspect:

```bash
sudo python network_sniffer.py <interface>
```

For example:

```bash
sudo python network_sniffer.py eth0
```

Packet capture privileges vary by operating system and environment.

## Test

The repository includes deterministic tests that construct packets in memory, so CI does not need access to a real network interface.

```bash
pytest -q
```

Python source compilation is also checked in CI:

```bash
python -m compileall -q .
```

## Continuous Integration

GitHub Actions runs the test suite and Python compilation checks on pushes and pull requests targeting `master` across Python 3.11, 3.12, and 3.13.

## Responsible use

Use packet-capture functionality only on networks, devices, and interfaces you are authorized to inspect. Do not intercept traffic belonging to other people or systems without permission.

See `SECURITY.md` for security-reporting guidance.

## Engineering notes

This repository intentionally contains small exercises. It is a **learning portfolio**, not production network-monitoring software. Automated tests validate the packet-processing logic but do not constitute a security audit.

## Status

**Learning portfolio / active refinement.**

## License

No license is currently specified.

---

**Author:** [Wonderadroit](https://github.com/Wonderadroit)
