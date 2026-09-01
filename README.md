# CodeAlpha Security Tasks

A small collection of Python exercises focused on **networking, packet analysis, and system inspection**. The repository documents hands-on learning work rather than production security software.

## Projects

### Network Sniffer

A lightweight packet-capture exercise using **Scapy**. It inspects IPv4 packets and reports TCP, UDP, and ICMP metadata such as addresses, ports, and protocol information.

```text
Network Interface → Packet Capture → Protocol Detection → Packet Metadata
```

### Process Utility

`ps.py` contains a separate Python exercise related to local system/process inspection.

## Requirements

- Python 3
- Scapy for the packet-sniffing exercise
- An environment where packet capture is permitted

Install Scapy:

```bash
python -m pip install scapy
```

Packet capture may require elevated privileges depending on the operating system.

## Responsible use

Use packet-capture functionality only on networks, devices, and interfaces you are authorized to inspect. Do not use this project to intercept traffic belonging to other people or systems without permission.

See `SECURITY.md` for security-reporting guidance.

## Engineering notes

This repository intentionally contains small exercises. The code is useful as a record of practical learning and experimentation, but it is **not presented as production-grade monitoring or security software**.

Future improvements may include automated tests, clearer module boundaries, stronger input handling, and documented execution examples.

## Status

**Learning portfolio / active refinement.**

## License

No license is currently specified.

---

**Author:** [Wonderadroit](https://github.com/Wonderadroit)
