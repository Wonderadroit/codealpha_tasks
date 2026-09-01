# CodeAlpha Security Tasks

A collection of small Python security and networking exercises completed while developing practical cybersecurity skills.

## Projects

### Network Sniffer
A lightweight packet-sniffing exercise built with **Scapy**. It inspects IP traffic and reports TCP, UDP, and ICMP packet information.

```text
Interface → Packet Capture → Protocol Detection → Packet Details
```

### Process Utility
`ps.py` contains a separate Python exercise focused on local process/system inspection.

## Requirements

- Python 3
- Scapy for `network_sniffer.py`
- An environment where packet capture is permitted

## Running the network sniffer

Install the dependency:

```bash
pip install scapy
```

Then import or call the packet-sniffing function from Python with an authorized network interface.

> Packet capture can require elevated privileges depending on the operating system. Only capture traffic on networks and devices you are authorized to inspect.

## Purpose

This repository is primarily a **learning portfolio**: small, focused exercises that demonstrate hands-on work with Python, networking, and security tooling.

## Status

Educational project. Individual exercises may be intentionally simple and are not presented as production security software.

## License

No license is currently specified.

---

**Author:** [Wonderadroit](https://github.com/Wonderadroit)
