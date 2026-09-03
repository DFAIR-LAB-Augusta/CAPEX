# CAPEX Usage Guide

A full walkthrough for setting up CAPEX from a fresh clone and running a
capture against real lab hardware. See the [README](../README.md) for a
quick reference on config format and `make` targets; this document covers
the parts that need more context: prerequisites, lab-specific setup, and
what's safe to run out of the box.

**This framework generates real attack traffic against real devices.
Only run it against hardware you own or are explicitly authorized to
test, on a network isolated from anything else that matters.**

---

## 1. Prerequisites

### System packages

The attack library shells out to real security tools. Install them with:

```bash
./scripts/install-deps.sh
```

(Debian/Ubuntu-based hosts, run as root.) This installs `tcpdump`, `nmap`,
`hping3`, `slowhttptest`, `hydra`, and `dsniff` (which provides
`arpspoof`). On other distributions, install the equivalent packages from
your package manager.

### Privileges

Several attacks need raw-socket access or packet capture, which typically
requires root or the `CAP_NET_RAW`/`CAP_NET_ADMIN` capabilities:

* `tcpdump` (packet capture, always running during a session)
* `hping3`-based attacks (`tcp_syn_flood`, `xmas_flood`-style scans,
  `ssdp_reflection`, `mdns_reflection` — anything using `--spoof` needs
  raw sockets to forge the source address)
* `nmap` (some scan types need raw sockets)
* `arpspoof` (`arp_spoof` kind — sends raw ARP frames)

The simplest approach for a dedicated lab host is running CAPEX as root.
If you'd rather not, grant the specific binaries the capabilities they
need instead (e.g. `setcap cap_net_raw+ep $(which hping3)`).

### Python environment

```bash
make sync
```

or directly:

```bash
uv sync --dev
```

This does **not** install the system packages above — that's a separate
step (`install-deps.sh`), since they're OS binaries, not Python packages.

---

## 2. Setting up a new lab

### `configs/devices.yaml`

List the real devices in your lab. Each entry needs `name` and `ip`;
`enabled: false` (or commenting the entry out) excludes a device from a
run without deleting its config:

```yaml
devices:
  - name: nestCam
    ip: 192.168.1.196
    enabled: true
```

### `configs/attacks.yaml`

The shipped file has ~20 attacks spanning all 8 MITRE ATT&CK categories
the project targets (recon, credential access, application-layer, C2,
exfiltration, impact, reflection/amplification, ARP spoofing — see the
README's "Attack System" section for the full `kind` list). Most are
`enabled: true` and safe to run as-is against typical consumer IoT
hardware. Two things need attention before a new lab's first run:

**`config_tamper` entries default to `enabled: false`** (both the two
shipped entries and the model default for the kind itself). These send
real, protocol-correct config-tampering requests — a payload that
actually succeeds against a specific device's firmware could brick it.
Don't flip one to `enabled: true` without first confirming, for the
*specific device* you're pointing it at, that the request is safe (e.g.
by testing manually against a spare unit, or reading that device's
firmware documentation).

**`arp_spoof` entries have placeholder `interface`/`gateway_ip` values**
(`eth0` / `192.168.1.1`). Verify these match your actual lab NIC name
(`ip link` to check) and router address before enabling — poisoning the
wrong interface or gateway does nothing useful and may disrupt an
unrelated network if the values are wrong.

**Reflection attacks (`ssdp_reflection`, `mdns_reflection`) assume the
target device responds to SSDP/mDNS discovery.** Most consumer
smart-home hardware does; if a specific device in your lab doesn't
implement either protocol, that attack simply won't elicit a response
against it (not harmful, just inert traffic).

---

## 3. Running a capture

```bash
make dry-run
```

Loads both config files, validates them against the typed models, and
prints the execution plan — every device and every attack that will run,
with its repeat count — without touching the network. Run this after any
config change; a validation error here means a config error, not a
network issue.

```bash
make run
```

Runs the full capture across every enabled device for the configured
duration (default 8 hours, override with `DURATION=<seconds>`). Each
device gets `tcpdump` running for the whole window; attacks are scheduled
and spread across the window per-device, with a safe period at the start
and end where no attacks run (`SAFE_PERIOD`, default 15 minutes) so the
capture has clean baseline traffic.

```bash
make run-device DEVICE=nestCam
```

Same as above, scoped to one device — useful for testing a new attack or
config change without waiting on a full multi-device run.

### What to expect

* `data/raw/<device>_flow.pcap` — the packet capture for that device
* `data/logs/<device>_CE.txt` — a text log with one line per attack
  invocation: label, attempt number, timestamp, and any detail the
  executor reported (e.g. `requests=142` for a flood, `responses=2` for
  an SSDP probe)

A successful run produces a non-empty `.pcap` for every enabled device
and a `.txt` log with one line per scheduled attack repeat. If a log is
missing entries or a pcap is empty/truncated, check `make dry-run`'s
output against what actually ran, and check stderr for the failing
attack's underlying tool (most executors surface tool errors as
exceptions rather than swallowing them).

---

## 4. Safety notes (read this)

* Everything in this repo is real: real tools, real protocol traffic,
  real attacks against real hardware. Nothing here is simulated or
  sandboxed by CAPEX itself — isolation is your responsibility.
* Run this only on a network you control, containing only devices you're
  authorized to test. Don't run it on shared infrastructure, a
  production network, or anything with a device you can't afford to
  brick or disrupt.
* `arp_spoof` (especially `bidirectional: true`) affects traffic for the
  whole LAN segment while it runs, not just the target device.
* `config_tamper` entries are disabled by default for a reason — see
  above. Vet before enabling, per-device.
* If in doubt about whether a given attack/device combination is safe,
  don't enable it until you've checked.
