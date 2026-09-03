# CAPEX: Capture for Evaluation

CAPEX is a configurable framework for orchestrating network traffic capture and controlled attack generation for intrusion detection and concept drift research.

It is designed to support reproducible dataset creation for systems such as FIRE and conformal evaluation pipelines, with an emphasis on structured configuration, extensibility, and modern Python practices.

---

## Overview

CAPEX provides:

* Config driven orchestration of network captures and attack execution
* Typed models and validation for devices and attack definitions
* Extensible attack system with registry based dispatch
* Structured logging and reproducible experiment outputs
* Integration with tcpdump and downstream flow generation tools

The system is intended for controlled environments such as lab networks, testbeds, or isolated research deployments.

---

## Project Structure

```text
.
├── configs/              # YAML configuration for devices and attacks
├── data/
│   ├── legacy/          # Historical datasets and artifacts
│   ├── logs/            # Attack event logs
│   └── raw/             # Captured PCAP files
├── scripts/             # Utility and legacy scripts
├── src/capex/           # Main application package
│   ├── attacks/         # Attack implementations and registry
│   ├── services/        # Capture orchestration logic
│   ├── cli.py           # Command line interface
│   ├── models.py        # Typed configuration models
│   ├── runner.py        # Command execution wrapper
│   ├── scheduler.py     # Attack scheduling logic
│   ├── capture.py       # Tcpdump integration
│   ├── config.py        # YAML loading
│   ├── validation.py    # Runtime validation
│   ├── paths.py         # Path helpers
│   ├── logging_utils.py # Logging configuration
│   └── exceptions.py    # Custom exception types
├── tests/               # Unit and integration tests
├── pyproject.toml       # Project configuration
└── Makefile             # Development commands
```

---

## Configuration

CAPEX is driven by YAML configuration files.

### Devices

`configs/devices.yaml`

```yaml
devices:
  - name: nestCam
    ip: 192.168.1.196
    enabled: true
```

### Attacks

`configs/attacks.yaml`

```yaml
attacks:
  - name: tcp_syn_flood
    label: TCP_SYN_Flood
    kind: command
    enabled: true
    repeats: 3
    command:
      - hping3
      - -S
      - -c
      - "100"
      - -p
      - "443"
      - "{target_ip}"
```

Attack types are resolved through the internal registry and can be extended without modifying orchestration logic.

---

## Usage

### Install dependencies

```bash
make sync
```

or directly:

```bash
uv sync --dev
```

---

### Validate configuration

```bash
make dry-run
```

This loads configs, validates them, and prints the execution plan without running anything.

---

### Run full capture

```bash
make run
```

---

### Run for a single device

```bash
make run-device DEVICE=nestCam
```

---

### Run tests

```bash
make test
```

---

## Output

* PCAP files are written to `data/raw/`
* Attack logs are written to `data/logs/`

Each device produces:

```
data/raw/<device>_flow.pcap
data/logs/<device>_CE.txt
```

Logs include timestamped records of each attack execution.

---

## Attack System

CAPEX uses a registry based dispatch model.

Each attack is defined by a `kind` field and mapped to an executor:

* `command` executes external binaries such as `nmap` or `hping3`
* `hulk` runs an in-process HTTP flood (HULK) against the target device; configurable via `duration_seconds` and `thread_count`
* `ssdp_discovery` sends a unicast SSDP M-SEARCH probe to the target device; configurable via `timeout_seconds`
* `banner_grab` connects to a device port and reports whatever banner it sends back; configurable via `port`, `timeout_seconds`, and an optional `probe`
* `hydra_brute_force` runs real `hydra` against a device using a combo file built (and capped) from `username_list`/`password_list`/`max_attempts`, so the attempt cap is enforced in code rather than trusted to CLI flags
* `http_fuzz` sends malformed/fuzzed and traversal HTTP requests (`paths`) to a device's web UI on a configurable `port`
* `c2_beacon` sends a single jittered check-in request per invocation, mimicking botnet C2 callback traffic; configurable via `port`, `path`, and `jitter_seconds`
* `c2_dns_beacon` sends a single jittered real DNS query per invocation as a C2 check-in beacon over UDP/53, distinct wire shape from `c2_beacon`; configurable via `port`, `domain`, and `jitter_seconds`
* `exfil_sim` sends a bulk outbound POST burst simulating data-staging/exfil traffic; configurable via `payload_size_bytes` and `chunk_size_bytes`
* `config_tamper` sends a real config/firmware-tampering-shaped HTTP request (`path`, `method`, `body`) and reports the response status; defaults to `enabled: false` at the model level - each entry needs per-device safety vetting before it's turned on, since a payload that succeeds could brick real hardware
* `arp_spoof` runs real `arpspoof` against a device for a bounded `duration_seconds`, poisoning its ARP relationship with `gateway_ip` on `interface` (classic on-path MITM)
* `placeholder` is a disabled stub for attacks not yet implemented (cannot be `enabled: true`)
* additional attack types can be added via the registry

To add a new attack:

1. Define a new config entry in `attacks.yaml`
2. Implement an executor in `src/capex/attacks/`
3. Register it in `registry.py`

No changes are required in the capture orchestration logic.

---

## Legacy Components

The following directory is retained for reproducibility of prior work:

* `scripts/oldCapScripts`

This corresponds to tooling used in earlier FIRE experiments and concept drift studies.

---

## Tooling

* Packet capture is performed using `tcpdump`
* Flow extraction is typically performed using CICFlowMeter
* Python environment and dependency management is handled via `uv`

---

## Notes

* Running capture and certain attack tools may require elevated privileges
* This framework is intended for controlled and authorized environments only
* Ensure proper isolation when generating traffic datasets

---

## Author

Seth Barrett
Augusta University
School of Computer and Cyber Sciences
