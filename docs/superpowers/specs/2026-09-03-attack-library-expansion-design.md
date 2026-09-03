# Attack Library Expansion for MITRE ATT&CK Coverage

Roadmap/design for issue #66. Goal: broaden CAPEX's attack set beyond DoS/flood
techniques so the multiclass concept-drift IDS work has genuinely distinct,
*authentic* attack classes to train and evaluate against, captured against
real lab IoT devices in a sandboxed environment.

## Motivation

Current attacks (`configs/attacks.yaml`) are all Impact/DoS-style floods
(`xmas_flood`, `tcp_syn_flood`, `udp_flood`, `http_flood`, `hulk_http_flood`)
plus one reconnaissance scan. That's effectively one MITRE ATT&CK category.
Public IoT-attack datasets are widely considered weak/unrealistic for this
kind of research; the explicit goal here is authentic, real-tool-driven
traffic (real `hydra`, `slowhttptest`, `arpspoof`, etc. against real
devices) — not synthetic or mocked attack traffic standing in for a class.

## Extension model (unchanged)

Every new attack fits the existing pattern:

1. Add a config entry to `configs/attacks.yaml` with a `kind`.
2. If `kind: command`, no new code needed — just command tokens (same as
   `xmas_flood`/`tcp_syn_flood`/etc using `hping3`/`nmap`).
3. If the attack needs in-process logic (multicast, raw sockets, custom
   protocol handling, timing control), add a native executor module under
   `src/capex/attacks/` implementing `BoundAttackExecutor` (see `hulk.py`
   for the reference shape), a matching `*AttackConfig` model in
   `models.py`, and register the `kind` in `registry.py`.

No changes to orchestration (`runner.py`, `scheduler.py`,
`services/capture_session.py`) are needed for any of the categories below.

## Workflow

- `enhancement/66-expand-attack-library` (off `dev`) is the shared local
  base each category branches from.
- Each category gets its own branch and its own PR **straight to `dev`**
  (not to the umbrella branch) — merged manually by the user, one at a time.
- After a category's PR merges, its sub-issue is closed with a comment
  linking the merge commit, same pattern as #70/#74.
- Categories are tackled roughly in the order listed below, but each is an
  independently mergeable unit.

## Categories

Each will get its own GitHub sub-issue under #66 with this scope:

1. **Reconnaissance / Discovery** — T1595, T1046. `nmap -sV` service/version
   detection (`command` kind, same shape as `xmas_flood`). UPnP/SSDP
   discovery (multicast M-SEARCH) and banner grabbing — new native executor
   (custom socket/multicast logic).
2. **Credential Access** — T1110, T1078.001. `hydra`/`medusa` brute force
   against HTTP basic auth, RTSP, telnet with IoT default-credential
   wordlists (`command` kind). New `max_attempts`/rate-limit config knob to
   bound lockout/brick risk even in the sandboxed lab.
3. **Application-layer** — T1499.002/.004, T1190. Slowloris/`slowhttptest`
   (`command` kind). Malformed/fuzzed HTTP requests and directory
   traversal/injection probes against device web UIs — new native executor.
4. **Lateral Movement / C2** — T1071. Simulated periodic beacon/check-in
   traffic with jittered intervals, mimicking real botnet C2 check-in
   patterns — new native executor (`c2_beacon`).
5. **Exfiltration** — T1041. Simulated bulk outbound transfer / data-staging
   bursts — new native executor (`exfil_sim`).
6. **Impact beyond flooding** — T1489, T1565. Simulated firmware/config
   tampering requests. Requires per-device safety vetting before enabling
   any specific payload — a bad request could brick real lab hardware
   regardless of sandboxing; scope narrows per-device as we get there.
7. **Reflection/Amplification DDoS** — T1498.002. SSDP/DNS/NTP reflection
   floods bouncing spoofed queries off amplifiers — the actual
   Mirai/Gafgyt DDoS-for-hire signature, distinct from the existing direct
   floods.
8. **ARP Spoofing / MITM** — T1557.002. Real ARP cache poisoning on the lab
   LAN (`arpspoof`/scapy) — common on-path step in real IoT botnet lateral
   movement; produces a packet signature nothing else in the set does.

## Testing

Each category PR follows existing repo conventions: unit tests for any new
executor/model (see `tests/test_hulk.py` and `tests/test_builtins.py` for
the pattern — construct executor, exercise `execute()`, assert on
returned detail string / side effects), `ruff` clean, `pytest-cov` gaps
closed per the repo's existing coverage bar (see #60).
