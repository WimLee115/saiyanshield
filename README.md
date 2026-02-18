# SaiyanShield

[![GitHub stars](https://img.shields.io/github/stars/WimLee115/saiyanshield?style=social)](https://github.com/WimLee115/saiyanshield/stargazers)
[![CI](https://github.com/WimLee115/saiyanshield-dev/actions/workflows/ci.yml/badge.svg)](https://github.com/WimLee115/saiyanshield-dev/actions)
[![Language](https://img.shields.io/badge/language-EN%20%7C%20NL-informational)](#-nederlands)
[![Rust](https://img.shields.io/badge/rust-edition%202024-orange)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Proprietary-blue)](#license)

```
       /\    /\
      /  \  /  \       ____        _                  ____  _     _      _     _
     / /\ \/ /\ \     / ___|  __ _(_)_   _  __ _ _ _ / ___|| |__ (_) ___| | __| |
    / /  \/  /  \ \   \___ \ / _` | | | | |/ _` | '_| \___ \| '_ \| |/ _ \ |/ _` |
   / /   /\   /  \ \   ___) | (_| | | |_| | (_| | | | ___) | | | | |  __/ | (_| |
  / /___/  \_/___\ \  |____/ \__,_|_|\__, |\__,_|_| |____/|_| |_|_|\___|_|\__,_|
  \/               \/                 |___/

  "I am the prince of all Saiyans!"  — Vegeta
  Power level: OVER 9000!
```

**Next-Generation Post-Quantum VPN Platform**

> *"My Saiyan pride won't let me lose!"* — Vegeta

SaiyanShield is a VPN platform built entirely in Rust with Python AI/ML models. It combines post-quantum cryptography, triple-layer symmetric encryption, integrated traffic obfuscation with decoy traffic, multi-adapter bonding, 20 real-time health monitoring algorithms (Scouter technology), an autonomous AI Analyst engine and a Dragon Ball Z-themed Vegeta Command Dashboard — in a single statically linked binary.

> If you find this project interesting, give it a star! It helps make the project visible.

**Copyright (c) 2026 WimLee115. All rights reserved.**

---

## Overview

> *"It's over 9000!"* — Vegeta

| Statistic | Value |
|-----------|-------|
| Rust codebase | 28,100+ lines |
| Python AI/ML | 2,700+ lines |
| Workspace crates | 14 Rust + 1 Python |
| Tests | 250+ (all green) |
| Benchmarks | 6 suites (Criterion) |
| Fuzz targets | 6 (libfuzzer) |
| Health algorithms | 20 (4 categories) |
| AI correlation rules | 8 |
| Threat categories | 13 |
| MITRE ATT&CK mappings | 13 |
| Encryption layers | 3 (ChaCha20 → AES-256 → XChaCha20) |
| Stealth modes | 6 |
| Watermark layers | 5 |

---

## Post-Quantum Cryptography

> *"My power is superior to yours!"* — Vegeta

### Hybrid Key Exchange

An attacker must break **both** schemes — even a quantum computer isn't enough:

- **ML-KEM-1024 (Kyber)** — FIPS 203 quantum-safe key encapsulation
- **X25519** — Classical ECDH as defense-in-depth
- **HKDF-SHA-512** — Domain-separated key derivation per encryption layer
- **AEAD-encrypted static key** — Initiator's public key encrypted with KEM shared secret during handshake
- **Directional session keys** — Separate send/recv cipher per role (initiator/responder)

### Hybrid Authentication

- **ML-DSA-87 (Dilithium5)** — FIPS 204 post-quantum digital signatures
- **Ed25519** — Classical signature backup
- **BLAKE3** — Hashing for fingerprints and integrity
- **Constant-time comparisons** — `subtle` crate against timing side-channels
- **Zeroize** — Automatic memory cleanup of secret keys

### Triple-Layer Encryption — Final Flash Protection

Every data packet passes through three independent ciphers in series:

| Layer | Algorithm | Nonce | Property |
|-------|-----------|-------|----------|
| 1 | ChaCha20-Poly1305 | 12 bytes | Constant-time, software-only |
| 2 | AES-256-GCM | 12 bytes | Hardware-accelerated (AES-NI) |
| 3 | XChaCha20-Poly1305 | 24 bytes | Extended nonce, misuse-resistant |

Overhead per packet: 96 bytes (48 bytes nonces + 48 bytes authentication tags).

---

## 20 Scouter Health Algorithms

> *"His power level... it's over 9000!"* — Vegeta's Scouter

Real-time health monitoring across 4 categories. All algorithms use real runtime metrics (latency, bandwidth, packet loss, CPU, memory, key rotations, handshakes).

### Network (6)

| # | Algorithm | Method |
|---|-----------|--------|
| 1 | Latency Monitor | RTT measurement and trend analysis |
| 2 | Bandwidth Analyzer | Throughput tracking and capacity estimation |
| 3 | Packet Loss Detector | Loss ratio monitoring with threshold alerts |
| 4 | Jitter Calculator | Inter-packet delay variation analysis |
| 5 | Stability Index | Composite score: latency + packet loss + key rotations |
| 6 | Congestion Predictor | Latency trend + packet loss + bandwidth variance |

### Security (7)

| # | Algorithm | Method |
|---|-----------|--------|
| 7 | DNS Leak Detector | Detects DNS queries outside the tunnel |
| 8 | IP Leak Prevention | IPv4/IPv6 address exposure detection |
| 9 | WebRTC Leak Guard | STUN/TURN IP disclosure prevention |
| 10 | Certificate Checker | Certificate chains and expiration |
| 11 | Protocol Integrity | Packet structure and sequence number verification |
| 12 | Firewall Auditor | Kill-switch firewall rule validation |
| 13 | Zero-Day Scanner (ML) | Multi-signal: error spikes + traffic anomalies + resource abuse + packet ratio |

### Performance (4)

| # | Algorithm | Method |
|---|-----------|--------|
| 14 | Encryption Perf | Cipher throughput and latency measurement |
| 15 | Memory Tracker | RSS and heap usage monitoring |
| 16 | CPU Balancer | Load distribution across encryption threads |
| 17 | Route Optimizer (ML) | 4-factor evaluation: latency + bandwidth + packet loss + key rotation health |

### AI/ML (3)

| # | Algorithm | Method |
|---|-----------|--------|
| 18 | Traffic Pattern Analyzer (ML) | 3-factor: packet size entropy + inter-arrival variance + bandwidth deviation |
| 19 | Anomaly Detector (ML) | 6-feature: error rate + CPU + memory + packet loss + latency + key rotation |
| 20 | Threat Intel Monitor (ML) | 5-signal: error rate + amplification + resource pressure + stability + bandwidth |

---

## AI Analyst Engine

> *"You are nothing compared to a real Saiyan warrior!"* — Vegeta

Autonomous investigation engine:

- **8 correlation rules** — DPI Analysis, MITM, Data Exfiltration, Crypto Weakness, DNS Attack, Resource Exhaustion, Bandwidth Throttling, Endpoint Compromise
- **Hypothesis engine** — Template matching, evidence testing, confidence scoring
- **13 threat categories** — Each with MITRE ATT&CK mapping
- **Investigation lifecycle** — Open → Analyzing → Concluded → Dismissed
- **NLG report generator** — Reasoning chains with verdict and tags
- **Alert fatigue reduction** — Max 10/hour, auto-dismiss after recovery

### Python ML Models

| Model | Architecture | Function |
|-------|-------------|----------|
| EventCorrelationGAT | Graph Attention Network | Event correlation |
| InvestigationTransformer | Transformer + CLS-token | Threat classification |
| HypothesisScorerMLP | 4-layer MLP + BatchNorm | Confidence calibration |
| AnomalyDetector | Autoencoder | Anomaly detection |
| TrafficClassifier | CNN | Traffic classification |
| ThreatPredictor | LSTM | Threat prediction |
| RouteOptimizerRL | Reinforcement Learning | Route optimization |
| CongestionPredictor | GRU | Congestion prediction |

---

## Ki-Suppression — Traffic Obfuscation

> *"You can't sense my ki!"* — Vegeta in Stealth Mode

Fully integrated in client and server — all VPN packets are automatically wrapped and unwrapped based on the configured stealth mode.

| Feature | Description |
|---------|-------------|
| HTTPS disguise | VPN traffic wrapped as TLS 1.3 Application Data records |
| WebSocket disguise | Traffic via WebSocket binary frames with masking |
| DNS-over-HTTPS | Traffic disguised as DoH queries |
| Domain fronting | TLS ClientHello SNI manipulation via CDN front domains |
| Decoy traffic | Poisson-distributed decoy traffic via `DecoyGenerator` (configurable interval) |
| Timing defense | Constant-time padding against analysis |
| Packet padding | Uniform packet size (256/512/1024/1500) |

### Domain Fronting

Real TLS ClientHello parsing and SNI replacement:

- Parses TLS record header, handshake header, session ID, cipher suites, compression methods, extensions
- Finds SNI extension (type 0x0000), extracts hostname
- Replaces hostname with front domain
- Restores all TLS length fields (record, handshake, extensions, SNI)

---

## Vegeta Command Dashboard

> *"Final Flash!"* — Vegeta

Dragon Ball Z-themed web dashboard at `http://localhost:3000`:

- **Ki-energy rain** — Canvas-based with katakana + Saiyan symbols
- **Saiyan color scheme** — Blue (#0A84FF), Gold (#FFD700), Orange aura (#FF6B00)
- **Theme switcher** — Saiyan Mode / Stealth Mode / Super Saiyan Mode
- **Bilingual** — Full English/Dutch language switcher
- **Vegeta boot intro** — Power level scanning with Vegeta quotes
- **Final Flash connect** — "FINAL FLASH ACTIVATE!" authentication
- **Real-time Scouter matrix** — 20 algorithms with color-coded power levels
- **Bandwidth/latency charts** — CSS bar charts (30 data points, color-coded)
- **AI Analyst feed** — Live investigations with verdict, tags and confidence
- **SSE streaming** — Real-time updates via Server-Sent Events
- **Token authentication** — Auto-generated token at startup

---

## Architecture

```
                         ┌───────────────────┐
                         │  saiyanshield-core │
                         │   (orchestrator)   │
                         └───────┬───────────┘
                                 │
  ┌──────────┬──────────┬───────┼───────┬──────────┬──────────┐
  │          │          │       │       │          │          │
┌─┴──────┐┌─┴───────┐┌─┴─────┐│┌──────┴─┐┌──────┴─┐┌──────┴──┐
│ crypto ││protocol ││tunnel │││stealth ││ health ││ analyst │
│  (PQ)  ││ (wire)  ││ (TUN) │││(ki-hid)││(scouter││  (AI)   │
└────────┘└─────────┘└───────┘│└────────┘└────────┘└─────────┘
                              │
                    ┌─────────┴───────────┐
                    │ saiyanshield-dashboard│
                    │  (Vegeta Command     │
                    │   terminal UI)       │
                    └────────┬────────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
        ┌─────┴────┐  ┌─────┴────┐  ┌──────┴─────┐
        │  client  │  │  server  │  │ watermark  │
        │(CLI+dash)│  │ (multi-  │  │(5-layer PQ)│
        └──────────┘  │ client)  │  └────────────┘
                      └──────────┘
              ┌──────────────┬──────────────┐
              │              │              │
        ┌─────┴────┐  ┌─────┴────┐  ┌──────┴─────┐
        │ adapter  │  │  macros  │  │saiyanshield│
        │(bonding) │  │(proc-mac)│  │-ai (Python)│
        └──────────┘  └──────────┘  └────────────┘
```

### 14 Rust Crates

| Crate | Description |
|-------|-------------|
| `saiyanshield-core` | Orchestrator: VPN engine, state machine, kill switch, DNS, split tunneling, metrics collector, key persistence |
| `saiyanshield-crypto` | Post-quantum: ML-KEM-1024 + X25519, ML-DSA-87 + Ed25519, triple-layer encryption, AEAD helpers, signed updates |
| `saiyanshield-protocol` | Wire protocol: PQ handshake with encrypted static key, directional sessions, key rotation, anti-replay |
| `saiyanshield-tunnel` | TUN device: async I/O via tokio, gateway management |
| `saiyanshield-adapter` | Multi-adapter bonding: failover, round robin, weighted, aggregate |
| `saiyanshield-stealth` | Ki-suppression: HTTPS/WebSocket/DoH disguise, domain fronting with SNI manipulation, decoy traffic |
| `saiyanshield-health` | 20 Scouter algorithms in 4 categories, ML-based heuristics |
| `saiyanshield-analyst` | AI Analyst: 8 correlation rules, hypothesis engine, 13 threat classes, MITRE ATT&CK |
| `saiyanshield-dashboard` | Vegeta Command Dashboard: DBZ theme, SSE streaming, REST API |
| `saiyanshield-watermark` | 5-layer watermark: compile-time BLAKE3, runtime, steganography, PQ signatures, protocol |
| `saiyanshield-macros` | Procedural macros for zero-boilerplate configuration |
| `saiyanshield-client` | Client binary: PQ handshake, TUN routing, kill switch, dashboard server |
| `saiyanshield-server` | Server binary: multi-client, TUN + NAT, per-client IP allocation |
| `saiyanshield-ai` | Python: 8 ML models (GAT, Transformer, MLP, LSTM, GRU, CNN, RL, Autoencoder) |

---

## Quick Start

### Requirements

- Rust 1.85+ (2024 edition)
- C compiler (for pqcrypto native libraries)
- Linux (kernel 3.x+ for TUN support)
- Root privileges (sudo) for TUN device, iptables and route configuration
- Python 3.10+ with PyTorch (optional, for AI/ML model training)

### Build

```bash
# Build all crates
cargo build --release

# Run all tests
cargo test --workspace

# Lint check
cargo clippy -- -D warnings
```

### Start Server

```bash
sudo ./target/release/saiyanshield-server \
    --bind 0.0.0.0 \
    --port 51820 \
    --verbose
```

### Start Client

```bash
sudo ./target/release/saiyanshield-client \
    --server 127.0.0.1 \
    --port 51820 \
    --stealth-mode https \
    --dashboard-port 3000 \
    --verbose
```

### Dashboard

```
http://localhost:3000
```

Token is shown at startup or found in `/tmp/saiyanshield-dashboard-token`.

---

## Feature Scripts

```bash
./20 [token]                    # Scouter matrix — 20 algorithms with power level bars
./On-Device [train|export|all]  # ML pipeline — training, ONNX export, evaluation
./Triple-Layer [info|verify]    # Cipher stack info and encryption verification
./Traffic [status|test-fronting] # Ki-suppression tests
./Web [start|status|test]       # Dashboard management
```

---

## Kill Switch — Saiyan Barrier

> *"Nobody gets through here!"* — Vegeta

Fail-closed firewall via dedicated `SAIYANSHIELD_KILLSWITCH` iptables chain:

- Blocks all traffic outside the VPN tunnel
- DNS leak prevention via `SAIYANSHIELD_DNS` chain
- Automatic cleanup on shutdown (also via `Drop` trait)
- Retry logic: 3 attempts + emergency flush

---

## Dashboard API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard SPA |
| GET | `/api/status` | Connection status, version, uptime, cipher suite |
| GET | `/api/metrics` | Live traffic and performance metrics |
| GET | `/api/health` | 20 Scouter algorithm reports |
| GET | `/api/config` | VPN configuration |
| POST | `/api/connect` | Start connection |
| POST | `/api/disconnect` | Stop connection |
| GET | `/api/alerts` | Active health alerts |
| GET | `/api/events` | SSE stream real-time updates |
| GET | `/api/analyst/summary` | AI Analyst statistics |
| GET | `/api/analyst/investigations` | Investigations (filter/pagination) |
| GET | `/api/analyst/active` | Active investigations |
| GET | `/api/watermark/verify` | Watermark integrity check |

---

## Security Model

> *"A true Saiyan always fights alone!"* — Vegeta

| Measure | Implementation |
|---------|---------------|
| Post-quantum hybrid | ML-KEM-1024 + X25519, ML-DSA-87 + Ed25519 |
| Triple-layer encryption | 3 independent ciphers, separately derived keys |
| Directional key isolation | Separate send/recv ciphers per session role |
| AEAD-encrypted handshake | Static public key encrypted with KEM shared secret |
| Encrypted session confirmation | Session confirmation via session cipher, not plaintext |
| Persistent identity keys | Server/client keys stored on disk (0600 permissions) |
| Constant-time crypto | `subtle` crate for all comparisons |
| Anti-replay | Sliding window bitmap on incoming packets |
| Source address validation | Server validates packets from expected IP |
| Kill switch | Dedicated iptables chains, fail-closed |
| Key rotation | Automatic every 60 seconds |
| Zeroization | All secret keys via `Zeroize` trait |
| Security headers | CSP, X-Frame-Options, XCTO, Referrer-Policy |
| Forward secrecy | Key rotation ratchet destroys old keys (proven with tests) |
| Config validation | Startup validation of all configuration fields |
| 5-layer watermark | Compile-time, runtime, steganography, signatures, protocol |

---

## Benchmarks

Performance benchmarks via [Criterion.rs](https://github.com/bheisler/criterion.rs) in 6 suites:

| Suite | What is measured |
|-------|-----------------|
| `crypto_bench` | KEM keypair/encap/decap, triple-layer encrypt/decrypt, packet serialization |
| `protocol_bench` | Handshake roundtrip, session encrypt/decrypt (100B-10KB), multi-hop circuit build, onion encrypt |
| `signing_bench` | HybridSigner keypair generation, sign (32B/1KB), verify |
| `health_bench` | All 20 Scouter algorithms, per category (Network/Security/Performance/AiMl) |
| `analyst_bench` | AnalystEngine ingest: healthy batch, attack batch |
| `stealth_bench` | Domain fronting SNI replacement, watermark verification |

```bash
cargo bench                        # All benchmarks
cargo bench --bench crypto_bench   # Single suite
```

---

## Multi-Adapter Bonding

Optional multi-adapter support for redundancy and bandwidth aggregation:

| Strategy | Description |
|----------|-------------|
| Failover | Automatic switchover on adapter failure |
| Round Robin | Packets distributed across active adapters |
| Weighted | Selection based on quality score (latency + packet loss) |
| Aggregate | All adapters simultaneously for maximum throughput |

- **Auto-detection** of WiFi adapters via `/sys/class/net`
- **Health monitoring** with configurable thresholds (latency, packet loss)
- **SO_BINDTODEVICE** binding for source-based routing
- **Configurable** via `[adapters]` section in config

---

## Key Management

Persistent identity keys for server and client:

- **Auto-generate** — Keys are generated on first startup if they don't exist
- **Secure storage** — Files with `0600` permissions (owner only)
- **Server**: KEM + signing keypairs in `/etc/saiyanshield/keys/`
- **Client**: KEM + signing keypairs in `/etc/saiyanshield/client-keys/`
- **Server public key distribution** — Client loads server public key via `server_public_key_path` config

---

## License

**Copyright (c) 2026 WimLee115. All rights reserved.**

Made by [WimLee115](https://github.com/WimLee115)

> *"Kakarot... I will surpass you!"* — Vegeta

---
---

# 🇳🇱 Nederlands

---

## Overzicht

> *"Het is over de 9000!"* — Vegeta

| Statistiek | Waarde |
|------------|--------|
| Rust codebase | 28.100+ regels |
| Python AI/ML | 2.700+ regels |
| Workspace crates | 14 Rust + 1 Python |
| Tests | 250+ (alle groen) |
| Benchmarks | 6 suites (Criterion) |
| Fuzz targets | 6 (libfuzzer) |
| Health algoritmen | 20 (4 categorieën) |
| AI correlatie-regels | 8 |
| Threat categorieën | 13 |
| MITRE ATT&CK mappings | 13 |
| Encryptielagen | 3 (ChaCha20 → AES-256 → XChaCha20) |
| Stealth modi | 6 |
| Watermerklagen | 5 |

SaiyanShield is een VPN-platform volledig gebouwd in Rust met Python AI/ML modellen. Het combineert post-quantum cryptografie, drielaagse symmetrische encryptie, geïntegreerde traffic obfuscation met decoy verkeer, multi-adapter bonding, 20 real-time health monitoring algoritmen (Scouter-technologie), een autonome AI Analyst engine en een Dragon Ball Z-thema Vegeta Command Dashboard — in een enkele statisch gelinkte binary.

---

## Post-Quantum Cryptografie

> *"Mijn kracht is superieur aan de jouwe!"* — Vegeta

### Hybride Sleuteluitwisseling

Een aanvaller moet **beide** schema's breken — zelfs een quantum computer is niet genoeg:

- **ML-KEM-1024 (Kyber)** — FIPS 203 quantum-safe key encapsulation
- **X25519** — Klassiek ECDH als defense-in-depth
- **HKDF-SHA-512** — Domein-gescheiden sleutelafleiding per encryptielaag
- **AEAD-encrypted static key** — Initiator's publieke sleutel versleuteld met KEM shared secret in handshake
- **Directionele sessiesleutels** — Gescheiden send/recv cipher per rol (initiator/responder)

### Hybride Authenticatie

- **ML-DSA-87 (Dilithium5)** — FIPS 204 post-quantum digitale handtekeningen
- **Ed25519** — Klassieke handtekening backup
- **BLAKE3** — Hashing voor fingerprints en integriteit
- **Constant-time vergelijkingen** — `subtle` crate tegen timing side-channels
- **Zeroize** — Automatische geheugenopruiming van geheime sleutels

### Triple-Layer Encryptie — Final Flash Bescherming

Elk datapakket passeert drie onafhankelijke ciphers in serie:

| Laag | Algoritme | Nonce | Eigenschap |
|------|-----------|-------|------------|
| 1 | ChaCha20-Poly1305 | 12 bytes | Constant-time, software-only |
| 2 | AES-256-GCM | 12 bytes | Hardware-accelerated (AES-NI) |
| 3 | XChaCha20-Poly1305 | 24 bytes | Extended nonce, misuse-resistant |

Overhead per pakket: 96 bytes (48 bytes nonces + 48 bytes authenticatie-tags).

---

## 20 Scouter Health Algoritmen

> *"Zijn power level... het is over de 9000!"* — Vegeta's Scouter

Real-time gezondheidsmonitoring over 4 categorieën. Alle algoritmen gebruiken echte runtime metrics (latency, bandwidth, packet loss, CPU, geheugen, key rotations, handshakes).

### Network (6)

| # | Algoritme | Methode |
|---|-----------|---------|
| 1 | Latency Monitor | RTT meting en trendanalyse |
| 2 | Bandwidth Analyzer | Doorvoer tracking en capaciteitsschatting |
| 3 | Packet Loss Detector | Verliesratio monitoring met drempelwaarschuwingen |
| 4 | Jitter Calculator | Inter-packet delay variatie analyse |
| 5 | Stability Index | Samengestelde score: latency + packet loss + key rotations |
| 6 | Congestion Predictor | Latency trend + packet loss + bandwidth variance |

### Security (7)

| # | Algoritme | Methode |
|---|-----------|---------|
| 7 | DNS Leak Detector | Detecteert DNS-queries buiten de tunnel |
| 8 | IP Leak Prevention | IPv4/IPv6-adresblootstelling |
| 9 | WebRTC Leak Guard | STUN/TURN IP-onthulling preventie |
| 10 | Certificate Checker | Certificaatketens en vervaldatum |
| 11 | Protocol Integrity | Pakketstructuur en volgnummer verificatie |
| 12 | Firewall Auditor | Kill-switch firewallregel validatie |
| 13 | Zero-Day Scanner (ML) | Multi-signaal: error spikes + traffic anomalieën + resource abuse + packet ratio |

### Performance (4)

| # | Algoritme | Methode |
|---|-----------|---------|
| 14 | Encryption Perf | Cipher doorvoer en latentie meting |
| 15 | Memory Tracker | RSS- en heap-gebruik monitoring |
| 16 | CPU Balancer | Lastverdeling over encryptiethreads |
| 17 | Route Optimizer (ML) | 4-factor evaluatie: latency + bandwidth + packet loss + key rotation health |

### AI/ML (3)

| # | Algoritme | Methode |
|---|-----------|---------|
| 18 | Traffic Pattern Analyzer (ML) | 3-factor: packet size entropy + inter-arrival variance + bandwidth deviation |
| 19 | Anomaly Detector (ML) | 6-feature: error rate + CPU + memory + packet loss + latency + key rotation |
| 20 | Threat Intel Monitor (ML) | 5-signaal: error rate + amplification + resource pressure + stability + bandwidth |

---

## AI Analyst Engine

> *"Je bent niks vergeleken met een echte Saiyan krijger!"* — Vegeta

Autonome investigatie-engine:

- **8 correlatie-regels** — DPI Analysis, MITM, Data Exfiltration, Crypto Weakness, DNS Attack, Resource Exhaustion, Bandwidth Throttling, Endpoint Compromise
- **Hypothese-engine** — Template matching, evidence testing, confidence scoring
- **13 threat categorieën** — Elk met MITRE ATT&CK mapping
- **Investigatie lifecycle** — Open → Analyzing → Concluded → Dismissed
- **NLG rapport generator** — Reasoning chains met verdict en tags
- **Alert fatigue reductie** — Max 10/uur, auto-dismiss na herstel

---

## Ki-Onderdrukking — Traffic Obfuscation

> *"Je kunt mijn ki niet voelen!"* — Vegeta in Stealth Mode

Volledig geïntegreerd in client en server — alle VPN-pakketten worden automatisch verpakt en uitgepakt op basis van de geconfigureerde stealth modus.

| Feature | Beschrijving |
|---------|-------------|
| HTTPS vermomming | VPN-verkeer verpakt als TLS 1.3 Application Data records |
| WebSocket vermomming | Verkeer via WebSocket binary frames met masking |
| DNS-over-HTTPS | Verkeer vermomd als DoH queries |
| Domain fronting | TLS ClientHello SNI-manipulatie via CDN front-domeinen |
| Dekverkeer | Poisson-verdeeld dekverkeer via `DecoyGenerator` (configureerbaar interval) |
| Timing verdediging | Constant-time padding tegen analyse |
| Pakketpadding | Uniforme pakketgrootte (256/512/1024/1500) |

---

## Vegeta Command Dashboard

> *"Final Flash!"* — Vegeta

Dragon Ball Z-thema web dashboard op `http://localhost:3000`:

- **Ki-energy rain** — Canvas-gebaseerd met katakana + Saiyan symbolen
- **Saiyan kleurenschema** — Blauw (#0A84FF), Goud (#FFD700), Oranje aura (#FF6B00)
- **Theme switcher** — Saiyan Mode / Stealth Mode / Super Saiyan Mode
- **Tweetalig** — Volledige Engels/Nederlands taalwisselaar
- **Vegeta boot intro** — Power level scanning met Vegeta quotes
- **Final Flash connect** — "FINAL FLASH ACTIVATE!" authenticatie
- **Real-time Scouter matrix** — 20 algoritmen met kleurgecodeerde power levels
- **Bandwidth/latency grafieken** — CSS bar charts (30 datapunten, color-coded)
- **AI Analyst feed** — Live investigations met verdict, tags en confidence
- **SSE streaming** — Real-time updates via Server-Sent Events
- **Token-authenticatie** — Auto-generated token bij opstart

---

## Kill Switch — Saiyan Barrier

> *"Niemand komt hier doorheen!"* — Vegeta

Fail-closed firewall via dedicated `SAIYANSHIELD_KILLSWITCH` iptables chain:

- Blokkeert al het verkeer buiten de VPN tunnel
- DNS leak preventie via `SAIYANSHIELD_DNS` chain
- Automatische opruiming bij afsluiting (ook via `Drop` trait)
- Retry logica: 3 pogingen + emergency flush

---

## Dashboard API

| Method | Pad | Beschrijving |
|--------|-----|-------------|
| GET | `/` | Dashboard SPA |
| GET | `/api/status` | Verbindingsstatus, versie, uptime, cipher suite |
| GET | `/api/metrics` | Live verkeers- en prestatiemetrics |
| GET | `/api/health` | 20 Scouter algoritme rapporten |
| GET | `/api/config` | VPN configuratie |
| POST | `/api/connect` | Verbinding starten |
| POST | `/api/disconnect` | Verbinding verbreken |
| GET | `/api/alerts` | Actieve health alerts |
| GET | `/api/events` | SSE stream real-time updates |
| GET | `/api/analyst/summary` | AI Analyst statistieken |
| GET | `/api/analyst/investigations` | Investigations (filter/paginatie) |
| GET | `/api/analyst/active` | Actieve investigations |
| GET | `/api/watermark/verify` | Watermerk integriteitscheck |

---

## Beveiligingsmodel

> *"Een ware Saiyan vecht altijd alleen!"* — Vegeta

| Maatregel | Implementatie |
|-----------|--------------|
| Post-quantum hybride | ML-KEM-1024 + X25519, ML-DSA-87 + Ed25519 |
| Triple-layer encryptie | 3 onafhankelijke ciphers, apart afgeleide sleutels |
| Directionele sleutelisolatie | Gescheiden send/recv ciphers per sessierol |
| AEAD-encrypted handshake | Static public key versleuteld met KEM shared secret |
| Versleutelde sessiebevestiging | Session confirmation via sessie-cipher, niet plaintext |
| Persistente identiteitssleutels | Server/client sleutels opgeslagen op schijf (0600 permissies) |
| Constant-time crypto | `subtle` crate voor alle vergelijkingen |
| Anti-replay | Sliding window bitmap op inkomende packets |
| Bron-adres validatie | Server valideert packets van verwacht IP |
| Kill switch | Dedicated iptables chains, fail-closed |
| Sleutelrotatie | Automatisch elke 60 seconden |
| Zeroization | Alle geheime sleutels via `Zeroize` trait |
| Security headers | CSP, X-Frame-Options, XCTO, Referrer-Policy |
| Forward secrecy | Key rotation ratchet vernietigt oude sleutels (bewezen met tests) |
| Config validatie | Startup-validatie van alle configuratievelden |
| 5-laags watermerk | Compile-time, runtime, steganografie, signatures, protocol |

---

## Benchmarks

| Suite | Wat wordt gemeten |
|-------|-------------------|
| `crypto_bench` | KEM keypair/encap/decap, triple-layer encrypt/decrypt, packet serialisatie |
| `protocol_bench` | Handshake roundtrip, session encrypt/decrypt (100B-10KB), multi-hop circuit build, onion encrypt |
| `signing_bench` | HybridSigner keypair generatie, sign (32B/1KB), verify |
| `health_bench` | Alle 20 Scouter algoritmen, per categorie (Network/Security/Performance/AiMl) |
| `analyst_bench` | AnalystEngine ingest: gezonde batch, attack batch |
| `stealth_bench` | Domain fronting SNI-vervanging, watermark verificatie |

---

## Multi-Adapter Bonding

| Strategie | Beschrijving |
|-----------|-------------|
| Failover | Automatische overschakeling bij adapter-falen |
| Round Robin | Pakketten verdeeld over actieve adapters |
| Weighted | Selectie op basis van kwaliteitsscore (latency + packet loss) |
| Aggregate | Alle adapters tegelijk voor maximale doorvoer |

---

## Sleutelbeheer

Persistente identiteitssleutels voor server en client:

- **Automatisch genereren** — Sleutels worden gegenereerd bij eerste opstart als ze niet bestaan
- **Veilige opslag** — Bestanden met `0600` permissies (alleen eigenaar)
- **Server**: KEM + signing keypairs in `/etc/saiyanshield/keys/`
- **Client**: KEM + signing keypairs in `/etc/saiyanshield/client-keys/`
- **Server public key distributie** — Client laadt server public key via `server_public_key_path` config

---

## Snel Starten

### Vereisten

- Rust 1.85+ (2024 edition)
- C compiler (voor pqcrypto native libraries)
- Linux (kernel 3.x+ voor TUN ondersteuning)
- Root rechten (sudo) voor TUN device, iptables en route configuratie
- Python 3.10+ met PyTorch (optioneel, voor AI/ML model training)

### Bouwen

```bash
# Bouw alle crates
cargo build --release

# Draai alle tests
cargo test --workspace

# Lint check
cargo clippy -- -D warnings
```

### Server starten

```bash
sudo ./target/release/saiyanshield-server \
    --bind 0.0.0.0 \
    --port 51820 \
    --verbose
```

### Client starten

```bash
sudo ./target/release/saiyanshield-client \
    --server 127.0.0.1 \
    --port 51820 \
    --stealth-mode https \
    --dashboard-port 3000 \
    --verbose
```

### Dashboard

```
http://localhost:3000
```

Token wordt getoond bij opstart of staat in `/tmp/saiyanshield-dashboard-token`.

---

## Licentie

**Copyright (c) 2026 WimLee115. Alle rechten voorbehouden.**

Gemaakt door [WimLee115](https://github.com/WimLee115)

> *"Kakarot... Ik zal je overtreffen!"* — Vegeta
