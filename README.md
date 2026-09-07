# TCP Session Monitor & Anomaly Detection System

A Python-based client-server system that simulates TCP communication and detects protocol-level anomalies in real time — including retransmissions, out-of-order packets, session hijacking, and active packet injection. Built as a Computer Communication Networks (CCN) course project.

## Overview

The system consists of a multi-threaded TCP server, one or more chat-style clients, a live GUI dashboard, and a dedicated anomaly-testing tool. Every message exchanged between client and server follows a custom lightweight protocol (`TYPE|LENGTH|DATA`) and is logged with full metadata (session ID, source/destination address, sequence number, timestamp). A background analyzer continuously scans this log to flag suspicious or malformed traffic.

## Components

- **`server.py`** — Multi-threaded TCP server that accepts multiple simultaneous client connections, assigns each a session ID, logs every received packet to `server_log.txt`, and sends back ACKs. Handles session termination via `LOGOUT`/`RST` messages and tracks reset sessions.
- **`client.py`** — Simple chat-style TCP client. Connects to the server, logs in, and lets the user send messages interactively (or type `exit` to log out).
- **`anomaly.py`** — Interactive anomaly-testing tool used to deliberately trigger abnormal network behavior against the server, including:
  - Retransmissions (duplicate sequence numbers)
  - Out-of-order sequences
  - Invalid SEQ/ACK behavior (skipped sequence numbers)
  - Repeated payloads
  - Session hijacking (spoofed session ID from a different socket)
  - Active packet injection (fake server responses, TCP RST injection, basic TCP spoofing)
- **`packet_analyzer.py`** — Background service that tails the server log in real time, reconstructs each session, and detects anomalies (retransmission, out-of-order, invalid sequence, length mismatch, repeated payload, hijack attempts, injected/spoofed packets).
- **`gui.py`** — A Tkinter-based live dashboard (`TCP Session Monitor`) that visualizes the session log across four tables: a main session overview, sender-side packet view, receiver-side packet view (with reconstruction status), and a dedicated anomalies table.

## Protocol Format

Each application-layer message is structured as:
```
TYPE|LENGTH|DATA
```
Where `TYPE` is one of `LOGIN`, `MSG`, `LOGOUT`, `RST`, `SERVER_RSP`, or `SPOOF`.

Packets are wrapped in JSON at the transport layer with `session_id`, `seq`, `data`, and `timestamp` fields before being sent over the socket.

## Anomaly Detection Logic

The analyzer flags a packet when it observes:
- A sequence number equal to or lower than the last seen one (retransmission / out-of-order)
- A gap between the expected and actual sequence number (invalid SEQ/ACK behavior)
- A mismatch between declared and actual payload length
- A payload identical to a previously seen one in the same session
- A change in source/destination address mid-session (possible session hijack)
- Control messages of type `SERVER_RSP`, `RST`, or `SPOOF` (treated as injected/malicious traffic)

## Tech Stack

- Python
- `socket`, `threading`, `json`, `time`
- `tkinter` / `ttk` (GUI dashboard)

## How to Run

1. Start the server:
   ```
   python server.py
   ```
2. Start one or more clients (optionally pass a session ID):
   ```
   python client.py 1
   ```
3. Launch the live dashboard to visualize traffic and anomalies:
   ```
   python gui.py
   ```
4. Use the anomaly tester to simulate abnormal/malicious traffic against the server:
   ```
   python anomaly.py
   ```

## Project Context

Developed as a Computer Communication Networks (CCN) course project to demonstrate TCP session handling, protocol design, and real-time anomaly/intrusion detection using pure Python sockets.
