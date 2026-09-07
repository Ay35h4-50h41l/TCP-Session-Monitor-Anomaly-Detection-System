import json
import os
import time

LOG_FILE = "server_log.txt"

# Store session information
sessions = {}
last_file_pos = 0

# -------------------- PROTOCOL PARSER --------------------
def parse_protocol(message):
    try:
        parts = message.split("|", 2)
        if len(parts) != 3:
            return None
        return parts[0], int(parts[1]), parts[2]
    except:
        return None

# -------------------- ANOMALY DETECTION --------------------
def detect_anomalies(session_id, seq, msg_type, length, data, last_seq, last_messages, src, dst):
    alerts = []

    if msg_type == "SERVER_RSP":
        alerts.append("Fake server response injected")
    elif msg_type == "RST":
        alerts.append("TCP RST injected (Session Terminated)")
    elif msg_type == "SPOOF":
        alerts.append("TCP Spoofing attempt")

    if session_id in sessions and (src != sessions[session_id]["src"] or dst != sessions[session_id]["dst"]):
        alerts.append("Session hijack attempt")

    # Ignore standard sequence and payload checks for injected control packets
    if msg_type not in ["RST", "SERVER_RSP", "SPOOF"]:
        if last_seq is not None and seq == last_seq:
            alerts.append("Retransmission")
        if last_seq is not None and seq < last_seq:
            alerts.append("Out-of-order")
        expected_seq = 1 if last_seq is None else last_seq + 1
        if seq != expected_seq:
            alerts.append("Invalid SEQ/ACK behavior")
        if length != len(data):
            alerts.append("Length mismatch")
        if data in last_messages:
            alerts.append("Repeated payload")

    return alerts

# -------------------- LIVE ANALYSIS LOOP --------------------
# No printing to screen
try:
    while True:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                f.seek(last_file_pos)
                lines = f.readlines()
                last_file_pos = f.tell()

                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        packet = json.loads(line)
                        session_id = packet["session_id"]
                        src = packet.get("src")
                        dst = packet.get("dst")
                        raw_data = packet["data"]
                    except:
                        continue

                    seq = packet.get("seq")
                    message = raw_data

                    # Initialize session
                    if session_id not in sessions:
                        sessions[session_id] = {
                            "last_seq": None,
                            "messages": [],
                            "src": src,
                            "dst": dst,
                            "anomalies": []
                        }

                    last_seq = sessions[session_id]["last_seq"]
                    last_messages = sessions[session_id]["messages"]

                    parsed = parse_protocol(message)
                    if parsed:
                        msg_type, length, data = parsed
                        alerts = detect_anomalies(session_id, seq, msg_type, length, data, last_seq, last_messages, src, dst)

                        if msg_type == "RST":
                            sessions[session_id]["last_seq"] = None
                            sessions[session_id]["messages"] = []
                        else:
                            sessions[session_id]["last_seq"] = seq
                            sessions[session_id]["messages"].append(data)

                        if alerts:
                            sessions[session_id]["anomalies"].append({
                                "seq": seq,
                                "message": f"{msg_type}|{length}|{data}",
                                "alerts": alerts
                            })
                    else:
                        # Malformed message
                        sessions[session_id]["anomalies"].append({
                            "seq": seq,
                            "message": message,
                            "alerts": ["Malformed"]
                        })

        # Sleep to avoid busy loop
        time.sleep(0.5)

except KeyboardInterrupt:
    # Exit gracefully
    pass