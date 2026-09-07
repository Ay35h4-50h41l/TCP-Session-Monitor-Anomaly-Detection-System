import tkinter as tk
from tkinter import ttk
import json
import time
import os

LOG_FILE = "server_log.txt"

sessions = {}
last_file_pos = 0
packet_counter = {}

# ------------------- Root Window -------------------
root = tk.Tk()
root.title("TCP Session Monitor")
root.state("zoomed")
root.configure(bg="#12141D")

# ------------------- Styles -------------------
FONT_MAIN = ("Segoe UI", 11)
FONT_HEADER = ("Segoe UI", 12, "bold")

style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview",
                background="#1A1C2B",
                foreground="#FFFFFF",
                fieldbackground="#1A1C2B",
                font=FONT_MAIN,
                rowheight=28)
style.configure("Treeview.Heading",
                background="#2A2D44",
                foreground="#E0E0E0",
                font=FONT_HEADER,
                relief="flat")
style.map("Treeview",
          background=[('selected', '#4E5AF2')],
          foreground=[('selected', '#FFFFFF')])

# ------------------- Utility Functions -------------------
def create_tree_with_scroll(frame, columns, height=8):
    container = tk.Frame(frame, bg="#12141D")
    container.pack(fill="both", expand=True)
    tree = ttk.Treeview(container, columns=columns, show="headings", height=height)
    vsb = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y")
    tree.pack(fill="both", expand=True)
    tree["show"] = "headings"
    return tree

def setup_tree_columns(tree, columns):
    for col in columns:
        tree.heading(col, text=col, anchor="center")
        tree.column(col, anchor="center", width=150)

# ------------------- Tables -------------------
main_frame = tk.LabelFrame(root, text="Main Session Table", fg="#FFFFFF", bg="#1A1C2B",
                           font=FONT_HEADER, padx=5, pady=5)
main_frame.pack(fill="x", padx=10, pady=5)
main_columns = ["Session ID", "Src Address", "Destination Address", "Reconstructed Message", "Delay (ms)", "ACK / N_ACK"]
main_tree = create_tree_with_scroll(main_frame, main_columns, height=6)
setup_tree_columns(main_tree, main_columns)

fragment_frame = tk.Frame(root, bg="#12141D")
fragment_frame.pack(fill="both", padx=10, pady=5, expand=True)

# Sender
sender_frame = tk.LabelFrame(fragment_frame, text="Sender", fg="#FFFFFF", bg="#1A1C2B",
                             font=FONT_HEADER, padx=5, pady=5)
sender_frame.pack(side="left", fill="both", expand=True, padx=5)
sender_columns = ["Session ID", "Packet No.", "Sequence Number (SEQ)", "Data"]
sender_tree = create_tree_with_scroll(sender_frame, sender_columns)
setup_tree_columns(sender_tree, sender_columns)

# Receiver
receiver_frame = tk.LabelFrame(fragment_frame, text="Receiver", fg="#FFFFFF", bg="#1A1C2B",
                               font=FONT_HEADER, padx=5, pady=5)
receiver_frame.pack(side="left", fill="both", expand=True, padx=5)
receiver_columns = ["Session ID", "Arrival Order", "Sequence Number (SEQ)", "Data", "Status"]
receiver_tree = create_tree_with_scroll(receiver_frame, receiver_columns)
setup_tree_columns(receiver_tree, receiver_columns)

# Anomaly
anomaly_frame = tk.LabelFrame(root, text="Anomalies", fg="#FFFFFF", bg="#1A1C2B",
                              font=FONT_HEADER, padx=5, pady=5)
anomaly_frame.pack(fill="both", padx=10, pady=5, expand=True)
anomaly_columns = ["Session ID", "Packet No.", "Reconstructed Message", "Anomaly", "Action Taken"]
anomaly_tree = create_tree_with_scroll(anomaly_frame, anomaly_columns, height=6)
setup_tree_columns(anomaly_tree, anomaly_columns)

# ------------------- Protocol & Alerts -------------------
def parse_protocol(message):
    try:
        parts = message.split("|", 2)
        if len(parts) != 3:
            return None
        return parts[0], int(parts[1]), parts[2]
    except:
        return None

def detect_anomalies(session_id, seq, last_seq, data, last_messages, src_addr, expected_src, msg_type):
    alerts = []

    if msg_type == "SERVER_RSP":
        alerts.append("Fake server response injected")
    elif msg_type == "RST":
        alerts.append("TCP RST injected (Session Terminated)")
    elif msg_type == "SPOOF":
        alerts.append("TCP Spoofing attempt")

    if src_addr and expected_src and src_addr != expected_src:
        alerts.append("Session hijack attempt")

    # Ignore standard sequence and payload checks for injected control packets
    if msg_type not in ["RST", "SERVER_RSP", "SPOOF"]:
        if last_seq is not None and seq == last_seq:
            alerts.append("Retransmission")
        if last_seq is not None and seq < last_seq:
            alerts.append("Out-of-order")
        # Gap in sequence
        expected_seq = 1 if last_seq is None else last_seq + 1
        if seq != expected_seq and seq > expected_seq:
            alerts.append("Invalid SEQ/ACK behavior")

        if data and data in last_messages:
            alerts.append("Repeated payload")

    return alerts

# ------------------- Live Update -------------------
def update_tables():
    global last_file_pos, packet_counter
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            f.seek(last_file_pos)
            lines = f.readlines()
            last_file_pos = f.tell()
            for line in lines:
                line = line.strip()
                if not line: continue
                try:
                    packet = json.loads(line)
                    session_id = packet["session_id"]
                    src_addr = packet.get("src", "unknown")
                    dst_addr = packet.get("dst", "unknown")
                    raw_data = packet["data"]

                    # Packet numbering
                    if session_id not in packet_counter: packet_counter[session_id] = 1
                    pkt_no = packet_counter[session_id]
                    packet_counter[session_id] += 1

                    # Robust extraction of seq/data directly from packet
                    seq = packet.get("seq", pkt_no)
                    message = raw_data

                    # Sender
                    sender_tree.insert("", "end", values=[session_id, pkt_no, seq, message])

                    # Session reconstruction
                    if session_id not in sessions:
                        sessions[session_id] = {"last_seq": None, "messages": [], "expected_src": src_addr}

                    last_seq = sessions[session_id]["last_seq"]
                    last_messages = sessions[session_id]["messages"]
                    expected_src = sessions[session_id]["expected_src"]

                    parsed = parse_protocol(message)
                    if parsed:
                        msg_type, length, data = parsed
                        alerts = detect_anomalies(session_id, seq, last_seq, data, last_messages, src_addr, expected_src, msg_type)

                        if msg_type == "RST":
                            sessions[session_id]["last_seq"] = None
                            sessions[session_id]["messages"] = []
                            packet_counter[session_id] = 1 # Reset packet numbering to 1 after RST
                        else:
                            sessions[session_id]["last_seq"] = seq
                            # Avoid saving repeated/empty injected anomalies as normal msgs
                            if data:
                                sessions[session_id]["messages"].append(data)

                        # Receiver table with LOGOUT highlighting
                        if msg_type == "LOGOUT":
                            receiver_tree.insert("", "end", values=[session_id, pkt_no, seq, data, "LOGOUT"], tags=("logout",))
                            receiver_tree.tag_configure("logout", background="#FF4444", foreground="#FFFFFF")
                        else:
                            receiver_tree.insert("", "end", values=[session_id, pkt_no, seq, data, "OK" if not alerts else ", ".join(alerts)])

                        # Main table
                        main_tree.insert("", "end", values=[session_id, src_addr, dst_addr, f"{msg_type}|{length}|{data}", "0", "ACK"])

                        # Anomaly table
                        if alerts:
                            anomaly_tree.insert("", "end", values=[session_id, pkt_no, f"{msg_type}|{length}|{data}", ", ".join(alerts), "Logged"])
                    else:
                        receiver_tree.insert("", "end", values=[session_id, pkt_no, seq, message, "Malformed"])
                        anomaly_tree.insert("", "end", values=[session_id, pkt_no, message, "Malformed", "Logged"])
                except:
                    continue
    root.after(500, update_tables)

update_tables()
root.mainloop()