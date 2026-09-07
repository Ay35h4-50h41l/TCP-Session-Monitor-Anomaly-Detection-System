import socket
import threading
import json
import time
import os

HOST = "127.0.0.1"
PORT = 5000
LOG_FILE = "server_log.txt"

lock = threading.Lock()
client_threads = []
running = True
reset_sessions = set()

# ----------------- Clear previous log -----------------
if os.path.exists(LOG_FILE):
    open(LOG_FILE, "w").close()
print(f"[INFO] Cleared previous log file: {LOG_FILE}")

# ----------------- Logging function -----------------
def log_packet(packet):
    with lock:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(packet) + "\n")
            f.flush()

# ----------------- Client handler -----------------
def handle_client(conn, addr, conn_id):
    global running
    print(f"[CONNECTED] Connection index {conn_id} from {addr}")
    try:
        while running:
            data = conn.recv(1024)
            if not data:
                break
            timestamp = time.time()
            try:
                # Decode JSON from client
                packet_json = json.loads(data.decode())
                msg = packet_json.get("data", "")
                seq = packet_json.get("seq", None)
                # IMPORTANT: Use the session_id sent by the client! 
                session_id = packet_json.get("session_id", conn_id)
            except:
                # fallback if not JSON
                msg = data.decode()
                seq = None
                session_id = conn_id

            # Check if this session was recently reset (e.g. by an injected TCP RST)
            # Natively enforce that the next client message has a reset sequence number
            force_reset = False
            if session_id in reset_sessions and not msg.startswith("RST") and not msg.startswith("LOGOUT"):
                seq = 1
                reset_sessions.remove(session_id)
                force_reset = True

            # Display in console
            print(f"[SESSION {session_id}] RECEIVED: {msg}")

            # Log packet
            packet_to_log = {
                "session_id": session_id,
                "src": f"{addr[0]}:{addr[1]}",
                "dst": f"{HOST}:{PORT}",
                "seq": seq,
                "data": msg,
                "timestamp": timestamp
            }
            log_packet(packet_to_log)

            # Send applicable ACK
            if force_reset:
                conn.send(b"ACK_RESET")
            else:
                conn.send(f"ACK from server for session {session_id}".encode())

            # If LOGOUT or RST, exit loop after logging
            if msg.startswith("LOGOUT") or msg.startswith("RST"):
                if msg.startswith("RST"):
                    reset_sessions.add(session_id)
                print(f"[SESSION {session_id}] Terminated (LOGOUT/RST received)")
                break

    except Exception as e:
        print(f"[ERROR] Connection {conn_id}: {e}")
    finally:
        conn.close()
        print(f"[DISCONNECTED] Connection {conn_id}")

# ----------------- Server main loop -----------------
def start_server():
    global running
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[STARTED] Server running on {HOST}:{PORT}")

    session_counter = 1
    try:
        while running:
            server.settimeout(1.0)
            try:
                conn, addr = server.accept()
                thread = threading.Thread(target=handle_client, args=(conn, addr, session_counter), daemon=True)
                thread.start()
                client_threads.append(thread)
                session_counter += 1
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Ctrl+C detected. Closing server...")
        running = False
    finally:
        server.close()
        for t in client_threads:
            t.join(timeout=1)
        print("[CLOSED] Server safely stopped.")

if __name__ == "__main__":
    start_server()