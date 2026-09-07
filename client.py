import socket
import json
import time
import sys

HOST = "127.0.0.1"
PORT = 5000
seq = 1

# -------------------- Protocol --------------------
def build_protocol_message(msg_type, data):
    length = len(data)
    return f"{msg_type}|{length}|{data}"

# -------------------- Send Packet --------------------
def send_packet(sock, session_id, message):
    global seq
    packet = {
        "session_id": session_id,
        "seq": seq,
        "data": message,
        "timestamp": time.time()
    }
    sock.send(json.dumps(packet).encode())
    try:
        ack = sock.recv(1024).decode()
        if "ACK_RESET" in ack:
            print(f"[CLIENT {session_id}] Server has reset this session automatically. Starting fresh from sequence 1 moving forward.")
            seq = 2  # Set to 2 because the packet that just got reset handled sequence 1 natively
            return
    except:
        ack = "No ACK"
    print(f"[CLIENT {session_id}] Sent: {message} | Received: {ack}")
    seq += 1

# -------------------- Chat Loop --------------------
def run_chat(session_id, username=f"user"):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        print(f"[CLIENT {session_id}] Connected. Type messages (exit to quit):")

        # LOGIN
        login_msg = build_protocol_message("LOGIN", f"user={username}")
        send_packet(sock, session_id, login_msg)

        while True:
            msg_input = input()
            if msg_input.lower() == "exit":
                logout_msg = build_protocol_message("LOGOUT", "")
                send_packet(sock, session_id, logout_msg)
                time.sleep(0.2)  # give server time to process
                print(f"[CLIENT {session_id}] Exiting chat.")
                break

            msg = build_protocol_message("MSG", msg_input)
            send_packet(sock, session_id, msg)

    except ConnectionRefusedError:
        print(f"[CLIENT {session_id}] Cannot connect to server.")
    except KeyboardInterrupt:
        print(f"\n[CLIENT {session_id}] Exiting (Ctrl+C).")
    finally:
        sock.close()

# -------------------- Main --------------------
if __name__ == "__main__":
    if len(sys.argv) > 1:
        session_id = int(sys.argv[1])
    else:
        session_id = 1

    run_chat(session_id, username=f"user{session_id}")