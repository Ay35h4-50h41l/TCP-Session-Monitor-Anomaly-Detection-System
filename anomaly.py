import socket
import json
import time
import os

HOST = "127.0.0.1"
PORT = 5000

# ----------------- Packet sender -----------------
def send_packet(sock, session_id, seq, msg_type, data):
    packet = {
        "session_id": session_id,
        "seq": seq,
        "data": f"{msg_type}|{len(data)}|{data}",
        "timestamp": time.time()
    }
    sock.send(json.dumps(packet).encode())
    try:
        ack = sock.recv(1024).decode()
    except:
        ack = "No ACK"
    print(f"[SENT] {packet['data']} | ACK: {ack}")

# ----------------- Menu -----------------
def menu():
    print("\n=== Anomaly Tester Menu ===")
    print("1. Normal Message")
    print("2. Retransmission (duplicate SEQ)")
    print("3. Out-of-order sequence")
    print("4. Invalid SEQ/ACK (skip sequence)")
    print("5. Repeated payload")
    print("6. Session hijack (use existing session ID)")
    print("7. Active Packet Injection")
    print("8. Exit")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# ----------------- Interactive Tester -----------------
def run_tester():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print("[INFO] Connected to server")

    session_id = int(input("Enter session ID for this test client: "))
    seq_dict = {session_id: 1}  # sequence tracker per session
    active_sessions = [session_id]

    while True:
        menu()
        choice = input("Select anomaly to test: ").strip()
        clear_screen()

        if choice == "1":
            data = input("Enter message content: ")
            seq = seq_dict[session_id]
            send_packet(sock, session_id, seq, "MSG", data)
            seq_dict[session_id] += 1

        elif choice == "2":
            data = input("Enter message to duplicate SEQ: ")
            seq = seq_dict[session_id]
            send_packet(sock, session_id, seq, "MSG", data)
            send_packet(sock, session_id, seq, "MSG", data + " duplicate")  # duplicate SEQ
            seq_dict[session_id] += 1

        elif choice == "3":
            # Out-of-order: send seq+1 before seq
            data1 = input("Enter first message (will be sent later): ")
            data2 = input("Enter second message (out-of-order): ")
            seq = seq_dict[session_id]
            send_packet(sock, session_id, seq + 1, "MSG", data2)  # out-of-order
            send_packet(sock, session_id, seq, "MSG", data1)
            seq_dict[session_id] += 2

        elif choice == "4":
            # Invalid SEQ: skip a sequence deliberately by adding a large offset
            # This clearly demonstrates a gap in expected sequence numbers
            data = input("Enter message content (skip a sequence): ")
            seq = seq_dict[session_id] + 5  # skip 5 sequence numbers to clearly invalidate
            send_packet(sock, session_id, seq, "MSG", data)
            seq_dict[session_id] = seq + 1

        elif choice == "5":
            data = input("Enter message to repeat payload: ")
            seq = seq_dict[session_id]
            send_packet(sock, session_id, seq, "MSG", data)
            send_packet(sock, session_id, seq + 1, "MSG", data)  # repeated payload
            seq_dict[session_id] += 2

        elif choice == "6":
            # Session hijack: we must use a DIFFERENT source socket to trigger the
            # source IP/port mismatch expected in proper hijack anomaly detection
            hijack_session = int(input("Enter existing session ID to hijack: "))
            data = input("Enter message to send as hijacker: ")

            # Create a new socket to simulate an attacker from a different port
            hijack_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            hijack_sock.connect((HOST, PORT))

            if hijack_session not in seq_dict:
                seq_dict[hijack_session] = 1 # Guess sequence if unknown locally
            seq = seq_dict[hijack_session]

            send_packet(hijack_sock, hijack_session, seq, "MSG", data)
            seq_dict[hijack_session] += 1
            hijack_sock.close()
            print(f"[INFO] Hijack attempt sent from a new source port for session {hijack_session}.")

        elif choice == "7":
            # Active Packet Injection (Mandatory assignment requirement)
            print("\n--- Active Packet Injection ---")
            print("a. Inject fake server response")
            print("b. Send TCP RST (terminate session)")
            print("c. Basic TCP spoofing")
            inj_choice = input("Select injection type (a/b/c): ").strip().lower()

            target_session = int(input("Enter target session ID for injection: "))

            # Create a separate socket to inject traffic independently
            inj_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            inj_sock.connect((HOST, PORT))

            if inj_choice == "a":
                # Inject fake server response
                data = input("Enter fake server response payload: ")
                send_packet(inj_sock, target_session, 9999, "SERVER_RSP", data)
                print("[INFO] Injected fake server response.")

            elif inj_choice == "b":
                # Send TCP RST (terminate session)
                seq = seq_dict.get(target_session, 1)
                send_packet(inj_sock, target_session, seq, "RST", "Connection reset by peer")
                seq_dict[target_session] = 1
                print(f"[INFO] Sent TCP RST. Session {target_session} terminated and sequence reset to 1.")

            elif inj_choice == "c":
                # Basic TCP spoofing
                spoofed_seq = int(input("Enter spoofed sequence number: "))
                data = input("Enter spoofed data: ")
                send_packet(inj_sock, target_session, spoofed_seq, "SPOOF", data)
                print("[INFO] Spoofed TCP packet sent.")
            else:
                print("Invalid injection choice.")

            inj_sock.close()

        elif choice == "8":
            logout = input("Send LOGOUT before exit? (y/n): ").strip().lower()
            if logout == "y":
                seq = seq_dict[session_id]
                send_packet(sock, session_id, seq, "LOGOUT", "")
            break

        else:
            print("Invalid choice. Try again.")

    sock.close()
    print("[INFO] Tester client disconnected")

# ----------------- Main -----------------
if __name__ == "__main__":
    run_tester()