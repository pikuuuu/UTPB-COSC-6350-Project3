import socket
import struct
import random
from Crypto import keys, PAYLOAD, aes_decrypt, recompose_byte

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555

def tcp_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((SERVER_HOST, SERVER_PORT))
            print(f"[INFO] Connected to {SERVER_HOST}:{SERVER_PORT}")

            total_crumbs = struct.unpack('!I', client_socket.recv(4))[0]
            print(f"[INFO] Total crumbs to receive: {total_crumbs}")
            crumbs = [None] * total_crumbs
            attempted_keys = [[] for _ in range(total_crumbs)]
            num_decoded = 0
            completion = 0
            ref_payload_size = 0

            while num_decoded < total_crumbs:
                for i in range(total_crumbs):
                    if crumbs[i] is not None:
                        # Skip already decoded crumbs
                        # client_socket.sendall(b'ACK')
                        # client_socket.sendall(b'1')  # 1 for decoded
                        continue

                    payload_size = struct.unpack('!I', client_socket.recv(4))[0]
                    ref_payload_size = payload_size
                    encrypted_payload = client_socket.recv(payload_size)

                    # Acknowledge receipt of crumb
                    # client_socket.sendall(b'ACK')

                    available_keys = [key for key in keys.values() if key not in attempted_keys[i]]
                    
                    if not available_keys:
                        # print(f"[WARN] No more keys to try for crumb {i}")
                        # client_socket.sendall(b'0')  # 0 for not decoded
                        continue

                    key = random.choice(available_keys)
                    try:
                        decrypted_payload = aes_decrypt(encrypted_payload, key)
                        if decrypted_payload == PAYLOAD:
                            crumb = next(k for k, v in keys.items() if v == key)
                            crumbs[i] = crumb
                            num_decoded += 1
                            new_completion = num_decoded / total_crumbs
                            if round(new_completion, 2) != round(completion, 2):
                                print(f"[INFO] Decoding progress: {completion:.0%}")
                            completion = new_completion
                        else:
                            attempted_keys[i].append(key)
                    except:
                        pass

                client_socket.sendall(struct.pack('!f', completion))

            if completion == 1.0:
                decoded_bytes = bytes(recompose_byte(crumbs[i:i+4]) for i in range(0, len(crumbs), 4))
                print("[INFO] File successfully received and decoded.")
            else:
                print("[WARN] File transmission incomplete.")

            # flush extra data crumbs
            while (extra_recv := client_socket.recv(4)) == struct.pack('!I', ref_payload_size):
                client_socket.recv(ref_payload_size)

            if extra_recv[:3] != b'ACK':
                print("[ERROR] Did not receive proper acknowledgment from server")

        except Exception as e:
            print(f"[ERROR] An error occurred: {e}")
        finally:
            print(f"[INFO] Connection closed.")

if __name__ == "__main__":
    tcp_client()
