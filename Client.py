import socket
import struct
import random
from Crypto import keys, PAYLOAD, aes_decrypt, recompose_byte

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555

def tcp_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            print(f"[INFO] Connecting to server at {SERVER_HOST}:{SERVER_PORT}...")
            client_socket.connect((SERVER_HOST, SERVER_PORT))
            print(f"[INFO] Connected to server!")

            total_crumbs = struct.unpack('!I', client_socket.recv(4))[0]
            print(f"[INFO] Expecting {total_crumbs} crumbs from the server.")
            crumbs = [None] * total_crumbs
            attempted_keys = [[] for _ in range(total_crumbs)]
            num_decoded = 0
            completion = 0

            while num_decoded < total_crumbs:
                for i in range(total_crumbs):
                    if crumbs[i] is not None:
                        continue

                    try:
                        payload_size = struct.unpack('!I', client_socket.recv(4))[0]
                        encrypted_payload = client_socket.recv(payload_size)
                    except Exception as e:
                        print(f"[WARN] Error receiving crumb {i}: {e}")
                        continue

                    available_keys = [key for key in keys.values() if key not in attempted_keys[i]]

                    if not available_keys:
                        print(f"[WARN] No keys left to try for crumb {i}. Marking as undecodable.")
                        crumbs[i] = "INVALID"  # Mark the crumb as invalid
                        continue

                    attempts = 0
                    success = False
                    for key in available_keys:
                        try:
                            decrypted_payload = aes_decrypt(encrypted_payload, key)
                            if decrypted_payload == PAYLOAD:
                                crumb = next(k for k, v in keys.items() if v == key)
                                crumbs[i] = crumb
                                num_decoded += 1
                                completion = num_decoded / total_crumbs
                                print(f"[INFO] Progress: {completion:.2%}")
                                print(f"[DEBUG] Crumb {i} successfully decrypted with key {key.hex()} after {attempts + 1} attempts")
                                success = True
                                break
                            else:
                                attempted_keys[i].append(key)
                        except Exception:
                            attempted_keys[i].append(key)
                        attempts += 1

                    if not success:
                        print(f"[WARN] Crumb {i} could not be decrypted after {attempts} attempts.")

                # Send progress to the server
                client_socket.sendall(struct.pack('!f', completion))

                if completion >= 1.0:
                    print("\n[SUCCESS] File successfully received and decoded!")
                    client_socket.sendall(b'ACK')
                    break

            if num_decoded < total_crumbs:
                print("[WARN] Some crumbs could not be decoded. Partial file received.")

        except Exception as e:
            print(f"[ERROR] An error occurred: {e}")
        finally:
            print("[INFO] Closing connection to server.")



if __name__ == "__main__":
    tcp_client()
