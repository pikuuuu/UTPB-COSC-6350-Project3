import socket
from concurrent.futures import ThreadPoolExecutor
import struct
from Crypto import keys, PAYLOAD, aes_encrypt, decompose_byte

HOST = '0.0.0.0'
PORT = 5555
TIMEOUT = 600
MAX_THREADS = 10

def handle_client(conn, addr):
    conn.settimeout(TIMEOUT)
    print(f"[INFO] Connection from {addr} established.")
    try:
        with open("risk.bmp", "rb") as file:
            file_content = file.read()
        
        crumbs = []
        for byte in file_content:
            crumbs.extend(decompose_byte(byte))
        
        total_crumbs = len(crumbs)
        print(f"[INFO] Total crumbs: {total_crumbs}")
        conn.sendall(struct.pack('!I', total_crumbs))
        
        while True:
            print(f"Sending crumbs to client...")
            for i, crumb in enumerate(crumbs):
                key = keys[crumb]
                encrypted_payload = aes_encrypt(PAYLOAD, key)
                conn.sendall(struct.pack('!I', len(encrypted_payload)))
                conn.sendall(encrypted_payload)
            
            # After sending all crumbs, get overall completion
            completion_data = conn.recv(4)
            if not completion_data:
                print("[INFO] Client disconnected.")
                break
            
            completion = struct.unpack('!f', completion_data)[0]
            
            if completion >= 1.0:
                print("[INFO] File fully transmitted and decoded by client.")
                # Acknowledge receipt of completion status
                conn.sendall(b'ACK')
                break
            
    except Exception as e:
        print(f"[ERROR] Error handling client {addr}: {e}")
    finally:
        conn.close()
        print(f"[INFO] Connection from {addr} closed.")

def start_server():
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((HOST, PORT))
            server_socket.listen()
            print(f"[INFO] Server started, listening on {PORT}...")

            while True:
                conn, addr = server_socket.accept()
                print(f"[INFO] Accepted connection from {addr}.")
                executor.submit(handle_client, conn, addr)

if __name__ == "__main__":
    start_server()
