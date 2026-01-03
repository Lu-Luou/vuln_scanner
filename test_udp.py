import socket
import threading

UDP_HOST = "127.0.0.1"
UDP_PORT = 54321
TCP_HOST = "127.0.0.1"
TCP_PORT = 54322


def run_udp_server() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((UDP_HOST, UDP_PORT))
        print(f"UDP server listening on {UDP_HOST}:{UDP_PORT}")
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except OSError as err:
                print("UDP recv error:", err)
                break
            print("udp recv from", addr, "->", data.decode(errors="replace"))
            try:
                sock.sendto(b"PONG from UDP server\n", addr)
            except OSError as err:
                print("UDP send error:", err)
    finally:
        sock.close()


def run_tcp_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((TCP_HOST, TCP_PORT))
        srv.listen(5)
        print(f"TCP server listening on {TCP_HOST}:{TCP_PORT}")
        while True:
            try:
                conn, addr = srv.accept()
            except OSError as err:
                print("TCP accept error:", err)
                break
            print("tcp conn from", addr)
            try:
                data = conn.recv(4096)
                if data:
                    print("tcp recv ->", data.decode(errors="replace"))
                    conn.sendall(b"PONG from TCP server\n")
            except OSError as err:
                print("TCP conn error:", err)
            finally:
                conn.close()
    finally:
        srv.close()


if __name__ == "__main__":
    threading.Thread(target=run_tcp_server, daemon=True).start()
    print("\n")
    threading.Thread(target=run_udp_server, daemon=True).start()
    try:
        threading.Event().wait()  # Mantiene el proceso vivo
    except KeyboardInterrupt:
        print("Cerrando servidores...")
