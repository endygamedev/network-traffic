import socket


def main():
    client = ("10.0.0.2", 9998)
    server = ("127.0.0.1", 9999)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(client)

    sock.sendto(b"Hello World", server)
    sock.close()



if __name__ == "__main__":
    main()
