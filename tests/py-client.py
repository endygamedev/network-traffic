#!/usr/bin/env python3

import socket
from argparse import ArgumentParser


def main(*, ip_server="127.0.0.1", port=9999, message="Hello", count=10) -> None:
    client = ("127.0.0.1", 9998)
    server = (ip_server, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(client)

    for _ in range(count):
        sock.sendto(bytes(message, "utf-8"), server)
    sock.close()


if __name__ == "__main__":
    parser = ArgumentParser()

    parser.add_argument("-m", "--message", dest="message",
                        help="message to be sent to the server", type=str)

    parser.add_argument("-c", "--count", dest="count",
                        help="number of times the message will be printed", type=int)

    parser.add_argument("-s", "--ip_server", dest="ip_server",
                        help="UDP server ip address", type=str)

    parser.add_argument("-p", "--port", dest="port",
                        help="UDP server port", type=int)

    args = {k: v for k, v in vars(parser.parse_args()).items() if v is not None}

    main(**args)

