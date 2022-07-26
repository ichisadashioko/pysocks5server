import os
import socket
import threading
import io
import struct
import time
import sys
import argparse
import traceback


def receive_socket_data_and_assert(
    socket_obj: socket.socket,
    length: int,
    message: str,
):
    bs = socket_obj.recv(length)
    bs_len = len(bs)
    if bs_len != length:
        raise Exception(f'{bs_len} != {length} - {message}')

    return bs


METHOD_NO_AUTHENTICATION_REQUIRED = 0

REQUEST_CMD_CONNECT = 1
REQUEST_CMD_BIND = 2
REQUEST_CMD_UDP_ASSOCIATE = 3
REQUEST_CMD_LIST = [
    REQUEST_CMD_CONNECT,
    REQUEST_CMD_BIND,
    REQUEST_CMD_UDP_ASSOCIATE,
]

ATYP_IPV4 = 1
ATYP_DOMAINNAME = 3
ATYP_IPV6 = 4

ATYP_LIST = [
    ATYP_IPV4,
    ATYP_DOMAINNAME,
    ATYP_IPV6,
]

DEFAULT_CONNECT_TIMEOUT = 5


def connect_to_the_internet(
    atyp: int,
    address: bytes,
    port: int,
):
    if atyp == ATYP_IPV4:
        socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif atyp == ATYP_DOMAINNAME:
        socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif atyp == ATYP_IPV6:
        socket_obj = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
        raise Exception(f'Unknown atyp {atyp}')

    socket_obj.connect((address, port,))


def handle_client(client_socket: socket.socket, address):
    try:
        bs = receive_socket_data_and_assert(client_socket, 1, 'version identifier')
        version = bs[0]
        if version != 5:
            raise Exception(f'unsupported socks version {version}')

        bs = receive_socket_data_and_assert(client_socket, 1, 'method byte count')
        method_byte_count = bs[0]
        if method_byte_count == 0:
            raise Exception('method_byte_count == 0')

        bs = receive_socket_data_and_assert(client_socket, method_byte_count, 'method bytes')

        found_supported_method = False
        for method in bs:
            if method == METHOD_NO_AUTHENTICATION_REQUIRED:
                found_supported_method = True
                break

        if not found_supported_method:
            print('no supported method found')
            client_socket.send(b'\x05\xff')
        else:
            client_socket.send(b'\x05\x00')

        bs = receive_socket_data_and_assert(client_socket, 4, 'client request header')
        version = bs[0]
        if version != 5:
            raise Exception(f'unsupported socks version {version}')

        request_command = bs[1]
        if request_command not in REQUEST_CMD_LIST:
            raise Exception(f'unsupported request command {request_command}')

        reserved_byte = bs[2]
        if reserved_byte != 0:
            raise Exception(f'unsupported reserved byte {reserved_byte} - must be 0')

        address_type = bs[3]

        if address_type not in ATYP_LIST:
            raise Exception(f'unsupported address type {address_type}')

        destination_address_bytes = None
        destination_address = {
            # 'ipv4_str': None,
            # 'ipv4_bytes': None,
            # 'domainname_bytes': None,
            # 'domainname_ascii_str': None,
            # 'ipv6_str': None,
            # 'ipv6_bytes': None,
        }

        if address_type == ATYP_IPV4:
            bs = receive_socket_data_and_assert(client_socket, 4, 'ipv4 address')
            destination_address['ipv4_bytes'] = bs
            destination_address['ipv4_str'] = socket.inet_ntoa(bs)
        elif address_type == ATYP_DOMAINNAME:
            bs = receive_socket_data_and_assert(client_socket, 1, 'domainname length')
            domainname_length = bs[0]
            bs = receive_socket_data_and_assert(client_socket, domainname_length, 'domainname bytes')
            destination_address['domainname_bytes'] = bs
            destination_address['domainname_ascii_str'] = bs.decode('ascii')
        elif address_type == ATYP_IPV6:
            bs = receive_socket_data_and_assert(client_socket, 16, 'ipv6 address')
            destination_address['ipv6_bytes'] = bs
            destination_address['ipv6_str'] = socket.inet_ntop(socket.AF_INET6, bs)
        else:
            raise Exception(f'unsupported address type {address_type}')

        bs = receive_socket_data_and_assert(client_socket, 2, 'port')
        destination_port = struct.unpack('>H', bs)[0]

        print(f'{address} -> {destination_address}:{destination_port}')

        if address_type == ATYP_DOMAINNAME:
            # TODO send dns request
            pass

        if request_command
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if address_type == ATYP_IPV4:
            proxy_socket.connect((destination_address['ipv4_str'], destination_port))
        elif address_type == ATYP_DOMAINNAME:
            proxy_socket.connect((destination_address['domainname_ascii_str'], destination_port))
        elif address_type == ATYP_IPV6:
            proxy_socket.connect((destination_address['ipv6_str'], destination_port))

    except Exception as ex:
        stacktrace = traceback.format_exc()
        print(ex)
        print(stacktrace)
    finally:
        client_socket.close()
        print(f'Closed connection to {address}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('port', type=int, nargs='?', default=1080)

    args = parser.parse_args()
    print('args', args)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    port_number = args.port

    server_socket.bind(('', port_number))
    server_socket.listen()

    while True:
        client_socket, address = server_socket.accept()
        print(f'Accepted connection from {address}')
        client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
        client_thread.start()


if __name__ == '__main__':
    main()
