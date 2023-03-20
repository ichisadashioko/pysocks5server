import os
import socket
import threading
import io
import struct
import time
import sys
import argparse
import traceback

RS = '\033[0m'
R = '\033[91m'
G = '\033[92m'
Y = '\033[93m'

BLACKLIST_DOMAINNAME_LIST = [
    # 'google.com',
    'googleapis.com',
    'crashlytics.com',
    'facebook.com',
    'darkreader.org',
    'exp-tas.com',
]

WHITELIST_DOMAINNAME_LIST = [
    'ajax.googleapis.com',
]


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
METHOD_GSSAPI = 1
METHOD_USERNAME_PASSWORD = 2
METHOD_NO_ACCEPTABLE_METHODS = 0xFF

REQUEST_CMD_CONNECT = 1
REQUEST_CMD_BIND = 2
REQUEST_CMD_UDP_ASSOCIATE = 3
REQUEST_CMD_LIST = [
    REQUEST_CMD_CONNECT,
    REQUEST_CMD_BIND,
    REQUEST_CMD_UDP_ASSOCIATE,
]

ATYP_IPV4_BS = b'\x01'
ATYP_DOMAINNAME_BS = b'\x03'
ATYP_IPV6_BS = b'\x04'

ATYP_IPV4 = 1
ATYP_DOMAINNAME = 3
ATYP_IPV6 = 4

# supported address types
ATYP_LIST = [
    ATYP_IPV4,
    ATYP_DOMAINNAME,
    ATYP_IPV6,
]

REP_SUCCESS = b'\x00'
REP_GENERAL_SOCKS_SERVER_FAILURE = b'\x01'
REP_CONNECTION_NOT_ALLOWED_BY_RULESET = b'\x02'
REP_NETWORK_UNREACHABLE = b'\x03'
REP_HOST_UNREACHABLE = b'\x04'
REP_CONNECTION_REFUSED = b'\x05'
REP_TTL_EXPIRED = b'\x06'
REP_COMMAND_NOT_SUPPORTED = b'\x07'
REP_ADDRESS_TYPE_NOT_SUPPORTED = b'\x08'


DEFAULT_CONNECT_TIMEOUT = 5


def connect_to_the_internet(
    atyp: int,
    address,
    port: int,
):
    print(f'{G}{atyp}{RS} {R}{address}:{port}{RS}')
    if atyp == ATYP_IPV4:
        socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif atyp == ATYP_DOMAINNAME:
        # TODO handle case when domainname length is equal to IPV4 length
        socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif atyp == ATYP_IPV6:
        socket_obj = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
        raise Exception(f'Unknown atyp {atyp}')

    socket_obj.settimeout(DEFAULT_CONNECT_TIMEOUT)
    address_port = (address, port)
    socket_obj.connect(address_port)
    socket_obj.settimeout(None)
    return socket_obj


def serialize_ip_address(
    ip_address_bytes: bytes,
):
    buffer = io.BytesIO()
    if len(ip_address_bytes) == 4:
        buffer.write(ATYP_IPV4_BS)
    elif len(ip_address_bytes) == 16:
        buffer.write(ATYP_IPV6_BS)
    else:
        raise Exception(f'Unknown ip address length {len(ip_address_bytes)}')
    buffer.write(ip_address_bytes)
    return buffer.getvalue()


def serialize_port_number(
    port_number: int,
):
    bs = struct.pack('!H', port_number)
    if len(bs) != 2:
        raise Exception(f'Unknown port number length {len(bs)}')
    return bs


def tunnel_socket_data(
    source_socket: socket.socket,
    destination_socket: socket.socket,
    log_list: list,
    error_log: list,
):
    try:
        while True:
            bs = source_socket.recv(16384)
            recv_ts = time.time_ns()
            log_list.append((recv_ts, bs,))
            recv_len = len(bs)
            if recv_len == 0:
                break

            sent_count = 0
            while sent_count < recv_len:
                sent_count += destination_socket.send(bs[sent_count:])
    except Exception as ex:
        stacktrace = traceback.format_exc()
        ts = time.time_ns()
        error_log.append({
            'time_ns': ts,
            'stacktrace': stacktrace,
            'exception': ex,
        })


def handle_client(client_socket: socket.socket, address):
    handle_client_ts = time.time_ns()
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
            elif method == METHOD_USERNAME_PASSWORD:
                # TODO handle username/password authentication
                found_supported_method = True
                break

        if not found_supported_method:
            # print('no supported method found')
            # client_socket.send(b'\x05\xff')
            raise Exception('no supported method found')

        if method != METHOD_NO_AUTHENTICATION_REQUIRED:
            raise Exception(f'unsupported method {method}')

        bs = b'\x05\x00'
        client_socket.send(bs)

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
        destination_address = None

        if address_type == ATYP_IPV4:
            bs = receive_socket_data_and_assert(client_socket, 4, 'ipv4 address')
            destination_address_bytes = bs
            destination_address = socket.inet_ntoa(bs)
            # destination_address['ipv4_str'] = socket.inet_ntoa(bs)
        elif address_type == ATYP_DOMAINNAME:
            bs = receive_socket_data_and_assert(client_socket, 1, 'domainname length')
            domainname_length = bs[0]
            bs = receive_socket_data_and_assert(client_socket, domainname_length, 'domainname bytes')
            destination_address_bytes = bs
            # TODO Do we need to decode bytes to string for domain name?
            destination_address = bs.decode('ascii')

            in_white_list = False
            for domain_str in WHITELIST_DOMAINNAME_LIST:
                if domain_str in destination_address:
                    in_white_list = True
                    break

            if not in_white_list:
                for domain_str in BLACKLIST_DOMAINNAME_LIST:
                    if domain_str in destination_address:
                        raise Exception(f'blacklisted domain name {domain_str} in {destination_address}')
            # destination_address['domainname_ascii_str'] = bs.decode('ascii')
        elif address_type == ATYP_IPV6:
            bs = receive_socket_data_and_assert(client_socket, 16, 'ipv6 address')
            destination_address_bytes = bs
            destination_address = socket.inet_ntop(socket.AF_INET6, bs)
            # destination_address['ipv6_str'] = socket.inet_ntop(socket.AF_INET6, bs)
        else:
            raise Exception(f'unsupported address type {address_type}')

        if destination_address is None:
            raise Exception('destination_address is None')

        bs = receive_socket_data_and_assert(client_socket, 2, 'port')
        destination_port = struct.unpack('>H', bs)[0]

        print(f'{address} -> {destination_address}:{destination_port}')

        if request_command != REQUEST_CMD_CONNECT:
            # TODO handle other request commands
            raise Exception(f'unsupported request command {request_command}')
        # if address_type == ATYP_DOMAINNAME:
        #     # TODO send dns request
        #     pass

        destination_socket_obj = connect_to_the_internet(
            atyp=address_type,
            address=destination_address,
            port=destination_port,
        )

        try:
            destination_ip_address, destination_connected_port = destination_socket_obj.getsockname()

            destination_ip_address_bytes = socket.inet_aton(destination_ip_address)
            destination_port_bytes = serialize_port_number(destination_connected_port)

            buffer = io.BytesIO()
            buffer.write(b'\x05')  # version
            buffer.write(b'\x00')  # reply code (success)
            buffer.write(b'\x00')  # reserved
            buffer.write(serialize_ip_address(destination_ip_address_bytes))
            buffer.write(destination_port_bytes)
            bs = buffer.getvalue()
            client_socket.send(bs)

            # start 2 threads to handle proxy communication
            client_to_destination_thread_log_list = []
            client_to_destination_thread_error_log = []
            socks5_client_to_destination_thread = threading.Thread(
                target=tunnel_socket_data,
                args=(
                    client_socket,
                    destination_socket_obj,
                    client_to_destination_thread_log_list,
                    client_to_destination_thread_error_log,
                ),
            )

            destination_to_client_thread_log_list = []
            destination_to_client_thread_error_log = []
            destination_to_socks5_client_thread = threading.Thread(
                target=tunnel_socket_data,
                args=(
                    destination_socket_obj,
                    client_socket,
                    destination_to_client_thread_log_list,
                    destination_to_client_thread_error_log,
                ),
            )

            socks5_client_to_destination_thread.start()
            destination_to_socks5_client_thread.start()

            print(time.time_ns(), 'waiting for socks5_client_to_destination_thread to finish')
            socks5_client_to_destination_thread.join()
            print(time.time_ns(), 'socks5_client_to_destination_thread finished')
            print(time.time_ns(), 'socks5_client_to_destination_thread finished')
            destination_to_socks5_client_thread.join()
            print(time.time_ns(), 'destination_to_socks5_client_thread finished')

            if len(client_to_destination_thread_error_log) > 0:
                for error in client_to_destination_thread_error_log:
                    print(error)

            if len(destination_to_client_thread_error_log) > 0:
                for error in destination_to_client_thread_error_log:
                    print(error)

        except Exception as destination_socket_exception:
            stacktrace = traceback.format_exc()
            print(f'{Y}{destination_socket_exception}{RS}')
            print(f'{R}{stacktrace}{RS}')
            error_log.append((time.time_ns(), destination_socket_exception, stacktrace,))
        finally:
            destination_socket_obj.close()
    except Exception as ex:
        stacktrace = traceback.format_exc()
        print(f'{Y}{ex}{RS}')
        print(f'{R}{stacktrace}{RS}')
    finally:
        client_socket.close()
        print(f'Closed connection to {address}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('port', type=int, nargs='?', default=10801)

    args = parser.parse_args()
    print('args', args)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port_number = args.port

    server_socket.bind(('0.0.0.0', port_number))
    print(time.time_ns(), f'Listening on port {port_number}')
    server_socket.listen()

    while True:
        print(time.time_ns(), 'Waiting for client to connect')
        client_socket, address = server_socket.accept()
        print(f'Accepted connection from {address}')
        client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
        client_thread.start()


if __name__ == '__main__':
    main()
