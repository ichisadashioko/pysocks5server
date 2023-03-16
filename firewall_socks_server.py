import os
import socket
import threading
import io
import struct
import time
import sys
import argparse
import traceback
import pickle
import gzip

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


def make_obj_pickle_friendly(obj):
    try:
        pickle.dumps(obj)
        return obj
    except Exception:
        if isinstance(obj, dict):
            return {
                key: make_obj_pickle_friendly(value)
                for key, value in obj.items()
            }
        elif isinstance(obj, list):
            return [
                make_obj_pickle_friendly(value)
                for value in obj
            ]
        elif isinstance(obj, tuple):
            return tuple(
                make_obj_pickle_friendly(value)
                for value in obj
            )
        else:
            return repr(obj)


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
                ts = time.time_ns()
                error_log.append({
                    'time_ns': ts,
                    'message': 'socks5 client socket closed',
                })

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


LOGGING_TYPE_FROM_CLIENT_TO_ME = 0
LOGGING_TYPE_FROM_ME_TO_CLIENT = 1
LOGGING_TYPE_FROM_ME_TO_DESTINATION = 2
LOGGING_TYPE_FROM_DESTINATION_TO_ME = 3


def handle_client(client_socket: socket.socket, address):
    handle_client_ts = time.time_ns()
    data_log = []
    error_log = []
    try:
        bs = receive_socket_data_and_assert(client_socket, 1, 'version identifier')
        data_log.append([LOGGING_TYPE_FROM_CLIENT_TO_ME, time.time_ns(), bs, ])
        version = bs[0]
        if version != 5:
            raise Exception(f'unsupported socks version {version}')

        bs = receive_socket_data_and_assert(client_socket, 1, 'method byte count')
        data_log.append([LOGGING_TYPE_FROM_CLIENT_TO_ME, time.time_ns(), bs, ])
        method_byte_count = bs[0]
        if method_byte_count == 0:
            raise Exception('method_byte_count == 0')

        bs = receive_socket_data_and_assert(client_socket, method_byte_count, 'method bytes')
        data_log.append([LOGGING_TYPE_FROM_CLIENT_TO_ME, time.time_ns(), bs, ])

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
        data_log.append([LOGGING_TYPE_FROM_ME_TO_CLIENT, time.time_ns(), bs, ])
        client_socket.send(bs)

        bs = receive_socket_data_and_assert(client_socket, 4, 'client request header')
        data_log.append([LOGGING_TYPE_FROM_CLIENT_TO_ME, time.time_ns(), bs, ])
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
            data_log.append([LOGGING_TYPE_FROM_CLIENT_TO_ME, time.time_ns(), bs, ])
            destination_address_bytes = bs
            destination_address = socket.inet_ntoa(bs)
            # destination_address['ipv4_str'] = socket.inet_ntoa(bs)
        elif address_type == ATYP_DOMAINNAME:
            bs = receive_socket_data_and_assert(client_socket, 1, 'domainname length')
            data_log.append([LOGGING_TYPE_FROM_CLIENT_TO_ME, time.time_ns(), bs, ])
            domainname_length = bs[0]
            bs = receive_socket_data_and_assert(client_socket, domainname_length, 'domainname bytes')
            data_log.append([LOGGING_TYPE_FROM_CLIENT_TO_ME, time.time_ns(), bs, ])
            destination_address_bytes = bs
            # TODO Do we need to decode bytes to string for domain name?
            destination_address = bs.decode('ascii')
            for domain_str in BLACKLIST_DOMAINNAME_LIST:
                if domain_str in destination_address:
                    raise Exception(f'blacklisted domain name {domain_str} in {destination_address}')
            # destination_address['domainname_ascii_str'] = bs.decode('ascii')
        elif address_type == ATYP_IPV6:
            bs = receive_socket_data_and_assert(client_socket, 16, 'ipv6 address')
            data_log.append([LOGGING_TYPE_FROM_CLIENT_TO_ME, time.time_ns(), bs, ])
            destination_address_bytes = bs
            destination_address = socket.inet_ntop(socket.AF_INET6, bs)
            # destination_address['ipv6_str'] = socket.inet_ntop(socket.AF_INET6, bs)
        else:
            raise Exception(f'unsupported address type {address_type}')

        if destination_address is None:
            raise Exception('destination_address is None')

        bs = receive_socket_data_and_assert(client_socket, 2, 'port')
        data_log.append([LOGGING_TYPE_FROM_CLIENT_TO_ME, time.time_ns(), bs, ])
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
            data_log.append([LOGGING_TYPE_FROM_ME_TO_CLIENT, time.time_ns(), bs, ])

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

            for (log_ts, log_bs) in client_to_destination_thread_log_list:
                data_log.append([LOGGING_TYPE_FROM_ME_TO_DESTINATION, log_ts, log_bs, ])

            for (log_ts, log_bs) in destination_to_client_thread_log_list:
                data_log.append([LOGGING_TYPE_FROM_DESTINATION_TO_ME, log_ts, log_bs, ])
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
        error_log.append((time.time_ns(), ex, stacktrace,))
    finally:
        output_log_data = {
            'data_log': data_log,
            'error_log': error_log,
        }

        output_log_data = make_obj_pickle_friendly(obj=output_log_data)
        output_root = 'output_log_data'
        if not os.path.exists(output_root):
            os.makedirs(output_root)
        # output_filepath = f'{handle_client_ts}_output_log_data.pickle.gzip'
        output_filepath = os.path.join(output_root, f'{handle_client_ts}.pickle.gzip')
        pickle_bs = pickle.dumps(output_log_data)
        with gzip.open(output_filepath, 'wb', compresslevel=9) as outfile:
            outfile.write(pickle_bs)

        client_socket.close()
        print(f'Closed connection to {address}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('port', type=int, nargs='?', default=1080)

    args = parser.parse_args()
    print('args', args)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    port_number = args.port

    # handle_client_thread_list = []

    server_socket.bind(('0.0.0.0', port_number))
    print(time.time_ns(), f'Listening on port {port_number}')
    server_socket.listen()

    while True:
        print(time.time_ns(), 'Waiting for client to connect')
        client_socket, address = server_socket.accept()
        print(f'Accepted connection from {address}')
        client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
        client_thread.start()
        # ts = time.time_ns()
        # handle_client_thread_list.append({
        #     'thread': client_thread,
        #     'time_ns': ts,
        # })


if __name__ == '__main__':
    main()

# 6. Replies
# The SOCKS request information is sent by the client as soon as it has established a connection to the SOCKS server, and completed the authentication negotiations. The server evaluates the request, and returns a reply formed as follows:
# +----+-----+-------+------+----------+----------+
# |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
# +----+-----+-------+------+----------+----------+
# | 1  |  1  | X'00' |  1   | Variable |    2     |
# +----+-----+-------+------+----------+----------+

# Where:
# - VER    protocol version: X'05'
# - REP    Reply field:
#   - X'00' succeeded
#   - X'01' general SOCKS server failure
#   - X'02' connection not allowed by ruleset
#   - X'03' Network unreachable
#   - X'04' Host unreachable
#   - X'05' Connection refused
#   - X'06' TTL expired
#   - X'07' Command not supported
#   - X'08' Address type not supported
#   - X'09' to X'FF' unassigned
# - RSV    RESERVED
# - ATYP   address type of following address
#   - X'01' IP V4 host address
#   - X'03' DOMAINNAME
#   - X'04' IP V6 host address
# - BND.ADDR       server bound address
# - BND.PORT       server bound port in network byte order (big endian)

# Fields marked RESERVED (RSV) must be set to X'00'.

# If the chosen method includes encapsulation for purposes of authentication, integrity and/or confidentiality, the replies are encapsulated in the method-dependent encapsulation.

# CONNECT
# In the reply to a CONNECT, BND.PORT contains the port number that the server assigned to connect to the target host, while BND.ADDR contains the associated IP address. The supplied BND.ADDR is often different from the IP address that the client uses to reach the SOCKS server, since such servers are often multi-homed. It is expected that the SOCKS server will use DST.ADDR and DST.PORT, and the client-side source address and port in evaluating the CONNECT request.

# TODO - reader note
# Who is the "target host"?
# What do "BND.ADDR" and "BND.PORT" used for? Does the client connect to that address and port to send SOCKS5 requests (again)?
# What is "multi-homed"? Does the SOCKS5 server only handle initial communication with the SOCK5 client and tells the client the address and port to connect to?
# ~~Why does this section placed below the "4. Requests" section? Ohh, nothing. This is the reply to what the client just sent.~~

# BIND
# The BIND request is used in protocols which require the client to accept connections from the server. FTP is a well-known example, which uses the primary client-to-server connection for commands and status reports, but may use a server-to-client connection for transferring data on demand (e.g. LS, GET, PUT).

# It is expected that the client side of an application protocol will use the BIND request only to establish secondary connections after a primary connection is established using CONNECT. It is expected that a SOCKS server will use DST.ADDR and DST.PORT in evaluating the BIND request.

# Two replies are sent from the SOCKS server to the client during a BIND operation. The first is sent after the server creates and binds a new socket. The BND.PORT field contains the port number that the server assigned to listen for an incoming connection. The BND.ADDR field contains the associated IP address. The client will typically use these pieces of information to notify (via the primary or control connection) the application server of the rendezvous address. The second reply occurs only after the anticipated incoming connection succeeds or fails.

# TODO - reader note
# The word "rendezvous" makes no sense for me in this context. What is the "rendezvous address"?

# In the second reply, the BND.PORT and BND.ADDR fields contain the address and port number of the connecting host.

# UDP ASSOCIATE
# The UDP ASSOCIATE request is used to establish an association within the UDP replay process to handle UDP datagrams. The DST.ADDR and DST.PORT fields contain the address and port that the client expects to use to send UDP datagrams on for the association. The server MAY use this information to limit access to the association. If the client is not in possesion of the information at the time of the UDP ASSOCIATE, the client MUST use a port number and address of all zeros.

# TODO - reader note
# So the SOCKS5 server opens a UDP socket and connects it to DST.ADDR and DST.PORT?

# A UDP association terminates when the TCP connection that the UDP ASSOCIATE request arrived on terminates.

# In the reply to a UDP ASSOCIATE request, the BND.PORT and BND.ADDR fields indicate the port number/address where the client MUST send UDP request messages to be replayed.

# TODO - reader note
# What is "UDP ASSOCIATE"?
# Does the SOCKS5 server must open a new UDP socket for the SOCKS5 client to send UDP requests to?

# Reply Processing
# When a reply (REP value other than X'00') indicates a failure, the SOCKS server MUST terminate the TCP connection shortly after sending the reply. This must be no more than 10 seconds after detecting the codition that caused a failure.

# If the reply code (REP value of X'00') indicates a success, and the request was either a BIND or a CONNECT, the client may now start passing data. If the selected authentication method supports encapsulation for the purposes of integrity, authentication and/or confidentiality, the data are encapsulated using the method-dependent encapsulation. Similarly, when data arrives at the SOCKS server for the client, the server MUST encapsulate the data as appropriate for the authentication method in use.
