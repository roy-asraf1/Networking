import api
import argparse
import threading
import socket
import time
import math

cache: dict[tuple[bytes, bool], api.CalculatorHeader] = {}
INDEFINITE = api.CalculatorHeader.MAX_CACHE_CONTROL


def process_request(request: api.CalculatorHeader, server_address: tuple[str, int]) -> tuple[api.CalculatorHeader, int, int, bool, bool, bool]:
    '''
    Function which processes the client request if specified we cache the result
    Returns the response, the time remaining before the server deems the response stale, the time remaining before the client deems the response stale, whether the response returned was from the cache, whether the response was stale, and whether we cached the response
    If the request.cache_control is 0, we don't use the cache and send a new request to the server. (like a reload)
    If the request.cache_control < time() - cache[request].unix_time_stamp, the client doesn't allow us to use the cache and we send a new request to the server.
    If the cache[request].cache_control is 0, the response must not be cached.
    '''
    if not request.is_request:
        raise TypeError("Received a response instead of a request")

    data = request.data
    server_time_remaining = None
    client_time_remaining = None
    was_stale = False
    cached = False
    # Check if the data is in the cache, if the requests cache-control is 0 we must not use the cache and request a new response
    if ((data, request.show_steps) in cache) and (request.cache_control != 0):
        response = cache[(data, request.show_steps)]
        current_time = int(time.time())
        age = current_time - response.unix_time_stamp
        res_cc = response.cache_control if response.cache_control != INDEFINITE else math.inf
        req_cc = request.cache_control if request.cache_control != INDEFINITE else math.inf
        server_time_remaining = res_cc - age
        client_time_remaining = req_cc - age
        # response is still 'fresh' both for the client and the server
        if server_time_remaining > 0 and client_time_remaining > 0:
            return response, server_time_remaining, client_time_remaining, True, False, False
        else:  # response is 'stale'
            was_stale = True

    # Request is not in the cache or the response is 'stale' so we need to send a new request to the server and cache the response
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        try:
            server_socket.connect(server_address)
        except ConnectionRefusedError:
            raise api.CalculatorServerError(
                "Connection refused by server and the request was not in the cache/it was stale")
        server_socket.sendall(request.pack())

        response = server_socket.recv(api.BUFFER_SIZE)

        try:
            response = api.CalculatorHeader.unpack(response)
        except Exception as e:
            raise api.CalculatorClientError(
                f'Error while unpacking request: {e}') from e

        if response.is_request:
            raise TypeError("Received a request instead of a response")

        current_time = int(time.time())
        age = current_time - response.unix_time_stamp
        res_cc = response.cache_control if response.cache_control != INDEFINITE else math.inf
        req_cc = request.cache_control if request.cache_control != INDEFINITE else math.inf
        server_time_remaining = res_cc - age
        client_time_remaining = req_cc - age
        # Cache the response if all sides agree to cache it
        if request.cache_result and response.cache_result and (server_time_remaining > 0 and client_time_remaining > 0):
            cache[(data, request.show_steps)] = response
            cached = True

    return response, server_time_remaining, client_time_remaining, False, was_stale, cached


def proxy(proxy_address: tuple[str, int], server_adress: tuple[str, int]) -> None:
    # socket(socket.AF_INET, socket.SOCK_STREAM)
    # (1) AF_INET is the address family for IPv4 (Address Family)
    # (2) SOCK_STREAM is the socket type for TCP (Socket Type) - [SOCK_DGRAM is the socket type for UDP]
    # Note: context manager ('with' keyword) closes the socket when the block is exited
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_socket:
        # SO_REUSEADDR is a socket option that allows the socket to be bound to an address that is already in use.
        proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Prepare the proxy socket
        # * Fill in start (1)
        # * Fill in end (1)

        threads = []
        print(f"Listening on {proxy_address[0]}:{proxy_address[1]}")

        while True:
            try:
                # Establish connection with client.
                
                client_socket, client_address = # * Fill in start (2) # * Fill in end (2)

                # Create a new thread to handle the client request
                thread = threading.Thread(target=client_handler, args=(
                    client_socket, client_address, server_adress))
                thread.start()
                threads.append(thread)
            except KeyboardInterrupt:
                print("Shutting down...")
                break

        for thread in threads:  # Wait for all threads to finish
            thread.join()


def client_handler(client_socket: socket.socket, client_address: tuple[str, int], server_address: tuple[str, int]) -> None:
    '''
    Function which handles client requests
    '''
    client_prefix = f"{{{client_address[0]}:{client_address[1]}}}"
    with client_socket:  # closes the socket when the block is exited
        print(f"{client_prefix} Connected established")
        while True:
            # Receive data from the client
            
            data = # * Fill in start (3) # * Fill in end (3)
            
            if not data:
                break
            try:
                # Process the request
                try:
                    request = api.CalculatorHeader.unpack(data)
                except Exception as e:
                    raise api.CalculatorClientError(
                        f'Error while unpacking request: {e}') from e

                print(f"{client_prefix} Got request of length {len(data)} bytes")

                response, server_time_remaining, client_time_remaining, cache_hit, was_stale, cached = process_request(
                    request, server_address)

                if cache_hit:
                    print(f"{client_prefix} Cache hit", end=" ,")
                elif was_stale:
                    print(f"{client_prefix} Cache miss, stale response", end=" ,")
                elif cached:
                    print(f"{client_prefix} Cache miss, response cached", end=" ,")
                else:
                    print(
                        f"{client_prefix} Cache miss, response not cached", end=" ,")
                print(
                    f"server time remaining: {server_time_remaining:.2f}, client time remaining: {client_time_remaining:.2f}")

                response = response.pack()
                print(
                    f"{client_prefix} Sending response of length {len(response)} bytes")

                # Send the response back to the client
                # * Fill in start (4)
                # * Fill in end (4)
                
            except Exception as e:
                print(f"Unexpected server error: {e}")
                client_socket.sendall(api.CalculatorHeader.from_error(api.CalculatorServerError(
                    "Internal proxy error", e), api.CalculatorHeader.STATUS_SERVER_ERROR, False, 0).pack())
            print(f"{client_prefix} Connection closed")


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(
        description='A Calculator Server.')

    arg_parser.add_argument('-pp', '--proxy_port', type=int, dest='proxy_port',
                            default=api.DEFAULT_PROXY_PORT, help='The port that the proxy listens on.')
    arg_parser.add_argument('-ph', '--proxy_host', type=str, dest='proxy_host',
                            default=api.DEFAULT_PROXY_HOST, help='The host that the proxy listens on.')
    arg_parser.add_argument('-sp', '--server_port', type=int, dest='server_port',
                            default=api.DEFAULT_SERVER_PORT, help='The port that the server listens on.')
    arg_parser.add_argument('-sh', '--server_host', type=str, dest='server_host',
                            default=api.DEFAULT_SERVER_HOST, help='The host that the server listens on.')

    args = arg_parser.parse_args()

    proxy_host = args.proxy_host
    proxy_port = args.proxy_port
    server_host = args.server_host
    server_port = args.server_port

    proxy((proxy_host, proxy_port), (server_host, server_port))
