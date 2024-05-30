import numbers
import api
import argparse
import socket
import threading

CACHE_POLICY = True  # whether to cache responses or not
# the maximum time that the response can be cached for (in seconds)
CACHE_CONTROL = 2 ** 16 - 1


def calculate(expression: api.Expr, steps: list[str] = []) -> tuple[numbers.Real, list[api.Expression]]:
    '''    
    Function which calculates the result of an expression and returns the result and the steps taken to calculate it.
    The function recursively descends into the expression tree and calculates the result of the expression.
    Each expression wraps the result of its subexpressions in parentheses and adds the result to the steps list.
    '''
    expr = api.type_fallback(expression)
    const = None
    if isinstance(expr, api.Constant) or isinstance(expr, api.NamedConstant):
        const = expr
    elif isinstance(expr, api.BinaryExpr):
        left_steps, right_steps = [], []
        left, left_steps = calculate(expr.left_operand, left_steps)
        for step in left_steps[:-1]:
            steps.append(api.BinaryExpr(
                step, expr.operator, expr.right_operand))
        right, left_steps = calculate(expr.right_operand, right_steps)
        for step in right_steps[:-1]:
            steps.append(api.BinaryExpr(left, expr.operator, step))
        steps.append(api.BinaryExpr(left, expr.operator, right))
        const = api.Constant(expr.operator.function(left, right))
        steps.append(const)
    elif isinstance(expr, api.UnaryExpr):
        operand_steps = []
        operand, operand_steps = calculate(expr.operand, operand_steps)
        for step in operand_steps[:-1]:
            steps.append(api.UnaryExpr(expr.operator, step))
        steps.append(api.UnaryExpr(expr.operator, operand))
        const = api.Constant(expr.operator.function(operand))
        steps.append(const)
    elif isinstance(expr, api.FunctionCallExpr):
        args = []
        for arg in expr.args:
            arg_steps = []
            arg, arg_steps = calculate(arg, arg_steps)
            for step in arg_steps[:-1]:
                steps.append(api.FunctionCallExpr(expr.function, *
                             (args + [step] + expr.args[len(args) + 1:])))
            args.append(arg)
        steps.append(api.FunctionCallExpr(expr.function, *args))
        const = api.Constant(expr.function.function(*args))
        steps.append(const)
    else:
        raise TypeError(f"Unknown expression type: {type(expr)}")
    return const.value, steps


def process_request(request: api.CalculatorHeader) -> api.CalculatorHeader:
    '''
    Function which processes a CalculatorRequest and builds a CalculatorResponse.
    '''
    result, steps = None, []
    try:
        if request.is_request:
            expr = api.data_to_expression(request)
            result, steps = calculate(expr, steps)
        else:
            raise TypeError("Received a response instead of a request")
    except Exception as e:
        return api.CalculatorHeader.from_error(e, api.CalculatorHeader.STATUS_CLIENT_ERROR, CACHE_POLICY, CACHE_CONTROL)

    if request.show_steps:
        steps = [api.stringify(step, add_brackets=True) for step in steps]
    else:
        steps = []

    return api.CalculatorHeader.from_result(result, steps, CACHE_POLICY, CACHE_CONTROL)


def server(host: str, port: int) -> None:
    # socket(socket.AF_INET, socket.SOCK_STREAM)
    # (1) AF_INET is the address family for IPv4 (Address Family)
    # (2) SOCK_STREAM is the socket type for TCP (Socket Type) - [SOCK_DGRAM is the socket type for UDP]
    # Note: context manager ('with' keyword) closes the socket when the block is exited
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # SO_REUSEADDR is a socket option that allows the socket to be bound to an address that is already in use.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Prepare the server socket
        # * Fill in start (1)
        # * Fill in end (1)

        threads = []
        print(f"Listening on {host}:{port}")

        while True:
            try:
                # Establish connection with client.
                
                client_socket, address = # * Fill in start (2) # * Fill in end (2)

                # Create a new thread to handle the client request
                thread = threading.Thread(target=client_handler, args=(
                    client_socket, address))
                thread.start()
                threads.append(thread)
            except KeyboardInterrupt:
                print("Shutting down...")
                break

        for thread in threads:  # Wait for all threads to finish
            thread.join()


def client_handler(client_socket: socket.socket, client_address: tuple[str, int]) -> None:
    '''
    Function which handles client requests
    '''
    client_addr = f"{client_address[0]}:{client_address[1]}"
    client_prefix = f"{{{client_addr}}}"
    with client_socket:  # closes the socket when the block is exited
        print(f"Conection established with {client_addr}")
        while True:
            
            data = # * Fill in start (3) # * Fill in end (3)
            if not data:
                break
            try:

                try:
                    request = api.CalculatorHeader.unpack(data)
                except Exception as e:
                    raise api.CalculatorClientError(
                        f'Error while unpacking request: {e}') from e

                print(f"{client_prefix} Got request of length {len(data)} bytes")

                response = process_request(request)

                response = response.pack()
                print(
                    f"{client_prefix} Sending response of length {len(response)} bytes")

                # * Fill in start (4)
                # * Fill in end (4)

            except Exception as e:
                print(f"Unexpected server error: {e}")
                client_socket.sendall(api.CalculatorHeader.from_error(
                    e, api.CalculatorHeader.STATUS_SERVER_ERROR, CACHE_POLICY, CACHE_CONTROL).pack())
            print(f"{client_prefix} Connection closed")


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(
        description='A Calculator Server.')

    arg_parser.add_argument('-p', '--port', type=int,
                            default=api.DEFAULT_SERVER_PORT, help='The port to listen on.')
    arg_parser.add_argument('-H', '--host', type=str,
                            default=api.DEFAULT_SERVER_HOST, help='The host to listen on.')

    args = arg_parser.parse_args()

    host = args.host
    port = args.port

    server(host, port)
