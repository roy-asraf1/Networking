from calculator import *
import pickle
import typing
import numbers
import struct
import warnings
import time

# Predefined variables
BUFFER_SIZE = 65536 # The buffer size is the maximum amount of data that can be received at once
DEFAULT_SERVER_HOST = "127.0.0.1" # The default host for the server
DEFAULT_SERVER_PORT = 9999 # The default port for the server
DEFAULT_PROXY_HOST = "127.0.0.1" # The default host for the proxy
DEFAULT_PROXY_PORT = 9998 # The default port for the proxy



# ========================================================================
# ============================= Protocol API =============================
# ========================================================================

# region Protocol API


'''
protocol "Unix Time Stamp:32,Total Length:16,Res.:3,Cache:1,Steps:1,Type:1,Status Code:10,Cache Control:16,Padding:16,Data:<=65440"
protocol:
* Unix Time Stamp (32 bits = 4 bytes):
    The time that the packet was sent, in seconds since 1970-01-01 00:00:00 UTC
* Total Length (16 bits = 2 bytes):
    The total length of the packet, in bytes (including the header and the data)
    This minimum value is 12 bytes (header only)
* Reserved (3 bits):
    Reserved for future use (must be 0)
* Flags (3 bits):
    - Cache (1 bit):
        Whether to cache the packet or not (1 = cache/cached, 0 = don't cache/didn't cache)
    - Steps (1 bit):
        Whether to include the computation steps in the response (1 = include/included, 0 = don't include/didn't include)
    - Type (1 bit):
        Whether the packet is a request (1 = request, 0 = response)
* Status Code (10 bits):
    The status code of the response (only valid if the packet is a response)
    2xx = success, 4xx = client error, 5xx = server error, 0 = not a response
* Cache Control (16 bits = 2 bytes):
    'Max-Age' value for the cache.
    If the 'Cache' flag is not set, this value is ignored.
    If the value is the maximum value for a 16-bit unsigned integer (65535), the cache will never expire.
    - For requests, this is the maximum age of the cached response that the client is willing to accept (in seconds).
      This means that the cache shouldn't return a cached response older then this value.
        * If max-age is 0, the server must recompute the response regardless of whether it is cached or not
    - For responses, this is the maximum time that the response can be cached for (in seconds)
        * If max-age is 0, the response must not be cached
* Padding (16 bits):
    Padding for future use (must be 0)
* Data (at most 65440 bits = 8180 bytes):
    The data of the packet
    It's at most 65440 bits because the total length is 16 bits, and the minimum value is 12 bytes (header only)
    2^16 - 12*8 = 65440
    

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Unix Time Stamp                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Total Length         | Res.|C|S|T|    Status Code    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Cache Control         |            Padding            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                              Data                             +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Unix Time Stamp: 32 bits = 4 bytes -> L
Total Length: 16 bits = 2 bytes -> H
Reserved + Flags + Status Code: 3 bits + 3 bits + 10 bits = 2 byte -> H
Cache Control: 16 bits = 2 bytes -> H
Padding: 16 bits = 2 bytes -> 2x
'''

class CalculatorHeader:
    HEADER_FORMAT: typing.Final[str] = '!LHHHxx'
    HEADER_MIN_LENGTH: typing.Final[int] = struct.calcsize(HEADER_FORMAT)
    # Big enough to hold the header and a lot of data
    HEADER_MAX_LENGTH: typing.Final[int] = 2**16
    HEADER_MAX_DATA_LENGTH: typing.Final[int] = HEADER_MAX_LENGTH - \
        HEADER_MIN_LENGTH

    # 16 bits -> 2**16 possible values -> 0 to 2**16 - 1
    MAX_CACHE_CONTROL: typing.Final[int] = 2**16 - 1
    
    STATUS_OK: typing.Final[int] = 200
    STATUS_CLIENT_ERROR: typing.Final[int] = 400
    STATUS_SERVER_ERROR: typing.Final[int] = 500
    STATUS_UNKNOWN: typing.Final[int] = 999

    def __init__(self, unix_time_stamp: int, total_length: typing.Optional[int], reserved: int, cache_result: bool, show_steps: bool, is_request: bool, status_code: int, cache_control: int, data: bytes = b'') -> None:
        self.unix_time_stamp = unix_time_stamp
        self.total_length = total_length
        if self.total_length is None:
            self.total_length = self.HEADER_MIN_LENGTH + len(data)
        if not (self.HEADER_MIN_LENGTH <= self.total_length <= self.HEADER_MAX_LENGTH):
            raise ValueError(
                f'Invalid total length: {self.total_length} (must be between {self.HEADER_MIN_LENGTH} and {self.HEADER_MAX_LENGTH} bytes inclusive)')
        elif self.total_length != self.HEADER_MIN_LENGTH + len(data):
            warnings.warn(
                f'The total length ({self.total_length}) does not match the length of the data ({len(data)})')
        self.reserved = reserved
        if self.reserved != 0:
            warnings.warn(f'The reserved bits ({self.reserved}) are not 0')
        self.cache_result = cache_result
        self.show_steps = show_steps
        self.is_request = is_request
        self.status_code = status_code
        if self.is_request and self.status_code != 0:
            warnings.warn(
                f'The status code ({self.status_code}) is not 0 for a request')
        self.cache_control = cache_control
        if self.cache_control != 0 and not self.cache_result:
            warnings.warn(
                f'The cache control value ({self.cache_control}) is not 0, but the cache result flag is not set. The cache control value will be ignored')
            self.cache_control = 0
        elif (not self.is_request) and self.cache_control == 0 and self.cache_result:
            warnings.warn(
                f'The cache control ({self.cache_control}) is 0, but the cache result flag is set. The response will not be cached')
            self.cache_result = False

        self.data = data
        if len(self.data) > self.HEADER_MAX_DATA_LENGTH:
            raise ValueError(
                f'Invalid data length: {len(self.data)} (must be at most {self.HEADER_MAX_DATA_LENGTH} bytes)')

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}(unix_time_stamp={self.unix_time_stamp}, total_length={self.total_length}, reserved={self.reserved}, cache_result={self.cache_result}, show_steps={self.show_steps}, is_request={self.is_request}, status_code={self.status_code}, cache_control={self.cache_control}, data={self.data})'

    def __str__(self) -> str:
        return f'{self.__class__.__name__}({self.unix_time_stamp}, {self.total_length}, {self.reserved}, {self.cache_result}, {self.show_steps}, {self.is_request}, {self.status_code}, {self.cache_control}, {self.data})'

    @staticmethod
    def pack_flags(reserved: int, cache_result: bool, show_steps: bool, is_request: bool, status_code: int) -> int:
        return (reserved << 13) | (cache_result << 12) | (show_steps << 11) | (is_request << 10) | status_code

    @staticmethod
    def unpack_flags(flags: int) -> typing.Tuple[int, bool, bool, bool, int]:
        status_code = flags & ((1 << 10) - 1)  # flags & 0b000_0_0_0_1111111111
        is_request = flags & (1 << 10)  # flags & 0b000_0_0_1_0000000000
        show_steps = flags & (1 << 11)  # flags & 0b000_0_1_0_0000000000
        cache_result = flags & (1 << 12)  # flags & 0b000_1_0_0_0000000000
        # flags & 0b111_0_0_0_0000000000
        reserved = (flags >> 13) & ((1 << 3) - 1)
        return reserved, bool(cache_result), bool(show_steps), bool(is_request), status_code

    def pack(self) -> bytes:
        return struct.pack(self.HEADER_FORMAT, self.unix_time_stamp, self.total_length, self.pack_flags(self.reserved, self.cache_result, self.show_steps, self.is_request, self.status_code), self.cache_control) + self.data

    @classmethod
    def unpack(cls, data: bytes) -> 'CalculatorHeader':
        if len(data) < cls.HEADER_MIN_LENGTH:
            raise ValueError(
                f'The data is too short ({len(data)} bytes) to be a valid header')
        unix_time_stamp, total_length, flags, cache_control = struct.unpack(
            cls.HEADER_FORMAT, data[:cls.HEADER_MIN_LENGTH])
        reserved, cache_result, show_steps, is_request, status_code = cls.unpack_flags(
            flags)
        return cls(unix_time_stamp=unix_time_stamp, total_length=total_length, reserved=reserved, cache_result=cache_result, show_steps=show_steps, is_request=is_request, status_code=status_code, cache_control=cache_control, data=data[cls.HEADER_MIN_LENGTH:])
    
    
    @classmethod
    def from_request(cls, data: bytes, show_steps: bool, cache_result: bool, cache_control: int) -> 'CalculatorHeader':
        return cls(unix_time_stamp=int(time.time()), total_length=None, reserved=0, cache_result=cache_result, show_steps=show_steps, is_request=True, status_code=0, cache_control=cache_control, data=data)
    
    @classmethod
    def from_expression(cls, expr: Expression, show_steps: bool, cache_result: bool, cache_control: int) -> 'CalculatorHeader':
        return cls.from_request(data=pickle.dumps(expr), show_steps=show_steps, cache_result=cache_result, cache_control=cache_control)
    
    @classmethod
    def from_response(cls, data: bytes, status_code: int, show_steps: bool, cache_result: bool, cache_control: int) -> 'CalculatorHeader':
        return cls(unix_time_stamp=int(time.time()), total_length=None, reserved=0, cache_result=cache_result, show_steps=show_steps, is_request=False, status_code=status_code, cache_control=cache_control, data=data)
    
    @classmethod
    def from_result(cls, result: numbers.Real, steps: list[str], cache_result: bool, cache_control: int) -> 'CalculatorHeader':
        return cls.from_response(data=pickle.dumps((result, steps)), status_code=CalculatorHeader.STATUS_OK, show_steps=bool(steps), cache_result=cache_result, cache_control=cache_control)
    
    @classmethod
    def from_error(cls, error: Exception, status_code: int, cache_result: bool, cache_control: int) -> 'CalculatorHeader':
        return cls.from_response(data=pickle.dumps(error), status_code=status_code, show_steps=False, cache_result=cache_result, cache_control=cache_control)
    
    def __bytes__(self) -> bytes:
        return self.pack()

def data_to_expression(header: CalculatorHeader) -> Expression:
    try:
        expr = pickle.loads(header.data)
        if not isinstance(expr, Expression):
            raise ValueError('Received data is not an Expression1')
        return expr
    except pickle.UnpicklingError as e:
        raise ValueError('Received data could not be deserialized') from e
    except Exception as e:
        raise ValueError('Received data is not an Expression2') from e

def data_to_result(header: CalculatorHeader) -> typing.Tuple[numbers.Real, list[str]]:
    try:
        result = pickle.loads(header.data)
        if not isinstance(result, tuple) or len(result) != 2 or not isinstance(result[0], numbers.Real) or not isinstance(result[1], list):
            raise ValueError('Received data is not a valid result')
        return result
    except pickle.UnpicklingError as e:
        raise ValueError('Received data could not be deserialized') from e
    except Exception as e:
        raise ValueError('Received data is not a valid result') from e

def data_to_error(header: CalculatorHeader) -> Exception:
    try:
        error = pickle.loads(header.data)
        if not isinstance(error, Exception):
            raise ValueError('Received data is not an Exception')
        return error
    except pickle.UnpicklingError as e:
        raise ValueError('Received data could not be deserialized') from e
    except Exception as e:
        raise ValueError('Received data is not an Exception') from e

class CalculatorError(Exception):
    pass

class CalculatorServerError(CalculatorError):
    pass

class CalculatorClientError(CalculatorError):
    pass

# endregion



