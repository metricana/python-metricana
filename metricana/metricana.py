import functools
import hmac
import os
import socket
import time

class Metricana(object):

    def __init__(self, user_id, api_key, host='metricana.com', port=3000):
        self.user_id = user_id
        self.api_key = api_key
        self.host = host
        self.port = port

        self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _get_nonce(self):
        return os.urandom(4).encode('hex')

    def _sign(self, message):
        full_message = '%s|%x|%d|%s' % (self._get_nonce(), time.time(), self.user_id, message)
        return '%s|%s' % (hmac.HMAC(self.api_key, full_message).hexdigest()[:8], full_message)

    def _send_signed(self, message):
        self._udp_socket.sendto(self._sign(message), socket.MSG_DONTWAIT, (self.host, self.port))

    def int(self, key, value):
        self._send_signed('i|%s|%d' % (key, value))

    def mark(self, key):
        self._send_signed('m|%s|m' % (key, ))

    def float(self, key, value):
        self._send_signed('f|%s|%f' % (key, value))

    def runtime(self, key):
        def create_decorator(f):
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                t_start = time.time()
                result = f(*args, **kwargs)
                t_end = time.time()
                self.float(key, t_end - t_start)
                return result
            return wrapper
        return create_decorator

    def block_runtime(self, key):
        class manager:
            def __init__(self, _key, _outer_self):
                self.key = _key
                self._outer_self = _outer_self

            def __enter__(self):
                self.ts_1 = time.time()

            def __exit__(self, *args):
                self. _outer_self.float(self.key, time.time() - self.ts_1)

        return manager(key, self)
