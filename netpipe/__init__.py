"""
NetPipe Python Client - connects to a Go NetPipe server.

    from netpipe import Client

    client = Client(host="127.0.0.1", port=5000)
    client.on_data(lambda data: print(data.decode()))
    client.connect()
    client.start()  # blocking listen loop
"""

from netpipe.client import Client

__version__ = "0.1.0"
__all__ = ["Client"]
