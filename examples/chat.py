"""
Simple chat client - connects to a NetPipe Go server and relays messages.

Usage:
    1. Start the Go server:   go run cmd/server/main.go
    2. Run this client:       python examples/chat.py
    3. Type messages and see them relayed through the server.
"""

from netpipe import Client


def main():
    client = Client(host="127.0.0.1", port=5000)

    @client.on_data
    def handle(data):
        print(data.decode(), end="")

    @client.on_disconnect
    def disconnected():
        print("disconnected from server")

    @client.on_reject
    def rejected(reason):
        print(f"rejected: {reason}")

    client.connect()
    print("connected to server")

    # listen in background so we can read stdin
    client.start_async()

    try:
        while True:
            line = input()
            client.send((line + "\n").encode())
    except (KeyboardInterrupt, EOFError):
        client.disconnect()


if __name__ == "__main__":
    main()
