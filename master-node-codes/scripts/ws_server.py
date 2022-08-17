#!/usr/bin/python3

import asyncio
import websockets
import requests

messages = []


async def ws_handler(websocket, path):
    try:
        while True:
            msg = input()
            messages.append(msg)
            if len(messages) >= 300:
                await websocket.send(str(messages))
                await websocket.recv()
                messages.clear()
    except (KeyboardInterrupt, EOFError):
        pass


if __name__ == '__main__':
    start_server = websockets.serve(ws_handler, '0.0.0.0', 8765)

    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_forever()

