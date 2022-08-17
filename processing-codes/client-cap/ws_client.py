import asyncio
import json
import os

import requests
import websockets

import extract

MASTER_NODE_IP = 'localhost'
WS_PORT = 8765
HTTP_PORT = 4040
FLOW_FILE = '../data/flows.json'


async def ws_handler():
    async with websockets.connect(f'ws://{MASTER_NODE_IP}:{WS_PORT}') as websocket:
        while True:
            rcv = eval(await websocket.recv())
            report = requests.get(f"http://{MASTER_NODE_IP}:{HTTP_PORT}/api/report").content.decode("utf-8")
            rpt = json.loads(report)
            processed_records = extract.extract(rcv, rpt)
            if processed_records:
                with open(FLOW_FILE, "a", encoding='utf8') as flow_file:
                    flow_file.write('\n'.join(processed_records) + '\n')
            await websocket.send('ok')


if __name__ == "__main__":
    if not os.path.exists("../data"):
        os.makedirs("../data")
    asyncio.get_event_loop().run_until_complete(ws_handler())
