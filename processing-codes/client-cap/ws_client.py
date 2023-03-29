import asyncio
import json
import os
import threading
import time

import requests
import websockets

import linker

MASTER_NODE_IP = 'localhost'
WS_PORT = 8765
HTTP_PORT = 4040
FLOW_FILE = '../data/flows.json'

cont = True
total_received = 0
total_processed = 0


async def ws_handler():
    global total_received, total_processed
    async with websockets.connect(f'ws://{MASTER_NODE_IP}:{WS_PORT}') as websocket:
        while cont:
            print(
                f"\rReceived \033[33m{total_received}\033[0m records, \033[34m{total_processed}\033[0m records are linked.",
                end='')
            rcv = eval(await websocket.recv())
            # Once receive a batch of flow logs, update the topology
            report = requests.get(f"http://{MASTER_NODE_IP}:{HTTP_PORT}/api/report").content.decode("utf-8")
            rpt = json.loads(report)
            processed_records = linker.link_with_opt(rcv, rpt)
            total_received += len(rcv)
            total_processed += len(processed_records)
            # with open("../data/flows.log", "a", encoding='utf8') as f:
            #     f.write('\n'.join(rcv) + '\n')
            # with open("../data/report.json", "w", encoding='utf8') as f:
            #     json.dump(rpt, f, indent=4)
            if processed_records:
                with open(FLOW_FILE, "a", encoding='utf8') as flow_file:
                    flow_file.write('\n'.join(processed_records) + '\n')
            await websocket.send('ok')


if __name__ == "__main__":
    if not os.path.exists("../data"):
        os.makedirs("../data")

    # create a thread to run websocket
    t = threading.Thread(target=asyncio.get_event_loop().run_until_complete, args=(ws_handler(),))
    t.start()
    input("> Capture Started. Press \033[1mENTER\033[0m to stop the client.\n")
    cont = False
    t.join()
    print(f"> Capture Finished. Linked flows can be found at \033[1m{FLOW_FILE}\033[0m.")
