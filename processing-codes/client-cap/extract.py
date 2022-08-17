import json
import re
import time

"""
    The format of conntrack records is  [CONN] [conntrack] {hostname|MsgType|TCPState|Orig(Src|SrcPort|Dst|DstPort)|Reply(Src|SrcPort|Dst|DstPort) CtID}
    The format of eBPF records is       [CONN] [eBPF] {hostname|timestamp|CPU|IPv4Event|pid|comm|Src|Dst|SrcPort|DstPort|NetNS|Fd}
"""

LOG_FILE = "../data/records.log"
REPORT_FILE = "../data/report.json"
services = {}
endpoints = {}
processes = {}
containers = {}
pods = {}


class Tuple:

    def __init__(self, src_addr, src_port, dst_addr, dst_port):
        self.src_addr = src_addr
        self.src_port = src_port
        self.dst_addr = dst_addr
        self.dst_port = dst_port

    def inverse(self):
        self.src_addr, self.dst_addr = self.dst_addr, self.src_addr
        self.src_port, self.dst_port = self.dst_port, self.src_port


class Record:

    def __init__(self, hostname, timestamp, four_tuple):
        self.hostname = hostname
        self.timestamp = timestamp
        self.four_tuple = four_tuple

    def short_json(self):
        return {"timestamp": self.timestamp, "hostname": self.hostname, "tuple": self.four_tuple.__dict__}


class eBPFRecord(Record):

    def __init__(self, hostname, timestamp, four_tuple, comm, pid, event, ns):
        super().__init__(hostname, timestamp, four_tuple)
        self.comm = comm
        self.pid = pid
        self.event = event
        self.ns = ns


class ConnTrackRecord(Record):

    def __init__(self, hostname, timestamp, four_tuple, tcp_state, msg_type, ctid):
        super().__init__(hostname, timestamp, four_tuple)
        self.tcp_state = tcp_state
        self.msg_type = msg_type
        self.ctid = ctid


def parse_eBPF(timestamp, record_str):
    fields = record_str.split("|")
    if fields[3] == "Accept":
        only_tuple = Tuple(fields[6], int(fields[8]), fields[7], int(fields[9]))
        only_tuple.inverse()
        return [eBPFRecord(fields[0], timestamp, only_tuple, fields[5], int(fields[4]), fields[3], fields[10])]
    else:
        return []


def parse_conntrack(timestamp, record_str):
    fields = record_str.split("|")
    orig_tuple = Tuple(fields[3], int(fields[4]), fields[5], int(fields[6]))
    dst_tuple = Tuple(fields[7], int(fields[8]), fields[9], int(fields[10]))
    return [ConnTrackRecord(fields[0], timestamp, orig_tuple, fields[2], fields[1], int(fields[11])),
            ConnTrackRecord(fields[0], timestamp, dst_tuple, fields[2], fields[1], int(fields[11]))]


def generate_ep_id(hostname, addr, port):
    if addr != "127.0.0.1":
        hostname = ""
    return f"{hostname};{addr};{port}"


LABEL_PREFIX = "kubernetes_labels_"
SERVICE_SELECTOR = "kubernetes_selector"


def compress_info(info):
    compressed_info = {"id": info["id"], "labels": {}}
    labels = compressed_info["labels"]
    if "latest" in info:
        latest = info["latest"]
        for info in latest:
            if info.startswith(LABEL_PREFIX):
                labels[info[len(LABEL_PREFIX):]] = latest[info]["value"]
        if "kubernetes_namespace" in latest:
            compressed_info["namespace"] = latest["kubernetes_namespace"]["value"]
        if "kubernetes_name" in latest:
            compressed_info["name"] = latest["kubernetes_name"]["value"]
        if SERVICE_SELECTOR in latest:
            compressed_info["selector"] = latest[SERVICE_SELECTOR]["value"]
    return compressed_info


def compress_pod(pod_info):
    service_info = {}
    if "parents" in pod_info and pod_info["parents"] is not None:
        if "service" in pod_info["parents"] and pod_info["parents"]["service"][0] in services:
            service_info = compress_info(services[pod_info["parents"]["service"][0]])
    pod_info = compress_info(pod_info)
    return {"pod": pod_info, "service": service_info}


def extract(records, report):
    global services
    global endpoints
    global processes
    global containers
    global pods
    process_to_pod = {}
    endpoints_to_pod = {}
    flows = []
    for line in records:
        # if "[CONN] [conntrack]" in line:
        #     rst = re.search(r"<probe> INFO: (.*)(\..*) \[CONN] \[conntrack] \{(.*)}", line.strip())
        #     time_array = time.strptime(rst.group(1), "%Y/%m/%d %H:%M:%S")
        #     flows += parse_conntrack((time.mktime(time_array)) + float(rst.group(2)), rst.group(3))
        if "[CONN] [eBPF]" in line:
            rst = re.search(r"<probe> INFO: (.*)(\..*) \[CONN] \[eBPF] \{(.*)}", line.strip())
            time_array = time.strptime(rst.group(1), "%Y/%m/%d %H:%M:%S")
            flows += parse_eBPF((time.mktime(time_array)) + float(rst.group(2)), rst.group(3))

        endpoints = report["Endpoint"]["nodes"]
        processes = report["Process"]["nodes"]
        containers = report["Container"]["nodes"]
        pods = report["Pod"]["nodes"]
        for process in processes:
            if processes[process]["parents"] and "container" in processes[process]["parents"]:
                ctn = processes[process]['parents']['container'][0]
                if ctn in containers and 'pod' in containers[ctn]['parents']:
                    pod = containers[ctn]['parents']['pod'][0]
                    if pod in pods:
                        process_to_pod[process] = pods[pod]

        for endpoint in endpoints:
            if "latest" in endpoints[endpoint]:
                hostinfo = endpoints[endpoint]["latest"]
                if "host_node_id" in hostinfo and "pid" in hostinfo:
                    host = hostinfo["host_node_id"]["value"].split(";")[0]
                    pid = hostinfo["pid"]["value"]
                    temp_str = host + ";" + pid
                    if temp_str in process_to_pod:
                        parted = endpoint.split(";")
                        if endpoint.startswith("master"):
                            parted[0] = "master"
                        reassembled = ';'.join(parted)
                        endpoints_to_pod[reassembled] = process_to_pod[temp_str]

    processed_records = []
    services = report["Service"]["nodes"]

    # print the hostname and the total number of records in the host
    for flow in flows:
        hostname = flow.hostname
        src_ep = generate_ep_id(hostname, flow.four_tuple.src_addr, flow.four_tuple.src_port)
        dst_ep = generate_ep_id(hostname, flow.four_tuple.dst_addr, flow.four_tuple.dst_port)
        if src_ep in endpoints_to_pod and dst_ep in endpoints_to_pod:
            tmp_dict = flow.short_json()
            tmp_dict["src"] = compress_pod(endpoints_to_pod[src_ep])
            tmp_dict["dst"] = compress_pod(endpoints_to_pod[dst_ep])
            processed_records.append(json.dumps(tmp_dict))

    return processed_records


if __name__ == "__main__":
    with open(LOG_FILE, 'r', encoding='utf8') as f:
        content = f.readlines()
    with open(REPORT_FILE, "r", encoding='utf8') as f:
        data = json.load(f)
    extract(content, data)
