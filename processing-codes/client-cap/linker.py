import json
import re
import time

"""
    The format of conntrack records:
        [CONN] [conntrack] {hostname|MsgType|TCPState|Orig(Src|SrcPort|Dst|DstPort)|Reply(Src|SrcPort|Dst|DstPort) CtID}
    The format of eBPF records:
        [CONN] [eBPF] {hostname|timestamp|CPU|IPv4Event|pid|comm|Src|Dst|SrcPort|DstPort|NetNS|Fd}
"""

LOG_FILE = "../data/flows.log"
REPORT_FILE = "../data/report.json"
services = {}
deployments = {}
endpoints = {}
processes = {}
containers = {}
pods = {}


class Tuple:
    """
        Represents the four tuple of a flow.
    """

    def __init__(self, src_addr, src_port, dst_addr, dst_port):
        self.src_addr = src_addr
        self.src_port = src_port
        self.dst_addr = dst_addr
        self.dst_port = dst_port

    def inverse(self):
        self.src_addr, self.dst_addr = self.dst_addr, self.src_addr
        self.src_port, self.dst_port = self.dst_port, self.src_port


class Record:
    """
    An abstract class representing one record of flow.
    """

    def __init__(self, hostname, timestamp, four_tuple):
        self.hostname = hostname
        self.timestamp = timestamp
        self.four_tuple = four_tuple

    def short_json(self):
        return {"timestamp": self.timestamp, "hostname": self.hostname, "tuple": self.four_tuple.__dict__,
                "src": {"pod": {}, "service": {}},
                "dst": {"pod": {}, "service": {}}
                }


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
    """
    Parse a eBPF object from one line of log.
    Only flow in state of 'Accept' will be parsed and the others will be dropped to avoid duplication.

    Returns:
        a list of valid eBPFRecord objects
    """
    fields = record_str.split("|")
    if fields[3] == "Accept":
        only_tuple = Tuple(fields[6], int(fields[8]), fields[7], int(fields[9]))
        only_tuple.inverse()
        return [eBPFRecord(fields[0], timestamp, only_tuple, fields[5], int(fields[4]), fields[3], fields[10])]
    else:
        return []


def parse_conntrack(timestamp, record_str):
    """
    Parse a ConnTrack object from one line of log.
    This method is not used in this version since we do not care about ConnTrack for now.
    """
    fields = record_str.split("|")
    orig_tuple = Tuple(fields[3], int(fields[4]), fields[5], int(fields[6]))
    dst_tuple = Tuple(fields[7], int(fields[8]), fields[9], int(fields[10]))
    return [ConnTrackRecord(fields[0], timestamp, orig_tuple, fields[2], fields[1], int(fields[11])),
            ConnTrackRecord(fields[0], timestamp, dst_tuple, fields[2], fields[1], int(fields[11]))]


def generate_ep_id(hostname, addr, port):
    """
    Generate the ID of one endpoint in the convention of Weave Scope: if the address is '127.0.0.1', then the ID will
    be '<hostname>;<addr>;<port>' else the ID will be ';<addr>;<port>'.
    """
    if addr != "127.0.0.1":
        hostname = ""
    return f"{hostname};{addr};{port}"


LABEL_PREFIX = "kubernetes_labels_"
SERVICE_SELECTOR = "kubernetes_selector"


def compress_info(info):
    """
    Optimize the information.
    This method will delete the unused fields.
    """
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
    """
    Compress the pod's info, delete the redundant information and try to link it to a service.

    Returns:
        a dictionary containing compressed information of pod and its corresponding service
    """
    service_info = {}
    if "parents" in pod_info and pod_info["parents"] is not None:
        if "service" in pod_info["parents"] and pod_info["parents"]["service"][0] in services:
            service_info = compress_info(services[pod_info["parents"]["service"][0]])
        if "deployment" in pod_info["parents"] and pod_info["parents"]["deployment"][0] in services:
            service_info = compress_info(services[pod_info["parents"]["deployment"][0]])
    pod_info = compress_info(pod_info)
    return {"pod": pod_info, "service": service_info}


def link_with_opt(records, report):
    """
    Link the flow with pods and services, optimize and output processed flows.

    Returns:
        a list of processes flows in the form which is readable by policy generator
    """
    global services
    global endpoints
    global processes
    global containers
    global pods
    global deployments
    flows = []

    endpoints = report["Endpoint"]["nodes"]
    processes = report["Process"]["nodes"]
    containers = report["Container"]["nodes"]
    pods = report["Pod"]["nodes"]
    services = report["Service"]["nodes"]
    deployments = report["Deployment"]["nodes"]

    svc_ip_to_id = {}
    pod_ip_to_id = {}
    pod_ip_to_svc_id = {}

    for pod_id in pods:
        pod_info = pods[pod_id]
        if "latest" not in pod_info or "kubernetes_ip" not in pod_info["latest"]:
            continue
        pod_ip = pod_info["latest"]["kubernetes_ip"]["value"]
        pod_ip_to_id[pod_ip] = pod_id
        if "parents" in pod_info and pod_info["parents"] is not None and "service" in pod_info["parents"]:
            pod_ip_to_svc_id[pod_ip] = pod_info["parents"]["service"][0]

    for svc_id in services:
        svc_info = services[svc_id]
        if "latest" in svc_info and "kubernetes_ip" in svc_info["latest"]:
            svc_ip_to_id[svc_info["latest"]["kubernetes_ip"]["value"]] = svc_id

    for line in records:
        rst = re.search(r"<probe> INFO: (.*)(\..*) \[CONN] \[eBPF] \{(.*)}", line.strip())
        if not rst:
            continue
        time_array = time.strptime(rst.group(1), "%Y/%m/%d %H:%M:%S")
        flows += parse_eBPF((time.mktime(time_array)) + float(rst.group(2)), rst.group(3))

    processed_records = []

    for flow in flows:
        src_ip, src_port = flow.four_tuple.src_addr, flow.four_tuple.src_port
        dst_ip, dst_port = flow.four_tuple.dst_addr, flow.four_tuple.dst_port
        if (src_ip not in pod_ip_to_id and src_ip not in svc_ip_to_id) or \
                (dst_ip not in pod_ip_to_id and dst_ip not in svc_ip_to_id):
            continue
        tmp_dict = flow.short_json()

        # source IP is a Pod IP
        if src_ip in pod_ip_to_id:
            tmp_dict["src"]["pod"] = compress_info(pods[pod_ip_to_id[src_ip]])
            if src_ip in pod_ip_to_svc_id:
                tmp_dict["src"]["service"] = compress_info(services[pod_ip_to_svc_id[src_ip]])
        # source IP is a Service IP
        else:
            tmp_dict["src"]["service"] = compress_info(services[svc_ip_to_id[src_ip]])

        # destination IP is a Pod IP
        if dst_ip in pod_ip_to_id:
            tmp_dict["dst"]["pod"] = compress_info(pods[pod_ip_to_id[dst_ip]])
            if dst_ip in pod_ip_to_svc_id:
                tmp_dict["dst"]["service"] = compress_info(services[pod_ip_to_svc_id[dst_ip]])
        # destination IP is a Service IP
        else:
            tmp_dict["dst"]["service"] = compress_info(services[svc_ip_to_id[dst_ip]])

        processed_records.append(json.dumps(tmp_dict))

    return processed_records


if __name__ == "__main__":
    with open(LOG_FILE, 'r', encoding='utf8') as f:
        content = f.readlines()
    with open(REPORT_FILE, "r", encoding='utf8') as f:
        data = json.load(f)
    rcd = link_with_opt(content, data)
    # print(len(rcd))
    print('\n'.join(rcd))
