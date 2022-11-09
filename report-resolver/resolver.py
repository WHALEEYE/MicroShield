import json
import os
import time
from enum import Enum

import yaml

import templates

LABEL_PREFIX = "kubernetes_labels_"
NAME_KEY = "kubernetes_name"
NAMESPACE_KEY = "kubernetes_namespace"
SERVICE_SELECTOR = "kubernetes_selector"
K8S_NS_LABEL = "kubernetes.io/metadata.name"
UUID_KEY = "kubernetes_cluster_uuid"
IGNORED_LABELS = ["controller-revision-hash", "statefulset.kubernetes.io/pod-name"]


def debug_info(info):
    if debug:
        print(f"\033[35m[DEBUG] {info}\033[0m")


class ResourceInfo:

    def __init__(self, resource_name, labels, namespace):
        self.name = resource_name
        self.labels = labels
        self.namespace = namespace

    def __eq__(self, other):
        return self.name == other.name and self.namespace == other.namespace


class Policy:
    """
    Represents a policy. Each policy object can generate a policy YAML file.
    """

    def __init__(self, resource_name, inside_labels, namespace, resource_type):
        self.name = f"{resource_type.name.lower()}-{resource_name}-{namespace}"
        self.template = templates.policy_template(self.name, namespace, inside_labels, False)
        self.rules = {}

    def add_rule(self, direction, outside_resource_id, outside_resource_info, port):
        if outside_resource_id not in self.rules:
            self.rules[outside_resource_id] = Rule(direction, outside_resource_info, port)
        elif port not in self.rules[outside_resource_id].ports:
            self.rules[outside_resource_id].add_port(port)

    def generate_yaml(self):
        if not self.rules:
            return None
        for pod_id, rule in self.rules.items():
            is_ingress = rule.direction == Direction.INGRESS
            rule_frame = templates.rule_template(is_ingress)
            pod_selector = rule_frame["from" if is_ingress else "to"][0]
            pod_selector["namespaceSelector"]["matchLabels"][K8S_NS_LABEL] = rule.outside_resource_ns
            pod_selector["podSelector"]["matchLabels"] = rule.outside_resource_labels
            for port in rule.ports:
                rule_frame["ports"].append({"port": port})
            self.template["spec"]["ingress" if is_ingress else "egress"].append(rule_frame)
        return yaml.dump(self.template)


class Direction(Enum):
    INGRESS = 1
    EGRESS = 2


class ResourceType(Enum):
    POD = 1
    DEPLOYMENT = 2


class Rule:

    def __init__(self, direction, outside_resource_info, port):
        self.direction = direction
        self.outside_resource_labels = outside_resource_info.labels
        self.outside_resource_ns = outside_resource_info.namespace
        self.ports = [port]

    def add_port(self, port):
        self.ports.append(port)

    def __eq__(self, other):
        return self.direction == other.direction and self.outside_resource_labels == other.outside_resource_labels and \
               self.outside_resource_ns == other.outside_resource_ns and self.ports == other.ports


def get_port_from_enp_id(enp_id):
    return int(enp_id.split(";")[-1])


def get_parent_id(info, parent_type):
    if "parents" in info and info["parents"] is not None:
        if parent_type in info["parents"]:
            return info["parents"][parent_type][0]
    return None


def parse_label(latest_info):
    """
    Parse the label string to a dictionary.
    """
    labels = {}
    for key, value in latest_info.items():
        if key.startswith(LABEL_PREFIX):
            label_name = key[len(LABEL_PREFIX):]
            if label_name in IGNORED_LABELS:
                continue
            labels[key[len(LABEL_PREFIX):]] = value["value"]
    return labels


def assemble_proc_id(host_node_id, pid):
    host_id = host_node_id.split(";")[0]
    return host_id + ";" + pid


def find_parent_container_id(proc_info, procs):
    failed_before = False
    while True:
        if get_parent_id(proc_info, "container") is not None:
            if failed_before:
                debug_info("Fallback applied when finding container ID: Go to Parent")
            debug_info("Found parent container ID")
            debug_info("---------------------------------------")
            return get_parent_id(proc_info, "container")
        debug_info(f"Failed to find parent container ID of {proc_info['id']}")
        if "latest" not in proc_info:
            debug_info("---------------------------------------")
            return None
        latest_info = proc_info["latest"]
        if "ppid" not in latest_info or "host_node_id" not in latest_info:
            debug_info("---------------------------------------")
            return None
        prt_proc_id = assemble_proc_id(latest_info["host_node_id"]["value"], latest_info["ppid"]["value"])
        if prt_proc_id not in procs:
            debug_info("---------------------------------------")
            return None
        proc_info = procs[prt_proc_id]
        failed_before = True
        debug_info(f"Go to Parent Proc: {prt_proc_id}")


def analyze_report(report, uuid):
    process_to_pod = {}
    enp_to_pod = {}
    enp_to_adj = {}
    pod_id_to_rsc_id = {}
    resource_id_to_info = {}

    policies = {}

    enps = report["Endpoint"]["nodes"]
    procs = report["Process"]["nodes"]
    ctns = report["Container"]["nodes"]
    pods = report["Pod"]["nodes"]
    deps = report["Deployment"]["nodes"]

    for proc_id, proc_info in procs.items():
        parent_ctn_id = find_parent_container_id(proc_info, procs)
        if parent_ctn_id not in ctns:
            continue
        prt_pod_id = get_parent_id(ctns[parent_ctn_id], "pod")
        if prt_pod_id not in pods:
            continue
        if pods[prt_pod_id]["latest"][UUID_KEY]["value"] != uuid:
            continue
        process_to_pod[proc_id] = prt_pod_id

    for enp_id, enp_info in enps.items():
        enp_to_adj[enp_id] = enp_info["adjacency"] if "adjacency" in enp_info else []
        if "latest" not in enp_info:
            continue
        enp_latest = enp_info["latest"]
        if "host_node_id" not in enp_latest or "pid" not in enp_latest:
            continue
        proc_id = assemble_proc_id(enp_latest["host_node_id"]["value"], enp_latest["pid"]["value"])
        if proc_id not in process_to_pod:
            continue
        enp_to_pod[enp_id] = process_to_pod[proc_id]

    for pod_id, pod_info in pods.items():
        pod_latest = pod_info["latest"]
        labels = parse_label(pod_latest)
        namespace = pod_latest[NAMESPACE_KEY]["value"]
        pod_name = pod_latest[NAME_KEY]["value"]
        prt_dep_id = get_parent_id(pods[pod_id], "deployment")
        resource_name = pod_name
        resource_id = pod_id
        resource_type = ResourceType.POD
        if prt_dep_id in deps and "latest" in deps[prt_dep_id]:
            resource_id = prt_dep_id
            resource_type = ResourceType.DEPLOYMENT
            resource_name = deps[prt_dep_id]["latest"][NAME_KEY]["value"]
        pod_id_to_rsc_id[pod_id] = resource_id
        if resource_id not in resource_id_to_info:
            resource_id_to_info[resource_id] = ResourceInfo(resource_name, labels, namespace)
        policies[resource_id] = Policy(resource_name, labels, namespace, resource_type)

    for enp_id, pod_id in enp_to_pod.items():
        adj_enps = enp_to_adj[enp_id]
        for adj_enp_id in adj_enps:
            if adj_enp_id not in enp_to_pod:
                continue
            adj_pod_id = enp_to_pod[adj_enp_id]
            if adj_pod_id == pod_id:
                continue
            adj_rsc_id = pod_id_to_rsc_id[adj_pod_id]
            rsc_id = pod_id_to_rsc_id[pod_id]
            policies[rsc_id].add_rule(Direction.EGRESS, adj_rsc_id, resource_id_to_info[adj_rsc_id],
                                      get_port_from_enp_id(adj_enp_id))
            policies[adj_rsc_id].add_rule(Direction.INGRESS, rsc_id, resource_id_to_info[rsc_id],
                                          get_port_from_enp_id(adj_enp_id))

    policy_yamls = {}
    for policy in policies.values():
        if policy.rules:
            policy_yamls[policy.name] = policy.generate_yaml()

    return policy_yamls


if __name__ == "__main__":
    debug = True
    start_time = time.time()
    # create folder named "policies" if not exist
    if not os.path.exists("policies"):
        os.makedirs("policies")
    # delete all files in the folder
    for file in os.listdir("policies"):
        os.remove(os.path.join("policies", file))
    test_report = json.load(open("report.json"))
    files = analyze_report(test_report, "33d1901faed141cf8ccacf5e94961607")
    for name, content in files.items():
        with open("policies/" + name + ".yaml", "w") as f:
            f.write(content)
    print("Time used: " + str(time.time() - start_time))
